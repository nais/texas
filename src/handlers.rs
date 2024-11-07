use axum::extract::{FromRequest, Request};
use axum::{async_trait, Form, RequestExt};
use std::collections::HashMap;

use crate::claims::{ClientAssertion, JWTBearerAssertion};
use crate::config::Config;
use crate::identity_provider::*;
use crate::jwks;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use jsonwebtoken as jwt;
use jsonwebtoken::Algorithm::RS512;
use jsonwebtoken::DecodingKey;
use log::{error, info};
use serde_json::{Value};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use crate::grants::{ClientCredentials, JWTBearer, OnBehalfOf, TokenExchange};

#[utoipa::path(
    post,
    path = "/api/v1/token",
    request_body(
        content(
            (TokenRequest = "application/json"),
            (TokenRequest = "application/x-www-form-urlencoded"),
        ),
        description = "Request a machine-to-machine token for a given `target` from the specified identity provider.",
        examples(
            ("Generate a token for Maskinporten" = (value = json!(TokenRequest{
                identity_provider: IdentityProvider::Maskinporten,
                target: "altinn:serviceowner/rolesandrights".to_string(),
            }))),
            ("Generate a token for Azure AD" = (value = json!(TokenRequest{
                identity_provider: IdentityProvider::AzureAD,
                target: "cluster:namespace:application".to_string(),
            }))),
        ),
    ),
    responses(
        (status = OK, description = "Success", body = TokenResponse, content_type = "application/json",
            examples(
                ("Token response" = (value = json!(TokenResponse{
                    // This token comes from mock-oauth2-server and is not a security issue
                    access_token: "eyJraWQiOiJ0b2tlbngiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyZjNjM2Y4YS03NTYwLTRjNWMtYmM4My0yNzVhY2Q1MWU1N2YiLCJhdWQiOiJteS10YXJnZXQiLCJuYmYiOjE3MzA5NzYxODQsImF6cCI6InlvbG8iLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdG9rZW54IiwiZXhwIjoxNzMwOTc5Nzg0LCJpYXQiOjE3MzA5NzYxODQsImp0aSI6IjBmNTM3M2YyLThjYmUtNDczOS05ZDU1LWY5MzE4YmFiNWQ2NyIsInRpZCI6InRva2VueCJ9.aQ-2TcdDRkWXbi3en6eMwzjSkYLH-S6aiAyss8MkkAPT_RGlZF_eCKFFsaKJ9YwQAzs4BN_d13W-xejPf6B_3Mn7xasDX_5r-M5ZwXxPWkRe5daqdqznF-vPAnIIjmqynjEYgijn79Rajorcu1sgW4bsrByp1lXNhntHar-8x62S_5oY40tEjIAHv7q2zKRxoKxKlcNpnLpKnZWrkJj7SboiCpGWc-W4JtcnNTHgKRXcFVfXSGD6EhHQ2HLDtmWJkk8NHTnjLI8IRt0mrkOs_nt2jNDDpH9ViqlWi7FOwi4C0OSfGHGukDYOeRc3vICgFGHyi0G6Avq9YXtuAP62_A".to_string(),
                    token_type: TokenType::Bearer,
                    expires_in_seconds: 3599,
                }))),
        )),
        (status = BAD_REQUEST, description = "Bad request", body = ErrorResponse, content_type = "application/json"),
        (status = INTERNAL_SERVER_ERROR, description = "Server error", body = ErrorResponse, content_type = "application/json"),
    )
)]
pub async fn token(
    State(state): State<HandlerState>,
    JsonOrForm(request): JsonOrForm<TokenRequest>,
) -> impl IntoResponse {
    match &request.identity_provider {
        IdentityProvider::AzureAD => state.azure_ad_cc.read().await.get_token(request).await.into_response(),
        IdentityProvider::Maskinporten => state.maskinporten.read().await.get_token(request).await.into_response(),
        IdentityProvider::TokenX => (StatusCode::BAD_REQUEST, "TokenX does not support machine-to-machine tokens".to_string()).into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/token/exchange",
    request_body(
        content(
            (TokenExchangeRequest = "application/json"),
            (TokenExchangeRequest = "application/x-www-form-urlencoded"),
        ),
        description = "Exchange a user token for a new token, scoped to the given `target`. The new token contains the user context that allows your application to act on behalf of the user.",
        examples(
            ("Exchange a token using TokenX" = (value = json!(TokenExchangeRequest{
                identity_provider: IdentityProvider::TokenX,
                target: "cluster:namespace:application".to_string(),
                user_token: "eyJraWQiOiJpZHBvcnRlbiIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIxOTQyMmVhNC04ZWUwLTQ0YTYtOThjNi0zODc0MjAyN2YyYWQiLCJhdWQiOiJkZWZhdWx0IiwibmJmIjoxNzMwOTc4MzgwLCJhenAiOiJ5b2xvIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2lkcG9ydGVuIiwiZXhwIjoxNzMwOTgxOTgwLCJpYXQiOjE3MzA5NzgzODAsImp0aSI6IjBhMDU5MDc3LTQwNzEtNDdlYS04MmM2LTU2NTY2OTk3Nzg3MiIsInRpZCI6ImlkcG9ydGVuIn0.JwgvrhPMRMaNJngiR6hzHfhg5Qy-yV4zuAtxRRvdjX4g2cBmsWj305U-lHJGsozjFhpGpA0lAn16bD3l1Z6x7CsO6kbQEwKQiJE9gB61RwSUEjV4-RbpVrKMJwppQg8gPLrb4SbTjjkylD7B9CfPiIZYtCNr6d-J0lupYiB7IlK7anUImCv7RqXTuhH0aklVpVmxOZRhzHJ6_WfhWS54MysZmeRZwOsSO-ofkrcznFFaArS1ODfrYgHx4dgVBjkE7RTcLP7nuwNtvbLg9ZVvIAT4Xh-3fu0pCL9NXoDiqBsQ0SukBAlBFfWQBFu1-34-bXkfRz2RgCR964WbKUQ8gQ".to_string(),
            }))),
            ("Exchange a token using Azure AD" = (value = json!(TokenExchangeRequest{
                identity_provider: IdentityProvider::AzureAD,
                target: "cluster:namespace:application".to_string(),
                user_token: "eyJraWQiOiJhenVyZWFkIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI1ZDYzMDliNi05OGUzLTQ1ODAtYTQwNS02MDExYzhhNjExYzgiLCJhdWQiOiJkZWZhdWx0IiwibmJmIjoxNzMwOTc4MjQyLCJhenAiOiJ5b2xvIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F6dXJlYWQiLCJleHAiOjE3MzA5ODE4NDIsImlhdCI6MTczMDk3ODI0MiwianRpIjoiZTU4ZGM2ZjctZjQ0NC00YzcxLThlNzAtNzRhNWY1MTRlZDAwIiwidGlkIjoiYXp1cmVhZCJ9.KhySKFTJVaE6tYhsxCZonYMXv4fKwjtOI4YIAIoOs3DwaXoynTvy2lgiHSfisq-jLTJFGf9eGNbvwc3jUtypclVpYy_8d3xbvuu6jrOA1zWYagZjYr1FNN1g8tlF0SXjtkK_Bg-eZusLnEEbrZK1KnQRWN0I5fXqS7-IVe07hKTOE1teg7of2nCjfJ-iOXhf1mkXqCoUfSbJuUX2PEUs0b9yXAh_J-5P75T6130KBfRw5T5gYI0Kab3u2vm6t-ihT2Kz0aMkUGv_39myDgiwP4TV2vt4PhUiwefPo7KD-4_dkHc7Q5xUv-DWgTLUfXL2lOWf2d0C5tVExLB86jq8hw".to_string(),
            }))),
        ),
    ),
    responses(
        (status = OK, description = "Success", body = TokenResponse, content_type = "application/json",
            examples(
                ("Token response" = (value = json!(TokenResponse{
                    access_token: "eyJraWQiOiJhenVyZWFkIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI1ZDYzMDliNi05OGUzLTQ1ODAtYTQwNS02MDExYzhhNjExYzgiLCJhdWQiOiJteS10YXJnZXQiLCJuYmYiOjE3MzA5NzgyNDIsImF6cCI6InlvbG8iLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXp1cmVhZCIsImV4cCI6MTczMDk4MTg0MiwiaWF0IjoxNzMwOTc4MjQyLCJqdGkiOiJkNDQ4NTRjNC1iYmZhLTRmZTMtYTMyNC0xZDQyNjdkZjdjZjYiLCJ0aWQiOiJhenVyZWFkIn0.fqTw40aXkzGqet7mMRfK-8cUICzBW7SKIb5UOh6sTvrqprJEtF1HG8MLRcjgjEVwShNkYzJiUZzOC7GSxcuYSiDFg9rboR0QPvTtYsPHWjBGCpvo7lJl27oyqS7QUS83Gsc3oGbCYxc_f4TWOVP8j6pVVZjHAietUd7A-KSwck_YkhmJxKpx7HUhK11AOLjcUlJzb_GpAf1zbog9aIsg9gg9DvWIXtyGqmmBAjr69faFzg7s6KssAQS6A3Qcn19nHC2-J_Ic5q-b8gIDGTq2w62GukbYjyjI7pMYYE04QPPmFI1jdKS9QygW8zX2wQ-10Tc4o4BmMMRjp1RvMm3t6Q".to_string(),
                    token_type: TokenType::Bearer,
                    expires_in_seconds: 3599,
                }))),
        )),
        (status = BAD_REQUEST, description = "Bad request", body = ErrorResponse, content_type = "application/json"),
        (status = INTERNAL_SERVER_ERROR, description = "Server error", body = ErrorResponse, content_type = "application/json"),
    )
)]
pub async fn token_exchange(
    State(state): State<HandlerState>,
    JsonOrForm(request): JsonOrForm<TokenExchangeRequest>,
) -> impl IntoResponse {
    match &request.identity_provider {
        IdentityProvider::AzureAD => state.azure_ad_obo.read().await.exchange_token(request).await.into_response(),
        IdentityProvider::Maskinporten => (StatusCode::BAD_REQUEST, "Maskinporten does not support token exchange".to_string()).into_response(),
        IdentityProvider::TokenX => state.token_x.read().await.exchange_token(request).await.into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/introspect",
    request_body(
        content(
            (IntrospectRequest = "application/json"),
            (IntrospectRequest = "application/x-www-form-urlencoded"),
        ),
        description = "Introspect a token. This means to validate the token and returns its claims. The `active` is not part of the claims, but indicates whether the token is valid.",
        examples(
            ("Token introspection" = (value = json!(IntrospectRequest{
                token: "eyJraWQiOiJ0b2tlbngiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJlMDE1NTQyYy0wZjgxLTQwZjUtYmJkOS03YzNkOTM2NjI5OGYiLCJhdWQiOiJteS10YXJnZXQiLCJuYmYiOjE3MzA5NzcyOTMsImF6cCI6InlvbG8iLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdG9rZW54IiwiZXhwIjoxNzMwOTgwODkzLCJpYXQiOjE3MzA5NzcyOTMsImp0aSI6ImU3Y2JhZGMzLTZiZGEtNDljMC1hMTk2LWM0NzMyOGRhODgwZSIsInRpZCI6InRva2VueCJ9.SIme9o5YE6pZXT9IMAx5upV3V4ww_TnDlqZG203pkySPBd_VqNGBXzOKHeOasIDpXEMlf8Yc-1nKgySjGOT3c46PIHEUrhQFXF6s9OpJAYAwy7L2n2DIFfEOLt8EpwSpM5hWDwnGpSdvebWlmoaA3ImFEB5dtnxLrVG-7dYEEzZjMfBOKFWrPp03FTO4qKOJUqCZR0tmZRmcPzymPWFIMjP2FTj6iz9zai93dhQmdvNVMGL9HBXF6ewKf_CTlUIx9XpwI2M-dhlyH2PIxyhix7Amuff_mHuEHTuCAFqMfjon-F438uyZmgicyrvhoUGxV8W1PfZEiLIv0RBeWRJ9gw".to_string()
            })))
        ),
    ),
    responses(
        (status = OK, description = "Success", body = IntrospectResponse, content_type = "application/json",
        examples(
                ("Valid token" = (value = json!(IntrospectResponse::new(HashMap::from(
                    [
                    ("aud".to_string(), Value::String("my-target".into())),
                    ("azp".to_string(), Value::String("yolo".into())),
                    ("exp".to_string(), Value::Number(1730980893.into())),
                    ("iat".to_string(), Value::Number(1730977293.into())),
                    ("iss".to_string(), Value::String("http://localhost:8080/tokenx".into())),
                    ("jti".to_string(), Value::String("e7cbadc3-6bda-49c0-a196-c47328da880e".into())),
                    ("nbf".to_string(), Value::Number(1730977293.into())),
                    ("sub".to_string(), Value::String("e015542c-0f81-40f5-bbd9-7c3d9366298f".into())),
                    ("tid".to_string(), Value::String("tokenx".into())),
                    ],
                ))))),
                ("Invalid token" = (value = json!(IntrospectResponse::new_invalid("token is expired".to_string())))),
             )
        ),
    )
)]
pub async fn introspect(
    State(state): State<HandlerState>,
    JsonOrForm(request): JsonOrForm<IntrospectRequest>,
) -> Result<impl IntoResponse, Json<IntrospectResponse>> {
    #[derive(serde::Deserialize)]
    struct IssuerClaim {
        iss: String,
    }

    // Need to decode the token to get the issuer before we actually validate it.
    let mut validation = jwt::Validation::new(RS512);
    validation.validate_exp = false;
    validation.insecure_disable_signature_validation();
    let key = DecodingKey::from_secret(&[]);
    let token_data = jwt::decode::<IssuerClaim>(&request.token, &key, &validation).
        map_err(IntrospectResponse::new_invalid)?;

    let identity_provider = state.identity_provider_from_issuer(&token_data.claims.iss);
    let claims = match identity_provider {
        Some(IdentityProvider::Maskinporten) => state.maskinporten.write().await.introspect(request.token).await,
        Some(IdentityProvider::AzureAD) => state.azure_ad_obo.write().await.introspect(request.token).await,
        Some(IdentityProvider::TokenX) => state.token_x.write().await.introspect(request.token).await,
        None => IntrospectResponse::new_invalid("token has unknown issuer".to_string()),
    };

    Ok((StatusCode::OK, Json(claims)))
}

#[derive(Clone)]
pub struct HandlerState {
    pub cfg: Config,
    pub maskinporten: Arc<RwLock<Provider<JWTBearer, JWTBearerAssertion>>>,
    pub azure_ad_obo: Arc<RwLock<Provider<OnBehalfOf, ClientAssertion>>>,
    pub azure_ad_cc: Arc<RwLock<Provider<ClientCredentials, ClientAssertion>>>,
    pub token_x: Arc<RwLock<Provider<TokenExchange, ClientAssertion>>>,
}

#[derive(Error, Debug)]
pub enum InitError {
    #[error("invalid private JWK format")]
    Jwk,

    #[error("fetch JWKS from remote endpoint: {0}")]
    Jwks(#[from] jwks::Error),
}

impl HandlerState {
    pub fn identity_provider_from_issuer(&self, iss: &str) -> Option<IdentityProvider> {
        match iss {
            s if s == self.cfg.maskinporten_issuer => Some(IdentityProvider::Maskinporten),
            s if s == self.cfg.azure_ad_issuer => Some(IdentityProvider::AzureAD),
            s if s == self.cfg.token_x_issuer => Some(IdentityProvider::TokenX),
            _ => None,
        }
    }

    pub async fn from_config(cfg: Config) -> Result<Self, InitError> {
        // TODO: we should be able to conditionally enable certain providers based on the configuration
        info!("Fetch JWKS for Maskinporten...");
        let maskinporten: Provider<JWTBearer, JWTBearerAssertion> = Provider::new(
            cfg.maskinporten_client_id.clone(),
            cfg.maskinporten_token_endpoint.clone(),
            cfg.maskinporten_client_jwk.clone(),
            jwks::Jwks::new(
                &cfg.maskinporten_issuer.clone(),
                &cfg.maskinporten_jwks_uri.clone(),
                None,
            ).await?,
        ).ok_or(InitError::Jwk)?;

        // TODO: these two AAD providers should be a single provider, but we need to figure out how to handle the different token requests
        info!("Fetch JWKS for Azure AD (on behalf of)...");
        let azure_ad_obo: Provider<OnBehalfOf, ClientAssertion> = Provider::new(
            cfg.azure_ad_client_id.clone(),
            cfg.azure_ad_token_endpoint.clone(),
            cfg.azure_ad_client_jwk.clone(),
            jwks::Jwks::new(
                &cfg.azure_ad_issuer.clone(),
                &cfg.azure_ad_jwks_uri.clone(),
                Some(cfg.azure_ad_client_id.clone())
            ).await?,
        )
            .ok_or(InitError::Jwk)?;

        info!("Fetch JWKS for Azure AD (client credentials)...");
        let azure_ad_cc: Provider<ClientCredentials, ClientAssertion> =
            Provider::new(
                cfg.azure_ad_client_id.clone(),
                cfg.azure_ad_token_endpoint.clone(),
                cfg.azure_ad_client_jwk.clone(),
                jwks::Jwks::new(
                    &cfg.azure_ad_issuer.clone(),
                    &cfg.azure_ad_jwks_uri.clone(),
                    Some(cfg.azure_ad_client_id.clone())
                ).await?,
            )
                .ok_or(InitError::Jwk)?;

        info!("Fetch JWKS for TokenX...");
        let token_x: Provider<TokenExchange, ClientAssertion> = Provider::new(
            cfg.token_x_client_id.clone(),
            cfg.token_x_token_endpoint.clone(),
            cfg.token_x_client_jwk.clone(),
            jwks::Jwks::new(
                &cfg.token_x_issuer.clone(),
                &cfg.token_x_jwks_uri.clone(),
                Some(cfg.token_x_client_id.clone())
            ).await?,
        )
            .ok_or(InitError::Jwk)?;

        Ok(Self {
            cfg,
            maskinporten: Arc::new(RwLock::new(maskinporten)),
            azure_ad_obo: Arc::new(RwLock::new(azure_ad_obo)),
            azure_ad_cc: Arc::new(RwLock::new(azure_ad_cc)),
            token_x: Arc::new(RwLock::new(token_x)),
        })
    }
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("identity provider error: {0}")]
    UpstreamRequest(reqwest::Error),

    #[error("upstream: status code {status_code}: {error}")]
    Upstream {
        status_code: StatusCode,
        error: ErrorResponse,
    },

    #[error("invalid JSON in token response: {0}")]
    JSON(reqwest::Error),

    #[error("cannot sign JWT claims")]
    Sign,

    #[error("invalid token: {0}")]
    Validate(jwt::errors::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        let error_response = ErrorResponse::from(self);
        let status_code = StatusCode::from(error_response.error.clone());
        (status_code, Json(error_response)).into_response()
    }
}

pub struct JsonOrForm<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for JsonOrForm<T>
where
    S: Send + Sync,
    Json<T>: FromRequest<()>,
    Form<T>: FromRequest<()>,
    T: 'static,
{
    type Rejection = Response;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type_header = req.headers().get(CONTENT_TYPE);
        let content_type = content_type_header.and_then(|value| value.to_str().ok());

        if let Some(content_type) = content_type {
            if content_type.starts_with("application/json") {
                let Json(payload) = req.extract().await.map_err(IntoResponse::into_response)?;
                return Ok(Self(payload));
            }

            if content_type.starts_with("application/x-www-form-urlencoded") {
                let Form(payload) = req.extract().await.map_err(IntoResponse::into_response)?;
                return Ok(Self(payload));
            }
        }

        Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response())
    }
}
