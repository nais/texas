use crate::claims::{Assertion, ClientAssertion, JWTBearerAssertion};
use crate::config::Config;
use crate::grants::{ClientCredentials, JWTBearer, OnBehalfOf, TokenExchange, TokenRequestBuilder};
use crate::identity_provider::*;
use crate::{config, jwks};
use axum::extract::rejection::{FormRejection, JsonRejection};
use axum::extract::FromRequest;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum::{async_trait, Form};
use jsonwebtoken as jwt;
use log::{error, info};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::instrument;

#[utoipa::path(
    post,
    path = "/api/v1/token",
    tag = "Endpoints",
    request_body(
        content(
            (TokenRequest = "application/json"),
            (TokenRequest = "application/x-www-form-urlencoded"),
        ),
        description = "Request a machine-to-machine token from the specified identity provider and for a given target.",
        examples(
            ("Generate a token for Maskinporten" = (value = json!(TokenRequest{
                identity_provider: IdentityProvider::Maskinporten,
                target: "altinn:serviceowner/rolesandrights".to_string(),
            }))),
            ("Generate a token for Azure AD" = (value = json!(TokenRequest{
                identity_provider: IdentityProvider::AzureAD,
                target: "api://cluster.namespace.application/.default".to_string(),
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
#[instrument(skip_all, name = "Handle /api/v1/token")]
pub async fn token(State(state): State<HandlerState>, JsonOrForm(request): JsonOrForm<TokenRequest>) -> Result<impl IntoResponse, ApiError> {
    for provider in state.providers {
        if !provider.read().await.should_handle_token_request(&request) {
            continue;
        }
        let response = provider.read().await.get_token(request).await?;
        return Ok(Json(response));
    }

    Err(ApiError::TokenRequestUnsupported(request.identity_provider))
}

#[utoipa::path(
    post,
    path = "/api/v1/token/exchange",
    tag = "Endpoints",
    request_body(
        content(
            (TokenExchangeRequest = "application/json"),
            (TokenExchangeRequest = "application/x-www-form-urlencoded"),
        ),
        description = "Exchange a user's token for a machine token, scoped to the given target. The returned token allows your application to act on behalf of the user.",
        examples(
            ("Exchange a token using TokenX" = (value = json!(TokenExchangeRequest{
                identity_provider: IdentityProvider::TokenX,
                target: "cluster:namespace:application".to_string(),
                user_token: "eyJraWQiOiJpZHBvcnRlbiIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIxOTQyMmVhNC04ZWUwLTQ0YTYtOThjNi0zODc0MjAyN2YyYWQiLCJhdWQiOiJkZWZhdWx0IiwibmJmIjoxNzMwOTc4MzgwLCJhenAiOiJ5b2xvIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2lkcG9ydGVuIiwiZXhwIjoxNzMwOTgxOTgwLCJpYXQiOjE3MzA5NzgzODAsImp0aSI6IjBhMDU5MDc3LTQwNzEtNDdlYS04MmM2LTU2NTY2OTk3Nzg3MiIsInRpZCI6ImlkcG9ydGVuIn0.JwgvrhPMRMaNJngiR6hzHfhg5Qy-yV4zuAtxRRvdjX4g2cBmsWj305U-lHJGsozjFhpGpA0lAn16bD3l1Z6x7CsO6kbQEwKQiJE9gB61RwSUEjV4-RbpVrKMJwppQg8gPLrb4SbTjjkylD7B9CfPiIZYtCNr6d-J0lupYiB7IlK7anUImCv7RqXTuhH0aklVpVmxOZRhzHJ6_WfhWS54MysZmeRZwOsSO-ofkrcznFFaArS1ODfrYgHx4dgVBjkE7RTcLP7nuwNtvbLg9ZVvIAT4Xh-3fu0pCL9NXoDiqBsQ0SukBAlBFfWQBFu1-34-bXkfRz2RgCR964WbKUQ8gQ".to_string(),
            }))),
            ("Exchange a token using Azure AD" = (value = json!(TokenExchangeRequest{
                identity_provider: IdentityProvider::AzureAD,
                target: "api://cluster.namespace.application/.default".to_string(),
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
#[instrument(skip_all, name = "Handle /api/v1/token/exchange")]
pub async fn token_exchange(State(state): State<HandlerState>, JsonOrForm(request): JsonOrForm<TokenExchangeRequest>) -> Result<impl IntoResponse, ApiError> {
    for provider in state.providers {
        if !provider.read().await.should_handle_token_exchange_request(&request) {
            continue;
        }
        let response = provider.read().await.exchange_token(request).await?;
        return Ok(Json(response));
    }

    Err(ApiError::TokenExchangeUnsupported(request.identity_provider))
}

#[utoipa::path(
    post,
    path = "/api/v1/introspect",
    tag = "Endpoints",
    request_body(
        content(
            (IntrospectRequest = "application/json"),
            (IntrospectRequest = "application/x-www-form-urlencoded"),
        ),
        description = "Validate a token and return its claims and metadata. The response object's _active_ field will be set to either true or false for valid and invalid tokens, respectively. The identity provider determines which claims are returned. Please see the examples and/or Nais documentation for details.",
        examples(
            ("Token introspection" = (value = json!(IntrospectRequest{
                token: "eyJraWQiOiJ0b2tlbngiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJlMDE1NTQyYy0wZjgxLTQwZjUtYmJkOS03YzNkOTM2NjI5OGYiLCJhdWQiOiJteS10YXJnZXQiLCJuYmYiOjE3MzA5NzcyOTMsImF6cCI6InlvbG8iLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdG9rZW54IiwiZXhwIjoxNzMwOTgwODkzLCJpYXQiOjE3MzA5NzcyOTMsImp0aSI6ImU3Y2JhZGMzLTZiZGEtNDljMC1hMTk2LWM0NzMyOGRhODgwZSIsInRpZCI6InRva2VueCJ9.SIme9o5YE6pZXT9IMAx5upV3V4ww_TnDlqZG203pkySPBd_VqNGBXzOKHeOasIDpXEMlf8Yc-1nKgySjGOT3c46PIHEUrhQFXF6s9OpJAYAwy7L2n2DIFfEOLt8EpwSpM5hWDwnGpSdvebWlmoaA3ImFEB5dtnxLrVG-7dYEEzZjMfBOKFWrPp03FTO4qKOJUqCZR0tmZRmcPzymPWFIMjP2FTj6iz9zai93dhQmdvNVMGL9HBXF6ewKf_CTlUIx9XpwI2M-dhlyH2PIxyhix7Amuff_mHuEHTuCAFqMfjon-F438uyZmgicyrvhoUGxV8W1PfZEiLIv0RBeWRJ9gw".to_string(),
                identity_provider: IdentityProvider::TokenX,
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
#[instrument(skip_all, name = "Handle /api/v1/introspect")]
pub async fn introspect(State(state): State<HandlerState>, JsonOrForm(request): JsonOrForm<IntrospectRequest>) -> Result<impl IntoResponse, Json<IntrospectResponse>> {
    for provider in state.providers {
        if !provider.read().await.should_handle_introspect_request(&request) {
            continue;
        }
        // We need to acquire a write lock here because introspect
        // might refresh its JWKS in-flight.
        return Ok(Json(provider.write().await.introspect(request.token).await));
    }

    let error_message = match request.issuer() {
        None => "token is invalid".to_string(),
        Some(iss) => format!("unrecognized issuer: '{iss}'"),
    };

    Err(Json(IntrospectResponse::new_invalid(error_message)))
}

#[derive(Clone)]
pub struct HandlerState {
    pub cfg: Config,
    pub providers: Vec<Arc<RwLock<Box<dyn ProviderHandler>>>>,
}

#[derive(Error, Debug)]
pub enum InitError {
    #[error("invalid private JWK format: {0}")]
    Jwk(ProviderError),

    #[error("fetch JWKS from remote endpoint: {0}")]
    Jwks(#[from] jwks::Error),
}

async fn new<R, A>(kind: IdentityProvider, provider_cfg: &config::Provider, audience: Option<String>) -> Result<Arc<RwLock<Box<dyn ProviderHandler>>>, InitError>
where
    R: TokenRequestBuilder + 'static,
    A: Assertion + 'static,
    Provider<R, A>: ShouldHandler,
{
    Ok(Arc::new(RwLock::new(Box::new(
        Provider::<R, A>::new(
            kind,
            provider_cfg.client_id.clone(),
            provider_cfg.token_endpoint.clone(),
            provider_cfg.client_jwk.clone(),
            jwks::Jwks::new(&provider_cfg.issuer.clone(), &provider_cfg.jwks_uri.clone(), audience).await?,
        ).map_err(InitError::Jwk)?,
    ))))
}

impl HandlerState {
    pub async fn from_config(cfg: Config) -> Result<Self, InitError> {
        let mut providers: Vec<Arc<RwLock<Box<dyn ProviderHandler>>>> = vec![];

        if let Some(provider_cfg) = &cfg.maskinporten {
            info!("Fetch JWKS for Maskinporten...");
            let provider = new::<JWTBearer, JWTBearerAssertion>(IdentityProvider::Maskinporten, provider_cfg, None).await?;
            providers.push(provider);
        }

        if let Some(provider_cfg) = &cfg.azure_ad {
            info!("Fetch JWKS for Azure AD (on behalf of)...");
            let provider = new::<OnBehalfOf, ClientAssertion>(IdentityProvider::AzureAD, provider_cfg, Some(provider_cfg.client_id.clone())).await?;
            providers.push(provider);

            info!("Fetch JWKS for Azure AD (client credentials)...");
            let provider = new::<ClientCredentials, ClientAssertion>(IdentityProvider::AzureAD, provider_cfg, Some(provider_cfg.client_id.clone())).await?;
            providers.push(provider);
        }

        if let Some(provider_cfg) = &cfg.token_x {
            info!("Fetch JWKS for TokenX...");
            let provider = new::<TokenExchange, ClientAssertion>(IdentityProvider::TokenX, provider_cfg, Some(provider_cfg.client_id.clone())).await?;
            providers.push(provider);
        }

        if let Some(provider_cfg) = &cfg.idporten {
            info!("Fetch JWKS for ID-porten...");
            let provider = new::<(), ()>(IdentityProvider::IDPorten, provider_cfg, Some(provider_cfg.client_id.clone())).await?;
            providers.push(provider);
        }

        Ok(Self { cfg, providers })
    }
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("identity provider error: {0}")]
    UpstreamRequest(reqwest::Error),

    #[error("upstream: status code {status_code}: {error}")]
    Upstream { status_code: StatusCode, error: ErrorResponse },

    #[error("invalid JSON in token response: {0}")]
    JSON(reqwest::Error),

    #[error("cannot sign JWT claims")]
    Sign,

    #[error("invalid token: {0}")]
    Validate(jwt::errors::Error),

    #[error("{0}")]
    UnsupportedMediaType(String),

    #[error("{0}")]
    UnprocessableContent(String),

    #[error("identity provider '{0}' is not configured")]
    UnsupportedIdentityProvider(IdentityProvider),

    #[error("identity provider '{0}' does not support token exchange")]
    TokenExchangeUnsupported(IdentityProvider),

    #[error("identity provider '{0}' does not support token requests")]
    TokenRequestUnsupported(IdentityProvider),
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
    T: 'static,
    Json<T>: FromRequest<S, Rejection=JsonRejection>,
    Form<T>: FromRequest<S, Rejection=FormRejection>,
{
    type Rejection = ApiError;

    #[instrument(skip_all, name = "Deserialize request")]
    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let content_type_header = req.headers().get(CONTENT_TYPE);
        let content_type = content_type_header.and_then(|value| value.to_str().ok());

        if let Some(content_type) = content_type {
            if content_type.starts_with("application/json") {
                return match Json::<T>::from_request(req, state).await {
                    Ok(payload) => Ok(Self(payload.0)),
                    Err(rejection) => Err(match rejection {
                        JsonRejection::MissingJsonContentType(err) => ApiError::UnsupportedMediaType(err.body_text()),
                        JsonRejection::JsonDataError(err) => ApiError::UnprocessableContent(err.body_text()),
                        JsonRejection::JsonSyntaxError(err) => ApiError::UnprocessableContent(err.body_text()),
                        JsonRejection::BytesRejection(err) => ApiError::UnprocessableContent(err.body_text()),
                        err => ApiError::UnprocessableContent(err.body_text()),
                    }),
                };
            }

            if content_type.starts_with("application/x-www-form-urlencoded") {
                return match Form::<T>::from_request(req, state).await {
                    Ok(payload) => Ok(Self(payload.0)),
                    Err(rejection) => Err(match rejection {
                        FormRejection::InvalidFormContentType(err) => ApiError::UnsupportedMediaType(err.body_text()),
                        FormRejection::FailedToDeserializeForm(err) => ApiError::UnprocessableContent(err.body_text()),
                        FormRejection::FailedToDeserializeFormBody(err) => ApiError::UnprocessableContent(err.body_text()),
                        FormRejection::BytesRejection(err) => ApiError::UnprocessableContent(err.body_text()),
                        err => ApiError::UnprocessableContent(err.body_text()),
                    }),
                };
            }
        }

        Err(ApiError::UnsupportedMediaType(format!(
            "unsupported media type: {}: expected one of `application/json`, `application/x-www-form-urlencoded`",
            content_type.unwrap_or("")
        )))
    }
}
