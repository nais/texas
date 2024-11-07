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

#[utoipa::path(
    post,
    path = "/api/v1/token",
    request_body(
        content(
            (TokenRequest = "application/json"),
            (TokenRequest = "application/x-www-form-urlencoded"),
        ),
        description = "Request a machine-to-machine token for a given `target`."
    ),
    responses(
        (status = OK, description = "Success", body = TokenResponse, content_type = "application/json"),
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
        description = "Exchange a user token for a new token, scoped to the given `target`. The new token contains the user context that allows your application to act on behalf of the user"
    ),
    responses(
        (status = OK, description = "Success", body = TokenResponse, content_type = "application/json"),
        (status = BAD_REQUEST, description = "Bad request", body = ErrorResponse, content_type = "application/json"),
        (status = INTERNAL_SERVER_ERROR, description = "Server error", body = ErrorResponse, content_type = "application/json"),
    )
)]
#[axum::debug_handler]
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
        description = "Introspect a token. This validates the token and returns its claims. The `active` field indicates whether the token is valid or not."
    ),
    responses(
        (status = OK, description = "Success", body = IntrospectResponse, content_type = "application/json",
        examples(
                ("Valid token" = (value = json!(IntrospectResponse::new(HashMap::from(
                    [("aud".to_string(), Value::String("dev-gcp:mynamespace:myapplication".to_string())),
                     ("iat".to_string(), Value::Number(1730969701.into())),
                     ("nbf".to_string(), Value::Number(1730969701.into())),
                     ("exp".to_string(), Value::Number(1730969731.into())),
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
    // Need to decode the token to get the issuer before we actually validate it.
    let mut validation = jwt::Validation::new(RS512);
    validation.validate_exp = false;
    validation.insecure_disable_signature_validation();
    let key = DecodingKey::from_secret(&[]);
    let token_data = jwt::decode::<Claims>(&request.token, &key, &validation).
        map_err(IntrospectResponse::new_invalid)?;

    let identity_provider = token_data.claims.identity_provider(state.cfg);
    let claims = match identity_provider {
        Some(IdentityProvider::Maskinporten) => state.maskinporten.write().await.introspect(request.token).await,
        Some(IdentityProvider::AzureAD) => state.azure_ad_obo.write().await.introspect(request.token).await,
        Some(IdentityProvider::TokenX) => state.token_x.write().await.introspect(request.token).await,
        None => IntrospectResponse::new_invalid("token has unknown issuer".to_string()),
    };

    Ok((StatusCode::OK, Json(claims)))
}

// TODO: rename to something more descriptive
#[derive(serde::Deserialize)]
struct Claims {
    iss: String,
}

impl Claims {
    pub fn identity_provider(&self, cfg: Config) -> Option<IdentityProvider> {
        match &self.iss {
            s if s == &cfg.maskinporten_issuer => Some(IdentityProvider::Maskinporten),
            s if s == &cfg.azure_ad_issuer => Some(IdentityProvider::AzureAD),
            s if s == &cfg.token_x_issuer => Some(IdentityProvider::TokenX),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct HandlerState {
    pub cfg: Config,
    pub maskinporten: Arc<RwLock<Provider<MaskinportenTokenRequest, JWTBearerAssertion>>>,
    pub azure_ad_obo: Arc<RwLock<Provider<AzureADOnBehalfOfTokenRequest, ClientAssertion>>>,
    pub azure_ad_cc: Arc<RwLock<Provider<AzureADClientCredentialsTokenRequest, ClientAssertion>>>,
    pub token_x: Arc<RwLock<Provider<TokenXTokenRequest, ClientAssertion>>>,
}

#[derive(Error, Debug)]
pub enum InitError {
    #[error("invalid private JWK format")]
    Jwk,

    #[error("fetch JWKS from remote endpoint: {0}")]
    Jwks(#[from] jwks::Error),
}

impl HandlerState {
    pub async fn from_config(cfg: Config) -> Result<Self, InitError> {
        // TODO: we should be able to conditionally enable certain providers based on the configuration
        info!("Fetch JWKS for Maskinporten...");
        let maskinporten: Provider<MaskinportenTokenRequest, JWTBearerAssertion> = Provider::new(
            cfg.maskinporten_client_id.clone(),
            cfg.maskinporten_token_endpoint.clone(),
            cfg.maskinporten_client_jwk.clone(),
            jwks::Jwks::new(&cfg.maskinporten_issuer.clone(), &cfg.maskinporten_jwks_uri.clone()).await?,
        ).ok_or(InitError::Jwk)?;

        // TODO: these two AAD providers should be a single provider, but we need to figure out how to handle the different token requests
        info!("Fetch JWKS for Azure AD (on behalf of)...");
        let azure_ad_obo: Provider<AzureADOnBehalfOfTokenRequest, ClientAssertion> = Provider::new(
            cfg.azure_ad_client_id.clone(),
            cfg.azure_ad_token_endpoint.clone(),
            cfg.azure_ad_client_jwk.clone(),
            jwks::Jwks::new(&cfg.azure_ad_issuer.clone(), &cfg.azure_ad_jwks_uri.clone()).await?,
        )
            .ok_or(InitError::Jwk)?;

        info!("Fetch JWKS for Azure AD (client credentials)...");
        let azure_ad_cc: Provider<AzureADClientCredentialsTokenRequest, ClientAssertion> =
            Provider::new(
                cfg.azure_ad_client_id.clone(),
                cfg.azure_ad_token_endpoint.clone(),
                cfg.azure_ad_client_jwk.clone(),
                jwks::Jwks::new(&cfg.azure_ad_issuer.clone(), &cfg.azure_ad_jwks_uri.clone()).await?,
            )
                .ok_or(InitError::Jwk)?;

        info!("Fetch JWKS for TokenX...");
        let token_x: Provider<TokenXTokenRequest, ClientAssertion> = Provider::new(
            cfg.token_x_client_id.clone(),
            cfg.token_x_token_endpoint.clone(),
            cfg.token_x_client_jwk.clone(),
            jwks::Jwks::new(&cfg.token_x_issuer.clone(), &cfg.token_x_jwks_uri.clone()).await?,
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
