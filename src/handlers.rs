use axum::extract::{FromRequest, Request};
use axum::{async_trait, Form, RequestExt};

use crate::config::Config;
use crate::identity_provider::*;
use crate::types;
use crate::types::{IdentityProvider, IntrospectRequest, TokenExchangeRequest, TokenRequest};
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use jsonwebtoken as jwt;
use jsonwebtoken::Algorithm::RS512;
use jsonwebtoken::DecodingKey;
use log::{error};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use crate::claims::{ClientAssertion, JWTBearerAssertion};

#[axum::debug_handler]
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

#[axum::debug_handler]
pub async fn token_exchange(
    State(state): State<HandlerState>,
    JsonOrForm(request): JsonOrForm<TokenExchangeRequest>,
) -> impl IntoResponse {
    match &request.identity_provider {
        IdentityProvider::AzureAD => state.azure_ad_obo.read().await.exchange_token(request.into()).await.into_response(),
        IdentityProvider::Maskinporten => (StatusCode::BAD_REQUEST, "Maskinporten does not support token exchange".to_string()).into_response(),
        IdentityProvider::TokenX => state.token_x.read().await.exchange_token(request.into()).await.into_response(),
    }
}

pub async fn introspect(
    State(state): State<HandlerState>,
    JsonOrForm(request): JsonOrForm<IntrospectRequest>,
) -> Result<impl IntoResponse, ApiError> {

    // Need to decode the token to get the issuer before we actually validate it.
    let mut validation = jwt::Validation::new(RS512);
    validation.validate_exp = false;
    validation.insecure_disable_signature_validation();
    let key = DecodingKey::from_secret(&[]);
    let token_data =
        jwt::decode::<Claims>(&request.token, &key, &validation).map_err(ApiError::Validate)?;

    let identity_provider = token_data.claims.identity_provider(state.cfg);
    let claims = match identity_provider {
        Some(IdentityProvider::Maskinporten) => state.maskinporten.write().await.introspect(request.token).await,
        Some(IdentityProvider::AzureAD) => state.azure_ad_obo.write().await.introspect(request.token).await,
        Some(IdentityProvider::TokenX) => state.token_x.write().await.introspect(request.token).await,
        None => panic!("Unknown issuer: {}", token_data.claims.iss),
    };

    Ok((StatusCode::OK, Json(claims)))
}

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

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("identity provider error: {0}")]
    UpstreamRequest(reqwest::Error),

    #[error("upstream error: {0}")]
    Upstream(types::ErrorResponse),

    #[error("invalid JSON in token response: {0}")]
    JSON(reqwest::Error),

    #[error("cannot sign JWT claims")]
    Sign,

    #[error("invalid token: {0}")]
    Validate(jwt::errors::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match &self {
            ApiError::UpstreamRequest(err) => (
                err.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                self.to_string(),
            ),
            ApiError::JSON(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ApiError::Upstream(_err) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ApiError::Validate(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            ApiError::Sign => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        }
            .into_response()
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
