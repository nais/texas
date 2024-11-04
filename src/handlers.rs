use axum::extract::{FromRequest, Request};
use axum::{async_trait, Form, RequestExt};

use crate::config::Config;
use crate::identity_provider::*;
use crate::types;
use crate::types::{IdentityProvider, IntrospectRequest, TokenRequest};
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use jsonwebtoken as jwt;
use jsonwebtoken::Algorithm::RS512;
use jsonwebtoken::DecodingKey;
use log::error;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[axum::debug_handler]
pub async fn token(
    State(state): State<HandlerState>,
    JsonOrForm(request): JsonOrForm<TokenRequest>,
) -> impl IntoResponse {
    match &request.identity_provider {
        IdentityProvider::AzureAD => state.azure_ad.read().await.get_token(state.clone(), request).await.into_response(),
        IdentityProvider::TokenX => todo!(),
        IdentityProvider::Maskinporten => state.maskinporten.read().await.get_token(state.clone(), request).await.into_response(),
    }
}

pub async fn introspect(
    State(state): State<HandlerState>,
    Json(request): Json<IntrospectRequest>,
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
        Some(IdentityProvider::Maskinporten) => {
            state
                .maskinporten
                .write()
                .await
                .introspect(request.token)
                .await
        }
        Some(IdentityProvider::AzureAD) => panic!("not implemented"),
        Some(IdentityProvider::TokenX) => panic!("not implemented"),
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
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct HandlerState {
    pub cfg: Config,
    pub maskinporten: Arc<RwLock<Provider<MaskinportenTokenRequest>>>,
    pub azure_ad: Arc<RwLock<Provider<AzureADOnBehalfOfTokenRequest>>>,
    // TODO: other providers
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("identity provider error: {0}")]
    UpstreamRequest(reqwest::Error),

    #[error("upstream error: {0}")]
    Upstream(types::ErrorResponse),

    #[error("invalid JSON in token response: {0}")]
    JSON(reqwest::Error),

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
