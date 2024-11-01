use axum::extract::{FromRequest, Request};
use axum::{async_trait, Form, RequestExt};

use crate::config::Config;
use crate::identity_provider::*;
use crate::types;
use crate::types::{IdentityProvider, IntrospectRequest, TokenRequest, TokenResponse};
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
) -> Result<impl IntoResponse, ApiError> {
    let endpoint = state.token_endpoint(&request.identity_provider).await;
    let params = state
        .token_request(
            &request.identity_provider,
            request.target,
            request.user_token,
        )
        .await;

    let client = reqwest::Client::new();
    let request_builder = client
        .post(endpoint)
        .header("accept", "application/json")
        .form(&params);

    let response = request_builder
        .send()
        .await
        .map_err(ApiError::UpstreamRequest)?;

    if response.status() >= StatusCode::BAD_REQUEST {
        let err: types::ErrorResponse = response.json().await.map_err(ApiError::JSON)?;
        return Err(ApiError::Upstream(err));
    }

    let res: TokenResponse = response
        .json()
        .await
        .inspect_err(|err| error!("Identity provider returned invalid JSON: {:?}", err))
        .map_err(ApiError::JSON)?;

    Ok((StatusCode::OK, Json(res)))
}

pub async fn introspection(
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

    let claims = match token_data.claims.iss {
        s if s == state.cfg.maskinporten_issuer => {
            state
                .maskinporten
                .write()
                .await
                .introspect(request.token)
                .await
        }
        _ => panic!("Unknown issuer: {}", token_data.claims.iss),
    };

    Ok((StatusCode::OK, Json(claims)))
}

#[derive(Clone)]
pub struct HandlerState {
    pub cfg: Config,
    pub maskinporten: Arc<RwLock<Maskinporten>>,
    pub azure_ad: Arc<RwLock<AzureAD>>,
    // TODO: other providers
}

impl HandlerState {
    async fn token_request(
        &self,
        identity_provider: &IdentityProvider,
        target: String,
        user_token: Option<String>,
    ) -> Box<dyn erased_serde::Serialize + Send> {
        match identity_provider {
            IdentityProvider::AzureAD => {
                if let Some(x) = user_token {
                    Box::new(self.azure_ad.read().await.on_behalf_of_request(target, x))
                } else {
                    Box::new(self.azure_ad.read().await.token_request(target))
                }
            }
            IdentityProvider::TokenX => todo!(),
            IdentityProvider::Maskinporten => {
                Box::new(self.maskinporten.read().await.token_request(target))
            }
        }
    }

    async fn token_endpoint(&self, identity_provider: &IdentityProvider) -> String {
        match identity_provider {
            IdentityProvider::AzureAD => self.azure_ad.read().await.token_endpoint(),
            IdentityProvider::TokenX => todo!(),
            IdentityProvider::Maskinporten => self.maskinporten.read().await.token_endpoint(),
        }
    }
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

#[derive(serde::Deserialize)]
struct Claims {
    iss: String,
}

pub struct JsonOrForm<T>(T);

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
