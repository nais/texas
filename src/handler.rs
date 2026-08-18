use std::sync::Arc;

use crate::http::client::{FetchError, body_preview};
use crate::oauth::identity_provider::IdentityProvider;
use crate::oauth::response::{ErrorResponse, OAuthErrorCode};
use crate::telemetry::inc_handler_errors;
use axum::Form;
use axum::Json;
use axum::extract::FromRequest;
use axum::extract::rejection::{FormRejection, JsonRejection};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use strum_macros::AsRefStr;
use thiserror::Error;
use tracing::instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

mod state;
mod token;
mod token_exchange;
mod token_introspect;

pub use state::{InitError, State};
// The __path_* functions are used by utoipa to generate OpenAPI documentation.
pub(crate) use token::{__path_token, token};
pub(crate) use token_exchange::{__path_token_exchange, token_exchange};
pub(crate) use token_introspect::{__path_token_introspect, token_introspect};

#[derive(Debug, AsRefStr, Error, Clone)]
pub enum ApiError {
    #[error("identity provider request failed: {0}")]
    UpstreamFailure(Arc<FetchError>),

    #[error("identity provider returned OAuth error: HTTP {status_code}: {error}")]
    UpstreamOAuthError {
        status_code: StatusCode,
        error: ErrorResponse,
    },

    #[error("cannot sign JWT claims")]
    Sign,

    #[error("{0}")]
    UnsupportedMediaType(String),

    #[error("{0}")]
    UnprocessableContent(String),

    #[error("identity provider '{0}' does not support token exchange")]
    TokenExchangeUnsupported(IdentityProvider),

    #[error("identity provider '{0}' does not support token requests")]
    TokenRequestUnsupported(IdentityProvider),

    #[error("identity provider '{0}' is not enabled")]
    IdentityProviderNotEnabled(IdentityProvider),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        let (status_code, error_response) = match self {
            // Upstream OAuth errors may differ between providers.
            //
            // They range from things we're in control of (such as assertions) to things we cannot
            // control (such as access to scopes, invalid downstream-supplied values, and so on).
            //
            // We propagate the error response as-is from the upstream instead of trying to handle
            // these ambiguities.
            ApiError::UpstreamOAuthError { status_code, error } => (status_code, error),
            ApiError::Sign => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse {
                    error: OAuthErrorCode::ServerError,
                    description: "Failed to sign assertion".to_string(),
                },
            ),
            ApiError::UpstreamFailure(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse {
                    error: OAuthErrorCode::ServerError,
                    description: format!("Identity provider request failed: {err}"),
                },
            ),
            ApiError::TokenExchangeUnsupported(_)
            | ApiError::TokenRequestUnsupported(_)
            | ApiError::IdentityProviderNotEnabled(_)
            | ApiError::UnprocessableContent(_)
            | ApiError::UnsupportedMediaType(_) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse {
                    error: OAuthErrorCode::InvalidRequest,
                    description: self.to_string(),
                },
            ),
        };
        (status_code, Json(error_response)).into_response()
    }
}

impl From<FetchError> for ApiError {
    fn from(error: FetchError) -> Self {
        let error = Arc::new(error);

        match error.as_ref() {
            FetchError::Send(_)
            | FetchError::BodyRead { .. }
            | FetchError::BodyTooLarge { .. }
            | FetchError::Decode(_) => Self::UpstreamFailure(error),
            FetchError::Status { status, body } => {
                if status.is_redirection() {
                    return Self::UpstreamFailure(error);
                }
                let error = serde_json::from_slice(body).unwrap_or_else(|err| {
                    tracing::warn!(
                        %status,
                        error = %err,
                        body_preview = %body_preview(body),
                        "identity provider returned an invalid OAuth error response"
                    );
                    ErrorResponse {
                        error: OAuthErrorCode::ServerError,
                        description: "identity provider returned an invalid error response"
                            .to_string(),
                    }
                });
                Self::UpstreamOAuthError {
                    status_code: *status,
                    error,
                }
            }
        }
    }
}

pub struct JsonOrForm<T>(pub T);

impl<S, T> FromRequest<S> for JsonOrForm<T>
where
    S: Send + Sync,
    T: 'static,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    Form<T>: FromRequest<S, Rejection = FormRejection>,
{
    type Rejection = ApiError;

    #[instrument(skip_all, name = "Deserialize request", err)]
    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let content_type_header = req.headers().get(CONTENT_TYPE);
        let content_type = content_type_header.and_then(|value| value.to_str().ok());

        if let Some(content_type) = content_type {
            if content_type.starts_with("application/json") {
                return match Json::<T>::from_request(req, state).await {
                    Ok(payload) => Ok(Self(payload.0)),
                    Err(rejection) => Err(match rejection {
                        JsonRejection::MissingJsonContentType(err) => {
                            ApiError::UnsupportedMediaType(err.body_text())
                        }
                        JsonRejection::JsonDataError(err) => {
                            ApiError::UnprocessableContent(err.body_text())
                        }
                        JsonRejection::JsonSyntaxError(err) => {
                            ApiError::UnprocessableContent(err.body_text())
                        }
                        JsonRejection::BytesRejection(err) => {
                            ApiError::UnprocessableContent(err.body_text())
                        }
                        err => ApiError::UnprocessableContent(err.body_text()),
                    }),
                };
            }

            if content_type.starts_with("application/x-www-form-urlencoded") {
                return match Form::<T>::from_request(req, state).await {
                    Ok(payload) => Ok(Self(payload.0)),
                    Err(rejection) => Err(match rejection {
                        FormRejection::InvalidFormContentType(err) => {
                            ApiError::UnsupportedMediaType(err.body_text())
                        }
                        FormRejection::FailedToDeserializeForm(err) => {
                            ApiError::UnprocessableContent(err.body_text())
                        }
                        FormRejection::FailedToDeserializeFormBody(err) => {
                            ApiError::UnprocessableContent(err.body_text())
                        }
                        FormRejection::BytesRejection(err) => {
                            ApiError::UnprocessableContent(err.body_text())
                        }
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

fn identity_provider_not_enabled_error(path: &str, provider: IdentityProvider) -> ApiError {
    let err = ApiError::IdentityProviderNotEnabled(provider);
    tracing::Span::current().set_attribute("texas.identity_provider.enabled", false);
    inc_handler_errors(path, provider, err.as_ref());
    err
}

#[cfg(test)]
mod tests {
    use super::{ApiError, ErrorResponse, FetchError, OAuthErrorCode};
    use axum::http::StatusCode;

    #[test]
    fn malformed_oauth_error_response_becomes_server_error() {
        let error = ApiError::from(FetchError::Status {
            status: StatusCode::BAD_REQUEST,
            body: b"not json".to_vec(),
        });

        assert!(matches!(
            error,
            ApiError::UpstreamOAuthError {
                status_code: StatusCode::BAD_REQUEST,
                error: ErrorResponse {
                    error: OAuthErrorCode::ServerError,
                    description,
                },
            } if description == "identity provider returned an invalid error response"
        ));
    }

    #[test]
    fn redirect_status_becomes_upstream_failure() {
        let error = ApiError::from(FetchError::Status {
            status: StatusCode::FOUND,
            body: b"redirect".to_vec(),
        });

        assert!(matches!(
            error,
            ApiError::UpstreamFailure(error) if matches!(
                error.as_ref(),
                FetchError::Status { status: StatusCode::FOUND, .. }
            )
        ));
    }

    #[test]
    fn oauth_error_without_description_is_valid() {
        let error = ApiError::from(FetchError::Status {
            status: StatusCode::BAD_REQUEST,
            body: br#"{"error":"invalid_grant"}"#.to_vec(),
        });

        assert!(matches!(
            error,
            ApiError::UpstreamOAuthError {
                status_code: StatusCode::BAD_REQUEST,
                error: ErrorResponse {
                    error: OAuthErrorCode::InvalidGrant,
                    description,
                },
            } if description.is_empty()
        ));
    }
}
