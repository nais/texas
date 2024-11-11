use crate::claims::{serialize, Assertion};
use crate::grants::{TokenRequestBuilder, TokenRequestBuilderParams};
use crate::handlers::ApiError;
use crate::jwks;
use axum::response::IntoResponse;
use axum::Json;
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use log::error;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use utoipa::ToSchema;

/// RFC 6749 token response from section 5.1.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: TokenType,
    /// Token expiry in seconds. Useful for caching purposes.
    #[serde(rename = "expires_in")]
    pub expires_in_seconds: usize,
}

/// Token type is always Bearer, but this might change in the future.
///
/// This data type exists primarily for forwards API compatibility.
#[derive(Deserialize, Serialize, ToSchema)]
pub enum TokenType {
    Bearer,
}

/// RFC 7662 introspection response from section 2.2.
///
/// For provider specific claims, see the respective reference pages:
///
/// - [Azure AD](https://doc.nais.io/auth/entra-id/reference/#claims)
/// - [TokenX](https://doc.nais.io/auth/tokenx/reference/#claims)
/// - [Maskinporten](https://doc.nais.io/auth/maskinporten/reference/#claims)
#[derive(Serialize, Deserialize, ToSchema, Debug, PartialEq)]
pub struct IntrospectResponse {
    /// Indicates whether the token is valid. If this field is `false`,
    /// the token is invalid and must not be used to authenticate or validate.
    active: bool,

    /// If active is false, this field will contain the reason why the token is invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,

    /// All claims from the token will also be present in the introspection response.
    /// Only included if `active` is `true`.
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

impl IntrospectResponse {
    pub fn new(claims: impl Into<HashMap<String, Value>>) -> Self {
        Self {
            active: true,
            error: None,
            extra: claims.into(),
        }
    }

    pub fn new_invalid(error_message: impl ToString) -> Self {
        Self {
            active: false,
            error: Some(error_message.to_string()),
            extra: Default::default(),
        }
    }
}

#[test]
fn test_introspect_response_serialization_format() {
    let ok = IntrospectResponse::new([("foo".into(), Value::String("bar".into()))]);
    let failed = IntrospectResponse::new_invalid("my error");

    let serialized = serde_json::to_string(&ok).unwrap();
    assert_eq!(serialized, r#"{"active":true,"foo":"bar"}"#);

    let serialized = serde_json::to_string(&failed).unwrap();
    assert_eq!(serialized, r#"{"active":false,"error":"my error"}"#);
}

/// RFC 6749 token response from section 5.2.
#[derive(Serialize, Deserialize, ToSchema, Debug, Clone, PartialEq)]
pub struct ErrorResponse {
    pub error: OAuthErrorCode,
    #[serde(rename = "error_description")]
    pub description: String,
}

impl Display for ErrorResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}",
            serde_json::to_string(&self.error).unwrap(),
            self.description
        )
    }
}

impl From<ApiError> for ErrorResponse {
    fn from(err: ApiError) -> Self {
        match err {
            ApiError::Sign => ErrorResponse {
                error: OAuthErrorCode::ServerError,
                description: "Failed to sign assertion".to_string(),
            },
            ApiError::UpstreamRequest(err) => ErrorResponse {
                error: OAuthErrorCode::ServerError,
                description: format!("Upstream request failed: {}", err),
            },
            ApiError::JSON(err) => ErrorResponse {
                error: OAuthErrorCode::ServerError,
                description: format!("Failed to parse JSON: {}", err),
            },
            ApiError::Upstream {
                status_code: _status_code,
                error,
            } => ErrorResponse {
                error: error.error,
                description: error.description,
            },
            ApiError::Validate(_) => ErrorResponse {
                error: OAuthErrorCode::ServerError,
                description: "Failed to validate token".to_string(),
            },
            ApiError::UnsupportedMediaType(_) => ErrorResponse {
                error: OAuthErrorCode::InvalidRequest,
                description: err.to_string(),
            },
            ApiError::UnprocessableContent(_) => ErrorResponse {
                error: OAuthErrorCode::InvalidRequest,
                description: err.to_string(),
            },
            ApiError::UnsupportedIdentityProvider(_) => ErrorResponse {
                error: OAuthErrorCode::InvalidRequest,
                description: err.to_string(),
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq)]
pub enum OAuthErrorCode {
    #[serde(rename = "invalid_request")]
    InvalidRequest,
    #[serde(rename = "invalid_client")]
    InvalidClient,
    #[serde(rename = "invalid_grant")]
    InvalidGrant,
    #[serde(rename = "unauthorized_client")]
    UnauthorizedClient,
    #[serde(rename = "unsupported_grant_type")]
    UnsupportedGrantType,
    #[serde(rename = "invalid_scope")]
    InvalidScope,
    #[serde(rename = "server_error")]
    ServerError,
}

impl From<OAuthErrorCode> for StatusCode {
    /// map oauth2 error codes that Texas should handle to InternalServerError
    fn from(value: OAuthErrorCode) -> Self {
        match value {
            OAuthErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
            OAuthErrorCode::InvalidClient => StatusCode::INTERNAL_SERVER_ERROR,
            OAuthErrorCode::InvalidGrant => StatusCode::INTERNAL_SERVER_ERROR,
            OAuthErrorCode::UnauthorizedClient => StatusCode::INTERNAL_SERVER_ERROR,
            OAuthErrorCode::UnsupportedGrantType => StatusCode::INTERNAL_SERVER_ERROR,
            OAuthErrorCode::InvalidScope => StatusCode::BAD_REQUEST,
            OAuthErrorCode::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Identity providers for use with token fetch, exchange and introspection.
///
/// Each identity provider is enabled when appropriately configured in `nais.yaml`.
#[derive(Deserialize, Serialize, ToSchema, Clone, Debug)]
pub enum IdentityProvider {
    #[serde(rename = "azuread")]
    AzureAD,
    #[serde(rename = "tokenx")]
    TokenX,
    #[serde(rename = "maskinporten")]
    Maskinporten,
}

impl Display for IdentityProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Ok(Value::String(s)) = serde_json::to_value(self) {
            f.write_str(&s)
        } else {
            Ok(())
        }
    }
}

/// Use this data type to request a token from the given identity provider.
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
pub struct TokenRequest {
    /// Who this token is intended for.
    ///
    /// Usually `cluster:namespace:application`.
    pub target: String,
    pub identity_provider: IdentityProvider,
}

/// Use this data type to exchange a user token for another similar token, scoped to the requested target.
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
pub struct TokenExchangeRequest {
    /// Who this token is intended for.
    ///
    /// Usually `cluster:namespace:application`.
    pub target: String,
    pub identity_provider: IdentityProvider,

    /// The token that contains the user's context.
    ///
    /// Usually found in the `Authorization` header in requests to your application.
    pub user_token: String,
}

/// This data type holds the OAuth token that will be validated in the introspect endpoint.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct IntrospectRequest {
    pub token: String,
}

#[derive(Clone)]
pub struct Provider<R, A> {
    client_id: String,
    pub token_endpoint: String,
    private_jwk: jwt::EncodingKey,
    client_assertion_header: jwt::Header,
    upstream_jwks: jwks::Jwks,
    _fake_request: PhantomData<R>,
    _fake_assertion: PhantomData<A>,
}

impl<R, A> Provider<R, A>
where
    R: Serialize + TokenRequestBuilder,
    A: Serialize + Assertion,
{
    pub fn new(
        client_id: String,
        token_endpoint: String,
        private_jwk: String,
        upstream_jwks: jwks::Jwks,
    ) -> Option<Self> {
        let client_private_jwk: jwk::JsonWebKey = private_jwk.parse().ok()?;
        let alg: jwt::Algorithm = client_private_jwk.algorithm?.into();
        let kid: String = client_private_jwk.key_id.clone()?;
        let mut client_assertion_header = jwt::Header::new(alg);
        client_assertion_header.kid = Some(kid);
        Some(Self {
            client_id,
            token_endpoint,
            client_assertion_header,
            upstream_jwks,
            private_jwk: client_private_jwk.key.to_encoding_key(),
            _fake_request: Default::default(),
            _fake_assertion: Default::default(),
        })
    }

    pub async fn introspect(&mut self, token: String) -> IntrospectResponse {
        self.upstream_jwks
            .validate(&token)
            .await
            .map(IntrospectResponse::new)
            .unwrap_or_else(IntrospectResponse::new_invalid)
    }

    async fn get_token_with_config(
        &self,
        config: TokenRequestBuilderParams,
    ) -> Result<impl IntoResponse, ApiError> {
        let params = R::token_request(config).ok_or(ApiError::Sign)?;

        let client = reqwest::Client::new();
        let response = client
            .post(self.token_endpoint.clone())
            .header("accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(ApiError::UpstreamRequest)?;

        let status = response.status();
        if status >= StatusCode::BAD_REQUEST {
            let err: ErrorResponse = response.json().await.map_err(ApiError::JSON)?;
            let err = ApiError::Upstream {
                status_code: status,
                error: err,
            };
            error!("get_token_with_config: {}", err);
            return Err(err);
        }

        let res: TokenResponse = response
            .json()
            .await
            .inspect_err(|err| error!("Identity provider returned invalid JSON: {:?}", err))
            .map_err(ApiError::JSON)?;

        Ok((StatusCode::OK, Json(res)))
    }

    pub async fn get_token(&self, request: TokenRequest) -> Result<impl IntoResponse, ApiError> {
        let token_request = TokenRequestBuilderParams {
            target: request.target.clone(),
            assertion: self.create_assertion(request.target),
            client_id: Some(self.client_id.clone()),
            user_token: None,
        };
        self.get_token_with_config(token_request).await
    }

    pub async fn exchange_token(
        &self,
        request: TokenExchangeRequest,
    ) -> Result<impl IntoResponse, ApiError> {
        let token_request = TokenRequestBuilderParams {
            target: request.target.clone(),
            assertion: self.create_assertion(request.target),
            client_id: Some(self.client_id.clone()),
            user_token: Some(request.user_token),
        };
        self.get_token_with_config(token_request).await
    }

    fn create_assertion(&self, target: String) -> String {
        let assertion = A::new(self.token_endpoint.clone(), self.client_id.clone(), target);
        serialize(assertion, &self.client_assertion_header, &self.private_jwk).unwrap()
        // FIXME: don't unwrap
    }
}
