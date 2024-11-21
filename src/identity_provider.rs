use crate::claims::{serialize, Assertion};
use crate::grants::{ClientCredentials, JWTBearer, OnBehalfOf, TokenExchange, TokenRequestBuilder, TokenRequestBuilderParams};
use crate::handlers::ApiError;
use crate::jwks;
use axum::async_trait;
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::time::Duration;
use thiserror::Error;
use tracing::error;
use tracing::instrument;
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
#[derive(Deserialize, Serialize, ToSchema)]
pub enum TokenType {
    Bearer,
}

/// RFC 7662 introspection response from section 2.2.
///
/// Identity provider's claims differ from one another.
/// Please refer to the Nais documentation for details:
///
/// - [Azure AD](https://doc.nais.io/auth/entra-id/reference/#claims)
/// - [IDPorten](https://doc.nais.io/auth/idporten/reference/#claims)
/// - [Maskinporten](https://doc.nais.io/auth/maskinporten/reference/#claims)
/// - [TokenX](https://doc.nais.io/auth/tokenx/reference/#claims)
#[derive(Serialize, Deserialize, ToSchema, Debug, PartialEq)]
pub struct IntrospectResponse {
    /// Indicates whether the token is valid. If this field is _false_,
    /// the token is invalid and *must* be rejected.
    active: bool,

    /// If the token is invalid, this field contains the reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,

    /// Claims from valid tokens are contained in the introspection response, but only if the token is valid.
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

/// RFC 6749 error response from section 5.2.
#[derive(Serialize, Deserialize, ToSchema, Debug, Clone, PartialEq)]
pub struct ErrorResponse {
    pub error: OAuthErrorCode,
    #[serde(rename = "error_description")]
    pub description: String,
}

impl Display for ErrorResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err = serde_json::to_string(&self.error).unwrap_or("BUG: unserializable error message".to_string());
        write!(f, "{}: {}", err, self.description)
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
            ApiError::Upstream { status_code: _status_code, error } => ErrorResponse {
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
            },
            ApiError::TokenExchangeUnsupported(_) => ErrorResponse {
                error: OAuthErrorCode::InvalidRequest,
                description: err.to_string(),
            },
            ApiError::TokenRequestUnsupported(_) => ErrorResponse {
                error: OAuthErrorCode::InvalidRequest,
                description: err.to_string(),
            },
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
#[derive(Deserialize, Serialize, ToSchema, Clone, Debug, PartialEq, Copy)]
pub enum IdentityProvider {
    #[serde(rename = "azuread")]
    AzureAD,
    #[serde(rename = "tokenx")]
    TokenX,
    #[serde(rename = "maskinporten")]
    Maskinporten,
    #[serde(rename = "idporten")]
    IDPorten,
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

/// Use this data type to request a machine token.
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
pub struct TokenRequest {
    /// The issued token will only be accepted by the targeted application, specified in this field.
    pub target: String,
    pub identity_provider: IdentityProvider,
}

/// Use this data type to exchange a user token for a machine token.
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
pub struct TokenExchangeRequest {
    /// The issued token will only be accepted by the targeted application, specified in this field.
    pub target: String,
    pub identity_provider: IdentityProvider,

    /// The user's access token, usually found in the _Authorization_ header in requests to your application.
    pub user_token: String,
}

/// This data type holds the OAuth token that will be validated in the introspect endpoint.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct IntrospectRequest {
    pub token: String,
    pub identity_provider: IdentityProvider,
}

impl IntrospectRequest {
    /// Decode the token to get the issuer of the request.
    pub fn issuer(&self) -> Option<String> {
        #[derive(serde::Deserialize)]
        struct IssuerClaim {
            iss: String,
        }

        let mut validation = jwt::Validation::new(jwt::Algorithm::RS512);
        validation.validate_exp = false;
        validation.set_required_spec_claims::<&str>(&[]);

        // To decode the issuer, we have to disable validation.
        // Validation is done in the Provider.
        validation.insecure_disable_signature_validation();

        let key = jwt::DecodingKey::from_secret(&[]);
        jwt::decode::<IssuerClaim>(&self.token, &key, &validation).ok().map(|data| data.claims.iss)
    }
}

#[derive(Clone)]
pub struct Provider<R, A> {
    client_id: String,
    pub token_endpoint: Option<String>,
    identity_provider_kind: IdentityProvider,
    private_jwk: Option<jwt::EncodingKey>,
    client_assertion_header: Option<jwt::Header>,
    upstream_jwks: jwks::Jwks,
    http_client: reqwest::Client,
    _fake_request: PhantomData<R>,
    _fake_assertion: PhantomData<A>,
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("initialize HTTP client: {0}")]
    InitializeHttpClient(#[from] reqwest::Error),

    #[error("parse private JWK: {0}")]
    PrivateJwkParseError(#[from] jwk::Error),

    #[error("private JWK is missing key id")]
    PrivateJwkMissingKid,

    #[error("private JWK is missing algorithm")]
    PrivateJwkMissingAlgorithm,
}

impl<R, A> Provider<R, A>
where
    R: TokenRequestBuilder,
    A: Assertion,
{
    pub fn new(
        kind: IdentityProvider,
        client_id: String,
        token_endpoint: Option<String>,
        private_jwk: Option<String>,
        upstream_jwks: jwks::Jwks,
    ) -> Result<Self, ProviderError> {
        let (client_private_jwk, client_assertion_header) = if let Some(private_jwk) = private_jwk {
            let client_private_jwk: jwk::JsonWebKey = private_jwk
                .parse()
                .map_err(ProviderError::PrivateJwkParseError)?;
            let alg: jwt::Algorithm = client_private_jwk.algorithm.ok_or(ProviderError::PrivateJwkMissingAlgorithm)?.into();
            let kid: String = client_private_jwk.key_id.clone().ok_or(ProviderError::PrivateJwkMissingKid)?;

            let mut header = jwt::Header::new(alg);
            header.kid = Some(kid);

            (Some(client_private_jwk.key.to_encoding_key()), Some(header))
        } else {
            (None, None)
        };

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(ProviderError::InitializeHttpClient)?;

        Ok(Self {
            client_id,
            token_endpoint,
            client_assertion_header,
            upstream_jwks,
            http_client,
            identity_provider_kind: kind,
            private_jwk: client_private_jwk,
            _fake_request: Default::default(),
            _fake_assertion: Default::default(),
        })
    }

    #[instrument(skip_all, name = "Create assertion for token signing request")]
    fn create_assertion(&self, target: String) -> Option<String> {
        let assertion = A::new(self.token_endpoint.as_ref()?.clone(), self.client_id.clone(), target);
        serialize(assertion, self.client_assertion_header.as_ref()?, self.private_jwk.as_ref()?).ok()
    }
}

#[async_trait]
impl<R, A> ProviderHandler for Provider<R, A>
where
    R: TokenRequestBuilder,
    A: Assertion,
    Provider<R, A>: ShouldHandler,
{
    async fn get_token(&self, request: TokenRequest) -> Result<TokenResponse, ApiError> {
        let token_request = TokenRequestBuilderParams {
            target: request.target.clone(),
            assertion: self.create_assertion(request.target).ok_or(ApiError::TokenRequestUnsupported(self.identity_provider_kind))?,
            client_id: Some(self.client_id.clone()),
            user_token: None,
        };
        self.get_token_from_idprovider(token_request).await
    }

    async fn exchange_token(&self, request: TokenExchangeRequest) -> Result<TokenResponse, ApiError> {
        let token_request = TokenRequestBuilderParams {
            target: request.target.clone(),
            assertion: self.create_assertion(request.target).ok_or(ApiError::TokenExchangeUnsupported(self.identity_provider_kind))?,
            client_id: Some(self.client_id.clone()),
            user_token: Some(request.user_token),
        };
        self.get_token_from_idprovider(token_request).await
    }

    async fn introspect(&mut self, token: String) -> IntrospectResponse {
        self.upstream_jwks.validate(&token).await.map(IntrospectResponse::new).unwrap_or_else(IntrospectResponse::new_invalid)
    }

    #[instrument(skip_all, name = "Request token from upstream identity provider")]
    async fn get_token_from_idprovider(&self, config: TokenRequestBuilderParams) -> Result<TokenResponse, ApiError> {
        let params = R::token_request(config).ok_or(ApiError::Sign)?;

        let headers = crate::tracing::trace_headers_from_current_span();

        let response = self.http_client
            .post(self.token_endpoint.clone().ok_or(ApiError::TokenRequestUnsupported(self.identity_provider_kind))?)
            .headers(headers)
            .header("accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(ApiError::UpstreamRequest)?;

        let status = response.status();
        if status >= StatusCode::BAD_REQUEST {
            let err: ErrorResponse = response.json().await.map_err(ApiError::JSON)?;
            let err = ApiError::Upstream { status_code: status, error: err };
            error!("get_token_with_config: {}", err);
            return Err(err);
        }

        Ok(response
            .json()
            .await
            .inspect_err(|err| error!("Identity provider returned invalid JSON: {:?}", err))
            .map_err(ApiError::JSON)?)
    }
}

#[async_trait]
pub trait ProviderHandler: ShouldHandler + Send + Sync {
    async fn get_token(&self, request: TokenRequest) -> Result<TokenResponse, ApiError>;
    async fn exchange_token(&self, request: TokenExchangeRequest) -> Result<TokenResponse, ApiError>;
    async fn introspect(&mut self, token: String) -> IntrospectResponse;
    async fn get_token_from_idprovider(&self, config: TokenRequestBuilderParams) -> Result<TokenResponse, ApiError>;
}
pub trait ShouldHandler: Send + Sync {
    fn should_handle_token_request(&self, _request: &TokenRequest) -> bool {
        false
    }

    fn should_handle_token_exchange_request(&self, _request: &TokenExchangeRequest) -> bool {
        false
    }

    fn should_handle_introspect_request(&self, _request: &IntrospectRequest) -> bool {
        false
    }
}

impl<A> ShouldHandler for Provider<JWTBearer, A>
where
    A: Serialize + Assertion,
{
    fn should_handle_token_request(&self, request: &TokenRequest) -> bool {
        self.identity_provider_kind == request.identity_provider
    }

    fn should_handle_introspect_request(&self, request: &IntrospectRequest) -> bool {
        self.identity_provider_kind == request.identity_provider
    }
    // JWTBearer grant does not support exchanging tokens.
}

impl<A> ShouldHandler for Provider<ClientCredentials, A>
where
    A: Serialize + Assertion,
{
    fn should_handle_token_request(&self, request: &TokenRequest) -> bool {
        self.identity_provider_kind == request.identity_provider
    }

    fn should_handle_introspect_request(&self, request: &IntrospectRequest) -> bool {
        self.identity_provider_kind == request.identity_provider
    }

    // ClientCredentials grant does not support exchanging tokens.
}

impl<A> ShouldHandler for Provider<TokenExchange, A>
where
    A: Serialize + Assertion,
{
    // TokenExchange grant does not support getting a machine-to-machine token.

    fn should_handle_token_exchange_request(&self, request: &TokenExchangeRequest) -> bool {
        self.identity_provider_kind == request.identity_provider
    }

    fn should_handle_introspect_request(&self, request: &IntrospectRequest) -> bool {
        self.identity_provider_kind == request.identity_provider
    }
}

impl<A> ShouldHandler for Provider<OnBehalfOf, A>
where
    A: Serialize + Assertion,
{
    // OnBehalfOf grant does not support getting a machine-to-machine token.

    fn should_handle_token_exchange_request(&self, request: &TokenExchangeRequest) -> bool {
        self.identity_provider_kind == request.identity_provider
    }
    fn should_handle_introspect_request(&self, request: &IntrospectRequest) -> bool {
        self.identity_provider_kind == request.identity_provider
    }
}

impl<A> ShouldHandler for Provider<(), A>
where
    A: Serialize + Assertion,
{
    fn should_handle_introspect_request(&self, request: &IntrospectRequest) -> bool {
        self.identity_provider_kind == request.identity_provider
    }
}
