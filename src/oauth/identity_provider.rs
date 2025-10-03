use crate::handler::ApiError;
use crate::http;
use crate::oauth::assertion::{Assertion, serialize};
use crate::oauth::grant::{
    ClientCredentials, JWTBearer, OnBehalfOf, TokenExchange, TokenRequestBuilder,
    TokenRequestBuilderParams,
};
use crate::oauth::token;
use async_trait::async_trait;
use derivative::Derivative;
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use thiserror::Error;
use tracing::error;
use tracing::instrument;
use utoipa::openapi::{ObjectBuilder, RefOr, Schema};
use utoipa::{PartialSchema, ToSchema};

/// RFC 6749 token response from section 5.1.
#[derive(Serialize, Deserialize, ToSchema, Clone, Hash, Debug, PartialEq)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: TokenType,
    /// Token expiry in seconds. Useful for caching purposes.
    #[serde(rename = "expires_in")]
    pub expires_in_seconds: u64,
}

/// Token type is always Bearer, but this might change in the future.
#[derive(Deserialize, Serialize, ToSchema, Clone, Hash, Debug, PartialEq)]
pub enum TokenType {
    Bearer,
}

/// Based on RFC 7662 introspection response from section 2.2.
///
/// Claims from the original token are copied verbatim to the introspection response as additional properties.
/// The claims present depend on the identity provider.
/// Please refer to the Nais documentation for details:
///
/// - [Azure AD](https://doc.nais.io/auth/entra-id/reference/#claims)
/// - [IDPorten](https://doc.nais.io/auth/idporten/reference/#claims)
/// - [Maskinporten](https://doc.nais.io/auth/maskinporten/reference/#claims)
/// - [TokenX](https://doc.nais.io/auth/tokenx/reference/#claims)
#[derive(Serialize, Deserialize, ToSchema, Debug, PartialEq, Clone)]
pub struct IntrospectResponse {
    /// Indicates whether the token is valid. If this field is _false_,
    /// the token is invalid and *must* be rejected.
    pub active: bool,

    /// If the token is invalid, this field contains the reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Claims from valid tokens are contained in the introspection response, but only if the token is valid.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
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
            extra: HashMap::default(),
        }
    }
}

impl Display for IntrospectResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.error.is_some() {
            return write!(f, "{}", self.error.as_deref().unwrap_or("unknown error"));
        }
        Ok(())
    }
}

#[test]
fn test_introspect_response_serialization_format() {
    use pretty_assertions::assert_eq;

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
        let err = serde_json::to_string(&self.error)
            .unwrap_or("BUG: unserializable error message".to_string());
        write!(f, "error={}: error_description={}", err, self.description)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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
    #[serde(untagged)]
    Unknown(String),
}

impl ToSchema for OAuthErrorCode {
    fn name() -> Cow<'static, str> {
        Cow::Borrowed("OAuthErrorCode")
    }
}

// This is a workaround as the "untagged" enum variant results in a schema type with nested objects, which is undesirable.
impl PartialSchema for OAuthErrorCode {
    fn schema() -> RefOr<Schema> {
        RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .description(Some(
                    "Known OAuth error codes from RFC 6749. Unknown variants may still be returned as these are propagated from the upstream identity provider.",
                ))
                .schema_type(utoipa::openapi::schema::Type::String)
                .enum_values(Some([
                    "invalid_request".to_string(),
                    "invalid_client".to_string(),
                    "invalid_grant".to_string(),
                    "unauthorized_client".to_string(),
                    "unsupported_grant_type".to_string(),
                    "invalid_scope".to_string(),
                    "server_error".to_string(),
                ]))
                .build(),
        ))
    }
}

#[test]
fn test_serde_oauth_error() {
    use pretty_assertions::assert_eq;

    let known_code_variant =
        r#"{"error":"invalid_request","error_description":"some description"}"#;
    let unknown_code_variant =
        r#"{"error":"unknown_error","error_description":"some description"}"#;

    let serialized = serde_json::from_str::<ErrorResponse>(known_code_variant);
    assert!(serialized.is_ok());
    let error_response = serialized.unwrap();
    assert_eq!(error_response.error, OAuthErrorCode::InvalidRequest);

    let serialized = serde_json::from_str::<ErrorResponse>(unknown_code_variant);
    assert!(serialized.is_ok());
    let error_response = serialized.unwrap();
    assert_eq!(
        error_response.error,
        OAuthErrorCode::Unknown("unknown_error".to_string())
    );
}

/// Identity providers for use with token fetch, exchange and introspection.
#[derive(Deserialize, Serialize, ToSchema, Clone, Debug, Hash, PartialEq, Eq, Copy)]
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
#[derive(Derivative)]
#[derivative(PartialEq, Hash)]
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug, Eq)]
pub struct TokenRequest {
    /// Scope or identifier for the target application.
    pub target: String,
    pub identity_provider: IdentityProvider,
    /// Resource indicator for audience-restricted tokens (RFC 8707).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Force renewal of token. Defaults to false if omitted.
    #[derivative(PartialEq = "ignore")]
    #[derivative(Hash = "ignore")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cache: Option<bool>,
}

/// Use this data type to exchange a user token for a machine token.
#[derive(Derivative)]
#[derivative(PartialEq, Hash)]
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug, Eq)]
pub struct TokenExchangeRequest {
    /// Scope or identifier for the target application.
    pub target: String,
    pub identity_provider: IdentityProvider,

    /// The user's access token, usually found in the _Authorization_ header in requests to your application.
    pub user_token: String,
    /// Force renewal of token. Defaults to false if omitted.
    #[derivative(PartialEq = "ignore")]
    #[derivative(Hash = "ignore")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cache: Option<bool>,
}

/// This data type holds the OAuth token that will be validated in the introspect endpoint.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct IntrospectRequest {
    pub token: String,
    pub identity_provider: IdentityProvider,
}

#[derive(Clone)]
pub struct Provider<R, A> {
    client_id: String,
    issuer: String,
    token_endpoint: Option<String>,
    identity_provider_kind: IdentityProvider,
    private_jwk: Option<jwt::EncodingKey>,
    client_assertion_header: Option<jwt::Header>,
    upstream_jwks: token::Jwks,
    http_client: reqwest_middleware::ClientWithMiddleware,
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
        issuer: String,
        token_endpoint: Option<String>,
        private_jwk: Option<String>,
        upstream_jwks: token::Jwks,
    ) -> Result<Self, ProviderError> {
        let (client_private_jwk, client_assertion_header) = if let Some(private_jwk) = private_jwk {
            let client_private_jwk: jwk::JsonWebKey =
                private_jwk.parse().map_err(ProviderError::PrivateJwkParseError)?;
            let alg: jwt::Algorithm = client_private_jwk
                .algorithm
                .ok_or(ProviderError::PrivateJwkMissingAlgorithm)?
                .into();
            let kid: String =
                client_private_jwk.key_id.clone().ok_or(ProviderError::PrivateJwkMissingKid)?;

            let mut header = jwt::Header::new(alg);
            header.kid = Some(kid);

            (Some(client_private_jwk.key.to_encoding_key()), Some(header))
        } else {
            (None, None)
        };

        let http_client =
            http::new_default_client().map_err(ProviderError::InitializeHttpClient)?;

        Ok(Self {
            client_id,
            token_endpoint,
            issuer,
            client_assertion_header,
            upstream_jwks,
            http_client,
            identity_provider_kind: kind,
            private_jwk: client_private_jwk,
            _fake_request: PhantomData,
            _fake_assertion: PhantomData,
        })
    }

    #[instrument(skip_all, name = "Create assertion for token signing request")]
    fn create_assertion(&self, target: String, resource: Option<String>) -> Option<String> {
        let assertion = A::new(
            self.issuer.clone(),
            self.client_id.clone(),
            target,
            resource,
        );
        serialize(
            assertion,
            self.client_assertion_header.as_ref()?,
            self.private_jwk.as_ref()?,
        )
        .ok()
    }
}

#[async_trait]
impl<R, A> ProviderHandler for Provider<R, A>
where
    R: TokenRequestBuilder,
    A: Assertion,
    Provider<R, A>: ShouldHandler,
{
    fn identity_provider_matches(&self, identity_provider: IdentityProvider) -> bool {
        self.identity_provider_kind == identity_provider
    }

    async fn get_token(&self, request: TokenRequest) -> Result<TokenResponse, ApiError> {
        let token_request = TokenRequestBuilderParams {
            target: request.target.clone(),
            assertion: self.create_assertion(request.target, request.resource).ok_or(
                ApiError::TokenRequestUnsupported(self.identity_provider_kind),
            )?,
            client_id: Some(self.client_id.clone()),
            user_token: None,
        };
        self.get_token_from_idprovider(token_request).await
    }

    async fn exchange_token(
        &self,
        request: TokenExchangeRequest,
    ) -> Result<TokenResponse, ApiError> {
        let token_request = TokenRequestBuilderParams {
            target: request.target.clone(),
            assertion: self.create_assertion(request.target, None).ok_or(
                ApiError::TokenExchangeUnsupported(self.identity_provider_kind),
            )?,
            client_id: Some(self.client_id.clone()),
            user_token: Some(request.user_token),
        };
        self.get_token_from_idprovider(token_request).await
    }

    async fn introspect(&mut self, token: String) -> IntrospectResponse {
        self.upstream_jwks
            .validate(&token)
            .await
            .map_or_else(IntrospectResponse::new_invalid, IntrospectResponse::new)
    }

    #[instrument(skip_all, name = "Request token from upstream identity provider")]
    async fn get_token_from_idprovider(
        &self,
        config: TokenRequestBuilderParams,
    ) -> Result<TokenResponse, ApiError> {
        let params = R::token_request(config).ok_or(ApiError::Sign)?;

        let response = self
            .http_client
            .post(
                self.token_endpoint.clone().ok_or(ApiError::TokenRequestUnsupported(
                    self.identity_provider_kind,
                ))?,
            )
            .header("accept", "application/json")
            .form(&params)
            .send()
            .await
            .inspect_err(|err| error!("Failed to get token from identity provider: {:?}", err))
            .map_err(ApiError::UpstreamRequest)?;

        let status = response.status();
        if status >= StatusCode::BAD_REQUEST {
            return Err(ApiError::Upstream {
                status_code: status,
                error: response
                    .json()
                    .await
                    .inspect_err(|err| error!("Identity provider returned invalid JSON: {:?}", err))
                    .map_err(ApiError::Json)?,
            });
        }

        Ok(response
            .json()
            .await
            .inspect_err(|err| error!("Identity provider returned invalid JSON: {:?}", err))
            .map_err(ApiError::Json)?)
    }
}

#[async_trait]
pub trait ProviderHandler: ShouldHandler + Send + Sync {
    fn identity_provider_matches(&self, identity_provider: IdentityProvider) -> bool;
    async fn get_token(&self, request: TokenRequest) -> Result<TokenResponse, ApiError>;
    async fn exchange_token(
        &self,
        request: TokenExchangeRequest,
    ) -> Result<TokenResponse, ApiError>;
    async fn introspect(&mut self, token: String) -> IntrospectResponse;
    async fn get_token_from_idprovider(
        &self,
        config: TokenRequestBuilderParams,
    ) -> Result<TokenResponse, ApiError>;
}

pub trait ShouldHandler: Send + Sync {
    fn should_handle_token_request(&self, _: &TokenRequest) -> bool {
        false
    }

    fn should_handle_token_exchange_request(&self, _: &TokenExchangeRequest) -> bool {
        false
    }

    fn should_handle_introspect_request(&self, _: &IntrospectRequest) -> bool {
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
