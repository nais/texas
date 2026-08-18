use crate::handler::ApiError;
use crate::http::client::{self, FetchError, body_preview};
use crate::oauth::assertion::{Assertion, serialize};
use crate::oauth::grant::{
    ClientCredentials, JWTBearer, OnBehalfOf, TokenExchange, TokenRequestBuilder,
    TokenRequestBuilderParams,
};
use crate::oauth::jwt::JwtValidator;
use crate::telemetry::record_identity_provider_latency;
use async_trait::async_trait;
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use std::borrow::Cow;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::sync::Arc;
use thiserror::Error;
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
/// - [Entra ID](https://doc.nais.io/auth/entra-id/reference/#claims)
/// - [ID-porten](https://doc.nais.io/auth/idporten/reference/#claims)
/// - [Maskinporten](https://doc.nais.io/auth/maskinporten/reference/#claims)
/// - [TokenX](https://doc.nais.io/auth/tokenx/reference/#claims)
///
/// For Ansattporten specifically, please refer to the Digdir documentation for details:
/// - [Ansattporten](https://docs.digdir.no/docs/ansattporten/ansattporten_om.html)
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
    #[serde(default)]
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
    #[serde(rename = "entra_id", alias = "azuread")]
    EntraID,
    #[serde(rename = "tokenx")]
    TokenX,
    #[serde(rename = "maskinporten")]
    Maskinporten,
    #[serde(rename = "idporten")]
    IDPorten,
    #[serde(rename = "ansattporten")]
    Ansattporten,
}

impl IdentityProvider {
    pub(crate) fn normalize_target(self, target: String) -> String {
        if self != Self::EntraID || target.starts_with("https://") || target.starts_with("api://") {
            return target;
        }

        let parts = target.split(':').collect::<Vec<_>>();
        if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
            return target;
        }

        format!("api://{}/.default", parts.join("."))
    }
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
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug, Eq)]
pub struct TokenRequest {
    /// Scope or identifier for the target application.
    pub target: String,
    pub identity_provider: IdentityProvider,
    /// Resource indicator for audience-restricted tokens [(RFC 8707)](https://www.rfc-editor.org/rfc/rfc8707.html).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<AuthorizationDetails>,
    /// Force renewal of token. Defaults to false if omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cache: Option<bool>,
}

/// Per-request inputs for a token request.
///
/// The token endpoint is not part of this struct: it is provider configuration
/// owned by `Provider`, and the caller resolves it so that a missing endpoint
/// maps to the error of the operation being performed.
#[derive(Clone)]
struct TokenRequestInputs {
    target: String,
    resource: Option<String>,
    authorization_details: Option<AuthorizationDetails>,
    user_token: Option<String>,
}

impl TokenRequest {
    pub(crate) fn with_normalized_target(&self) -> Self {
        Self {
            target: self.identity_provider.normalize_target(self.target.clone()),
            ..self.clone()
        }
    }
}

// Manual PartialEq/Hash so that `skip_cache` does not influence cache lookup keys.
impl PartialEq for TokenRequest {
    fn eq(&self, other: &Self) -> bool {
        self.target == other.target
            && self.identity_provider == other.identity_provider
            && self.resource == other.resource
            && self.authorization_details == other.authorization_details
    }
}

impl Hash for TokenRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.target.hash(state);
        self.identity_provider.hash(state);
        self.resource.hash(state);
        self.authorization_details.hash(state);
    }
}

/// Authorization details for rich authorization requests [(RFC 9396)](https://www.rfc-editor.org/rfc/rfc9396.html).
/// Must be a JSON array of objects, the exact contents of which depend on the identity provider.
/// Texas does not validate this property and only forwards its value to the identity provider.
#[derive(Serialize, ToSchema, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorizationDetails(pub Vec<Map<String, Value>>);

impl<'de> Deserialize<'de> for AuthorizationDetails {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RequestValue {
            Seq(Vec<Map<String, Value>>), // Directly as a JSON array
            Str(String),                  // As a JSON string (for form-encoded data)
        }

        match RequestValue::deserialize(deserializer)? {
            RequestValue::Seq(v) => Ok(AuthorizationDetails::from(v)),
            RequestValue::Str(s) => {
                let v: Vec<Map<String, Value>> = serde_json::from_str(&s).map_err(|e| {
                    serde::de::Error::custom(format!(
                        "failed to parse authorization_details JSON string: {}",
                        e
                    ))
                })?;
                Ok(AuthorizationDetails::from(v))
            }
        }
    }
}

impl From<Vec<Map<String, Value>>> for AuthorizationDetails {
    fn from(v: Vec<Map<String, Value>>) -> Self {
        AuthorizationDetails(v)
    }
}

/// Use this data type to exchange a user token for a machine token.
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug, Eq)]
pub struct TokenExchangeRequest {
    /// Scope or identifier for the target application.
    pub target: String,
    pub identity_provider: IdentityProvider,

    /// The user's access token, usually found in the _Authorization_ header in requests to your application.
    pub user_token: String,
    /// Force renewal of token. Defaults to false if omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cache: Option<bool>,
}

impl TokenExchangeRequest {
    pub(crate) fn with_normalized_target(&self) -> Self {
        Self {
            target: self.identity_provider.normalize_target(self.target.clone()),
            ..self.clone()
        }
    }
}

// Manual PartialEq/Hash so that `skip_cache` does not influence cache lookup keys.
impl PartialEq for TokenExchangeRequest {
    fn eq(&self, other: &Self) -> bool {
        self.target == other.target
            && self.identity_provider == other.identity_provider
            && self.user_token == other.user_token
    }
}

impl Hash for TokenExchangeRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.target.hash(state);
        self.identity_provider.hash(state);
        self.user_token.hash(state);
    }
}

/// This data type holds the OAuth token that will be validated in the introspect endpoint.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct IntrospectRequest {
    pub token: String,
    pub identity_provider: IdentityProvider,
}

pub struct Provider<R, A> {
    client_id: String,
    issuer: String,
    token_endpoint: Option<String>,
    identity_provider_kind: IdentityProvider,
    private_jwk: Option<jwt::EncodingKey>,
    client_assertion_header: Option<jwt::Header>,
    jwt_validator: JwtValidator,
    http_client: client::Client,
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
        jwt_validator: JwtValidator,
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

        let http_client = client::token().map_err(ProviderError::InitializeHttpClient)?;

        Ok(Self {
            client_id,
            token_endpoint,
            issuer,
            client_assertion_header,
            jwt_validator,
            http_client,
            identity_provider_kind: kind,
            private_jwk: client_private_jwk,
            _fake_request: PhantomData,
            _fake_assertion: PhantomData,
        })
    }

    #[instrument(skip_all, name = "Create assertion for token signing request")]
    fn create_assertion(
        &self,
        target: String,
        resource: Option<String>,
        authorization_details: Option<AuthorizationDetails>,
    ) -> Option<String> {
        let assertion = A::new(
            self.issuer.clone(),
            self.client_id.clone(),
            target,
            resource,
            authorization_details,
        );
        serialize(
            assertion,
            self.client_assertion_header.as_ref()?,
            self.private_jwk.as_ref()?,
        )
        .ok()
    }

    #[instrument(skip_all, name = "Request token from upstream identity provider")]
    async fn get_token_from_idprovider(
        &self,
        inputs: TokenRequestInputs,
        token_endpoint: &str,
    ) -> Result<TokenResponse, ApiError> {
        let identity_provider = self.identity_provider_kind;
        self.http_client
            .post(
                token_endpoint,
                || {
                    let assertion = self
                        .create_assertion(
                            inputs.target.clone(),
                            inputs.resource.clone(),
                            inputs.authorization_details.clone(),
                        )
                        .ok_or(ApiError::Sign)?;
                    let params = R::token_request(TokenRequestBuilderParams {
                        target: inputs.target.clone(),
                        assertion,
                        client_id: Some(self.client_id.clone()),
                        user_token: inputs.user_token.clone(),
                    })
                    .ok_or(ApiError::Sign)?;
                    Ok::<_, ApiError>(params)
                },
                |elapsed| record_identity_provider_latency(identity_provider, elapsed),
            )
            .await
    }
}

impl From<FetchError> for ApiError {
    fn from(error: FetchError) -> Self {
        match error {
            error @ (FetchError::Send(_) | FetchError::BodyRead { .. } | FetchError::Decode(_)) => {
                Self::UpstreamFailure(Arc::new(error))
            }
            FetchError::Status { status, body } => {
                if status.is_redirection() {
                    return Self::UpstreamFailure(Arc::new(FetchError::Status { status, body }));
                }
                let error = serde_json::from_slice(&body).unwrap_or_else(|err| {
                    tracing::warn!(
                        %status,
                        error = %err,
                        body_preview = %body_preview(&body),
                        "identity provider returned an invalid OAuth error response"
                    );
                    ErrorResponse {
                        error: OAuthErrorCode::ServerError,
                        description: "identity provider returned an invalid error response"
                            .to_string(),
                    }
                });
                Self::UpstreamOAuthError {
                    status_code: status,
                    error,
                }
            }
        }
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
        let token_endpoint = self.token_endpoint.as_deref().ok_or(
            ApiError::TokenRequestUnsupported(self.identity_provider_kind),
        )?;
        self.get_token_from_idprovider(
            TokenRequestInputs {
                target: request.target,
                resource: request.resource,
                authorization_details: request.authorization_details,
                user_token: None,
            },
            token_endpoint,
        )
        .await
    }

    async fn exchange_token(
        &self,
        request: TokenExchangeRequest,
    ) -> Result<TokenResponse, ApiError> {
        let token_endpoint = self.token_endpoint.as_deref().ok_or(
            ApiError::TokenExchangeUnsupported(self.identity_provider_kind),
        )?;
        self.get_token_from_idprovider(
            TokenRequestInputs {
                target: request.target,
                resource: None,
                authorization_details: None,
                user_token: Some(request.user_token),
            },
            token_endpoint,
        )
        .await
    }

    async fn introspect(&self, token: String) -> IntrospectResponse {
        self.jwt_validator
            .validate(&token)
            .await
            .map_or_else(IntrospectResponse::new_invalid, IntrospectResponse::new)
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
    async fn introspect(&self, token: String) -> IntrospectResponse;
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

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationDetails, ErrorResponse, IdentityProvider, OAuthErrorCode, Provider,
        ProviderHandler, TokenExchangeRequest, TokenRequest, TokenRequestInputs,
    };
    use crate::handler::ApiError;
    use crate::http::client::FetchError;
    use crate::http::client::{Client, ClientConfig};
    use crate::oauth::assertion::ClientAssertion;
    use crate::oauth::grant::TokenExchange;
    use crate::oauth::jwt::JwtValidator;
    use axum::Router;
    use axum::extract::{Form, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use jsonwebkey as jwk;
    use pretty_assertions::assert_eq;
    use rstest::rstest;
    use serde::Deserialize;
    use serde_json::json;
    use std::collections::HashMap;
    use std::hash::{DefaultHasher, Hash, Hasher};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // build AuthorizationDetails without deserializing a JSON string.
    macro_rules! auth_details {
        ( [ $( { $($k:tt : $v:tt),* $(,)? } ),* $(,)? ] ) => {
            AuthorizationDetails::from(vec![
                $({
                    let mut m = ::serde_json::Map::new();
                    $(
                        m.insert($k.to_string(), ::serde_json::json!($v));
                    )*
                    m
                }),*
            ])
        };
    }

    #[derive(Deserialize, Debug)]
    struct AuthorizationDetailsWrapper {
        authorization_details: AuthorizationDetails,
    }

    #[rstest]
    #[case("azuread", IdentityProvider::EntraID)]
    #[case("entra_id", IdentityProvider::EntraID)]
    #[case("tokenx", IdentityProvider::TokenX)]
    #[case("maskinporten", IdentityProvider::Maskinporten)]
    #[case("idporten", IdentityProvider::IDPorten)]
    #[case("ansattporten", IdentityProvider::Ansattporten)]
    fn valid_identity_provider_should_deserialize(
        #[case] input: String,
        #[case] expected: IdentityProvider,
    ) {
        let deserialized =
            serde_json::from_str::<IdentityProvider>(&format!(r#""{}""#, input)).unwrap();
        assert_eq!(deserialized, expected);
    }

    #[rstest]
    #[case(
        IdentityProvider::EntraID,
        "cluster:namespace:application",
        "api://cluster.namespace.application/.default"
    )]
    #[case(
        IdentityProvider::EntraID,
        "https://application.example",
        "https://application.example"
    )]
    #[case(
        IdentityProvider::EntraID,
        "api://application/.default",
        "api://application/.default"
    )]
    #[case(
        IdentityProvider::TokenX,
        "cluster:namespace:application",
        "cluster:namespace:application"
    )]
    #[case(IdentityProvider::EntraID, "ordinary-scope", "ordinary-scope")]
    #[case(IdentityProvider::EntraID, "cluster:namespace", "cluster:namespace")]
    #[case(
        IdentityProvider::EntraID,
        "cluster::application",
        "cluster::application"
    )]
    fn identity_provider_normalizes_tokenx_target_for_entra_id(
        #[case] identity_provider: IdentityProvider,
        #[case] target: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(
            identity_provider.normalize_target(target.to_string()),
            expected
        );
    }

    #[test]
    fn normalized_requests_preserve_the_original_target() {
        let token_request = TokenRequest {
            target: "cluster:namespace:application".to_string(),
            identity_provider: IdentityProvider::EntraID,
            resource: None,
            authorization_details: None,
            skip_cache: None,
        };
        let exchange_request = TokenExchangeRequest {
            target: "cluster:namespace:application".to_string(),
            identity_provider: IdentityProvider::EntraID,
            user_token: "user-token".to_string(),
            skip_cache: None,
        };

        let normalized_token_request = token_request.with_normalized_target();
        let normalized_exchange_request = exchange_request.with_normalized_target();

        assert_eq!(
            normalized_token_request.target,
            "api://cluster.namespace.application/.default"
        );
        assert_eq!(
            normalized_exchange_request.target,
            "api://cluster.namespace.application/.default"
        );
        assert_eq!(token_request.target, "cluster:namespace:application");
        assert_eq!(exchange_request.target, "cluster:namespace:application");
    }

    #[rstest]
    #[case(|mut req: TokenRequest| { req.target = "some_target".to_string(); req }, true)]
    #[case(|mut req: TokenRequest| { req.target = "some_other_target".to_string(); req }, false)]
    #[case(|mut req: TokenRequest| { req.identity_provider = IdentityProvider::Maskinporten; req }, true)]
    #[case(|mut req: TokenRequest| { req.identity_provider = IdentityProvider::TokenX; req }, false)]
    #[case(|mut req: TokenRequest| { req.resource = None; req }, true)]
    #[case(|mut req: TokenRequest| { req.resource = Some("some_resource".to_string()); req }, false)]
    #[case(|mut req: TokenRequest| { req.authorization_details = None; req }, true)]
    #[case(|mut req: TokenRequest| { req.authorization_details = Some(auth_details!([])); req }, false)]
    #[case(|mut req: TokenRequest| { req.authorization_details = Some(auth_details!([ { "type": "some_type" } ])); req }, false)]
    // skip_cache does not affect equality
    #[case(|mut req: TokenRequest| { req.skip_cache = None; req }, true)]
    #[case(|mut req: TokenRequest| { req.skip_cache = Some(true); req }, true)]
    #[case(|mut req: TokenRequest| { req.skip_cache = Some(false); req }, true)]
    fn token_request_equality_should_work(
        #[case] mutate: fn(TokenRequest) -> TokenRequest,
        #[case] expect_equal: bool,
    ) {
        let original = TokenRequest {
            target: "some_target".to_string(),
            identity_provider: IdentityProvider::Maskinporten,
            resource: None,
            authorization_details: None,
            skip_cache: None,
        };
        let mutated = mutate(original.clone());
        assert_eq!(original == mutated, expect_equal);

        let mut hasher1 = DefaultHasher::new();
        original.hash(&mut hasher1);
        let h1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        mutated.hash(&mut hasher2);
        let h2 = hasher2.finish();

        if expect_equal {
            assert_eq!(h1, h2);
        } else {
            assert_ne!(h1, h2);
        }
    }

    #[rstest]
    #[case(
        r#"[{"type":"some_type"}]"#,
        auth_details!([ { "type": "some_type" } ])
    )]
    #[case(
        r#"[{"type":"some_type"},{"some_array":[{"type": "some_other_type"}]}]"#,
        auth_details!([
            { "type": "some_type" },
            { "some_array": [ { "type": "some_other_type" } ] }
        ])
    )]
    #[case(r#"[]"#, auth_details!([]))]
    fn valid_json_authorization_details_should_deserialize(
        #[case] input: &str,
        #[case] expected: AuthorizationDetails,
    ) {
        let deserialized = serde_json::from_str::<AuthorizationDetails>(input);
        assert!(deserialized.is_ok());
        assert_eq!(deserialized.unwrap(), expected);
    }

    #[rstest]
    #[case("not a json array")]
    #[case(r#"{"type":"some_type"}"#)]
    #[case(r#"[{"type":"some_type"}"#)] // unterminated array
    #[case(r#"42"#)]
    #[case(r#"null"#)]
    #[case(r#"true"#)]
    #[case(r#"false"#)]
    fn invalid_json_authorization_details_should_not_deserialize(#[case] input: &str) {
        let deserialized = serde_json::from_str::<AuthorizationDetails>(input);
        assert!(deserialized.is_err());
    }

    #[rstest]
    #[case(
        "authorization_details=%5B%7B%22type%22%3A%22some_type%22%7D%5D",
        auth_details!([ { "type": "some_type" } ])
    )]
    #[case(
        "authorization_details=%5B%7B%22type%22%3A%22some_type%22%7D%2C%7B%22some_array%22%3A%5B%7B%22type%22%3A%20%22some_other_type%22%7D%5D%7D%5D",
        auth_details!([
            { "type": "some_type"},
            { "some_array": [ { "type": "some_other_type" } ] }
        ])
    )]
    #[case("authorization_details=%5B%5D", auth_details!([]))]
    fn valid_form_authorization_details_should_deserialize(
        #[case] form: &str,
        #[case] expected: AuthorizationDetails,
    ) {
        let res = serde_urlencoded::from_str::<AuthorizationDetailsWrapper>(form).unwrap();
        assert_eq!(res.authorization_details, expected);
    }

    #[rstest]
    #[case("authorization_details=not+a+json+array")] // invalid JSON
    #[case("authorization_details=%7B%22type%22%3A%22t%22%7D")] // {"type":"some_type"} - object, not array
    #[case("authorization_details=%5B%7B%22type%22%3A%22t%22%7D")] // [{"type":"some_type"} - unterminated array
    fn invalid_form_authorization_details_should_not_deserialize(#[case] form: &str) {
        let res = serde_urlencoded::from_str::<AuthorizationDetailsWrapper>(form);
        assert!(res.is_err());
    }

    #[rstest]
    #[case(auth_details!([]), json!([]))]
    #[case(auth_details!([ { "type": "some_type" } ]), json!([ { "type": "some_type" } ]))]
    fn authorization_details_should_serialize(
        #[case] input: AuthorizationDetails,
        #[case] expected: serde_json::Value,
    ) {
        let serialized = serde_json::to_value(&input).unwrap();
        assert_eq!(serialized, expected);
    }

    const JWKS_BODY: &str = r#"{"keys":[]}"#;

    struct MockIdentityProvider {
        url: String,
        assertions: Arc<Mutex<Vec<String>>>,
        server: tokio::task::JoinHandle<()>,
    }

    impl MockIdentityProvider {
        async fn serving(responses: Vec<(StatusCode, &'static str)>) -> Self {
            let assertions = Arc::new(Mutex::new(Vec::new()));
            let state = Arc::new(MockState {
                responses: responses
                    .into_iter()
                    .map(|(status, body)| (status, body.to_string()))
                    .collect(),
                attempts: AtomicUsize::new(0),
                assertions: assertions.clone(),
            });
            let router = Router::new()
                .route(
                    "/jwks",
                    get(|| async {
                        (
                            StatusCode::OK,
                            [("content-type", "application/json")],
                            JWKS_BODY,
                        )
                            .into_response()
                    }),
                )
                .route("/token", post(token))
                .with_state(state);
            let (listener, url) = bind().await;
            let server = tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            });
            Self {
                url,
                assertions,
                server,
            }
        }

        async fn serving_split_body(body: &'static str, delay: Duration) -> Self {
            let (listener, url) = bind().await;
            let assertions = Arc::new(Mutex::new(Vec::new()));
            let server_assertions = assertions.clone();
            let server = tokio::spawn(async move {
                let attempts = Arc::new(AtomicUsize::new(0));
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let attempts = attempts.clone();
                    let assertions = server_assertions.clone();
                    tokio::spawn(async move {
                        serve_split_body(stream, body, delay, &attempts, &assertions).await;
                    });
                }
            });
            Self {
                url,
                assertions,
                server,
            }
        }

        fn token_endpoint(&self) -> String {
            format!("{}/token", self.url)
        }

        fn assertions(&self) -> Vec<String> {
            self.assertions.lock().unwrap().clone()
        }
    }

    impl Drop for MockIdentityProvider {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    async fn bind() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        (listener, url)
    }

    struct MockState {
        responses: Vec<(StatusCode, String)>,
        attempts: AtomicUsize,
        assertions: Arc<Mutex<Vec<String>>>,
    }

    async fn token(
        State(state): State<Arc<MockState>>,
        Form(form): Form<HashMap<String, String>>,
    ) -> Response {
        state.assertions.lock().unwrap().push(form["client_assertion"].clone());
        let attempt = state.attempts.fetch_add(1, Ordering::Relaxed);
        let (status, body) =
            state.responses.get(attempt).or_else(|| state.responses.last()).unwrap();
        (
            *status,
            [("content-type", "application/json")],
            body.clone(),
        )
            .into_response()
    }

    async fn serve_split_body(
        mut stream: TcpStream,
        body: &'static str,
        delay: Duration,
        attempts: &AtomicUsize,
        assertions: &Mutex<Vec<String>>,
    ) {
        let Some((mut request, headers_end)) = read_headers(&mut stream).await else {
            return;
        };

        if request.starts_with(b"GET /jwks") {
            write_headers(&mut stream, JWKS_BODY.len()).await;
            stream.write_all(JWKS_BODY.as_bytes()).await.unwrap();
            return;
        }

        assert!(request.starts_with(b"POST /token"));
        let headers = std::str::from_utf8(&request[..headers_end]).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.strip_prefix("content-length: ")
                    .or_else(|| line.strip_prefix("Content-Length: "))
            })
            .and_then(|length| length.parse::<usize>().ok())
            .unwrap_or(0);
        let body_start = headers_end + 4;
        let mut buffer = [0; 1024];
        while request.len() < body_start + content_length {
            let bytes_read = stream.read(&mut buffer).await.unwrap();
            if bytes_read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..bytes_read]);
        }
        let form = serde_urlencoded::from_bytes::<HashMap<String, String>>(
            &request[body_start..body_start + content_length],
        )
        .unwrap();
        assertions.lock().unwrap().push(form["client_assertion"].clone());

        let first_attempt = attempts.fetch_add(1, Ordering::Relaxed) == 0;
        let (head, tail) = body.split_at(body.len() / 2);
        write_headers(&mut stream, body.len()).await;
        stream.write_all(head.as_bytes()).await.unwrap();
        if first_attempt {
            tokio::time::sleep(delay).await;
        }
        stream.write_all(tail.as_bytes()).await.unwrap();
    }

    async fn read_headers(stream: &mut TcpStream) -> Option<(Vec<u8>, usize)> {
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let bytes_read = stream.read(&mut buffer).await.unwrap();
            if bytes_read == 0 {
                return None;
            }
            request.extend_from_slice(&buffer[..bytes_read]);
            if let Some(headers_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                return Some((request, headers_end));
            }
        }
    }

    async fn write_headers(stream: &mut TcpStream, content_length: usize) {
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
    }

    async fn provider_with_read_timeout(
        base_url: &str,
        read_timeout: Duration,
        max_retries: u32,
    ) -> Provider<TokenExchange, ClientAssertion> {
        let jwks_url = format!("{base_url}/jwks");
        let jwt_validator = JwtValidator::new(&jwks_url, &jwks_url, None).await.unwrap();
        let mut provider = Provider::<TokenExchange, ClientAssertion>::new(
            IdentityProvider::TokenX,
            "client-id".to_string(),
            format!("{base_url}/issuer"),
            Some(format!("{base_url}/token")),
            Some({
                let mut key = jwk::JsonWebKey::new(jwk::Key::generate_p256());
                key.set_algorithm(jwk::Algorithm::ES256).unwrap();
                key.key_id = Some("client-key".to_string());
                key.to_string()
            }),
            jwt_validator,
        )
        .unwrap();
        provider.http_client = Client::new(ClientConfig {
            connect_timeout: Duration::from_secs(1),
            read_timeout,
            request_timeout: Duration::from_secs(10),
            pool_max_idle_per_host: 100,
            pool_idle_timeout: Duration::from_secs(10),
            max_retries,
        })
        .unwrap();
        provider
    }

    fn token_request_inputs() -> TokenRequestInputs {
        TokenRequestInputs {
            target: "target".to_string(),
            resource: None,
            authorization_details: None,
            user_token: Some("user-token".to_string()),
        }
    }

    fn token_request() -> TokenRequest {
        TokenRequest {
            target: "target".to_string(),
            identity_provider: IdentityProvider::TokenX,
            resource: None,
            authorization_details: None,
            skip_cache: None,
        }
    }

    fn token_exchange_request() -> TokenExchangeRequest {
        TokenExchangeRequest {
            target: "target".to_string(),
            identity_provider: IdentityProvider::TokenX,
            user_token: "user-token".to_string(),
            skip_cache: None,
        }
    }

    #[tokio::test]
    async fn assertion_failure_is_reported_as_sign_error() {
        let server = MockIdentityProvider::serving(vec![]).await;
        let mut provider = provider_with_read_timeout(&server.url, Duration::from_secs(1), 1).await;
        provider.private_jwk = None;

        assert!(matches!(
            provider.get_token(token_request()).await,
            Err(ApiError::Sign)
        ));
        assert!(server.assertions().is_empty());
    }

    #[tokio::test]
    async fn missing_token_endpoint_reports_operation_specific_error() {
        let server = MockIdentityProvider::serving(vec![]).await;
        let mut provider = provider_with_read_timeout(&server.url, Duration::from_secs(1), 1).await;
        provider.token_endpoint = None;

        assert!(matches!(
            provider.get_token(token_request()).await,
            Err(ApiError::TokenRequestUnsupported(IdentityProvider::TokenX))
        ));
        assert!(matches!(
            provider.exchange_token(token_exchange_request()).await,
            Err(ApiError::TokenExchangeUnsupported(IdentityProvider::TokenX))
        ));
        assert!(server.assertions().is_empty());
    }

    #[tokio::test]
    async fn delayed_token_response_body_is_reported_as_body_read_error() {
        let server = MockIdentityProvider::serving_split_body(
            r#"{"access_token":"token","token_type":"Bearer","expires_in":3600}"#,
            Duration::from_millis(2_000),
        )
        .await;
        let provider = provider_with_read_timeout(&server.url, Duration::from_millis(500), 0).await;

        let error = provider
            .get_token_from_idprovider(token_request_inputs(), &server.token_endpoint())
            .await
            .unwrap_err();

        match error {
            ApiError::UpstreamFailure(error) => {
                let FetchError::BodyRead { status, source } = error.as_ref() else {
                    panic!("expected body read error, got {error:?}");
                };
                assert_eq!(*status, StatusCode::OK);
                assert!(source.is_decode());
                assert!(source.is_timeout());
            }
            error => panic!("expected upstream response error, got {error:?}"),
        }
    }

    #[tokio::test]
    async fn retrying_delayed_token_response_body_succeeds() {
        let server = MockIdentityProvider::serving_split_body(
            r#"{"access_token":"token","token_type":"Bearer","expires_in":3600}"#,
            Duration::from_millis(2_000),
        )
        .await;
        let provider = provider_with_read_timeout(&server.url, Duration::from_millis(500), 1).await;

        let response = provider
            .get_token_from_idprovider(token_request_inputs(), &server.token_endpoint())
            .await
            .unwrap();

        assert_eq!(response.access_token, "token");
        let assertions = server.assertions();
        assert_eq!(assertions.len(), 2);
        assert_ne!(assertions[0], assertions[1]);
    }

    #[tokio::test]
    async fn malformed_oauth_error_response_preserves_upstream_status() {
        let server =
            MockIdentityProvider::serving(vec![(StatusCode::BAD_REQUEST, "not json")]).await;
        let provider = provider_with_read_timeout(&server.url, Duration::from_secs(1), 1).await;

        let error = provider
            .get_token_from_idprovider(token_request_inputs(), &server.token_endpoint())
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            ApiError::UpstreamOAuthError {
                status_code: StatusCode::BAD_REQUEST,
                error: ErrorResponse {
                    error: OAuthErrorCode::ServerError,
                    ..
                },
            }
        ));
    }

    #[tokio::test]
    async fn redirect_response_is_reported_as_upstream_failure() {
        let server = MockIdentityProvider::serving(vec![(StatusCode::FOUND, "redirect")]).await;
        let provider = provider_with_read_timeout(&server.url, Duration::from_secs(1), 1).await;

        let error = provider
            .get_token_from_idprovider(token_request_inputs(), &server.token_endpoint())
            .await
            .unwrap_err();

        assert!(
            matches!(error, ApiError::UpstreamFailure(error) if matches!(
                error.as_ref(),
                FetchError::Status { status: StatusCode::FOUND, .. }
            ))
        );
    }

    #[tokio::test]
    async fn oauth_error_without_description_is_valid() {
        let server = MockIdentityProvider::serving(vec![(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_grant"}"#,
        )])
        .await;
        let provider = provider_with_read_timeout(&server.url, Duration::from_secs(1), 1).await;

        let error = provider
            .get_token_from_idprovider(token_request_inputs(), &server.token_endpoint())
            .await
            .unwrap_err();

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

    #[tokio::test]
    async fn retrying_token_request_regenerates_assertion() {
        let server = MockIdentityProvider::serving(vec![
            (StatusCode::SERVICE_UNAVAILABLE, r#"{"error":"temporary"}"#),
            (
                StatusCode::OK,
                r#"{"access_token":"token","token_type":"Bearer","expires_in":3600}"#,
            ),
        ])
        .await;
        let provider = provider_with_read_timeout(&server.url, Duration::from_secs(1), 1).await;

        let response = provider
            .get_token_from_idprovider(token_request_inputs(), &server.token_endpoint())
            .await
            .unwrap();

        assert_eq!(response.access_token, "token");
        let assertions = server.assertions();
        assert_eq!(assertions.len(), 2);
        assert_ne!(assertions[0], assertions[1]);
    }

    #[tokio::test]
    async fn malformed_token_json_is_not_retried() {
        let server = MockIdentityProvider::serving(vec![(StatusCode::OK, "not json")]).await;
        let provider = provider_with_read_timeout(&server.url, Duration::from_secs(1), 3).await;

        let error = provider
            .get_token_from_idprovider(token_request_inputs(), &server.token_endpoint())
            .await
            .unwrap_err();

        assert!(matches!(error, ApiError::UpstreamFailure(_)));
        assert_eq!(server.assertions().len(), 1);
    }
}
