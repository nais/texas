use crate::handler::ApiError;
use crate::http::client;
use crate::oauth::assertion::{Assertion, serialize};
use crate::oauth::grant::{
    ClientCredentials, JWTBearer, OnBehalfOf, TokenExchange, TokenRequestBuilder,
    TokenRequestBuilderParams,
};
use crate::oauth::jwt::JwtValidator;
use crate::oauth::request::{
    AuthorizationDetails, IntrospectRequest, TokenExchangeRequest, TokenRequest,
};
use crate::oauth::response::{IntrospectResponse, TokenResponse};
use crate::telemetry::record_identity_provider_latency;
use async_trait::async_trait;
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::PartialEq;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use thiserror::Error;
use tracing::instrument;
use utoipa::ToSchema;

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

/// Per-request inputs for a token request.
#[derive(Clone)]
struct TokenRequestInputs {
    target: String,
    resource: Option<String>,
    authorization_details: Option<AuthorizationDetails>,
    user_token: Option<String>,
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
    use super::{IdentityProvider, Provider, ProviderHandler, TokenRequestInputs};
    use crate::handler::ApiError;
    use crate::http::client::FetchError;
    use crate::http::client::{Client, ClientConfig};
    use crate::oauth::assertion::ClientAssertion;
    use crate::oauth::grant::TokenExchange;
    use crate::oauth::jwt::JwtValidator;
    use crate::oauth::request::{TokenExchangeRequest, TokenRequest};
    use axum::Router;
    use axum::extract::{Form, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use jsonwebkey as jwk;
    use pretty_assertions::assert_eq;
    use rstest::rstest;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

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
    fn identity_provider_normalizes_target(
        #[case] identity_provider: IdentityProvider,
        #[case] target: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(
            identity_provider.normalize_target(target.to_string()),
            expected
        );
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
