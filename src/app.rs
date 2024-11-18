use crate::config::Config;
use crate::handlers::__path_introspect;
use crate::handlers::__path_token;
use crate::handlers::__path_token_exchange;
use crate::handlers::{introspect, token, token_exchange, HandlerState};
use axum::body::Bytes;
use axum::extract::MatchedPath;
use axum::http::{HeaderMap, Request};
use axum::response::Response;
use axum::Router;
use log::info;
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_http::HeaderExtractor;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use std::time::Duration;
use opentelemetry::baggage::BaggageExt;
use opentelemetry::KeyValue;
use tokio::net::TcpListener;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::trace::TraceLayer;
use tracing::{info_span, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

pub struct App {
    router: Router,
    listener: TcpListener,
}

#[derive(OpenApi)]
struct ApiDoc;

impl App {
    pub async fn new(cfg: Config) -> Self {
        let bind_address = cfg.bind_address.clone();
        let listener = TcpListener::bind(bind_address).await.unwrap();

        let state = HandlerState::from_config(cfg).await.unwrap();
        let app = Self::router(state).await;

        info!("Serving on http://{:?}", listener.local_addr().unwrap());
        #[cfg(feature = "openapi")]
        info!("Swagger API documentation: http://{:?}/swagger-ui", listener.local_addr().unwrap());

        Self { router: app, listener }
    }

    pub async fn run(self) -> std::io::Result<()> {
        axum::serve(self.listener, self.router).await
    }

    #[cfg(test)]
    pub fn address(&self) -> Option<String> {
        self.listener.local_addr().map(|addr| addr.to_string()).ok()
    }

    async fn router(state: HandlerState) -> Router {
        #[allow(unused)]
        let (router, openapi) = OpenApiRouter::with_openapi(ApiDoc::openapi())
            .routes(routes!(token))
            .routes(routes!(token_exchange))
            .routes(routes!(introspect))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(|request: &Request<_>| {
                        // Log the matched route's path (with placeholders not filled in).
                        // Use request.uri() or OriginalUri if you want the real path.
                        let path = request
                            .extensions()
                            .get::<MatchedPath>()
                            .map(MatchedPath::as_str);

                        // get tracing context from request
                        let propagator = TraceContextPropagator::new();
                        let parent_context = propagator.extract(&HeaderExtractor(request.headers()));

                        let root_span = info_span!(
                            "http_request",
                            method = ?request.method(),
                            path,
                        );

                        let context = parent_context.with_baggage(vec![KeyValue::new("path".to_string(), path.unwrap_or_default().to_string())]);
                        root_span.set_parent(context.clone());
                        root_span
                    })
                    .on_request(|_request: &Request<_>, _span: &Span| {
                        // You can use `_span.record("some_other_field", value)` in one of these
                        // closures to attach a value to the initially empty field in the info_span
                        // created above.
                    })
                    .on_response(|response: &Response, latency: Duration, span: &Span| {
                        let path = span.context().baggage().get("path").map(|x| x.to_string()).unwrap_or_default();
                        
                        tracing::info!(
                            histogram.http_response_secs = latency.as_secs_f64(),
                            status_code = response.status().as_u16(),
                            path = path,
                        );
                    })
                    .on_body_chunk(|_chunk: &Bytes, _latency: Duration, _span: &Span| {
                        // ...
                    })
                    .on_eos(
                        |_trailers: Option<&HeaderMap>, _stream_duration: Duration, _span: &Span| {
                            // ...
                        },
                    )
                    .on_failure(
                        |_error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {
                            // ...
                        },
                    ),
            )
            .with_state(state)
            .split_for_parts();

        #[cfg(feature = "openapi")]
        use utoipa_swagger_ui::SwaggerUi;
        #[cfg(feature = "openapi")]
        let router = router.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi.clone()));

        router
    }
}

#[cfg(test)]
mod tests {
    use crate::app::tests::RequestFormat::Json;
    use crate::app::App;
    use crate::claims::epoch_now_secs;
    use crate::config::Config;
    use crate::identity_provider::{ErrorResponse, IdentityProvider, IntrospectRequest, IntrospectResponse, OAuthErrorCode, TokenExchangeRequest, TokenRequest, TokenResponse};
    use jsonwebkey as jwk;
    use jsonwebtoken as jwt;
    use log::{info, LevelFilter};
    use reqwest::{Error, Response, StatusCode};
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::fmt::Debug;
    use testcontainers::{ContainerAsync, GenericImage};

    /// Test a full round-trip of the `/token`, `/token/exchange`, and `/introspect` endpoints.
    ///
    /// Content-type encodings tested are both `application/json` and `application/x-www-form-urlencoded`.
    ///
    /// Test token exchange as follows:
    ///   1. Request an initial token from the mock oauth2 server using the `/token` endpoint
    ///   2. Exchange that token into a on-behalf-of token using Texas' `/token` endpoint
    ///   3. Introspect the resulting token and check parameters
    ///
    /// Test client credentials as follows:
    ///   1. Request a client credentials token using Texas' `/token` endpoint
    ///   2. Introspect the resulting token and check parameters
    #[tokio::test]
    async fn test_all_providers_integration_tests() {
        let testapp = TestApp::new().await;
        let address = testapp.app.address().unwrap();
        let join_handler = tokio::spawn(async move {
            testapp.app.run().await.unwrap();
        });
        let identity_provider_address = format!("{}:{}", testapp.docker.host.clone(), testapp.docker.port);

        // All happy cases
        for format in [RequestFormat::Form, RequestFormat::Json] {
            machine_to_machine_token(
                testapp.cfg.maskinporten.clone().unwrap().issuer.clone(),
                "scope".to_string(),
                address.to_string(),
                IdentityProvider::Maskinporten,
                format.clone(),
            )
                .await;

            machine_to_machine_token(
                testapp.cfg.azure_ad.clone().unwrap().issuer.clone(),
                testapp.cfg.azure_ad.clone().unwrap().client_id.clone(),
                address.to_string(),
                IdentityProvider::AzureAD,
                format.clone(),
            )
                .await;

            token_exchange_token(
                testapp.cfg.azure_ad.clone().unwrap().issuer.clone(),
                testapp.cfg.azure_ad.clone().unwrap().client_id.clone(),
                address.to_string(),
                identity_provider_address.to_string(),
                IdentityProvider::AzureAD,
                format.clone(),
            )
                .await;

            token_exchange_token(
                testapp.cfg.token_x.clone().unwrap().issuer.clone(),
                testapp.cfg.token_x.clone().unwrap().client_id.clone(),
                address.to_string(),
                identity_provider_address.to_string(),
                IdentityProvider::TokenX,
                format.clone(),
            )
                .await;

            introspect_idporten_token(testapp.cfg.idporten.clone().unwrap().issuer.clone(), address.to_string(), identity_provider_address.to_string(), format).await;
        }

        test_token_invalid_identity_provider(&address).await;
        test_token_invalid_content_type(&address).await;
        test_token_exchange_missing_or_empty_user_token(&address).await;
        test_introspect_token_is_not_a_jwt(&address).await;
        test_introspect_token_missing_issuer(&address).await;
        test_introspect_token_unrecognized_issuer(&address).await;
        test_introspect_token_issuer_mismatch(&address, &identity_provider_address).await;
        test_introspect_token_missing_kid(&address, &identity_provider_address).await;
        test_introspect_token_missing_key_in_jwks(&address, &identity_provider_address).await;
        test_introspect_token_is_expired(&address, &identity_provider_address).await;
        test_introspect_token_is_issued_in_the_future(&address, &identity_provider_address).await;
        test_introspect_token_has_not_before_in_the_future(&address, &identity_provider_address).await;
        test_introspect_token_invalid_audience(&address).await;
        // TODO: implement these tests:
        // * /token
        //   * [ ] upstream network error / reqwest error
        //   * [ ] upstream responded with code >= 400
        //      * [ ] json deserialize error
        //      * [ ] oauth error
        //   * [ ] upstream responded with success code but non-json body
        //
        // * /token/exchange
        //   * [x] missing or empty user token
        //   * [ ] upstream network error / reqwest error
        //   * [ ] upstream responded with code >= 400
        //      * [ ] json deserialize error
        //      * [ ] oauth error
        //   * [ ] upstream responded with success code but non-json body
        //
        // * /introspect
        //   * [x] token is not a jwt
        //   * [x] token does not contain iss claim
        //   * [x] token is issued by unrecognized issuer
        //   * [x] token does not have kid (key id) in header
        //   * [x] token is signed with a key that is not in the jwks
        //   * [x] invalid or expired timestamps in nbf, iat, exp
        //   * [x] invalid or missing aud (for certain providers)
        //   * [ ] refreshing jwks fails
        //     * [ ] fetch / network error / reqwest error
        //     * [ ] decode error
        //     * [ ] jwks has key with blank or missing key id

        join_handler.abort();
    }

    async fn test_introspect_token_unrecognized_issuer(address: &str) {
        let token = Token::sign_with_kid(
            TokenClaims::from([
                ("iss".into(), Value::String("snafu".into())),
                ("nbf".into(), (epoch_now_secs()).into()),
                ("iat".into(), (epoch_now_secs()).into()),
                ("exp".into(), (epoch_now_secs() + 120).into()),
            ]),
            &IdentityProvider::Maskinporten.to_string(),
        );
        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::Maskinporten,
            },
            IntrospectResponse::new_invalid("invalid token: InvalidIssuer"),
            StatusCode::OK,
        )
            .await;
    }

    async fn test_introspect_token_issuer_mismatch(address: &str, identity_provider_address: &str) {
        let iss = format!("http://{}/maskinporten", identity_provider_address);
        let token = Token::sign_with_kid(TokenClaims::from([
            ("iss".into(), Value::String(iss)),
            ("nbf".into(), (epoch_now_secs()).into()),
            ("iat".into(), (epoch_now_secs()).into()),
            ("exp".into(), (epoch_now_secs() + 120).into()),
        ]), &IdentityProvider::Maskinporten.to_string());

        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::AzureAD,
            },
            IntrospectResponse::new_invalid("token can not be validated with this identity provider"),
            StatusCode::OK,
        )
            .await;
    }

    async fn test_introspect_token_missing_issuer(address: &str) {
        let token = Token::sign_with_kid(TokenClaims::from([
            ("nbf".into(), (epoch_now_secs()).into()),
            ("iat".into(), (epoch_now_secs()).into()),
            ("exp".into(), (epoch_now_secs() + 120).into()),
        ]), &IdentityProvider::Maskinporten.to_string());

        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::Maskinporten,
            },
            IntrospectResponse::new_invalid("invalid token: Missing required claim: iss"),
            StatusCode::OK,
        )
            .await;
    }

    async fn test_introspect_token_is_not_a_jwt(address: &str) {
        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token: "not a jwt".to_string(),
                identity_provider: IdentityProvider::AzureAD,
            },
            IntrospectResponse::new_invalid("invalid token header: InvalidToken"),
            StatusCode::OK,
        )
            .await;
    }

    async fn test_introspect_token_missing_kid(address: &str, identity_provider_address: &str) {
        let token = Token::sign(TokenClaims::from([("iss".into(), format!("http://{}/maskinporten", identity_provider_address).into())]));
        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::AzureAD,
            },
            IntrospectResponse::new_invalid("missing key id from token header"),
            StatusCode::OK,
        )
            .await;
    }

    async fn test_introspect_token_missing_key_in_jwks(address: &str, identity_provider_address: &str) {
        let token = Token::sign_with_kid(TokenClaims::from([("iss".into(), format!("http://{}/maskinporten", identity_provider_address).into())]), "missing-key");

        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::Maskinporten,
            },
            IntrospectResponse::new_invalid("token can not be validated with this identity provider"),
            StatusCode::OK,
        )
            .await;
    }

    async fn test_introspect_token_is_expired(address: &str, identity_provider_address: &str) {
        // token is expired
        let token = Token::sign_with_kid(
            TokenClaims::from([
                ("iss".into(), format!("http://{}/maskinporten", identity_provider_address).into()),
                ("nbf".into(), (epoch_now_secs()).into()),
                ("iat".into(), (epoch_now_secs()).into()),
                ("exp".into(), (epoch_now_secs() - 120).into()),
            ]),
            "maskinporten",
        );

        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::Maskinporten,
            },
            IntrospectResponse::new_invalid("invalid token: ExpiredSignature"),
            StatusCode::OK,
        )
            .await;
    }

    async fn test_introspect_token_is_issued_in_the_future(address: &str, identity_provider_address: &str) {
        let token = Token::sign_with_kid(
            TokenClaims::from([
                ("iss".into(), format!("http://{}/maskinporten", identity_provider_address).into()),
                ("nbf".into(), (epoch_now_secs()).into()),
                ("iat".into(), (epoch_now_secs() + 120).into()),
                ("exp".into(), (epoch_now_secs() + 300).into()),
            ]),
            "maskinporten",
        );

        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::Maskinporten,
            },
            IntrospectResponse::new_invalid("invalid token: ImmatureSignature"),
            StatusCode::OK,
        )
            .await;
    }

    async fn test_introspect_token_has_not_before_in_the_future(address: &str, identity_provider_address: &str) {
        let token = Token::sign_with_kid(
            TokenClaims::from([
                ("iss".into(), format!("http://{}/maskinporten", identity_provider_address).into()),
                ("nbf".into(), (epoch_now_secs() + 120).into()),
                ("iat".into(), (epoch_now_secs()).into()),
                ("exp".into(), (epoch_now_secs() + 300).into()),
            ]),
            "maskinporten",
        );

        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::Maskinporten,
            },
            IntrospectResponse::new_invalid("invalid token: ImmatureSignature"),
            StatusCode::OK,
        )
            .await;
    }

    async fn test_introspect_token_invalid_audience(address: &str) {
        let response = post_request(
            format!("http://{}/api/v1/token", address.to_string()),
            TokenRequest {
                target: "invalid".to_string(),
                identity_provider: IdentityProvider::AzureAD,
            },
            Json,
        )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "failed to get token: {:?}", response.text().await.unwrap());

        let body: TokenResponse = response.json().await.unwrap();
        assert!(body.expires_in_seconds > 0);
        assert!(!body.access_token.is_empty());

        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token: body.access_token.clone(),
                identity_provider: IdentityProvider::AzureAD,
            },
            IntrospectResponse::new_invalid("invalid token: InvalidAudience"),
            StatusCode::OK,
        )
            .await;
    }

    async fn test_token_exchange_missing_or_empty_user_token(address: &str) {
        test_well_formed_json_request(
            &format!("http://{}/api/v1/token/exchange", address),
            TokenExchangeRequest {
                target: "target".to_string(),
                identity_provider: IdentityProvider::AzureAD,
                user_token: "".to_string(),
            },
            ErrorResponse {
                error: OAuthErrorCode::InvalidRequest,
                description: "invalid request: missing or empty assertion parameter".to_string(),
            },
            StatusCode::BAD_REQUEST,
        )
            .await;
    }

    async fn test_token_invalid_identity_provider(address: &str) {
        let response = post_request(
            format!("http://{}/api/v1/token", address),
            json!({"target":"dontcare","identity_provider":"invalid"}),
            RequestFormat::Json,
        )
            .await
            .unwrap();

        assert_eq!(response.status(), 400);
        assert_eq!(
            response.text().await.unwrap(),
            r#"{"error":"invalid_request","error_description":"Failed to deserialize the JSON body into the target type: identity_provider: unknown variant `invalid`, expected one of `azuread`, `tokenx`, `maskinporten`, `idporten` at line 1 column 30"}"#
        );

        let response = post_request(
            format!("http://{}/api/v1/token", address),
            HashMap::from([("target", "dontcare"), ("identity_provider", "invalid")]),
            RequestFormat::Form,
        )
            .await
            .unwrap();

        assert_eq!(response.status(), 400);
        assert_eq!(
            response.text().await.unwrap(),
            r#"{"error":"invalid_request","error_description":"Failed to deserialize form body: unknown variant `invalid`, expected one of `azuread`, `tokenx`, `maskinporten`, `idporten`"}"#
        );
    }

    async fn test_token_invalid_content_type(address: &str) {
        let client = reqwest::Client::new();
        let request = client
            .post(format!("http://{}/api/v1/token", address))
            .header("accept", "application/json")
            .header("content-type", "text/plain")
            .body("some plain text");
        let response = request.send().await.unwrap();

        assert_eq!(response.status(), 400);
        assert_eq!(
            response.text().await.unwrap(),
            r#"{"error":"invalid_request","error_description":"unsupported media type: text/plain: expected one of `application/json`, `application/x-www-form-urlencoded`"}"#
        );
    }

    async fn machine_to_machine_token(expected_issuer: String, target: String, address: String, identity_provider: IdentityProvider, request_format: RequestFormat) {
        let response = post_request(
            format!("http://{}/api/v1/token", address.clone().to_string()),
            TokenRequest { target, identity_provider },
            request_format.clone(),
        )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "failed to get token: {:?}", response.text().await.unwrap());

        let body: TokenResponse = response.json().await.unwrap();
        assert!(body.expires_in_seconds > 0);
        assert!(!body.access_token.is_empty());

        let response = post_request(
            format!("http://{}/api/v1/introspect", address.clone().to_string()),
            IntrospectRequest {
                token: body.access_token.clone(),
                identity_provider,
            },
            request_format,
        )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body: HashMap<String, Value> = response.json().await.unwrap();
        assert_eq!(body["active"], Value::Bool(true));
        assert_eq!(body["iss"], Value::String(expected_issuer.to_string()));
    }

    /// this tests the full token exchange roundtrip:
    ///  1. fetch user token from mock-oauth2-server
    ///  2. exchange user token for on-behalf-of token at /token/exchange
    ///  3. introspect the resulting token at /introspect
    async fn token_exchange_token(expected_issuer: String, target: String, address: String, identity_provider_address: String, identity_provider: IdentityProvider, request_format: RequestFormat) {
        #[derive(Serialize)]
        struct AuthorizeRequest {
            grant_type: String,
            code: String,
            client_id: String,
            client_secret: String,
        }

        // This request goes directly to the mock oauth2 server, which only accepts form encoding
        let user_token_response = post_request(
            format!("http://{}/token", identity_provider_address),
            AuthorizeRequest {
                grant_type: "authorization_code".to_string(),
                code: "mycode".to_string(),
                client_id: "myclientid".to_string(),
                client_secret: "myclientsecret".to_string(),
            },
            RequestFormat::Form,
        )
            .await
            .unwrap();

        assert_eq!(user_token_response.status(), 200);
        let user_token: TokenResponse = user_token_response.json().await.unwrap();

        let response = post_request(
            format!("http://{}/api/v1/token/exchange", address.clone().to_string()),
            TokenExchangeRequest {
                target,
                identity_provider,
                user_token: user_token.access_token,
            },
            request_format.clone(),
        )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "failed to exchange token: {:?}", response.text().await.unwrap());

        let body: TokenResponse = response.json().await.unwrap();
        assert!(body.expires_in_seconds > 0);
        assert!(!body.access_token.is_empty());

        let response = post_request(
            format!("http://{}/api/v1/introspect", address.clone().to_string()),
            IntrospectRequest {
                token: body.access_token.clone(),
                identity_provider,
            },
            request_format,
        )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body: HashMap<String, Value> = response.json().await.unwrap();
        assert_eq!(body["active"], Value::Bool(true));
        assert_eq!(body["iss"], Value::String(expected_issuer.to_string()));
        assert!(!body["sub"].to_string().is_empty());
    }

    async fn introspect_idporten_token(expected_issuer: String, address: String, identity_provider_address: String, request_format: RequestFormat) {
        #[derive(Serialize)]
        struct AuthorizeRequest {
            grant_type: String,
            code: String,
            client_id: String,
            client_secret: String,
        }

        // This request goes directly to the mock oauth2 server, which only accepts form encoding
        let user_token_response = post_request(
            format!("http://{}/idporten/token", identity_provider_address),
            AuthorizeRequest {
                grant_type: "authorization_code".to_string(),
                code: "mycode".to_string(),
                client_id: "myclientid".to_string(),
                client_secret: "myclientsecret".to_string(),
            },
            RequestFormat::Form,
        )
            .await
            .unwrap();

        assert_eq!(user_token_response.status(), 200);
        let user_token: TokenResponse = user_token_response.json().await.unwrap();

        let response = post_request(
            format!("http://{}/api/v1/introspect", address.clone().to_string()),
            IntrospectRequest {
                token: user_token.access_token.clone(),
                identity_provider: IdentityProvider::IDPorten,
            },
            request_format,
        )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body: HashMap<String, Value> = response.json().await.unwrap();
        assert_eq!(body["active"], Value::Bool(true));
        assert_eq!(body.contains_key("error"), false);
        assert_eq!(body["iss"], Value::String(expected_issuer.to_string()));
        assert!(!body["sub"].to_string().is_empty());
    }

    #[derive(Clone)]
    enum RequestFormat {
        Json,
        Form,
    }

    async fn post_request(url: String, params: impl Serialize, format: RequestFormat) -> Result<Response, Error> {
        let client = reqwest::Client::new();
        let request = client.post(url).header("accept", "application/json");
        let request = match format {
            RequestFormat::Json => request.json(&params),
            RequestFormat::Form => request.form(&params),
        };
        request.send().await
    }

    async fn test_well_formed_json_request<T: Serialize, U: DeserializeOwned + PartialEq + Debug>(url: &str, request: T, response: U, status_code: StatusCode) {
        let http_response = post_request(url.to_string(), request, RequestFormat::Json).await.unwrap();

        assert_eq!(http_response.status(), status_code);
        assert_eq!(http_response.json::<U>().await.unwrap(), response);
    }

    struct TestApp {
        app: App,
        cfg: Config,
        docker: DockerRuntimeParams,
    }

    impl TestApp {
        async fn new() -> Self {
            env_logger::builder().filter_level(LevelFilter::Info).init();

            let docker = DockerRuntimeParams::init().await;

            match docker.container {
                None => info!("Expecting mock-oauth2-server natively in docker-compose on localhost:8080"),
                Some(_) => info!("Running mock-oauth2-server on {}:{}", docker.host, docker.port,),
            }

            // Set up Texas
            let cfg = Config::mock(docker.host.clone(), docker.port);
            let app = App::new(cfg.clone()).await;

            Self { app, cfg, docker }
        }
    }

    type TokenClaims = HashMap<String, Value>;

    struct Token {
        header: jwt::Header,
        claims: TokenClaims,
    }

    impl Token {
        /// Matches signing key used in mock-oauth2-server
        const SIGNING_KEY: &'static str = r#"{"p":"_LNnIjBshCrFuxtjUC2KKzg_NTVv26UZh5j12_9r5mYTxb8yW047jOYFEGvIdMkTRLGOBig6fLWzgd62lnLainzV35J6K6zr4jQfTldLondlkldMR6nQrp1KfnNUuRbKvzpNKkhl12-f1l91l0tCx3s4blztvWgdzN2xBfvWV68","kty":"RSA","q":"9MIWsbIA3WjiR_Ful5FM8NCgb6JdS2D6ySHVepoNI-iAPilcltF_J2orjfLqAxeztTskPi45wtF_-eV4GIYSzvMo-gFiXLMrvEa7WaWizMi_7Bu9tEk3m_f3IDLN9lwULYoebkDbiXx6GOiuj0VkuKz8ckYFNKLCMP9QRLFff-0","d":"J6UX848X8tNz-09PFvcFDUVqak32GXzoPjnuDjBsxNUvG7LxenLmM_i8tvYl0EW9Ztn4AiCqJUoHw5cX3jz_mSqGl7ciaDedpKm_AetcZwHiEuT1EpSKRPMmOMQSqcJqXrdbbWB8gdUrnTKZIlJCfj7yqgT16ypC43TnwjA0UwxhG5pHaYjKI3pPdoHg2BzA-iubHjVn15Sz7-pnjBmeGDbEFa7ADY-1yPHCmqqvPKTNhoCNW6RpG34Id9hXslPa3X-7pAhJrDBd0_NPlktSA2rUkifYiZURhHR5ijhe0v3uw6kYP8f_foVm_C8O1ExkxXh9Dg8KDZ89dbsSOtBc0Q","e":"AQAB","use":"sig","kid":"l7C_WJgbZ_6e59vPrFETAehX7Dsp7fIyvSV4XhotsGs","qi":"cQFN5q5WhYkzgd1RS0rGqvpX1AkmZMrLv2MW04gSfu0dDwpbsSAu8EUCQW9oA4pr6V7R9CBSu9kdN2iY5SR-hZvEad5nDKPV1F3TMQYv5KpRiS_0XhfV5PcolUJVO_4p3h8d-mo2hh1Sw2fairAKOzvnwJCQ6DFkiY7H1cqwA54","dp":"YTql9AGtvyy158gh7jeXcgmySEbHQzvDFulDr-IXIg8kjHGEbp0rTIs0Z50RA95aC5RFkRjpaBKBfvaySjDm5WIi6GLzntpp6B8l7H6qG1jVO_la4Df2kzjx8LVvY8fhOrKz_hDdHodUeKdCF3RdvWMr00ruLnJhBPJHqoW7cwE","alg":"RS256","dq":"IZA4AngRbEtEtG7kJn6zWVaSmZxfRMXwvgIYvy4-3Qy2AVA0tS3XTPVfMaD8_B2U9CY_CxPVseR-sysHc_12uNBZbycfcOzU84WTjXCMSZ7BysPnGMDtkkLHra-p1L29upz1HVNhh5H9QEswHM98R2LZX2ZAsn4bORLZ1AGqweU","n":"8ZqUp5Cs90XpNn8tJBdUUxdGH4bjqKjFj8lyB3x50RpTuECuwzX1NpVqyFENDiEtMja5fdmJl6SErjnhj6kbhcmfmFibANuG-0WlV5yMysdSbocd75C1JQbiPdpHdXrijmVFMfDnoZTQ-ErNsqqngTNkn5SXBcPenli6Cf9MTSchZuh_qFj_B7Fp3CWKehTiyBcLlNOIjYsXX8WQjZkWKGpQ23AWjZulngWRektLcRWuEKTWaRBtbAr3XAfSmcqTICrebaD3IMWKHDtvzHAt_pt4wnZ06clgeO2Wbc980usnpsF7g8k9p81RcbS4JEZmuuA9NCmOmbyADXwgA9_-Aw"}"#;

        fn new(claims: TokenClaims) -> Self {
            Self {
                header: jwt::Header::new(jwt::Algorithm::RS256),
                claims,
            }
        }

        fn sign(claims: TokenClaims) -> String {
            Self::new(claims).encode()
        }

        fn sign_with_kid(claims: TokenClaims, kid: &str) -> String {
            let mut token = Self::new(claims);
            token.header.kid = Some(kid.to_string());
            token.encode()
        }

        fn encode(&self) -> String {
            let key = Self::get_signing_key();
            jwt::encode(&self.header, &self.claims, &key.key.to_encoding_key()).unwrap()
        }

        fn get_signing_key() -> jwk::JsonWebKey {
            Self::SIGNING_KEY.parse().unwrap()
        }
    }

    struct DockerRuntimeParams {
        container: Option<ContainerAsync<GenericImage>>,
        host: String,
        port: u16,
    }

    impl DockerRuntimeParams {
        #[cfg(feature = "docker")]
        const MOCK_OAUTH_SERVER_JSON_CONFIG: &'static str = r#"{
        "tokenProvider" : {
            "keyProvider" : {
               "initialKeys" : "{\"p\":\"_LNnIjBshCrFuxtjUC2KKzg_NTVv26UZh5j12_9r5mYTxb8yW047jOYFEGvIdMkTRLGOBig6fLWzgd62lnLainzV35J6K6zr4jQfTldLondlkldMR6nQrp1KfnNUuRbKvzpNKkhl12-f1l91l0tCx3s4blztvWgdzN2xBfvWV68\",\"kty\":\"RSA\",\"q\":\"9MIWsbIA3WjiR_Ful5FM8NCgb6JdS2D6ySHVepoNI-iAPilcltF_J2orjfLqAxeztTskPi45wtF_-eV4GIYSzvMo-gFiXLMrvEa7WaWizMi_7Bu9tEk3m_f3IDLN9lwULYoebkDbiXx6GOiuj0VkuKz8ckYFNKLCMP9QRLFff-0\",\"d\":\"J6UX848X8tNz-09PFvcFDUVqak32GXzoPjnuDjBsxNUvG7LxenLmM_i8tvYl0EW9Ztn4AiCqJUoHw5cX3jz_mSqGl7ciaDedpKm_AetcZwHiEuT1EpSKRPMmOMQSqcJqXrdbbWB8gdUrnTKZIlJCfj7yqgT16ypC43TnwjA0UwxhG5pHaYjKI3pPdoHg2BzA-iubHjVn15Sz7-pnjBmeGDbEFa7ADY-1yPHCmqqvPKTNhoCNW6RpG34Id9hXslPa3X-7pAhJrDBd0_NPlktSA2rUkifYiZURhHR5ijhe0v3uw6kYP8f_foVm_C8O1ExkxXh9Dg8KDZ89dbsSOtBc0Q\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"l7C_WJgbZ_6e59vPrFETAehX7Dsp7fIyvSV4XhotsGs\",\"qi\":\"cQFN5q5WhYkzgd1RS0rGqvpX1AkmZMrLv2MW04gSfu0dDwpbsSAu8EUCQW9oA4pr6V7R9CBSu9kdN2iY5SR-hZvEad5nDKPV1F3TMQYv5KpRiS_0XhfV5PcolUJVO_4p3h8d-mo2hh1Sw2fairAKOzvnwJCQ6DFkiY7H1cqwA54\",\"dp\":\"YTql9AGtvyy158gh7jeXcgmySEbHQzvDFulDr-IXIg8kjHGEbp0rTIs0Z50RA95aC5RFkRjpaBKBfvaySjDm5WIi6GLzntpp6B8l7H6qG1jVO_la4Df2kzjx8LVvY8fhOrKz_hDdHodUeKdCF3RdvWMr00ruLnJhBPJHqoW7cwE\",\"alg\":\"RS256\",\"dq\":\"IZA4AngRbEtEtG7kJn6zWVaSmZxfRMXwvgIYvy4-3Qy2AVA0tS3XTPVfMaD8_B2U9CY_CxPVseR-sysHc_12uNBZbycfcOzU84WTjXCMSZ7BysPnGMDtkkLHra-p1L29upz1HVNhh5H9QEswHM98R2LZX2ZAsn4bORLZ1AGqweU\",\"n\":\"8ZqUp5Cs90XpNn8tJBdUUxdGH4bjqKjFj8lyB3x50RpTuECuwzX1NpVqyFENDiEtMja5fdmJl6SErjnhj6kbhcmfmFibANuG-0WlV5yMysdSbocd75C1JQbiPdpHdXrijmVFMfDnoZTQ-ErNsqqngTNkn5SXBcPenli6Cf9MTSchZuh_qFj_B7Fp3CWKehTiyBcLlNOIjYsXX8WQjZkWKGpQ23AWjZulngWRektLcRWuEKTWaRBtbAr3XAfSmcqTICrebaD3IMWKHDtvzHAt_pt4wnZ06clgeO2Wbc980usnpsF7g8k9p81RcbS4JEZmuuA9NCmOmbyADXwgA9_-Aw\"}",
               "algorithm" : "RS256"
            }
          }
        }"#;

        /// Runs Docker from Rust, no external setup needed
        #[cfg(feature = "docker")]
        async fn init() -> DockerRuntimeParams {
            use reqwest::StatusCode;
            use testcontainers::core::wait::HttpWaitStrategy;
            use testcontainers::core::{ImageExt, IntoContainerPort, WaitFor};
            use testcontainers::runners::AsyncRunner;

            // Set up Docker container
            let container = GenericImage::new("ghcr.io/navikt/mock-oauth2-server", "2.1.10")
                .with_exposed_port(8080.tcp())
                .with_wait_for(WaitFor::Http(
                    HttpWaitStrategy::new("/maskinporten/.well-known/openid-configuration").with_expected_status_code(StatusCode::OK),
                ))
                .with_env_var("JSON_CONFIG", Self::MOCK_OAUTH_SERVER_JSON_CONFIG)
                .start()
                .await
                .unwrap();
            let host = container.get_host().await.unwrap().to_string();
            let port = container.get_host_port_ipv4(8080).await.unwrap();
            Self {
                container: Some(container),
                host,
                port,
            }
        }

        /// Requires docker-compose up to be running.
        #[cfg(not(feature = "docker"))]
        async fn init() -> DockerRuntimeParams {
            Self {
                container: None,
                host: "localhost".to_string(),
                port: 8080,
            }
        }
    }
}
