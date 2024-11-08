use crate::config::Config;
use crate::handlers::__path_introspect;
use crate::handlers::__path_token;
use crate::handlers::__path_token_exchange;
use crate::handlers::{introspect, token, token_exchange, HandlerState};
use axum::Router;
use log::info;
use tokio::net::TcpListener;
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

        Self {
            router: app,
            listener,
        }
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
            .with_state(state)
            .split_for_parts();

        #[cfg(feature = "openapi")]
        use utoipa_swagger_ui::SwaggerUi;
        #[cfg(feature = "openapi")]
        let router = router.merge(SwaggerUi::new("/swagger-ui")
            .url("/api-docs/openapi.json", openapi.clone()));

        router
    }
}

#[cfg(test)]
mod tests {
    use crate::app::App;
    use crate::config::Config;
    use crate::identity_provider::{IdentityProvider, IntrospectRequest, TokenExchangeRequest, TokenRequest, TokenResponse};
    use log::{info, LevelFilter};
    use reqwest::{Error, Response};
    use serde::Serialize;
    use serde_json::Value;
    use std::collections::HashMap;
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

        for format in [RequestFormat::Form, RequestFormat::Json] {
            machine_to_machine_token(
                testapp.cfg.maskinporten_issuer.clone(),
                "scope".to_string(),
                address.to_string(),
                IdentityProvider::Maskinporten,
                format.clone(),
            ).await;

            machine_to_machine_token(
                testapp.cfg.azure_ad_issuer.clone(),
                testapp.cfg.azure_ad_client_id.clone(),
                address.to_string(),
                IdentityProvider::AzureAD,
                format.clone(),
            ).await;

            token_exchange_token(
                testapp.cfg.azure_ad_issuer.clone(),
                testapp.cfg.azure_ad_client_id.clone(),
                address.to_string(),
                format!("{}:{}", testapp.docker.host.clone(), testapp.docker.port),
                IdentityProvider::AzureAD,
                format.clone(),
            ).await;

            token_exchange_token(
                testapp.cfg.token_x_issuer.clone(),
                testapp.cfg.token_x_client_id.clone(),
                address.to_string(),
                format!("{}:{}", testapp.docker.host.clone(), testapp.docker.port),
                IdentityProvider::TokenX,
                format,
            ).await;
        }

        invalid_identity_provider_in_token_request(address.to_string()).await;
        invalid_content_type_in_token_request(address.to_string()).await;

        // TODO: implement these tests:
        // * /token
        //   * upstream network error / reqwest error
        //   * upstream responded with code >= 400
        //      * json deserialize error
        //      * oauth error
        //   * upstream responded with success code but non-json body
        //
        // * /token/exchange
        //   * missing or empty user token
        //   * upstream network error / reqwest error
        //   * upstream responded with code >= 400
        //      * json deserialize error
        //      * oauth error
        //   * upstream responded with success code but non-json body
        //
        // * /introspect
        //   * token is not a jwt
        //   * token does not contain iss claim
        //   * token is issued by unrecognized issuer
        //   * token has invalid header
        //   * token does not have kid (key id) in header
        //   * token is signed with a key that is not in the jwks
        //   * invalid or expired timestamps in nbf, iat, exp
        //   * invalid or missing aud (for certain providers)
        //   * refreshing jwks fails
        //     * fetch / network error / reqwest error
        //     * decode error
        //     * jwks has key with blank or missing key id

        join_handler.abort();
    }

    async fn invalid_identity_provider_in_token_request(address: String) {
        let response = post_request(
            format!("http://{}/api/v1/token", address.clone().to_string()),
            HashMap::from([
                ("target", "dontcare") ,
                ("identity_provider", "invalid"),
            ]),
            RequestFormat::Json,
        ).await.unwrap();

        assert_eq!(response.status(), 400);
        assert_eq!(response.text().await.unwrap(), "{\"error\":\"invalid_request\",\"error_description\":\"request cannot be deserialized\"}");
    }

    async fn invalid_content_type_in_token_request(address: String) {
        let client = reqwest::Client::new();
        let request = client.post(format!("http://{}/api/v1/token", address.clone().to_string()),)
            .header("accept", "application/json")
            .header("content-type", "text/plain")
            .body("some plain text");
        let response = request.send().await.unwrap();

        assert_eq!(response.status(), 400);
        assert_eq!(response.text().await.unwrap(), "{\"error\":\"invalid_request\",\"error_description\":\"unsupported media type text/plain\"}");
    }

    async fn machine_to_machine_token(expected_issuer: String, target: String, address: String, identity_provider: IdentityProvider, request_format: RequestFormat) {
        let response = post_request(
            format!("http://{}/api/v1/token", address.clone().to_string()),
            TokenRequest {
                target,
                identity_provider,
            },
            request_format.clone(),
        ).await.unwrap();

        assert_eq!(response.status(), 200, "failed to get token: {:?}", response.text().await.unwrap());

        let body: TokenResponse = response.json().await.unwrap();
        assert!(body.expires_in_seconds > 0);
        assert!(!body.access_token.is_empty());

        let response = post_request(
            format!("http://{}/api/v1/introspect", address.clone().to_string()),
            IntrospectRequest {
                token: body.access_token.clone(),
            },
            request_format,
        ).await.unwrap();

        assert_eq!(response.status(), 200);
        let body: HashMap<String, Value> = response.json().await.unwrap();
        assert_eq!(body["active"], Value::Bool(true));
        assert_eq!(body["iss"], Value::String(expected_issuer.to_string()));
    }

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
        ).await.unwrap();

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
        ).await.unwrap();

        assert_eq!(response.status(), 200, "failed to exchange token: {:?}", response.text().await.unwrap());

        let body: TokenResponse = response.json().await.unwrap();
        assert!(body.expires_in_seconds > 0);
        assert!(!body.access_token.is_empty());

        let response = post_request(
            format!("http://{}/api/v1/introspect", address.clone().to_string()),
            IntrospectRequest {
                token: body.access_token.clone(),
            },
            request_format,
        ).await.unwrap();

        assert_eq!(response.status(), 200);
        let body: HashMap<String, Value> = response.json().await.unwrap();
        assert_eq!(body["active"], Value::Bool(true));
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
                Some(_) => info!("Running mock-oauth2-server on {}:{}", docker.host, docker.port, ),
            }

            // Set up Texas
            let cfg = Config::mock(docker.host.clone(), docker.port);
            let app = App::new(cfg.clone()).await;

            Self {
                app,
                cfg,
                docker,
            }
        }
    }

    struct DockerRuntimeParams {
        container: Option<ContainerAsync<GenericImage>>,
        host: String,
        port: u16,
    }

    impl DockerRuntimeParams {
        /// Runs Docker from Rust, no external setup needed
        #[cfg(feature = "docker")]
        async fn init() -> DockerRuntimeParams {
            use reqwest::StatusCode;
            use testcontainers::core::wait::HttpWaitStrategy;
            use testcontainers::core::{IntoContainerPort, WaitFor};
            use testcontainers::runners::AsyncRunner;

            // Set up Docker container
            let container = GenericImage::new("ghcr.io/navikt/mock-oauth2-server", "2.1.10")
                .with_exposed_port(8080.tcp())
                .with_wait_for(WaitFor::Http(HttpWaitStrategy::new("/maskinporten/.well-known/openid-configuration").with_expected_status_code(StatusCode::OK)))
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
