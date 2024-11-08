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
    use crate::identity_provider::{ErrorResponse, IdentityProvider, IntrospectRequest, IntrospectResponse, OAuthErrorCode, TokenExchangeRequest, TokenRequest, TokenResponse};
    use axum::routing::get;
    use axum::{Json, Router};
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

        invalid_identity_provider_in_token_request(&address).await;
        invalid_content_type_in_token_request(&address).await;
        missing_or_empty_user_token(&address).await;
        introspect_token_is_not_a_jwt(&address).await;
        test_introspect_missing_issuer(&address).await;
        test_introspect_unrecognized_issuer(&address).await;
        introspect_token_missing_kid(&address).await;
        introspect_token_missing_key_in_jwks(&address).await;
        introspect_token_invalid_timestamps(&address).await;

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
        //   * [ ] invalid or expired timestamps in nbf, iat, exp
        //   * [ ] invalid or missing aud (for certain providers)
        //   * [ ] refreshing jwks fails
        //     * [ ] fetch / network error / reqwest error
        //     * [ ] decode error
        //     * [ ] jwks has key with blank or missing key id

        join_handler.abort();
    }

    async fn test_introspect_unrecognized_issuer(address: &str) {
        let token = TokenServer::token(
            TokenClaims::from([
                ("iss".into(), Value::String("snafu".into())),
            ])
        );
        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token,
            },
            IntrospectResponse::new_invalid("token has unknown issuer: snafu"),
            StatusCode::OK,
        ).await;
    }

    async fn test_introspect_missing_issuer(address: &str) {
        let token = TokenServer::token(TokenClaims::new());
        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token,
            },
            IntrospectResponse::new_invalid("JSON error: missing field `iss` at line 1 column 2"),
            StatusCode::OK,
        ).await;
    }

    async fn introspect_token_is_not_a_jwt(address: &str) {
        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token: "this is not a token".to_string(),
            },
            IntrospectResponse::new_invalid("InvalidToken"),
            StatusCode::OK,
        ).await;
    }

    async fn introspect_token_missing_kid(address: &str) {
        let token = TokenServer::token(
            TokenClaims::from([
                ("iss".into(), Value::String("http://localhost:8080/maskinporten".into())),
            ])
        );
        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token,
            },
            IntrospectResponse::new_invalid("missing key id from token header"),
            StatusCode::OK,
        ).await;
    }

    async fn introspect_token_missing_key_in_jwks(address: &str) {
        let token = TokenServer::token_with_kid(
            TokenClaims::from([
                ("iss".into(), Value::String("http://localhost:8080/maskinporten".into())),
            ]),
            "missing-key",
        );

        test_well_formed_json_request(
            &format!("http://{}/api/v1/introspect", address),
            IntrospectRequest {
                token,
            },
            IntrospectResponse::new_invalid("signing key with missing-key not in json web key set"),
            StatusCode::OK,
        ).await;
    }
    //   * [ ] invalid or expired timestamps in nbf, iat, exp
    async fn introspect_token_invalid_timestamps(address: &str) {

    }

    async fn yolo() {
        let server = TokenServer::new().await;
        let address = server.address();
        let join_handler = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        // Set up Texas
        //let cfg = Config::mock(address, server.port());
        //let app = App::new(cfg.clone()).await;


        let client = reqwest::Client::new();
        let response = client.get(format!("http://{}/jwks", address)).send().await.unwrap();
        println!("{:?}", response.text().await.unwrap());
        join_handler.abort();
    }

    struct TokenServer {
        listener: tokio::net::TcpListener,
        keys: HashMap<String, Vec<jwk::JsonWebKey>>,
    }

    type TokenClaims = HashMap<String, Value>;

    struct Token {
        header: jwt::Header,
        claims: TokenClaims,
    }

    impl Token {
        fn new(claims: TokenClaims) -> Self {
            Self {
                header: jwt::Header::new(jwt::Algorithm::RS256),
                claims,
            }
        }

        fn sign(self, key: &jwk::JsonWebKey) -> String {
            jwt::encode(
                &self.header,
                &self.claims,
                &key.key.to_encoding_key(),
            ).unwrap()
        }
    }

    impl TokenServer {
        const SIGNING_KEY: &'static str = r#"{"p":"_LNnIjBshCrFuxtjUC2KKzg_NTVv26UZh5j12_9r5mYTxb8yW047jOYFEGvIdMkTRLGOBig6fLWzgd62lnLainzV35J6K6zr4jQfTldLondlkldMR6nQrp1KfnNUuRbKvzpNKkhl12-f1l91l0tCx3s4blztvWgdzN2xBfvWV68","kty":"RSA","q":"9MIWsbIA3WjiR_Ful5FM8NCgb6JdS2D6ySHVepoNI-iAPilcltF_J2orjfLqAxeztTskPi45wtF_-eV4GIYSzvMo-gFiXLMrvEa7WaWizMi_7Bu9tEk3m_f3IDLN9lwULYoebkDbiXx6GOiuj0VkuKz8ckYFNKLCMP9QRLFff-0","d":"J6UX848X8tNz-09PFvcFDUVqak32GXzoPjnuDjBsxNUvG7LxenLmM_i8tvYl0EW9Ztn4AiCqJUoHw5cX3jz_mSqGl7ciaDedpKm_AetcZwHiEuT1EpSKRPMmOMQSqcJqXrdbbWB8gdUrnTKZIlJCfj7yqgT16ypC43TnwjA0UwxhG5pHaYjKI3pPdoHg2BzA-iubHjVn15Sz7-pnjBmeGDbEFa7ADY-1yPHCmqqvPKTNhoCNW6RpG34Id9hXslPa3X-7pAhJrDBd0_NPlktSA2rUkifYiZURhHR5ijhe0v3uw6kYP8f_foVm_C8O1ExkxXh9Dg8KDZ89dbsSOtBc0Q","e":"AQAB","use":"sig","kid":"l7C_WJgbZ_6e59vPrFETAehX7Dsp7fIyvSV4XhotsGs","qi":"cQFN5q5WhYkzgd1RS0rGqvpX1AkmZMrLv2MW04gSfu0dDwpbsSAu8EUCQW9oA4pr6V7R9CBSu9kdN2iY5SR-hZvEad5nDKPV1F3TMQYv5KpRiS_0XhfV5PcolUJVO_4p3h8d-mo2hh1Sw2fairAKOzvnwJCQ6DFkiY7H1cqwA54","dp":"YTql9AGtvyy158gh7jeXcgmySEbHQzvDFulDr-IXIg8kjHGEbp0rTIs0Z50RA95aC5RFkRjpaBKBfvaySjDm5WIi6GLzntpp6B8l7H6qG1jVO_la4Df2kzjx8LVvY8fhOrKz_hDdHodUeKdCF3RdvWMr00ruLnJhBPJHqoW7cwE","alg":"RS256","dq":"IZA4AngRbEtEtG7kJn6zWVaSmZxfRMXwvgIYvy4-3Qy2AVA0tS3XTPVfMaD8_B2U9CY_CxPVseR-sysHc_12uNBZbycfcOzU84WTjXCMSZ7BysPnGMDtkkLHra-p1L29upz1HVNhh5H9QEswHM98R2LZX2ZAsn4bORLZ1AGqweU","n":"8ZqUp5Cs90XpNn8tJBdUUxdGH4bjqKjFj8lyB3x50RpTuECuwzX1NpVqyFENDiEtMja5fdmJl6SErjnhj6kbhcmfmFibANuG-0WlV5yMysdSbocd75C1JQbiPdpHdXrijmVFMfDnoZTQ-ErNsqqngTNkn5SXBcPenli6Cf9MTSchZuh_qFj_B7Fp3CWKehTiyBcLlNOIjYsXX8WQjZkWKGpQ23AWjZulngWRektLcRWuEKTWaRBtbAr3XAfSmcqTICrebaD3IMWKHDtvzHAt_pt4wnZ06clgeO2Wbc980usnpsF7g8k9p81RcbS4JEZmuuA9NCmOmbyADXwgA9_-Aw"}"#;
        async fn new() -> Self {
            let mut keys = HashMap::<String, Vec<jwk::JsonWebKey>>::new();
            keys.insert("keys".to_string(), vec![Self::get_signing_key()]);
            Self {
                listener: tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
                keys,
            }
        }

        fn port(&self) -> u16 {
            self.listener.local_addr().unwrap().port()
        }

        fn address(&self) -> String {
            self.listener.local_addr().unwrap().to_string()
        }

        fn token(claims: TokenClaims) -> String {
            Token::new(claims).sign(&Self::get_signing_key())
        }

        fn token_with_kid(claims: TokenClaims, kid: &str) -> String {
            let mut token = Token::new(claims);
            token.header.kid = Some(kid.to_string());
            token.sign(&Self::get_signing_key())
        }

        pub async fn run(self) -> std::io::Result<()> {
            let app = Router::new()
                .route("/jwks", get(|| async { Json(self.keys) }));

            axum::serve(self.listener, app).await
        }

        fn get_signing_key() -> jwk::JsonWebKey {
            Self::SIGNING_KEY.parse().unwrap()
        }
    }

    async fn missing_or_empty_user_token(address: &str) {
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
        ).await;
    }

    async fn invalid_identity_provider_in_token_request(address: &str) {
        let response = post_request(
            format!("http://{}/api/v1/token", address),
            json!({"target":"dontcare","identity_provider":"invalid"}),
            RequestFormat::Json,
        ).await.unwrap();

        assert_eq!(response.status(), 400);
        assert_eq!(response.text().await.unwrap(), r#"{"error":"invalid_request","error_description":"Failed to deserialize the JSON body into the target type: identity_provider: unknown variant `invalid`, expected one of `azuread`, `tokenx`, `maskinporten` at line 1 column 30"}"#);

        let response = post_request(
            format!("http://{}/api/v1/token", address),
            HashMap::from([("target", "dontcare"), ("identity_provider", "invalid")]),
            RequestFormat::Form,
        ).await.unwrap();

        assert_eq!(response.status(), 400);
        assert_eq!(response.text().await.unwrap(), r#"{"error":"invalid_request","error_description":"Failed to deserialize form body: unknown variant `invalid`, expected one of `azuread`, `tokenx`, `maskinporten`"}"#);
    }

    async fn invalid_content_type_in_token_request(address: &str) {
        let client = reqwest::Client::new();
        let request = client.post(format!("http://{}/api/v1/token", address))
            .header("accept", "application/json")
            .header("content-type", "text/plain")
            .body("some plain text");
        let response = request.send().await.unwrap();

        assert_eq!(response.status(), 400);
        assert_eq!(response.text().await.unwrap(), r#"{"error":"invalid_request","error_description":"unsupported media type: text/plain: expected one of `application/json`, `application/x-www-form-urlencoded`"}"#);
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

    async fn test_well_formed_json_request<T: Serialize, U: DeserializeOwned + PartialEq + Debug>(
        url: &str,
        request: T,
        response: U,
        status_code: StatusCode,
    ) {
        let http_response = post_request(
            url.to_string(),
            request,
            RequestFormat::Json,
        ).await.unwrap();

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
