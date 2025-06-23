use crate::helpers::http::RequestFormat;
use crate::helpers::{config, docker, http, jwt};
use axum::http::StatusCode;
use log::info;
use pretty_assertions::assert_eq;
use texas::app::App;
use texas::config::Config;
use texas::oauth::identity_provider::{
    IntrospectRequest, IntrospectResponse, TokenExchangeRequest, TokenRequest, TokenResponse,
};

pub struct TestApp {
    pub app: App,
    pub cfg: Config,
    pub docker: Option<docker::RuntimeParams>,
}

impl TestApp {
    pub async fn new() -> Self {
        let docker = docker::RuntimeParams::init().await;

        match docker.container {
            None => {
                info!("Expecting mock-oauth2-server natively in docker-compose on localhost:8080")
            }
            Some(_) => info!(
                "Running mock-oauth2-server on {}:{}",
                docker.host, docker.port,
            ),
        }

        // Set up Texas
        let cfg = config::mock(docker.host.clone(), docker.port);
        let app = App::new_from_config(cfg.clone()).await.unwrap();

        Self {
            app,
            cfg,
            docker: Some(docker),
        }
    }

    pub async fn new_no_providers() -> Self {
        // Set up Texas
        let cfg = config::mock_no_providers();
        let app = App::new_from_config(cfg.clone()).await.unwrap();

        Self {
            app,
            cfg,
            docker: None,
        }
    }

    pub fn address(&self) -> String {
        self.app.listener.local_addr().map(|addr| addr.to_string()).unwrap()
    }

    pub async fn run(self) {
        self.app.run().await;
    }
}

pub fn token_url(address: &str) -> String {
    format!("http://{}/api/v1/token", address)
}

pub fn token_exchange_url(address: &str) -> String {
    format!("http://{}/api/v1/token/exchange", address)
}

pub fn introspect_url(address: &str) -> String {
    format!("http://{}/api/v1/introspect", address)
}

pub async fn test_happy_path_token(
    address: &str,
    request: TokenRequest,
    request_format: RequestFormat,
) -> TokenResponse {
    http::test_well_formed_request(
        token_url(address).as_str(),
        request,
        request_format,
        StatusCode::OK,
        |resp: TokenResponse| {
            assert!(resp.expires_in_seconds > 0);
            assert!(!resp.access_token.is_empty());
        },
    )
    .await
}

pub async fn test_happy_path_token_exchange(
    address: &str,
    request: TokenExchangeRequest,
    request_format: RequestFormat,
) -> TokenResponse {
    http::test_well_formed_request(
        token_exchange_url(address).as_str(),
        request,
        request_format,
        StatusCode::OK,
        |resp: TokenResponse| {
            assert!(resp.expires_in_seconds > 0);
            assert!(!resp.access_token.is_empty());
        },
    )
    .await
}

pub async fn test_happy_path_introspect(
    address: &str,
    expected_issuer: &str,
    request: IntrospectRequest,
    request_format: RequestFormat,
) -> IntrospectResponse {
    http::test_well_formed_request(
        introspect_url(address).as_str(),
        request,
        request_format,
        StatusCode::OK,
        |resp: IntrospectResponse| {
            assert!(resp.active);
            assert!(resp.error.is_none());
            assert!(jwt::has_claims(&resp));
            assert!(jwt::issuer(&resp).is_some());
            assert!(jwt::jwt_id(&resp).is_some());
            assert_eq!(jwt::issuer(&resp).unwrap(), expected_issuer);
        },
    )
    .await
}
