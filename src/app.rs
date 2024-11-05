use crate::handlers;
use crate::handlers::{introspect, token, token_exchange};
use axum::routing::post;
use axum::Router;

pub fn new(state: handlers::HandlerState) -> Router {
    Router::new()
        .route("/token", post(token))
        .route("/token/exchange", post(token_exchange))
        .route("/introspect", post(introspect))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use crate::config::Config;
    use log::{info};
    use reqwest::{Error, Response};
    use testcontainers::{ContainerAsync, GenericImage};
    use serde::Serialize;
    use serde_json::Value;

    use crate::handlers::HandlerState;
    use crate::identity_provider::{IdentityProvider, IntrospectRequest, TokenExchangeRequest, TokenRequest, TokenResponse};
    // TODO: add some error case tests

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
    async fn test_roundtrip() {
        #[allow(unused_mut)]
        let mut host;
        #[allow(unused_mut)]
        let mut host_port;
        #[allow(unused_variables, unused_mut)]
        let mut container: ContainerAsync<GenericImage>;

        #[cfg(feature = "docker")]
        {
            use testcontainers::core::{IntoContainerPort, WaitFor};
            use testcontainers::core::wait::HttpWaitStrategy;
            use testcontainers::runners::AsyncRunner;
            use reqwest::{StatusCode};

            // Set up Docker container
            container = GenericImage::new("ghcr.io/navikt/mock-oauth2-server", "2.1.10")
                .with_exposed_port(8080.tcp())
                .with_wait_for(WaitFor::Http(HttpWaitStrategy::new("/maskinporten/.well-known/openid-configuration").with_expected_status_code(StatusCode::OK)))
                .start()
                .await
                .unwrap();
            host = container.get_host().await.unwrap().to_string();
            host_port = container.get_host_port_ipv4(8080).await.unwrap();
        }
        #[cfg(not(feature = "docker"))]
        // Requires docker-compose up to be running
        {
            host = "localhost".to_string();
            host_port = 8080;
        }

        // Set up Texas
        let cfg = Config::mock(host.to_string(), host_port);
        let listener = tokio::net::TcpListener::bind(cfg.bind_address.clone())
            .await
            .unwrap();
        let state = HandlerState::from_config(cfg.clone()).await.unwrap();
        let app = super::new(state);
        let address = listener.local_addr().unwrap();
        info!("Serving on {:?}", address.clone());
        let join_handler = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        for format in [RequestFormat::Form, RequestFormat::Json] {
            machine_to_machine_token(cfg.maskinporten_issuer.clone(), address.to_string(), IdentityProvider::Maskinporten, format.clone()).await;
            machine_to_machine_token(cfg.azure_ad_issuer.clone(), address.to_string(), IdentityProvider::AzureAD, format.clone()).await;

            token_exchange_token(cfg.azure_ad_issuer.clone(), address.to_string(), format!("{}:{}", host, host_port), IdentityProvider::AzureAD, format.clone()).await;
            token_exchange_token(cfg.token_x_issuer.clone(), address.to_string(), format!("{}:{}", host, host_port), IdentityProvider::TokenX, format).await;
        }

        join_handler.abort();
    }

    async fn machine_to_machine_token(expected_issuer: String, address: String, identity_provider: IdentityProvider, request_format: RequestFormat) {
        let response = post_request(
            format!("http://{}/token", address.clone().to_string()),
            TokenRequest {
                target: "mytarget".to_string(),
                identity_provider,
            },
            request_format.clone(),
        ).await.unwrap();

        assert_eq!(response.status(), 200, "failed to get token: {:?}", response.text().await.unwrap());

        let body: TokenResponse = response.json().await.unwrap();
        assert!(body.expires_in_seconds > 0);
        assert!(!body.access_token.is_empty());

        let response = post_request(
            format!("http://{}/introspect", address.clone().to_string()),
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

    async fn token_exchange_token(expected_issuer: String, address: String, identity_provider_address: String, identity_provider: IdentityProvider, request_format: RequestFormat) {
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
            format!("http://{}/token/exchange", address.clone().to_string()),
            TokenExchangeRequest {
                target: "mytarget".to_string(),
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
            format!("http://{}/introspect", address.clone().to_string()),
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
        let request = client
            .post(url)
            .header("accept", "application/json");
        let request = match format {
            RequestFormat::Json => request.json(&params),
            RequestFormat::Form => request.form(&params),
        };
        request
            .send()
            .await
    }
}
