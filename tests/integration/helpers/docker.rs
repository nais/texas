#[cfg(feature = "docker")]
use serde::{Deserialize, Serialize};
use testcontainers::{ContainerAsync, GenericImage};

pub struct RuntimeParams {
    pub container: Option<ContainerAsync<GenericImage>>,
    pub host: String,
    pub port: u16,
}

impl RuntimeParams {
    /// Runs Docker from Rust, no external setup needed
    #[cfg(feature = "docker")]
    pub async fn init() -> RuntimeParams {
        use reqwest::StatusCode;
        use testcontainers::core::wait::HttpWaitStrategy;
        use testcontainers::core::{ImageExt, IntoContainerPort, WaitFor};
        use testcontainers::runners::AsyncRunner;

        fn wait_for_provider(identity_provider: &str) -> WaitFor {
            WaitFor::Http(Box::new(
                HttpWaitStrategy::new(format!(
                    "/{identity_provider}/.well-known/openid-configuration"
                ))
                .with_expected_status_code(StatusCode::OK),
            ))
        }

        let container = GenericImage::new("ghcr.io/navikt/mock-oauth2-server", "6.1.4")
            .with_exposed_port(8080.tcp())
            .with_wait_for(wait_for_provider("entra_id"))
            .with_wait_for(wait_for_provider("idporten"))
            .with_wait_for(wait_for_provider("ansattporten"))
            .with_wait_for(wait_for_provider("maskinporten"))
            .with_wait_for(wait_for_provider("tokenx"))
            .with_env_var("JSON_CONFIG", MockOAuthServerConfig::new().to_json())
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(8080).await.unwrap();
        Self {
            container: Some(container),
            host: "127.0.0.1".to_string(),
            port,
        }
    }

    /// Requires docker-compose up to be running.
    #[cfg(not(feature = "docker"))]
    pub async fn init() -> RuntimeParams {
        Self {
            container: None,
            host: "localhost".to_string(),
            port: 8080,
        }
    }
}

#[cfg(feature = "docker")]
#[derive(Debug, Serialize, Deserialize)]
struct MockOAuthServerConfig {
    #[serde(rename = "tokenProvider")]
    token_provider: TokenProvider,
}

#[cfg(feature = "docker")]
#[derive(Debug, Serialize, Deserialize)]
struct TokenProvider {
    #[serde(rename = "keyProvider")]
    key_provider: KeyProvider,
}

#[cfg(feature = "docker")]
#[derive(Debug, Serialize, Deserialize)]
struct KeyProvider {
    #[serde(rename = "initialKeys")]
    initial_keys: String,
    algorithm: String,
}

#[cfg(feature = "docker")]
impl MockOAuthServerConfig {
    pub fn new() -> Self {
        Self {
            token_provider: TokenProvider {
                key_provider: KeyProvider {
                    initial_keys: include_str!("../../fixtures/rsa-private.jwk").trim().to_string(),
                    algorithm: "RS256".to_string(),
                },
            },
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap().to_string()
    }
}
