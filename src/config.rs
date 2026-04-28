use crate::config::Error::{MissingEnv, ParseBool};
use crate::http;
use serde::{Deserialize, Serialize};
use std::str::ParseBoolError;
use thiserror::Error;

#[derive(Serialize, Debug, Clone, Default)]
pub struct Config {
    pub bind_address: String,
    pub probe_bind_address: Option<String>,
    pub maskinporten: Option<Provider>,
    pub entra_id: Option<Provider>,
    pub token_x: Option<Provider>,
    pub idporten: Option<Provider>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Provider {
    pub client_id: String,
    pub client_jwk: Option<String>,
    pub jwks_uri: String,
    pub issuer: String,
    pub token_endpoint: Option<String>,
}

impl Config {
    pub async fn new_from_env() -> Result<Self, Error> {
        let entra_id = RawProvider::new_from_azure_env()?;
        let maskinporten = RawProvider::new_from_maskinporten_env()?;
        let token_x = RawProvider::new_from_tokenx_env()?;
        let idporten = RawProvider::new_from_idporten_env()?;

        Ok(Self {
            bind_address: std::env::var("BIND_ADDRESS").unwrap_or("127.0.0.1:3000".to_string()),
            probe_bind_address: std::env::var("PROBE_BIND_ADDRESS").ok(),
            entra_id: match entra_id {
                Some(provider) => Some(provider.resolve(ProviderKind::EntraID).await?),
                None => None,
            },
            maskinporten: match maskinporten {
                Some(provider) => Some(provider.resolve(ProviderKind::Maskinporten).await?),
                None => None,
            },
            token_x: match token_x {
                Some(provider) => Some(provider.resolve(ProviderKind::TokenX).await?),
                None => None,
            },
            idporten: match idporten {
                Some(provider) => Some(provider.resolve(ProviderKind::IDPorten).await?),
                None => None,
            },
        })
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("missing required environment variable '{0}'")]
    MissingEnv(String),

    #[error("parse boolean option '{0}': {1}")]
    ParseBool(String, ParseBoolError),

    #[error("initialize HTTP client: {0}")]
    InitializeHttpClient(reqwest::Error),

    #[error("fetch provider metadata from '{url}': {source:?}")]
    ProviderMetadataFetch {
        url: String,
        source: reqwest_middleware::Error,
    },

    #[error("decode provider metadata from '{url}': {source}")]
    ProviderMetadataDecode { url: String, source: reqwest::Error },

    #[error("missing configuration for provider '{provider}': set {well_known_env} or {field_env}")]
    MissingProviderConfigField {
        provider: &'static str,
        field_env: &'static str,
        well_known_env: &'static str,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProviderKind {
    EntraID,
    IDPorten,
    Maskinporten,
    TokenX,
}

struct ProviderEnv {
    provider_name: &'static str,
    well_known_env: &'static str,
    issuer_env: &'static str,
    jwks_uri_env: &'static str,
    token_endpoint_env: &'static str,
}

impl ProviderKind {
    fn env(self) -> ProviderEnv {
        match self {
            ProviderKind::EntraID => ProviderEnv {
                provider_name: "entra_id",
                well_known_env: "AZURE_APP_WELL_KNOWN_URL",
                issuer_env: "AZURE_OPENID_CONFIG_ISSUER",
                jwks_uri_env: "AZURE_OPENID_CONFIG_JWKS_URI",
                token_endpoint_env: "AZURE_OPENID_CONFIG_TOKEN_ENDPOINT",
            },
            ProviderKind::IDPorten => ProviderEnv {
                provider_name: "idporten",
                well_known_env: "IDPORTEN_WELL_KNOWN_URL",
                issuer_env: "IDPORTEN_ISSUER",
                jwks_uri_env: "IDPORTEN_JWKS_URI",
                token_endpoint_env: "",
            },
            ProviderKind::Maskinporten => ProviderEnv {
                provider_name: "maskinporten",
                well_known_env: "MASKINPORTEN_WELL_KNOWN_URL",
                issuer_env: "MASKINPORTEN_ISSUER",
                jwks_uri_env: "MASKINPORTEN_JWKS_URI",
                token_endpoint_env: "MASKINPORTEN_TOKEN_ENDPOINT",
            },
            ProviderKind::TokenX => ProviderEnv {
                provider_name: "tokenx",
                well_known_env: "TOKEN_X_WELL_KNOWN_URL",
                issuer_env: "TOKEN_X_ISSUER",
                jwks_uri_env: "TOKEN_X_JWKS_URI",
                token_endpoint_env: "TOKEN_X_TOKEN_ENDPOINT",
            },
        }
    }
}

#[derive(Default, Deserialize)]
struct AuthorizationServerMetadata {
    issuer: Option<String>,
    token_endpoint: Option<String>,
    jwks_uri: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
struct RawProvider {
    pub client_id: String,
    pub client_jwk: Option<String>,
    pub well_known_url: Option<String>,
    pub jwks_uri: Option<String>,
    pub issuer: Option<String>,
    pub token_endpoint: Option<String>,
}

impl RawProvider {
    fn enabled_from_env(env_var: &str) -> Result<bool, Error> {
        let Ok(envvar) = std::env::var(env_var) else {
            return Ok(false);
        };

        envvar.parse().map_err(|err| ParseBool(env_var.to_string(), err))
    }

    fn new_from_maskinporten_env() -> Result<Option<Self>, Error> {
        if !Self::enabled_from_env("MASKINPORTEN_ENABLED")? {
            return Ok(None);
        }

        Ok(Some(Self {
            client_id: must_read_env("MASKINPORTEN_CLIENT_ID")?,
            client_jwk: Some(must_read_env("MASKINPORTEN_CLIENT_JWK")?),
            well_known_url: read_env("MASKINPORTEN_WELL_KNOWN_URL"),
            jwks_uri: read_env("MASKINPORTEN_JWKS_URI"),
            issuer: read_env("MASKINPORTEN_ISSUER"),
            token_endpoint: read_env("MASKINPORTEN_TOKEN_ENDPOINT"),
        }))
    }

    fn new_from_azure_env() -> Result<Option<Self>, Error> {
        if !Self::enabled_from_env("AZURE_ENABLED")? {
            return Ok(None);
        }

        Ok(Some(Self {
            client_id: must_read_env("AZURE_APP_CLIENT_ID")?,
            client_jwk: Some(must_read_env("AZURE_APP_JWK")?),
            well_known_url: read_env("AZURE_APP_WELL_KNOWN_URL"),
            jwks_uri: read_env("AZURE_OPENID_CONFIG_JWKS_URI"),
            issuer: read_env("AZURE_OPENID_CONFIG_ISSUER"),
            token_endpoint: read_env("AZURE_OPENID_CONFIG_TOKEN_ENDPOINT"),
        }))
    }

    fn new_from_idporten_env() -> Result<Option<Self>, Error> {
        if !Self::enabled_from_env("IDPORTEN_ENABLED")? {
            return Ok(None);
        }

        Ok(Some(Self {
            client_id: must_read_env("IDPORTEN_AUDIENCE")?,
            client_jwk: None,
            well_known_url: read_env("IDPORTEN_WELL_KNOWN_URL"),
            jwks_uri: read_env("IDPORTEN_JWKS_URI"),
            issuer: read_env("IDPORTEN_ISSUER"),
            token_endpoint: None,
        }))
    }

    fn new_from_tokenx_env() -> Result<Option<Self>, Error> {
        if !Self::enabled_from_env("TOKEN_X_ENABLED")? {
            return Ok(None);
        }

        Ok(Some(Self {
            client_id: must_read_env("TOKEN_X_CLIENT_ID")?,
            client_jwk: Some(must_read_env("TOKEN_X_PRIVATE_JWK")?),
            well_known_url: read_env("TOKEN_X_WELL_KNOWN_URL"),
            jwks_uri: read_env("TOKEN_X_JWKS_URI"),
            issuer: read_env("TOKEN_X_ISSUER"),
            token_endpoint: read_env("TOKEN_X_TOKEN_ENDPOINT"),
        }))
    }

    async fn resolve(self, kind: ProviderKind) -> Result<Provider, Error> {
        let env = kind.env();
        let should_fetch_metadata = self.well_known_url.is_some()
            && (self.issuer.is_none()
                || self.jwks_uri.is_none()
                || (kind != ProviderKind::IDPorten && self.token_endpoint.is_none()));

        let metadata = if should_fetch_metadata {
            let url = self.well_known_url.as_deref().unwrap_or_default();
            log::debug!("Fetch metadata for {} from '{}'...", env.provider_name, url);
            fetch_provider_metadata(url).await?
        } else {
            AuthorizationServerMetadata::default()
        };

        let issuer = self.issuer.or(metadata.issuer).ok_or(Error::MissingProviderConfigField {
            provider: env.provider_name,
            field_env: env.issuer_env,
            well_known_env: env.well_known_env,
        })?;
        let jwks_uri =
            self.jwks_uri.or(metadata.jwks_uri).ok_or(Error::MissingProviderConfigField {
                provider: env.provider_name,
                field_env: env.jwks_uri_env,
                well_known_env: env.well_known_env,
            })?;
        let token_endpoint = self.token_endpoint.or(metadata.token_endpoint);

        if kind != ProviderKind::IDPorten && token_endpoint.is_none() {
            return Err(Error::MissingProviderConfigField {
                provider: env.provider_name,
                field_env: env.token_endpoint_env,
                well_known_env: env.well_known_env,
            });
        }

        Ok(Provider {
            client_id: self.client_id,
            client_jwk: self.client_jwk,
            jwks_uri,
            issuer,
            token_endpoint,
        })
    }
}

fn must_read_env(env: &str) -> Result<String, Error> {
    std::env::var(env).map_err(|_| MissingEnv(env.to_string()))
}

fn read_env(env: &str) -> Option<String> {
    std::env::var(env).ok()
}

async fn fetch_provider_metadata(url: &str) -> Result<AuthorizationServerMetadata, Error> {
    let client = http::client::jwks().map_err(Error::InitializeHttpClient)?;
    let request = client.get(url).header("accept", "application/json");

    request
        .send()
        .await
        .map_err(|source| Error::ProviderMetadataFetch {
            url: url.to_string(),
            source,
        })?
        .json()
        .await
        .map_err(|source| Error::ProviderMetadataDecode {
            url: url.to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::{ProviderKind, RawProvider};
    use axum::{Json, Router, routing::get};
    use serde_json::{Value, json};

    #[tokio::test]
    async fn resolves_provider_config_from_openid_connect_metadata() {
        let (base_url, _server) = metadata_server(vec![(
            "/oidc/.well-known/openid-configuration",
            json!({
                "issuer": "https://issuer.example",
                "token_endpoint": "https://issuer.example/token",
                "jwks_uri": "https://issuer.example/jwks",
                "userinfo_endpoint": "https://issuer.example/userinfo"
            }),
        )])
        .await;

        let resolved = RawProvider {
            client_id: "client-id".to_string(),
            client_jwk: Some("private-jwk".to_string()),
            well_known_url: Some(format!("{base_url}/oidc/.well-known/openid-configuration")),
            issuer: None,
            token_endpoint: None,
            jwks_uri: None,
        }
        .resolve(ProviderKind::EntraID)
        .await
        .unwrap();

        assert_eq!(resolved.issuer, "https://issuer.example");
        assert_eq!(
            resolved.token_endpoint.as_deref(),
            Some("https://issuer.example/token")
        );
        assert_eq!(resolved.jwks_uri, "https://issuer.example/jwks");
    }

    #[tokio::test]
    async fn resolves_provider_config_from_oauth_authorization_server_metadata() {
        let (base_url, _server) = metadata_server(vec![(
            "/oauth/.well-known/oauth-authorization-server",
            json!({
                "issuer": "https://maskinporten.example",
                "token_endpoint": "https://maskinporten.example/token",
                "jwks_uri": "https://maskinporten.example/jwks",
                "grant_types_supported": ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
            }),
        )])
        .await;

        let resolved = RawProvider {
            client_id: "client-id".to_string(),
            client_jwk: Some("private-jwk".to_string()),
            well_known_url: Some(format!(
                "{base_url}/oauth/.well-known/oauth-authorization-server"
            )),
            issuer: None,
            token_endpoint: None,
            jwks_uri: None,
        }
        .resolve(ProviderKind::Maskinporten)
        .await
        .unwrap();

        assert_eq!(resolved.issuer, "https://maskinporten.example");
        assert_eq!(
            resolved.token_endpoint.as_deref(),
            Some("https://maskinporten.example/token")
        );
        assert_eq!(resolved.jwks_uri, "https://maskinporten.example/jwks");
    }

    #[tokio::test]
    async fn idporten_does_not_require_token_endpoint_in_metadata() {
        let (base_url, _server) = metadata_server(vec![(
            "/idporten/.well-known/openid-configuration",
            json!({
                "issuer": "https://idporten.example",
                "jwks_uri": "https://idporten.example/jwks"
            }),
        )])
        .await;

        let resolved = RawProvider {
            client_id: "client-id".to_string(),
            client_jwk: None,
            well_known_url: Some(format!(
                "{base_url}/idporten/.well-known/openid-configuration"
            )),
            issuer: None,
            token_endpoint: None,
            jwks_uri: None,
        }
        .resolve(ProviderKind::IDPorten)
        .await
        .unwrap();

        assert_eq!(resolved.issuer, "https://idporten.example");
        assert_eq!(resolved.token_endpoint, None);
        assert_eq!(resolved.jwks_uri, "https://idporten.example/jwks");
    }

    #[tokio::test]
    async fn missing_manual_issuer_has_provider_specific_error() {
        let err = RawProvider {
            client_id: "client-id".to_string(),
            client_jwk: Some("private-jwk".to_string()),
            well_known_url: None,
            issuer: None,
            token_endpoint: Some("https://maskinporten.example/token".to_string()),
            jwks_uri: Some("https://maskinporten.example/jwks".to_string()),
        }
        .resolve(ProviderKind::Maskinporten)
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "missing configuration for provider 'maskinporten': set MASKINPORTEN_WELL_KNOWN_URL or MASKINPORTEN_ISSUER"
        );
    }

    #[tokio::test]
    async fn missing_manual_jwks_uri_has_provider_specific_error() {
        let err = RawProvider {
            client_id: "client-id".to_string(),
            client_jwk: None,
            well_known_url: None,
            issuer: Some("https://idporten.example".to_string()),
            token_endpoint: None,
            jwks_uri: None,
        }
        .resolve(ProviderKind::IDPorten)
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "missing configuration for provider 'idporten': set IDPORTEN_WELL_KNOWN_URL or IDPORTEN_JWKS_URI"
        );
    }

    #[tokio::test]
    async fn missing_manual_token_endpoint_has_provider_specific_error() {
        let err = RawProvider {
            client_id: "client-id".to_string(),
            client_jwk: Some("private-jwk".to_string()),
            well_known_url: None,
            issuer: Some("https://entra.example".to_string()),
            token_endpoint: None,
            jwks_uri: Some("https://entra.example/jwks".to_string()),
        }
        .resolve(ProviderKind::EntraID)
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "missing configuration for provider 'entra_id': set AZURE_APP_WELL_KNOWN_URL or AZURE_OPENID_CONFIG_TOKEN_ENDPOINT"
        );
    }

    async fn metadata_server(routes: Vec<(&str, Value)>) -> (String, tokio::task::JoinHandle<()>) {
        let mut router = Router::new();

        for (path, response) in routes {
            let body = response.clone();
            router = router.route(path, get(move || async move { Json(body.clone()) }));
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        (format!("http://{address}"), server)
    }
}
