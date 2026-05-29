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
    pub ansattporten: Option<Provider>,
}

impl Config {
    pub async fn new_from_env() -> Result<Self, Error> {
        Ok(Self {
            bind_address: std::env::var("BIND_ADDRESS").unwrap_or("127.0.0.1:3000".to_string()),
            probe_bind_address: std::env::var("PROBE_BIND_ADDRESS").ok(),
            entra_id: ENTRA_ID.resolve().await?,
            maskinporten: MASKINPORTEN.resolve().await?,
            token_x: TOKEN_X.resolve().await?,
            idporten: IDPORTEN.resolve().await?,
            ansattporten: ANSATTPORTEN.resolve().await?,
        })
    }
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Provider {
    pub client_id: String,
    pub client_jwk: Option<String>,
    pub jwks_uri: String,
    pub issuer: String,
    pub token_endpoint: Option<String>,
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

enum ProviderMode {
    Exchange {
        client_jwk_env: &'static str,
        token_endpoint_env: &'static str,
    },
    IntrospectOnly,
}

struct ProviderConfig {
    name: &'static str,
    enabled_env: &'static str,
    client_id_env: &'static str,
    well_known_env: &'static str,
    issuer_env: &'static str,
    jwks_uri_env: &'static str,
    mode: ProviderMode,
}

const ENTRA_ID: ProviderConfig = ProviderConfig {
    name: "Entra ID",
    enabled_env: "AZURE_ENABLED",
    client_id_env: "AZURE_APP_CLIENT_ID",
    well_known_env: "AZURE_APP_WELL_KNOWN_URL",
    issuer_env: "AZURE_OPENID_CONFIG_ISSUER",
    jwks_uri_env: "AZURE_OPENID_CONFIG_JWKS_URI",
    mode: ProviderMode::Exchange {
        client_jwk_env: "AZURE_APP_JWK",
        token_endpoint_env: "AZURE_OPENID_CONFIG_TOKEN_ENDPOINT",
    },
};

const IDPORTEN: ProviderConfig = ProviderConfig {
    name: "ID-porten",
    enabled_env: "IDPORTEN_ENABLED",
    client_id_env: "IDPORTEN_AUDIENCE",
    well_known_env: "IDPORTEN_WELL_KNOWN_URL",
    issuer_env: "IDPORTEN_ISSUER",
    jwks_uri_env: "IDPORTEN_JWKS_URI",
    mode: ProviderMode::IntrospectOnly,
};

const ANSATTPORTEN: ProviderConfig = ProviderConfig {
    name: "Ansattporten",
    enabled_env: "ANSATTPORTEN_ENABLED",
    client_id_env: "ANSATTPORTEN_AUDIENCE",
    well_known_env: "ANSATTPORTEN_WELL_KNOWN_URL",
    issuer_env: "ANSATTPORTEN_ISSUER",
    jwks_uri_env: "ANSATTPORTEN_JWKS_URI",
    mode: ProviderMode::IntrospectOnly,
};

const MASKINPORTEN: ProviderConfig = ProviderConfig {
    name: "Maskinporten",
    enabled_env: "MASKINPORTEN_ENABLED",
    client_id_env: "MASKINPORTEN_CLIENT_ID",
    well_known_env: "MASKINPORTEN_WELL_KNOWN_URL",
    issuer_env: "MASKINPORTEN_ISSUER",
    jwks_uri_env: "MASKINPORTEN_JWKS_URI",
    mode: ProviderMode::Exchange {
        client_jwk_env: "MASKINPORTEN_CLIENT_JWK",
        token_endpoint_env: "MASKINPORTEN_TOKEN_ENDPOINT",
    },
};

const TOKEN_X: ProviderConfig = ProviderConfig {
    name: "TokenX",
    enabled_env: "TOKEN_X_ENABLED",
    client_id_env: "TOKEN_X_CLIENT_ID",
    well_known_env: "TOKEN_X_WELL_KNOWN_URL",
    issuer_env: "TOKEN_X_ISSUER",
    jwks_uri_env: "TOKEN_X_JWKS_URI",
    mode: ProviderMode::Exchange {
        client_jwk_env: "TOKEN_X_PRIVATE_JWK",
        token_endpoint_env: "TOKEN_X_TOKEN_ENDPOINT",
    },
};

impl ProviderConfig {
    async fn resolve(&self) -> Result<Option<Provider>, Error> {
        match UnresolvedProvider::from_env(self)? {
            Some(unresolved) => Ok(Some(unresolved.resolve(self).await?)),
            None => Ok(None),
        }
    }
}

#[derive(Debug)]
struct UnresolvedProvider {
    client_id: String,
    client_jwk: Option<String>,
    well_known_url: Option<String>,
    jwks_uri: Option<String>,
    issuer: Option<String>,
    token_endpoint: Option<String>,
}

impl UnresolvedProvider {
    fn from_env(config: &ProviderConfig) -> Result<Option<Self>, Error> {
        let enabled = match std::env::var(config.enabled_env) {
            Ok(val) => val.parse().map_err(|e| ParseBool(config.enabled_env.to_string(), e))?,
            Err(_) => false,
        };
        if !enabled {
            return Ok(None);
        }

        let (client_jwk, token_endpoint) = match config.mode {
            ProviderMode::Exchange {
                client_jwk_env,
                token_endpoint_env,
            } => (
                Some(must_read_env(client_jwk_env)?),
                read_env(token_endpoint_env),
            ),
            ProviderMode::IntrospectOnly => (None, None),
        };

        Ok(Some(Self {
            client_id: must_read_env(config.client_id_env)?,
            client_jwk,
            well_known_url: read_env(config.well_known_env),
            jwks_uri: read_env(config.jwks_uri_env),
            issuer: read_env(config.issuer_env),
            token_endpoint,
        }))
    }

    async fn resolve(self, config: &ProviderConfig) -> Result<Provider, Error> {
        let required_token_endpoint_env = match config.mode {
            ProviderMode::Exchange {
                token_endpoint_env, ..
            } => Some(token_endpoint_env),
            ProviderMode::IntrospectOnly => None,
        };

        let needs_metadata = self.issuer.is_none()
            || self.jwks_uri.is_none()
            || (required_token_endpoint_env.is_some() && self.token_endpoint.is_none());

        let metadata = match self.well_known_url.as_deref() {
            Some(url) if needs_metadata => {
                log::debug!(
                    "{}: fetching metadata from {}={}",
                    config.name,
                    config.well_known_env,
                    url,
                );
                fetch_provider_metadata(url).await?
            }
            Some(url) => {
                log::debug!(
                    "{}: all fields provided via env, skipping metadata fetch from {}={}",
                    config.name,
                    config.well_known_env,
                    url,
                );
                AuthorizationServerMetadata::default()
            }
            None => AuthorizationServerMetadata::default(),
        };

        let issuer = self.issuer.or(metadata.issuer).ok_or(Error::MissingProviderConfigField {
            provider: config.name,
            field_env: config.issuer_env,
            well_known_env: config.well_known_env,
        })?;

        let jwks_uri =
            self.jwks_uri.or(metadata.jwks_uri).ok_or(Error::MissingProviderConfigField {
                provider: config.name,
                field_env: config.jwks_uri_env,
                well_known_env: config.well_known_env,
            })?;

        let token_endpoint = self.token_endpoint.or(metadata.token_endpoint);

        if let Some(field_env) = required_token_endpoint_env
            && token_endpoint.is_none()
        {
            return Err(Error::MissingProviderConfigField {
                provider: config.name,
                field_env,
                well_known_env: config.well_known_env,
            });
        }

        let provider = Provider {
            client_id: self.client_id,
            client_jwk: self.client_jwk,
            jwks_uri,
            issuer,
            token_endpoint,
        };

        log::debug!("{}: client_id={}", config.name, provider.client_id);
        log::debug!("{}: issuer={}", config.name, provider.issuer);
        log::debug!("{}: jwks_uri={}", config.name, provider.jwks_uri);
        if let Some(ref ep) = provider.token_endpoint {
            log::debug!("{}: token_endpoint={}", config.name, ep);
        }

        Ok(provider)
    }
}

fn must_read_env(env: &str) -> Result<String, Error> {
    std::env::var(env).map_err(|_| MissingEnv(env.to_string()))
}

fn read_env(env: &str) -> Option<String> {
    std::env::var(env).ok()
}

#[derive(Default, Deserialize)]
struct AuthorizationServerMetadata {
    issuer: Option<String>,
    token_endpoint: Option<String>,
    jwks_uri: Option<String>,
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
    use super::{ANSATTPORTEN, ENTRA_ID, IDPORTEN, MASKINPORTEN, UnresolvedProvider};
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

        let resolved = UnresolvedProvider {
            client_id: "client-id".to_string(),
            client_jwk: Some("private-jwk".to_string()),
            well_known_url: Some(format!("{base_url}/oidc/.well-known/openid-configuration")),
            issuer: None,
            token_endpoint: None,
            jwks_uri: None,
        }
        .resolve(&ENTRA_ID)
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

        let resolved = UnresolvedProvider {
            client_id: "client-id".to_string(),
            client_jwk: Some("private-jwk".to_string()),
            well_known_url: Some(format!(
                "{base_url}/oauth/.well-known/oauth-authorization-server"
            )),
            issuer: None,
            token_endpoint: None,
            jwks_uri: None,
        }
        .resolve(&MASKINPORTEN)
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

        let resolved = UnresolvedProvider {
            client_id: "client-id".to_string(),
            client_jwk: None,
            well_known_url: Some(format!(
                "{base_url}/idporten/.well-known/openid-configuration"
            )),
            issuer: None,
            token_endpoint: None,
            jwks_uri: None,
        }
        .resolve(&IDPORTEN)
        .await
        .unwrap();

        assert_eq!(resolved.issuer, "https://idporten.example");
        assert_eq!(resolved.token_endpoint, None);
        assert_eq!(resolved.jwks_uri, "https://idporten.example/jwks");
    }

    #[tokio::test]
    async fn ansattporten_does_not_require_token_endpoint_in_metadata() {
        let (base_url, _server) = metadata_server(vec![(
            "/ansattporten/.well-known/openid-configuration",
            json!({
                "issuer": "https://ansattporten.example",
                "jwks_uri": "https://ansattporten.example/jwks"
            }),
        )])
        .await;

        let resolved = UnresolvedProvider {
            client_id: "client-id".to_string(),
            client_jwk: None,
            well_known_url: Some(format!(
                "{base_url}/ansattporten/.well-known/openid-configuration"
            )),
            issuer: None,
            token_endpoint: None,
            jwks_uri: None,
        }
        .resolve(&ANSATTPORTEN)
        .await
        .unwrap();

        assert_eq!(resolved.issuer, "https://ansattporten.example");
        assert_eq!(resolved.token_endpoint, None);
        assert_eq!(resolved.jwks_uri, "https://ansattporten.example/jwks");
    }

    #[tokio::test]
    async fn missing_manual_issuer_has_provider_specific_error() {
        let err = UnresolvedProvider {
            client_id: "client-id".to_string(),
            client_jwk: Some("private-jwk".to_string()),
            well_known_url: None,
            issuer: None,
            token_endpoint: Some("https://maskinporten.example/token".to_string()),
            jwks_uri: Some("https://maskinporten.example/jwks".to_string()),
        }
        .resolve(&MASKINPORTEN)
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "missing configuration for provider 'Maskinporten': set MASKINPORTEN_WELL_KNOWN_URL or MASKINPORTEN_ISSUER"
        );
    }

    #[tokio::test]
    async fn missing_manual_jwks_uri_has_provider_specific_error() {
        let err = UnresolvedProvider {
            client_id: "client-id".to_string(),
            client_jwk: None,
            well_known_url: None,
            issuer: Some("https://idporten.example".to_string()),
            token_endpoint: None,
            jwks_uri: None,
        }
        .resolve(&IDPORTEN)
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "missing configuration for provider 'ID-porten': set IDPORTEN_WELL_KNOWN_URL or IDPORTEN_JWKS_URI"
        );
    }

    #[tokio::test]
    async fn missing_manual_token_endpoint_has_provider_specific_error() {
        let err = UnresolvedProvider {
            client_id: "client-id".to_string(),
            client_jwk: Some("private-jwk".to_string()),
            well_known_url: None,
            issuer: Some("https://entra.example".to_string()),
            token_endpoint: None,
            jwks_uri: Some("https://entra.example/jwks".to_string()),
        }
        .resolve(&ENTRA_ID)
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "missing configuration for provider 'Entra ID': set AZURE_APP_WELL_KNOWN_URL or AZURE_OPENID_CONFIG_TOKEN_ENDPOINT"
        );
    }

    #[tokio::test]
    async fn explicit_values_override_metadata() {
        let (base_url, _server) = metadata_server(vec![(
            "/oidc/.well-known/openid-configuration",
            json!({
                "issuer": "https://from-metadata.example",
                "token_endpoint": "https://from-metadata.example/token",
                "jwks_uri": "https://from-metadata.example/jwks"
            }),
        )])
        .await;

        let resolved = UnresolvedProvider {
            client_id: "client-id".to_string(),
            client_jwk: Some("private-jwk".to_string()),
            well_known_url: Some(format!("{base_url}/oidc/.well-known/openid-configuration")),
            issuer: Some("https://explicit.example".to_string()),
            token_endpoint: Some("https://explicit.example/token".to_string()),
            jwks_uri: None, // only this one falls back to metadata
        }
        .resolve(&ENTRA_ID)
        .await
        .unwrap();

        assert_eq!(resolved.issuer, "https://explicit.example");
        assert_eq!(
            resolved.token_endpoint.as_deref(),
            Some("https://explicit.example/token")
        );
        assert_eq!(resolved.jwks_uri, "https://from-metadata.example/jwks");
    }

    #[tokio::test]
    async fn explicit_values_used_when_all_fields_present() {
        let resolved = UnresolvedProvider {
            client_id: "client-id".to_string(),
            client_jwk: Some("private-jwk".to_string()),
            well_known_url: Some("http://should-not-resolve.example/metadata".to_string()),
            issuer: Some("https://explicit.example".to_string()),
            token_endpoint: Some("https://explicit.example/token".to_string()),
            jwks_uri: Some("https://explicit.example/jwks".to_string()),
        }
        .resolve(&ENTRA_ID)
        .await
        .unwrap();

        assert_eq!(resolved.issuer, "https://explicit.example");
        assert_eq!(
            resolved.token_endpoint.as_deref(),
            Some("https://explicit.example/token")
        );
        assert_eq!(resolved.jwks_uri, "https://explicit.example/jwks");
    }

    struct AbortOnDrop(tokio::task::JoinHandle<()>);

    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn metadata_server(routes: Vec<(&str, Value)>) -> (String, AbortOnDrop) {
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

        (format!("http://{address}"), AbortOnDrop(server))
    }
}
