use crate::config::Error::{MissingEnv, ParseBool};
use log::info;
use serde::Serialize;
use std::str::ParseBoolError;
use thiserror::Error;

#[derive(Serialize, Debug, Clone, Default)]
pub struct Config {
    pub bind_address: String,
    pub probe_bind_address: Option<String>,
    pub maskinporten: Option<Provider>,
    pub azure_ad: Option<Provider>,
    pub token_x: Option<Provider>,
    pub idporten: Option<Provider>,
}

#[derive(Serialize, Clone, Debug)]
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
}

impl Provider {
    fn is_provider_enabled(prefix: &str) -> Result<bool, Error> {
        let key = format!("{prefix}_ENABLED");
        let Ok(envvar) = std::env::var(&key) else {
            return Ok(false);
        };

        envvar.parse().map_err(|err| ParseBool(key, err))
    }

    fn new_from_env_with_prefix(prefix: &str) -> Result<Option<Self>, Error> {
        if !Self::is_provider_enabled(prefix)? {
            return Ok(None);
        }
        Ok(Some(Self {
            client_id: must_read_env(&format!("{prefix}_CLIENT_ID"))?,
            client_jwk: Some(must_read_env(&format!("{prefix}_CLIENT_JWK"))?),
            jwks_uri: must_read_env(&format!("{prefix}_JWKS_URI"))?,
            issuer: must_read_env(&format!("{prefix}_ISSUER"))?,
            token_endpoint: Some(must_read_env(&format!("{prefix}_TOKEN_ENDPOINT"))?),
        }))
    }

    fn new_from_azure_env() -> Result<Option<Self>, Error> {
        if !Self::is_provider_enabled("AZURE")? {
            return Ok(None);
        }
        Ok(Some(Self {
            client_id: must_read_env("AZURE_APP_CLIENT_ID")?,
            client_jwk: Some(must_read_env("AZURE_APP_JWK")?),
            jwks_uri: must_read_env("AZURE_OPENID_CONFIG_JWKS_URI")?,
            issuer: must_read_env("AZURE_OPENID_CONFIG_ISSUER")?,
            token_endpoint: Some(must_read_env("AZURE_OPENID_CONFIG_TOKEN_ENDPOINT")?),
        }))
    }

    fn new_from_idporten_env() -> Result<Option<Self>, Error> {
        if !Self::is_provider_enabled("IDPORTEN")? {
            return Ok(None);
        }
        Ok(Some(Self {
            client_id: must_read_env("IDPORTEN_AUDIENCE")?,
            client_jwk: None,
            jwks_uri: must_read_env("IDPORTEN_JWKS_URI")?,
            issuer: must_read_env("IDPORTEN_ISSUER")?,
            token_endpoint: None,
        }))
    }

    fn new_from_tokenx_env() -> Result<Option<Self>, Error> {
        if !Self::is_provider_enabled("TOKEN_X")? {
            return Ok(None);
        }
        Ok(Some(Self {
            client_id: must_read_env("TOKEN_X_CLIENT_ID")?,
            client_jwk: Some(must_read_env("TOKEN_X_PRIVATE_JWK")?),
            jwks_uri: must_read_env("TOKEN_X_JWKS_URI")?,
            issuer: must_read_env("TOKEN_X_ISSUER")?,
            token_endpoint: Some(must_read_env("TOKEN_X_TOKEN_ENDPOINT")?),
        }))
    }
}

pub fn print_texas_logo() {
    info!(r"      ____");
    info!(r"           !");
    info!(r"     !     !");
    info!(r"     !      `-  _ _    _ ");
    info!(r"     |              ```  !      _");
    info!(r"_____!                   !     | |");
    info!(r"\,                        \    | |_ _____  ____ _ ___");
    info!(r"  l    _                  ;    | __/ _ \ \/ / _` / __|");
    info!(r"   \ _/  \.              /     | ||  __/>  < (_| \__ \");
    info!(r"           \           .’       \__\___/_/\_\__,_|___/");
    info!(r"            .       ./’");
    info!(r"             `.    ,");
    info!(r"               \   ;");
    info!(r"                 ``’");
}

fn must_read_env(env: &str) -> Result<String, Error> {
    std::env::var(env).map_err(|_| MissingEnv(env.to_string()))
}

impl Config {
    pub fn new_from_env() -> Result<Self, Error> {
        Ok(Self {
            bind_address: std::env::var("BIND_ADDRESS").unwrap_or("127.0.0.1:3000".to_string()),
            probe_bind_address: std::env::var("PROBE_BIND_ADDRESS").ok(),
            azure_ad: Provider::new_from_azure_env()?,
            maskinporten: Provider::new_from_env_with_prefix("MASKINPORTEN")?,
            token_x: Provider::new_from_tokenx_env()?,
            idporten: Provider::new_from_idporten_env()?,
        })
    }
}
