use crate::cache::{CachedTokenResponse, TokenResponseExpiry};
use crate::config;
use crate::config::Config;
use crate::oauth::assertion::{Assertion, ClientAssertion, JWTBearerAssertion};
use crate::oauth::grant::{
    ClientCredentials, JWTBearer, OnBehalfOf, TokenExchange, TokenRequestBuilder,
};
use crate::oauth::identity_provider::{
    IdentityProvider, Provider, ProviderError, ProviderHandler, ShouldHandler,
    TokenExchangeRequest, TokenRequest,
};
use crate::oauth::token;
use log::debug;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum InitError {
    #[error("invalid private JWK format: {0}")]
    Jwk(ProviderError),

    #[error("fetch JWKS from remote endpoint: {0}")]
    Jwks(#[from] token::Error),
}

#[derive(Clone)]
pub struct State {
    pub cfg: Config,
    pub providers: Vec<Arc<RwLock<Box<dyn ProviderHandler>>>>,
    pub token_cache: moka::future::Cache<TokenRequest, CachedTokenResponse>,
    pub token_exchange_cache: moka::future::Cache<TokenExchangeRequest, CachedTokenResponse>,
}

impl State {
    pub async fn from_config(cfg: Config) -> Result<Self, InitError> {
        const CACHE_MAX_CAPACITY: u64 = 262144;
        let mut providers: Vec<Arc<RwLock<Box<dyn ProviderHandler>>>> = vec![];

        if let Some(provider_cfg) = &cfg.maskinporten {
            debug!(
                "Fetch JWKS for Maskinporten from '{}'...",
                provider_cfg.jwks_uri
            );
            let provider = new::<JWTBearer, JWTBearerAssertion>(
                IdentityProvider::Maskinporten,
                provider_cfg,
                None,
            )
            .await?;
            providers.push(provider);
        }

        if let Some(provider_cfg) = &cfg.entra_id {
            debug!(
                "Fetch JWKS for Entra ID (on behalf of) from '{}'...",
                provider_cfg.jwks_uri
            );
            let provider = new::<OnBehalfOf, ClientAssertion>(
                IdentityProvider::EntraID,
                provider_cfg,
                Some(provider_cfg.client_id.clone()),
            )
            .await?;
            providers.push(provider);

            debug!(
                "Fetch JWKS for Entra ID (client credentials) from '{}'...",
                provider_cfg.jwks_uri
            );
            let provider = new::<ClientCredentials, ClientAssertion>(
                IdentityProvider::EntraID,
                provider_cfg,
                Some(provider_cfg.client_id.clone()),
            )
            .await?;
            providers.push(provider);
        }

        if let Some(provider_cfg) = &cfg.token_x {
            debug!("Fetch JWKS for TokenX from '{}'...", provider_cfg.jwks_uri);
            let provider = new::<TokenExchange, ClientAssertion>(
                IdentityProvider::TokenX,
                provider_cfg,
                Some(provider_cfg.client_id.clone()),
            )
            .await?;
            providers.push(provider);
        }

        if let Some(provider_cfg) = &cfg.idporten {
            debug!(
                "Fetch JWKS for ID-porten from '{}'...",
                provider_cfg.jwks_uri
            );
            let provider = new::<(), ()>(
                IdentityProvider::IDPorten,
                provider_cfg,
                Some(provider_cfg.client_id.clone()),
            )
            .await?;
            providers.push(provider);
        }

        let token_cache = moka::future::CacheBuilder::default()
            .max_capacity(CACHE_MAX_CAPACITY)
            .expire_after(TokenResponseExpiry)
            .build();

        let token_exchange_cache = moka::future::CacheBuilder::default()
            .max_capacity(CACHE_MAX_CAPACITY)
            .expire_after(TokenResponseExpiry)
            .build();

        Ok(Self {
            cfg,
            providers,
            token_cache,
            token_exchange_cache,
        })
    }
}

async fn new<R, A>(
    kind: IdentityProvider,
    provider_cfg: &config::Provider,
    audience: Option<String>,
) -> Result<Arc<RwLock<Box<dyn ProviderHandler>>>, InitError>
where
    R: TokenRequestBuilder + 'static,
    A: Assertion + 'static,
    Provider<R, A>: ShouldHandler,
{
    Ok(Arc::new(RwLock::new(Box::new(
        Provider::<R, A>::new(
            kind,
            provider_cfg.client_id.clone(),
            provider_cfg.issuer.clone(),
            provider_cfg.token_endpoint.clone(),
            provider_cfg.client_jwk.clone(),
            token::Jwks::new(
                &provider_cfg.issuer.clone(),
                &provider_cfg.jwks_uri.clone(),
                audience,
            )
            .await
            .map_err(InitError::Jwks)?,
        )
        .map_err(InitError::Jwk)?,
    ))))
}
