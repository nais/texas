pub mod handlers;
pub mod identity_provider;
pub mod jwks;
pub mod types;
mod claims;
mod router;

use crate::claims::{ClientAssertion, JWTBearerAssertion};
use crate::config::Config;
use crate::identity_provider::{AzureADClientCredentialsTokenRequest, AzureADOnBehalfOfTokenRequest, MaskinportenTokenRequest, TokenXTokenRequest};
use clap::Parser;
use dotenv::dotenv;
use identity_provider::Provider;
use log::{info, LevelFilter};
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod config {
    use clap::Parser;

    #[derive(Parser, Debug, Clone)]
    #[command(version, about, long_about = None)]
    pub struct Config {
        #[arg(short, long, env, default_value = "127.0.0.1:3000")]
        pub bind_address: String,

        // TODO: we should be able to conditionally enable each provider; we currently require all providers to be configured
        //  all arguments within a provider must be present if the provider is enabled
        #[arg(env)]
        pub maskinporten_client_id: String,
        #[arg(env)]
        pub maskinporten_client_jwk: String,
        #[arg(env)]
        pub maskinporten_jwks_uri: String,
        #[arg(env)]
        pub maskinporten_issuer: String,
        #[arg(env)]
        pub maskinporten_token_endpoint: String,

        #[arg(env = "AZURE_APP_CLIENT_ID")]
        pub azure_ad_client_id: String,
        #[arg(env = "AZURE_APP_CLIENT_JWK")]
        pub azure_ad_client_jwk: String,
        #[arg(env = "AZURE_OPENID_CONFIG_JWKS_URI")]
        pub azure_ad_jwks_uri: String,
        #[arg(env = "AZURE_OPENID_CONFIG_ISSUER")]
        pub azure_ad_issuer: String,
        #[arg(env = "AZURE_OPENID_CONFIG_TOKEN_ENDPOINT")]
        pub azure_ad_token_endpoint: String,

        #[arg(env)]
        pub token_x_client_id: String,
        #[arg(env)]
        pub token_x_client_jwk: String,
        #[arg(env)]
        pub token_x_jwks_uri: String,
        #[arg(env)]
        pub token_x_issuer: String,
        #[arg(env)]
        pub token_x_token_endpoint: String,
    }
}

fn print_texas_logo() {
    info!(r#"      ____"#);
    info!(r#"           !"#);
    info!(r#"     !     !"#);
    info!(r#"     !      `-  _ _    _ "#);
    info!(r#"     |              ```  !      _"#);
    info!(r#"_____!                   !     | |"#);
    info!(r#"\,                        \    | |_ _____  ____ _ ___"#);
    info!(r#"  l    _                  ;    | __/ _ \ \/ / _` / __|"#);
    info!(r#"   \ _/  \.              /     | ||  __/>  < (_| \__ \"#);
    info!(r#"           \           .’       \__\___/_/\_\__,_|___/"#);
    info!(r#"            .       ./’"#);
    info!(r#"             `.    ,"#);
    info!(r#"               \   ;"#);
    info!(r#"                 ``’"#);
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Debug)
        .init();

    print_texas_logo();

    info!("Starting up");

    let _ = dotenv(); // load .env if present

    let cfg = Config::parse();

    let state = setup_state(cfg.clone()).await;
    let app = router::new(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind_address)
        .await
        .unwrap();

    info!("Serving on {:?}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

async fn setup_state(cfg: Config) -> handlers::HandlerState {
    // TODO: we should be able to conditionally enable certain providers based on the configuration
    info!("Fetch JWKS for Maskinporten...");
    let maskinporten: Provider<MaskinportenTokenRequest, JWTBearerAssertion> = Provider::new(
        cfg.maskinporten_issuer.clone(),
        cfg.maskinporten_client_id.clone(),
        cfg.maskinporten_token_endpoint.clone(),
        cfg.maskinporten_client_jwk.clone(),
        jwks::Jwks::new(&cfg.maskinporten_issuer.clone(), &cfg.maskinporten_jwks_uri.clone())
            .await
            .unwrap(),
    ).unwrap();

    // TODO: these two AAD providers should be a single provider, but we need to figure out how to handle the different token requests
    info!("Fetch JWKS for Azure AD (on behalf of)...");
    let azure_ad_obo: Provider<AzureADOnBehalfOfTokenRequest, ClientAssertion> = Provider::new(
        cfg.azure_ad_issuer.clone(),
        cfg.azure_ad_client_id.clone(),
        cfg.azure_ad_token_endpoint.clone(),
        cfg.azure_ad_client_jwk.clone(),
        jwks::Jwks::new(&cfg.azure_ad_issuer.clone(), &cfg.azure_ad_jwks_uri.clone())
            .await
            .unwrap(),
    ).unwrap();

    info!("Fetch JWKS for Azure AD (client credentials)...");
    let azure_ad_cc: Provider<AzureADClientCredentialsTokenRequest, ClientAssertion> = Provider::new(
        cfg.azure_ad_issuer.clone(),
        cfg.azure_ad_client_id.clone(),
        cfg.azure_ad_token_endpoint.clone(),
        cfg.azure_ad_client_jwk.clone(),
        jwks::Jwks::new(&cfg.azure_ad_issuer.clone(), &cfg.azure_ad_jwks_uri.clone())
            .await
            .unwrap(),
    ).unwrap();

    info!("Fetch JWKS for TokenX...");
    let token_x: Provider<TokenXTokenRequest, ClientAssertion> = Provider::new(
        cfg.token_x_issuer.clone(),
        cfg.token_x_client_id.clone(),
        cfg.token_x_token_endpoint.clone(),
        cfg.token_x_client_jwk.clone(),
        jwks::Jwks::new(&cfg.token_x_issuer.clone(), &cfg.token_x_jwks_uri.clone())
            .await
            .unwrap(),
    ).unwrap();

    handlers::HandlerState {
        cfg: cfg.clone(),
        maskinporten: Arc::new(RwLock::new(maskinporten)),
        azure_ad_obo: Arc::new(RwLock::new(azure_ad_obo)),
        azure_ad_cc: Arc::new(RwLock::new(azure_ad_cc)),
        token_x: Arc::new(RwLock::new(token_x)),
    }
}
