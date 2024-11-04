pub mod handlers;
pub mod identity_provider;
pub mod jwks;
pub mod types;
mod claims;

use crate::config::Config;
use axum::routing::post;
use axum::Router;
use clap::Parser;
use dotenv::dotenv;
use log::{info, LevelFilter};
use std::sync::Arc;
use tokio::sync::RwLock;
use identity_provider::Provider;
use crate::claims::{ClientAssertion, JWTBearerAssertion};
use crate::identity_provider::{AzureADClientCredentialsTokenRequest, AzureADOnBehalfOfTokenRequest, MaskinportenTokenRequest, TokenXTokenRequest};

pub mod config {
    use clap::Parser;

    #[derive(Parser, Debug, Clone)]
    #[command(version, about, long_about = None)]
    pub struct Config {
        #[arg(short, long, env, default_value = "127.0.0.1:3000")]
        pub bind_address: String,

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

    info!("Fetch JWKS for Maskinporten...");
    let maskinporten: Provider<MaskinportenTokenRequest, JWTBearerAssertion> = Provider::new(
        cfg.maskinporten_issuer.clone(),
        cfg.maskinporten_client_id.clone(),
        cfg.maskinporten_token_endpoint.clone(),
        cfg.maskinporten_client_jwk.clone(),
        jwks::Jwks::new(&cfg.maskinporten_issuer, &cfg.maskinporten_jwks_uri)
            .await
            .unwrap(),
    ).unwrap();

    info!("Fetch JWKS for Azure AD (on behalf of)...");
    let azure_ad_obo: Provider<AzureADOnBehalfOfTokenRequest, ClientAssertion> = Provider::new(
        cfg.azure_ad_issuer.clone(),
        cfg.azure_ad_client_id.clone(),
        cfg.azure_ad_token_endpoint.clone(),
        cfg.azure_ad_client_jwk.clone(),
        jwks::Jwks::new(&cfg.azure_ad_issuer, &cfg.azure_ad_jwks_uri)
            .await
            .unwrap(),
    ).unwrap();

    info!("Fetch JWKS for Azure AD (client credentials)...");
    let azure_ad_cc: Provider<AzureADClientCredentialsTokenRequest, ClientAssertion> = Provider::new(
        cfg.azure_ad_issuer.clone(),
        cfg.azure_ad_client_id.clone(),
        cfg.azure_ad_token_endpoint.clone(),
        cfg.azure_ad_client_jwk.clone(),
        jwks::Jwks::new(&cfg.azure_ad_issuer, &cfg.azure_ad_jwks_uri)
            .await
            .unwrap(),
    ).unwrap();

    info!("Fetch JWKS for TokenX...");
    let token_x: Provider<TokenXTokenRequest, ClientAssertion> = Provider::new(
        cfg.token_x_issuer.clone(),
        cfg.token_x_client_id.clone(),
        cfg.token_x_token_endpoint.clone(),
        cfg.token_x_client_jwk.clone(),
        jwks::Jwks::new(&cfg.token_x_issuer, &cfg.token_x_jwks_uri)
            .await
            .unwrap(),
    ).unwrap();

    let state = handlers::HandlerState {
        cfg: cfg.clone(),
        maskinporten: Arc::new(RwLock::new(maskinporten)),
        azure_ad_obo: Arc::new(RwLock::new(azure_ad_obo)),
        azure_ad_cc: Arc::new(RwLock::new(azure_ad_cc)),
        token_x: Arc::new(RwLock::new(token_x)),
    };

    let app = Router::new()
        .route("/token", post(handlers::token))
        .route("/token_exchange", post(handlers::token_exchange))
        .route(
            "/introspect",
            post(handlers::introspect),
        )
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(cfg.bind_address)
        .await
        .unwrap();

    info!("Serving on {:?}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}
