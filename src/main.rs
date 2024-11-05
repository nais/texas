pub mod handlers;
pub mod identity_provider;
pub mod jwks;
mod claims;
mod app;
mod config;

use config::Config;
use clap::Parser;
use dotenv::dotenv;
use log::{info, LevelFilter};
use handlers::HandlerState;

#[tokio::main]
async fn main() {
    env_logger::builder().filter_level(LevelFilter::Debug).init();

    config::print_texas_logo();

    info!("Starting up");

    let _ = dotenv(); // load .env if present

    let cfg = Config::parse();
    let bind_address = cfg.bind_address.clone();
    let state = HandlerState::from_config(cfg).await.unwrap();
    let app = app::new(state);

    let listener = tokio::net::TcpListener::bind(bind_address)
        .await
        .unwrap();

    info!("Serving on {:?}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}
