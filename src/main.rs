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
use crate::app::App;

#[tokio::main]
async fn main() {
    env_logger::builder().filter_level(LevelFilter::Debug).init();

    config::print_texas_logo();
    info!("Starting up");

    let _ = dotenv(); // load .env if present
    let cfg = Config::parse();
    let app = App::new(cfg).await;
    app.run().await.unwrap()
}
