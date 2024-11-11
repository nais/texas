mod app;
mod claims;
mod config;
mod grants;
pub mod handlers;
pub mod identity_provider;
pub mod jwks;

use crate::app::App;
use config::Config;
use dotenv::dotenv;
use log::{error, info, LevelFilter};

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Debug)
        .init();

    config::print_texas_logo();
    info!("Starting up");

    let _ = dotenv(); // load .env if present

    let cfg = match Config::new_from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            error!("configuration: {}", err);
            return;
        }
    };

    let app = App::new(cfg).await;
    app.run().await.unwrap()
}
