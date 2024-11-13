mod app;
mod claims;
mod config;
mod grants;
pub mod handlers;
pub mod identity_provider;
pub mod jwks;
mod tracing;

use crate::app::App;
use crate::tracing::{init_tracing_subscriber, test};
use config::Config;
use dotenv::dotenv;
use log::{error, info};

#[tokio::main]
async fn main() {
    let _guard = init_tracing_subscriber();

    test().await;

    /*env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .init();
    */
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
