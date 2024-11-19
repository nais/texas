use texas::app::App;
use texas::tracing::{init_tracing_subscriber};
use texas::config::Config;
use dotenv::dotenv;
use log::{error, info};

#[tokio::main]
async fn main() {
    let _guard = init_tracing_subscriber();

    texas::config::print_texas_logo();
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
