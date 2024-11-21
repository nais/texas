use std::process::ExitCode;
use texas::app::App;
use texas::tracing::{init_tracing_subscriber};
use dotenv::dotenv;
use log::{error, info};

#[tokio::main]
async fn main() -> ExitCode {
    let _guard = match init_tracing_subscriber() {
        Ok(guard) => guard,
        Err(err) => {
            error!("initialize tracing: {err}");
            return ExitCode::FAILURE;
        }
    };

    texas::config::print_texas_logo();
    info!("Starting up");

    let _ = dotenv(); // load .env if present

    match App::new_from_env().await {
        Ok(app) => {
            match app.run().await {
                Ok(_) => ExitCode::SUCCESS,
                Err(err) => {
                    error!("fatal: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(err) => {
            error!("{err}");
            ExitCode::FAILURE
        }
    }
}
