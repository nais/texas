use log::{error, info, warn};
use std::process::ExitCode;
use std::time::Duration;
use texas::app::App;
use texas::tracing::init_tracing_subscriber;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> ExitCode {
    dotenv::dotenv().ok();

    // Keep guard in scope for tracing shutdown on program exit.
    let _guard = match init_tracing_subscriber() {
        Ok(guard) => guard,
        Err(err) => {
            error!("initialize tracing: {err}");
            return ExitCode::FAILURE;
        }
    };

    #[cfg(feature = "local")]
    texas::config::print_texas_logo();

    info!("Starting {} {} built on {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"), env!("BUILD_TIME"));

    let Some(app) = init_app_with_retry().await else {
        error!("unable to initialize application, giving up.");
        return ExitCode::FAILURE;
    };

    match app.run().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            error!("fatal: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Retry initializing application if we hit a network error.
async fn init_app_with_retry() -> Option<App> {
    const MAX_RETRIES: usize = 10;

    for i in 1..=MAX_RETRIES {
        match App::new_from_env().await {
            Ok(app) => return Some(app),
            Err(texas::app::Error::InitHandlerState(err)) => {
                warn!("{err} (attempt {i}/{MAX_RETRIES})");
                sleep(Duration::from_secs(1)).await;
            }
            Err(err) => {
                error!("{err}");
                return None;
            }
        }
    }

    None
}
