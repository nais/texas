use log::{error, info};
use std::process::ExitCode;
use texas::http::server::Server;
use texas::telemetry::init_tracing_subscriber;

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> ExitCode {
    #[cfg(feature = "local")]
    let _ = dotenv::dotenv();

    // Keep guard in scope for tracing shutdown on program exit.
    let guard = init_tracing_subscriber();
    if let Err(err) = guard {
        error!("initialize tracing: {err}");
        return ExitCode::FAILURE;
    }

    #[cfg(feature = "local")]
    texas::config::print_texas_logo();

    info!(
        "Starting {} {} built on {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("BUILD_TIME")
    );

    match Server::new_from_env().await {
        Ok(app) => {
            app.run().await;
            ExitCode::SUCCESS
        }
        Err(err) => {
            error!("unable to initialize application: {err}");
            ExitCode::FAILURE
        }
    }
}
