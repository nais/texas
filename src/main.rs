use log::{error, info};
use std::process::ExitCode;
use texas::http::server::Server;
use texas::telemetry::init_tracing_subscriber;

#[tokio::main]
async fn main() -> ExitCode {
    #[cfg(feature = "local")]
    let _ = dotenvy::dotenv();

    // Keep guard in scope for tracing shutdown on program exit.
    let guard = init_tracing_subscriber();
    if let Err(err) = guard {
        error!("initialize tracing: {err}");
        return ExitCode::FAILURE;
    }

    #[cfg(feature = "local")]
    print_texas_logo();

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

#[cfg(feature = "local")]
fn print_texas_logo() {
    info!(r"      ____");
    info!(r"           !");
    info!(r"     !     !");
    info!(r"     !      `-  _ _    _ ");
    info!(r"     |              ```  !      _");
    info!(r"_____!                   !     | |");
    info!(r"\,                        \    | |_ _____  ____ _ ___");
    info!(r"  l    _                  ;    | __/ _ \ \/ / _` / __|");
    info!(r"   \ _/  \.              /     | ||  __/>  < (_| \__ \");
    info!(r"           \           .’       \__\___/_/\_\__,_|___/");
    info!(r"            .       ./’");
    info!(r"             `.    ,");
    info!(r"               \   ;");
    info!(r"                 ``’");
}
