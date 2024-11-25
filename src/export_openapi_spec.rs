use std::io::Write;
use texas::app::App;
use texas::config::DownstreamApp;
use texas::handlers::HandlerState;

/// Write the OpenAPI specification to standard output.
#[tokio::main]
async fn main() {
    let mut stdout = std::io::stdout();
    let cfg = texas::config::Config::default();
    let token_cache = moka::future::Cache::new(0);
    let (_, openapi) = App::routes(HandlerState{ cfg, token_cache, providers: vec![] }, DownstreamApp::default());
    let data = openapi.to_pretty_json().unwrap();
    stdout.write_all(data.as_bytes()).unwrap();
}