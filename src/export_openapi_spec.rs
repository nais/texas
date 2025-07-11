use std::io::Write;
use texas::handler::HandlerState;

/// Write the OpenAPI specification to standard output.
#[tokio::main]
async fn main() {
    let mut stdout = std::io::stdout();
    let cfg = texas::config::Config::default();
    let token_cache = moka::future::Cache::new(0);
    let token_exchange_cache = moka::future::Cache::new(0);
    let (_, openapi) = texas::app::api_router(HandlerState {
        cfg,
        token_cache,
        token_exchange_cache,
        providers: vec![],
    });
    let data = openapi.to_pretty_json().unwrap();
    stdout.write_all(data.as_bytes()).unwrap();
}
