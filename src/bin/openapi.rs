use moka::future::Cache;
use std::io::Write;
use texas::config::Config;
use texas::handler::State;
use texas::http;

/// Write the OpenAPI specification to standard output.
#[tokio::main]
async fn main() {
    let mut stdout = std::io::stdout();
    let cfg = Config::default();
    let token_cache = Cache::new(0);
    let token_exchange_cache = Cache::new(0);
    let (_, openapi) = http::router::api(State {
        cfg,
        token_cache,
        token_exchange_cache,
        providers: vec![],
    });
    let data = openapi.to_pretty_json().unwrap();
    stdout.write_all(data.as_bytes()).unwrap();
}
