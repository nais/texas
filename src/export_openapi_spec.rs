use std::io::Write;
use texas::app::App;
use texas::handlers::HandlerState;

/// Write the OpenAPI specification to standard output.
#[tokio::main]
async fn main() {
    let mut stdout = std::io::stdout();
    let cfg = texas::config::Config::default();
    let (_, openapi) = App::routes(HandlerState{ cfg, providers: vec![] });
    let data = openapi.to_pretty_json().unwrap();
    stdout.write_all(data.as_bytes()).unwrap();
}