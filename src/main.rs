use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use dotenv::dotenv;
use serde::Serialize;

/// Simple program to greet a person
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long, env = "TEXAS_NAME")]
    texas_name: String,

    /// Number of times to greet
    #[arg(short, long, default_value_t = 1)]
    count: u8,
}

#[tokio::main]
async fn main() {
    let _ = dotenv(); // load .env if present

    let args = Args::parse();

    for _ in 0..args.count {
        println!("Howdy, {}!", args.texas_name);
    }

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root)).with_state(Handler { args });

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root(State(handler): State<Handler>) -> (StatusCode, Json<RootResponse>) {
    let resp = RootResponse {
        name: handler.args.texas_name,
    };

    (StatusCode::OK, Json(resp))
}

#[derive(Clone)]
struct Handler {
    args: Args,
}

#[derive(Serialize)]
struct RootResponse {
    name: String,
}
