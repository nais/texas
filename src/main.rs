use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use clap::Parser;
use dotenv::dotenv;
use serde::{Deserialize, Serialize};

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

    let app = Router::new()
        .route("/token", post(token)).with_state(Handler { args });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn token(State(handler): State<Handler>, Json(payload): Json<TokenRequest>) -> (StatusCode, Json<TokenResponse>) {
    let resp = TokenResponse {
        access_token: format!("{} {}", handler.args.texas_name, payload.user_token.unwrap_or_default()),
        token_type: TokenType::Bearer,
        expires_in_seconds: 3600,
    };

    (StatusCode::OK, Json(resp))
}

#[derive(Clone)]
struct Handler {
    args: Args,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: TokenType,
    #[serde(rename = "expires_in")]
    expires_in_seconds: usize,
}

#[derive(Serialize)]
enum TokenType {
    Bearer
}

#[derive(Deserialize, Serialize)]
struct TokenRequest {
    target: String, // typically <cluster>:<namespace>:<app>
    identity_provider: IdentityProvider,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    force: Option<bool>,
}

#[derive(Deserialize, Serialize)]
enum IdentityProvider {
    #[serde(rename = "entra")]
    EntraID,
    #[serde(rename = "tokenx")]
    TokenX,
    #[serde(rename = "maskinporten")]
    Maskinporten,
}
