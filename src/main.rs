use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use clap::{Args, Parser};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Config {
    #[arg(short, long, env, default_value = "127.0.0.1:3000")]
    bind_addr: String,
    #[arg(env)]
    maskinporten_client_id: String,
    #[arg(env)]
    maskinporten_client_jwk: String,
    #[arg(env)]
    maskinporten_issuer: String,
    #[arg(env)]
    maskinporten_token_endpoint: String,
}

#[tokio::main]
async fn main() {
    let _ = dotenv(); // load .env if present

    let cfg = Config::parse();

    let app = Router::new()
        .route("/token", post(token)).with_state(cfg.clone());

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn token(State(cfg): State<Config>, Json(payload): Json<TokenRequest>) -> (StatusCode, Json<TokenResponse>) {
    let resp = TokenResponse {
        access_token: "dummy".to_string(),
        token_type: TokenType::Bearer,
        expires_in_seconds: 3600,
    };

    (StatusCode::OK, Json(resp))
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
