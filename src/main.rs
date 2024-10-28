use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use axum::response::{IntoResponse, Response};
use clap::{Parser};
use dotenv::dotenv;
use log::{error, info, LevelFilter};
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

fn print_texas_logo() {
    info!(r#"      ____"#);
    info!(r#"           !"#);
    info!(r#"     !     !"#);
    info!(r#"     !      `-  _ _    _ "#);
    info!(r#"     |              ```  !      _"#);
    info!(r#"_____!                   !     | |"#);
    info!(r#"\,                        \    | |_ _____  ____ _ ___"#);
    info!(r#"  l    _                  ;    | __/ _ \ \/ / _` / __|"#);
    info!(r#"   \ _/  \.              /     | ||  __/>  < (_| \__ \"#);
    info!(r#"           \           .’       \__\___/_/\_\__,_|___/"#);
    info!(r#"            .       ./’"#);
    info!(r#"             `.    ,"#);
    info!(r#"               \   ;"#);
    info!(r#"                 ``’"#);
}

#[tokio::main]
async fn main() {
    env_logger::builder().filter_level(LevelFilter::Debug).init();

    print_texas_logo();

    let _ = dotenv(); // load .env if present

    let cfg = Config::parse();

    let app = Router::new()
        .route("/token", post(token)).with_state(cfg.clone());

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await.unwrap();

    info!("Serving on {:?}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

enum Error {
    Maskinporten(reqwest::Error),
    JSON,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Error::Maskinporten(m) => {
                (m.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), m.to_string())
            }
            Error::JSON => {
                (StatusCode::BAD_GATEWAY, "could not deserialize json".to_string())
            }
        }.into_response()
    }
}

async fn token(State(cfg): State<Config>, Json(_payload): Json<TokenRequest>) -> Result<impl IntoResponse, Error> {
    let params = ClientTokenRequest {
        grant_type: "client_credentials".to_string(),
        client_id: cfg.maskinporten_client_id,
        client_secret: cfg.maskinporten_client_jwk,
    };

    let client = reqwest::Client::new();
    let res: TokenResponse = client.post(cfg.maskinporten_token_endpoint)
        .header("accept", "application/json")
        .form(&params)
        .send()
        .await
        .map_err(Error::Maskinporten)?
        .json().await
        .inspect_err(|err| {
            error!("Maskinporten returned invalid JSON: {:?}", err)
        })
        .map_err(|_| Error::JSON)?
        ;

    Ok((StatusCode::OK, Json(res)))
}

#[derive(Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: TokenType,
    #[serde(rename = "expires_in")]
    expires_in_seconds: usize,
}

#[derive(Serialize)]
struct ClientTokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
}

#[derive(Deserialize, Serialize)]
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
