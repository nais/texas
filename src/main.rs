pub mod identity_provider;
pub mod jwks;

use std::sync::Arc;
use crate::config::Config;
use axum::routing::post;
use axum::{Router};
use clap::Parser;
use dotenv::dotenv;
use log::{info, LevelFilter};
use tokio::sync::RwLock;

pub mod config {
    use clap::Parser;

    #[derive(Parser, Debug, Clone)]
    #[command(version, about, long_about = None)]
    pub struct Config {
        #[arg(short, long, env, default_value = "127.0.0.1:3000")]
        pub bind_addr: String,
        #[arg(env)]
        pub maskinporten_client_id: String,
        #[arg(env)]
        pub maskinporten_client_jwk: String,
        #[arg(env)]
        pub maskinporten_jwks_uri: String,
        #[arg(env)]
        pub maskinporten_issuer: String,
        #[arg(env)]
        pub maskinporten_token_endpoint: String,
    }
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

    let maskinporten = identity_provider::Maskinporten::new(
        cfg.clone(),
        jwks::Jwks::new_from_jwks_endpoint(&cfg.maskinporten_jwks_uri).await.unwrap(),
    );

    let state = handlers::HandlerState {
        cfg: cfg.clone(),
        maskinporten: Arc::new(RwLock::new(maskinporten)),
    };

    let app = Router::new()
        .route("/token", post(handlers::token)).with_state(state.clone())
        .route("/introspection", post(handlers::introspection).with_state(state.clone()));

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await.unwrap();

    info!("Serving on {:?}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

pub mod handlers {
    use std::sync::Arc;
    use crate::config::Config;
    use crate::identity_provider::*;
    use crate::types;
    use crate::types::{IdentityProvider, IntrospectRequest, TokenRequest, TokenResponse};
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::Json;
    use jsonwebtoken as jwt;
    use jsonwebtoken::Algorithm::RS512;
    use jsonwebtoken::DecodingKey;
    use log::error;
    use thiserror::Error;
    use tokio::sync::{RwLock};

    #[derive(Debug, Error)]
    pub enum ApiError {
        #[error("identity provider error: {0}")]
        UpstreamRequest(reqwest::Error),

        #[error("upstream error: {0}")]
        Upstream(types::ErrorResponse),

        #[error("invalid JSON in token response: {0}")]
        JSON(reqwest::Error),

        #[error("invalid token: {0}")]
        Validate(jwt::errors::Error),
    }

    impl IntoResponse for ApiError {
        fn into_response(self) -> Response {
            match &self {
                ApiError::UpstreamRequest(err) => {
                    (err.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), self.to_string())
                }
                ApiError::JSON(_) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
                }
                ApiError::Upstream(_err) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
                }
                ApiError::Validate(_) => {
                    (StatusCode::BAD_REQUEST, self.to_string())
                }
            }.into_response()
        }
    }

    #[derive(Clone)]
    pub struct HandlerState {
        pub cfg: Config,
        pub maskinporten: Arc<RwLock<Maskinporten>>,
        // TODO: other providers
    }

    #[axum::debug_handler]
    pub async fn token(State(state): State<HandlerState>, Json(request): Json<TokenRequest>) -> Result<impl IntoResponse, ApiError> {
        let (endpoint, params) = match request.identity_provider {
            IdentityProvider::EntraID => (EntraID(state.cfg.clone()).token_endpoint(), EntraID(state.cfg).token_request(request.target)),
            IdentityProvider::TokenX => (TokenX(state.cfg.clone()).token_endpoint(), TokenX(state.cfg).token_request(request.target)),
            IdentityProvider::Maskinporten => {
                let maskinporten = state.maskinporten.read().await;
                (maskinporten.token_endpoint(), maskinporten.token_request(request.target))
            },
        };

        let client = reqwest::Client::new();
        let request_builder = client.post(endpoint)
            .header("accept", "application/json")
            .form(&params);

        let response = request_builder
            .send()
            .await
            .map_err(ApiError::UpstreamRequest)?
            ;

        if response.status() >= StatusCode::BAD_REQUEST {
            let err: types::ErrorResponse = response.json().await.map_err(ApiError::JSON)?;
            return Err(ApiError::Upstream(err));
        }

        let res: TokenResponse = response
            .json().await
            .inspect_err(|err| {
                error!("Identity provider returned invalid JSON: {:?}", err)
            })
            .map_err(ApiError::JSON)?
            ;

        Ok((StatusCode::OK, Json(res)))
    }

    pub async fn introspection(State(state): State<HandlerState>, Json(request): Json<IntrospectRequest>) -> Result<impl IntoResponse, ApiError> {
        // Need to decode the token to get the issuer before we actually validate it.
        let mut validation = jwt::Validation::new(RS512);
        validation.validate_exp = false;
        validation.insecure_disable_signature_validation();
        let key = DecodingKey::from_secret(&[]);
        let token_data = jwt::decode::<Claims>(&request.token, &key, &validation).map_err(ApiError::Validate)?;
        let issuer = token_data.claims.iss;

        let claims = match issuer {
            s if s == state.cfg.maskinporten_issuer => state.maskinporten.write().await.introspect(request.token).await,
            _ => panic!("Unknown issuer: {}", issuer),
        };

        Ok((StatusCode::OK, Json(claims)))
    }

    #[derive(serde::Deserialize)]
    struct Claims {
        iss: String,
    }
}

pub mod types {
    use serde::{Deserialize, Serialize};
    use std::fmt::{Display, Formatter};

    /// This is an upstream RFCXXXX token response.
    #[derive(Serialize, Deserialize)]
    pub struct TokenResponse {
        pub access_token: String,
        pub token_type: TokenType,
        #[serde(rename = "expires_in")]
        pub expires_in_seconds: usize,
    }

    #[derive(Deserialize, Debug, Clone)]
    pub struct ErrorResponse {
        pub error: String,
        #[serde(rename = "error_description")]
        pub description: String,
    }

    impl Display for ErrorResponse {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}: {}", self.error, self.description)
        }
    }

    /// This is the token request sent to our identity provider.
    /// TODO: hard coded parameters that only works with Maskinporten for now.
    #[derive(Serialize)]
    pub struct ClientTokenRequest {
        pub client_id: String,
        pub grant_type: String,
        pub assertion: String,
    }

    /// For forwards API compatibility. Token type is always Bearer,
    /// but this might change in the future.
    #[derive(Deserialize, Serialize)]
    pub enum TokenType {
        Bearer
    }

    /// This is a token request that comes from the application we are serving.
    #[derive(Deserialize)]
    pub struct TokenRequest {
        pub target: String, // typically <cluster>:<namespace>:<app>
        pub identity_provider: IdentityProvider,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub user_token: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub force: Option<bool>,
    }

    #[derive(Deserialize)]
    pub struct IntrospectRequest {
        pub token: String,
    }

    #[derive(Deserialize, Serialize)]
    pub enum IdentityProvider {
        #[serde(rename = "entra")]
        EntraID,
        #[serde(rename = "tokenx")]
        TokenX,
        #[serde(rename = "maskinporten")]
        Maskinporten,
    }
}

