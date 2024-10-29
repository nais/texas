use axum::routing::post;
use axum::Router;
use clap::{Parser};
use dotenv::dotenv;
use log::{info, LevelFilter};
use crate::config::Config;

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

    let app = Router::new()
        .route("/token", post(handlers::token)).with_state(cfg.clone());

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await.unwrap();

    info!("Serving on {:?}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

pub mod handlers {
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::{Json};
    use axum::response::{IntoResponse, Response};
    use log::{error};
    use thiserror::Error;
    use crate::config::Config;
    use crate::idprovider::*;
    use crate::types;
    use crate::types::{IdentityProvider, TokenRequest, TokenResponse};

    #[derive(Debug, Error)]
    pub enum ApiError {
        #[error("identity provider error: {0}")]
        UpstreamRequest(reqwest::Error),

        #[error("upstream error")]
        Upstream(types::ErrorResponse),

        #[error("invalid JSON in token response: {0}")]
        JSON(reqwest::Error),
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
            }.into_response()
        }
    }

    pub async fn token(State(cfg): State<Config>, Json(request): Json<TokenRequest>) -> Result<impl IntoResponse, ApiError> {
        let provider: Box<dyn Idprovider + Send> = match request.identity_provider {
            IdentityProvider::EntraID => Box::new(EntraID(cfg)),
            IdentityProvider::TokenX => Box::new(TokenX(cfg)),
            IdentityProvider::Maskinporten => Box::new(Maskinporten(cfg)),
        };

        let params = provider.oauth_request();

        let client = reqwest::Client::new();
        let request_builder = client.post(provider.oauth_endpoint())
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
                error!("Maskinporten returned invalid JSON: {:?}", err)
            })
            .map_err(ApiError::JSON)?
            ;

        Ok((StatusCode::OK, Json(res)))
    }
}

pub mod types {
    use serde::{Deserialize, Serialize};

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

    /// This is the token request sent to our identity provider.
    #[derive(Serialize)]
    pub struct ClientTokenRequest {
        pub grant_type: String,
        pub client_id: String,
        pub client_secret: String,
    }

    /// For forwards API compatibility. Token type is always Bearer,
    /// but this might change in the future.
    #[derive(Deserialize, Serialize)]
    pub enum TokenType {
        Bearer
    }

    /// This is a token request that comes from the application we are serving.
    #[derive(Deserialize, Serialize)]
    pub struct TokenRequest {
        pub target: String, // typically <cluster>:<namespace>:<app>
        pub identity_provider: IdentityProvider,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub user_token: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub force: Option<bool>,
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

pub mod idprovider {
    use crate::config::Config;
    use crate::types::ClientTokenRequest;

    pub trait Idprovider {
        fn oauth_request(&self) -> ClientTokenRequest;
        fn oauth_endpoint(&self) -> String;
    }

    #[derive(Clone, Debug)]
    pub struct Maskinporten(pub Config);

    #[derive(Clone, Debug)]
    pub struct EntraID(pub Config);

    #[derive(Clone, Debug)]
    pub struct TokenX(pub Config);

    impl Idprovider for EntraID {
        fn oauth_request(&self) -> ClientTokenRequest {
            ClientTokenRequest {
                grant_type: "client_credentials".to_string(), // FIXME: urn:ietf:params:oauth:grant-type:jwt-bearer for OBO
                client_id: "".to_string(),
                client_secret: "".to_string(),
            }
        }

        fn oauth_endpoint(&self) -> String {
            todo!()
        }
    }

    impl Idprovider for TokenX {
        fn oauth_request(&self) -> ClientTokenRequest {
            ClientTokenRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
                client_id: "".to_string(),
                client_secret: "".to_string(),
            }
        }

        fn oauth_endpoint(&self) -> String {
            todo!()
        }
    }

    impl Idprovider for Maskinporten {
        fn oauth_request(&self) -> ClientTokenRequest {
            ClientTokenRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
                client_id: self.0.maskinporten_client_id.to_string(),
                client_secret: self.0.maskinporten_client_jwk.to_string(),
            }
        }

        fn oauth_endpoint(&self) -> String {
            self.0.maskinporten_token_endpoint.to_string()
        }
    }
}
