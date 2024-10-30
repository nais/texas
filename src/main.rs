use crate::config::Config;
use axum::routing::post;
use axum::Router;
use clap::Parser;
use dotenv::dotenv;
use log::{info, LevelFilter};

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

    let app = Router::new()
        .route("/token", post(handlers::token)).with_state(cfg.clone())
        .route("/introspection", post(handlers::introspection).with_state(cfg.clone()));

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await.unwrap();

    info!("Serving on {:?}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

pub mod handlers {
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
    use crate::jwks::Jwks;

    #[derive(Debug, Error)]
    pub enum ApiError {
        #[error("identity provider error: {0}")]
        UpstreamRequest(reqwest::Error),

        #[error("upstream error: {0}")]
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

    // TODO: create providers outside of this, possibly use State to store them
    pub async fn token(State(cfg): State<Config>, Json(request): Json<TokenRequest>) -> Result<impl IntoResponse, ApiError> {
        let key_set = Jwks::new_from_jwks_endpoint(&cfg.maskinporten_jwks_uri).await.unwrap();

        let provider: Box<dyn Provider + Send> = match request.identity_provider {
            IdentityProvider::EntraID => Box::new(EntraID(cfg)),
            IdentityProvider::TokenX => Box::new(TokenX(cfg)),
            IdentityProvider::Maskinporten => Box::new(Maskinporten::new(cfg, key_set)),
        };

        let params = provider.token_request(request.target);

        let client = reqwest::Client::new();
        let request_builder = client.post(provider.token_endpoint())
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

    pub async fn introspection(State(cfg): State<Config>, Json(request): Json<IntrospectRequest>) -> Result<impl IntoResponse, ApiError> {
        // Need to decode the token to get the issuer before we actually validate it.
        let mut validation = jwt::Validation::new(RS512);
        validation.validate_exp = false;
        validation.insecure_disable_signature_validation();
        let key = DecodingKey::from_secret(&[]);
        let token_data = jwt::decode::<Claims>(&request.token, &key, &validation).unwrap();
        let issuer = token_data.claims.iss;

        let key_set = Jwks::new_from_jwks_endpoint(&cfg.maskinporten_jwks_uri).await.unwrap();

        let provider = match issuer {
            s if s == cfg.maskinporten_issuer => Box::new(Maskinporten::new(cfg, key_set)),
            _ => panic!("Unknown issuer: {}", issuer),
        };

        let claims = provider.introspect(request.token);

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

pub mod jwks {
    use std::collections::HashMap;
    use jsonwebkey as jwk;
    use jsonwebtoken as jwt;
    use serde::Deserialize;
    use serde_json::Value;
    use crate::jwks::Error::{InvalidToken, KeyNotInJWKS};

    #[derive(Clone, Debug)]
    pub struct Jwks {
        endpoint: String,
        keys: HashMap<String, jwk::JsonWebKey>,
    }

    #[derive(Debug)]
    pub enum Error {
        Fetch(reqwest::Error),
        JsonDecode(reqwest::Error),
        MissingKeyID,
        InvalidTokenHeader(jwt::errors::Error),
        KeyNotInJWKS,
        InvalidToken(jwt::errors::Error),
    }

    impl Jwks {
        pub async fn new_from_jwks_endpoint(endpoint: &str) -> Result<Jwks, Error> {
            #[derive(Deserialize)]
            struct Response {
                keys: Vec<jwk::JsonWebKey>,
            }

            let client = reqwest::Client::new();
            let request_builder = client.get(endpoint)
                .header("accept", "application/json");

            let response: Response = request_builder
                .send().await
                .map_err(Error::Fetch)?
                .json().await
                .map_err(Error::JsonDecode)?
                ;

            let mut keys: HashMap<String, jwk::JsonWebKey> = HashMap::new();
            for key in response.keys {
                keys.insert(key.key_id.clone().ok_or(Error::MissingKeyID)?, key);
            }

            Ok(Self {
                keys,
                endpoint: endpoint.to_string(),
            })
        }

        pub async fn refresh(&mut self) -> Result<(), Error> {
            let new_jwks = Self::new_from_jwks_endpoint(&self.endpoint).await?;
            self.keys = new_jwks.keys;
            Ok(())
        }

        /// Check a JWT against a JWKS.
        /// Returns the JWT's claims on success.
        // TODO: ensure all the things are properly validated
        pub fn validate(
            &self,
            token: &str,
        ) -> Result<HashMap<String, Value>, Error> {
            let alg = jwt::Algorithm::RS256;
            let validation = jwt::Validation::new(alg);

            let key_id = jwt::decode_header(&token)
                .map_err(Error::InvalidTokenHeader)?
                .kid.ok_or(Error::MissingKeyID)?
                ;

            let signing_key = self.keys.get(&key_id).ok_or(KeyNotInJWKS)?;

            Ok(jwt::decode::<HashMap<String, Value>>(&token, &signing_key.key.to_decoding_key(), &validation)
                .map_err(InvalidToken)?
                .claims
            )
        }
    }
}

pub mod identity_provider {
    use crate::config::Config;
    use crate::types::ClientTokenRequest;
    use jsonwebkey as jwk;
    use jsonwebtoken as jwt;
    use serde_json::Value;
    use std::collections::HashMap;

    pub trait Provider {
        fn token_request(&self, target: String) -> ClientTokenRequest;
        fn token_endpoint(&self) -> String;
        fn introspect(&self, token: String) -> HashMap<String, Value>;
    }

    #[derive(Clone, Debug)]
    pub struct Maskinporten {
        pub cfg: Config,
        private_jwk: jwk::JsonWebKey,
        upstream_jwks: crate::jwks::Jwks,
    }


    #[derive(Clone, Debug)]
    pub struct EntraID(pub Config);

    #[derive(Clone, Debug)]
    pub struct TokenX(pub Config);

    impl Provider for EntraID {
        fn token_request(&self, _target: String) -> ClientTokenRequest {
            ClientTokenRequest {
                grant_type: "client_credentials".to_string(), // FIXME: urn:ietf:params:oauth:grant-type:jwt-bearer for OBO
                client_id: todo!(),
                assertion: todo!(),
            }
        }

        fn token_endpoint(&self) -> String {
            todo!()
        }

        fn introspect(&self, _token: String) -> HashMap<String, Value> {
            todo!()
        }
    }

    impl Provider for TokenX {
        fn token_request(&self, _target: String) -> ClientTokenRequest {
            ClientTokenRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
                client_id: todo!(),
                assertion: todo!(),
            }
        }

        fn token_endpoint(&self) -> String {
            todo!()
        }

        fn introspect(&self, _token: String) -> HashMap<String, Value> {
            todo!()
        }
    }

    impl Provider for Maskinporten {
        fn token_request(&self, target: String) -> ClientTokenRequest {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let jti = uuid::Uuid::new_v4();

            let claims = AssertionClaims {
                exp: (now + 30) as usize,
                iat: now as usize,
                jti: jti.to_string(),
                scope: target.to_string(),
                iss: self.cfg.maskinporten_client_id.to_string(),
                aud: self.cfg.maskinporten_issuer.to_string(),
            };

            let encoding_key: jwt::EncodingKey = self.private_jwk.key.to_encoding_key();
            let alg: jwt::Algorithm = self.private_jwk.algorithm.unwrap().into();
            let kid: String = self.private_jwk.key_id.clone().unwrap();
            let mut header = jwt::Header::new(alg);
            header.kid = Some(kid);

            let token = jwt::encode(
                &header,
                &claims,
                &encoding_key,
            ).unwrap();

            ClientTokenRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
                client_id: self.cfg.maskinporten_client_id.clone(),
                assertion: token, // Use JWK to create an assertion
            }
        }

        fn token_endpoint(&self) -> String {
            self.cfg.maskinporten_token_endpoint.to_string()
        }

        fn introspect(&self, token: String) -> HashMap<String, Value> {
            self.upstream_jwks.validate(&token)
                .map(|mut hashmap| {
                    hashmap.insert("active".to_string(), Value::Bool(true));
                    hashmap
                })
                .unwrap_or_else(|err| {
                    HashMap::from([
                        ("active".to_string(), Value::Bool(false)),
                        ("error".to_string(), Value::String(format!("{:?}", err)))
                    ])
                })
        }
    }

    impl Maskinporten {
        pub(crate) fn new(cfg: Config, upstream_jwks: crate::jwks::Jwks) -> Self {
            let the_jwk: jwk::JsonWebKey = cfg.maskinporten_client_jwk.parse().unwrap();
            Self {
                cfg,
                upstream_jwks,
                private_jwk: the_jwk,
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct AssertionClaims {
        exp: usize,
        iat: usize,
        jti: String,
        scope: String,
        iss: String,
        aud: String,
    }
}
