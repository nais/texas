use crate::config::Config;
use crate::jwks;
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;

pub trait Provider<T: Serialize> {
    fn token_request(&self, target: String) -> T;
    fn token_endpoint(&self) -> String;
    fn introspect(&mut self, token: String) -> impl std::future::Future<Output=HashMap<String, Value>> + Send;
}

#[derive(Clone)]
pub struct Maskinporten {
    pub cfg: Config,
    private_jwk: jwt::EncodingKey,
    client_assertion_header: jwt::Header,
    upstream_jwks: jwks::Jwks,
}

#[derive(Clone, Debug)]
pub struct EntraID(pub Config);

#[derive(Clone, Debug)]
pub struct TokenX(pub Config);

#[derive(Serialize)]
pub struct EntraIDTokenRequest {}

impl Provider<EntraIDTokenRequest> for EntraID {
    fn token_request(&self, _target: String) -> EntraIDTokenRequest {
        EntraIDTokenRequest {}
    }

    fn token_endpoint(&self) -> String {
        todo!()
    }

    async fn introspect(&mut self, _token: String) -> HashMap<String, Value> {
        todo!()
    }
}

#[derive(Serialize)]
pub struct TokenXTokenRequest {}

impl Provider<TokenXTokenRequest> for TokenX {
    fn token_request(&self, _target: String) -> TokenXTokenRequest {
        TokenXTokenRequest {}
    }

    fn token_endpoint(&self) -> String {
        todo!()
    }

    async fn introspect(&mut self, _token: String) -> HashMap<String, Value> {
        todo!()
    }
}

#[derive(Serialize)]
pub struct MaskinportenTokenRequest {
    grant_type: String,
    assertion: String,
}

impl Provider<MaskinportenTokenRequest> for Maskinporten {
    fn token_request(&self, target: String) -> MaskinportenTokenRequest {
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

        let token = jwt::encode(
            &self.client_assertion_header,
            &claims,
            &self.private_jwk,
        ).unwrap();

        MaskinportenTokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            assertion: token,
        }
    }

    fn token_endpoint(&self) -> String {
        self.cfg.maskinporten_token_endpoint.to_string()
    }

    async fn introspect(&mut self, token: String) -> HashMap<String, Value> {
        self.upstream_jwks.validate(&token).await
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
    pub fn new(cfg: Config, upstream_jwks: jwks::Jwks) -> Self {
        let client_private_jwk: jwk::JsonWebKey = cfg.maskinporten_client_jwk.parse().unwrap();
        let alg: jwt::Algorithm = client_private_jwk.algorithm.unwrap().into();
        let kid: String = client_private_jwk.key_id.clone().unwrap();

        let mut header = jwt::Header::new(alg);
        header.kid = Some(kid);

        Self {
            cfg,
            upstream_jwks,
            private_jwk: client_private_jwk.key.to_encoding_key(),
            client_assertion_header: header,
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
