use crate::config::Config;
use crate::jwks;
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use jsonwebtoken::{EncodingKey, Header};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;

pub trait Provider<T: Serialize> {
    fn token_request(&self, target: String) -> T;
    fn token_endpoint(&self) -> String;
    fn introspect(
        &mut self,
        token: String,
    ) -> impl std::future::Future<Output = HashMap<String, Value>> + Send;
}

#[derive(Clone)]
pub struct Maskinporten {
    pub cfg: Config,
    private_jwk: jwt::EncodingKey,
    client_assertion_header: jwt::Header,
    upstream_jwks: jwks::Jwks,
}

#[derive(Clone)]
pub struct AzureAD {
    pub cfg: Config,
    private_jwk: jwt::EncodingKey,
    client_assertion_header: jwt::Header,
    upstream_jwks: jwks::Jwks,
}

#[derive(Clone, Debug)]
pub struct TokenX(pub Config);

#[derive(Serialize)]
pub struct AzureADClientCredentialsTokenRequest {
    grant_type: String, // client_credentials
    client_id: String,
    client_assertion: String,
    client_assertion_type: String, // urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    scope: String,
}

#[derive(Serialize)]
pub struct AzureADOnBehalfOfTokenRequest {
    grant_type: String, // urn:ietf:params:oauth:grant-type:jwt-bearer
    client_id: String,
    client_assertion: String,
    client_assertion_type: String, // urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    scope: String,
    requested_token_use: String, // on_behalf_of
    assertion: String,
}

impl AzureAD {
    pub fn on_behalf_of_request(
        &self,
        target: String,
        user_token: String,
    ) -> AzureADOnBehalfOfTokenRequest {
        let client_assertion = AssertionClaims::new(
            self.cfg.azure_ad_issuer.clone(),
            self.cfg.azure_ad_client_id.clone(),
            None,
            Some(self.cfg.azure_ad_client_id.clone()),
        )
        .serialize(&self.client_assertion_header, &self.private_jwk)
        .unwrap();

        AzureADOnBehalfOfTokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            client_id: self.cfg.azure_ad_client_id.clone(),
            client_assertion,
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                .to_string(),
            scope: target,
            requested_token_use: "on_behalf_of".to_string(),
            assertion: user_token,
        }
    }

    pub fn new(cfg: Config, upstream_jwks: jwks::Jwks) -> Self {
        let client_private_jwk: jwk::JsonWebKey = cfg.azure_ad_client_jwk.parse().unwrap();
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

impl Provider<AzureADClientCredentialsTokenRequest> for AzureAD {
    fn token_request(&self, _target: String) -> AzureADClientCredentialsTokenRequest {
        AzureADClientCredentialsTokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: self.cfg.maskinporten_client_id.clone(),
            client_assertion: "".to_string(),
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                .to_string(),
            scope: "".to_string(),
        }
    }

    fn token_endpoint(&self) -> String {
        self.cfg.azure_ad_token_endpoint.to_string()
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
        let token = AssertionClaims::new(
            self.cfg.maskinporten_issuer.clone(),
            self.cfg.maskinporten_client_id.clone(),
            Some(target),
            None,
        )
        .serialize(&self.client_assertion_header, &self.private_jwk)
        .unwrap();

        MaskinportenTokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            assertion: token,
        }
    }

    fn token_endpoint(&self) -> String {
        self.cfg.maskinporten_token_endpoint.to_string()
    }

    async fn introspect(&mut self, token: String) -> HashMap<String, Value> {
        self.upstream_jwks
            .validate(&token)
            .await
            .map(|mut hashmap| {
                hashmap.insert("active".to_string(), Value::Bool(true));
                hashmap
            })
            .unwrap_or_else(|err| {
                HashMap::from([
                    ("active".to_string(), Value::Bool(false)),
                    ("error".to_string(), Value::String(format!("{:?}", err))),
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
    nbf: usize,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    iss: String,
    aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
}

impl AssertionClaims {
    fn new(issuer: String, client_id: String, scope: Option<String>, sub: Option<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jti = uuid::Uuid::new_v4();

        AssertionClaims {
            exp: (now + 30) as usize,
            iat: now as usize,
            nbf: now as usize,
            jti: jti.to_string(),
            scope,
            sub,
            iss: client_id, // issuer of the token is the client itself
            aud: issuer,    // audience of the token is the issuer
        }
    }

    fn serialize(
        &self,
        client_assertion_header: &Header,
        key: &EncodingKey,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        jwt::encode(client_assertion_header, &self, key)
    }
}
