use jsonwebtoken as jwt;
use serde::Serialize;

pub trait Assertion {
    fn new(token_endpoint: String, client_id: String, target: String) -> Self;
}

#[derive(Serialize)]
pub struct ClientAssertion {
    exp: usize,
    iat: usize,
    nbf: usize,
    jti: String,
    sub: String,
    iss: String,
    aud: String,
}

#[derive(Serialize)]
pub struct JWTBearerAssertion {
    exp: usize,
    iat: usize,
    nbf: usize,
    jti: String,
    scope: String,
    iss: String,
    aud: String,
}

impl Assertion for JWTBearerAssertion {
    fn new(token_endpoint: String, client_id: String, target: String) -> Self {
        let now = epoch_now_secs();
        let jti = uuid::Uuid::new_v4();

        Self {
            exp: (now + 30) as usize,
            iat: now as usize,
            nbf: now as usize,
            jti: jti.to_string(),
            iss: client_id,      // issuer of the token is the client itself
            aud: token_endpoint, // audience of the token is the issuer
            scope: target,
        }
    }
}

impl Assertion for ClientAssertion {
    fn new(token_endpoint: String, client_id: String, _target: String) -> Self {
        let now = epoch_now_secs();
        let jti = uuid::Uuid::new_v4();

        Self {
            exp: (now + 30) as usize,
            iat: now as usize,
            nbf: now as usize,
            jti: jti.to_string(),
            iss: client_id.clone(), // issuer of the token is the client itself
            aud: token_endpoint,    // audience of the token is the issuer
            sub: client_id,
        }
    }
}

fn epoch_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn serialize<T: Serialize>(
    claims: T,
    client_assertion_header: &jwt::Header,
    key: &jwt::EncodingKey,
) -> Result<String, jsonwebtoken::errors::Error> {
    jwt::encode(client_assertion_header, &claims, key)
}
