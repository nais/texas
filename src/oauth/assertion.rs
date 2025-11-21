use crate::oauth::identity_provider::AuthorizationDetails;
use jsonwebtoken as jwt;
use serde::Serialize;

const EXPIRY_LEEWAY_SECONDS: u64 = 30;

pub trait Assertion: Send + Sync + Serialize {
    fn new(
        issuer: String,
        client_id: String,
        target: String,
        resource: Option<String>,
        authorization_details: Option<AuthorizationDetails>,
    ) -> Self;
}

#[derive(Serialize)]
pub struct ClientAssertion {
    exp: u64,
    iat: u64,
    nbf: u64,
    jti: String,
    sub: String,
    iss: String,
    aud: String,
}

#[derive(Serialize)]
pub struct JWTBearerAssertion {
    exp: u64,
    iat: u64,
    nbf: u64,
    jti: String,
    scope: String,
    iss: String,
    aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_details: Option<AuthorizationDetails>,
}

impl Assertion for JWTBearerAssertion {
    fn new(
        issuer: String,
        client_id: String,
        target: String,
        resource: Option<String>,
        authorization_details: Option<AuthorizationDetails>,
    ) -> Self {
        let now = epoch_now_secs();
        let jti = uuid::Uuid::new_v4();

        Self {
            exp: now + EXPIRY_LEEWAY_SECONDS,
            iat: now,
            nbf: now,
            jti: jti.to_string(),
            iss: client_id, // issuer of the token is the client itself
            aud: issuer,    // audience of the token is the issuer
            scope: target,
            resource,              // resource indicator for audience-restricted tokens
            authorization_details, // authorization_details for rich authorization requests
        }
    }
}

impl Assertion for ClientAssertion {
    fn new(
        issuer: String,
        client_id: String,
        _target: String,
        _resource: Option<String>,
        _authorization_details: Option<AuthorizationDetails>,
    ) -> Self {
        let now = epoch_now_secs();
        let jti = uuid::Uuid::new_v4();

        Self {
            exp: now + EXPIRY_LEEWAY_SECONDS,
            iat: now,
            nbf: now,
            jti: jti.to_string(),
            iss: client_id.clone(), // issuer of the token is the client itself
            aud: issuer,            // audience of the token is the issuer
            sub: client_id,
        }
    }
}

impl Assertion for () {
    fn new(
        _token_endpoint: String,
        _client_id: String,
        _target: String,
        _resource: Option<String>,
        _authorization_details: Option<AuthorizationDetails>,
    ) -> Self {
    }
}

pub fn epoch_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("SystemTime::now() should be after UNIX_EPOCH")
        .as_secs()
}

pub fn serialize<T: Serialize>(
    claims: T,
    client_assertion_header: &jwt::Header,
    key: &jwt::EncodingKey,
) -> Result<String, jsonwebtoken::errors::Error> {
    jwt::encode(client_assertion_header, &claims, key)
}
