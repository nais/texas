use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde_json::Value;
use std::collections::HashMap;
use texas::oauth::request::AuthorizationDetails;
use texas::oauth::response::IntrospectResponse;

/// Matches signing key used in mock-oauth2-server
const SIGNING_KEY: &str = include_str!("../../fixtures/rsa-private.jwk");

pub type TokenClaims = HashMap<String, Value>;

pub struct Token {
    header: jwt::Header,
    claims: TokenClaims,
    signing_key: jwt::EncodingKey,
}

impl Token {
    fn new(claims: TokenClaims) -> Self {
        Self {
            header: jwt::Header::new(jwt::Algorithm::RS256),
            claims,
            signing_key: jwt::EncodingKey::from_rsa_pem(
                SIGNING_KEY.parse::<jwk::JsonWebKey>().unwrap().key.to_pem().as_bytes(),
            )
            .unwrap(),
        }
    }

    pub fn sign(claims: TokenClaims) -> String {
        Self::new(claims).encode()
    }

    pub fn sign_with_kid(claims: TokenClaims, kid: &str) -> String {
        let mut token = Self::new(claims);
        token.header.kid = Some(kid.to_string());
        token.encode()
    }

    fn encode(&self) -> String {
        jwt::encode(&self.header, &self.claims, &self.signing_key).unwrap()
    }
}

pub trait IntrospectClaims {
    fn has_claims(&self) -> bool;
    fn get_claim(&self, claim: &str) -> Option<&Value>;

    fn get_string_claim(&self, claim: &str) -> String {
        self.get_claim(claim)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or("".to_string())
    }
    fn get_authorization_details(&self) -> AuthorizationDetails {
        self.get_claim("authorization_details")
            .and_then(|v| {
                serde_json::from_value(v.clone())
                    .inspect_err(|e| {
                        tracing::error!("Failed to parse authorization_details: {}", e)
                    })
                    .ok()
            })
            .unwrap_or(AuthorizationDetails::from(vec![]))
    }
    fn subject(&self) -> String {
        self.get_string_claim("sub")
    }
    fn issuer(&self) -> String {
        self.get_string_claim("iss")
    }
    fn jwt_id(&self) -> String {
        self.get_string_claim("jti")
    }
}

impl IntrospectClaims for IntrospectResponse {
    fn has_claims(&self) -> bool {
        !self.extra.is_empty()
    }
    fn get_claim(&self, claim: &str) -> Option<&Value> {
        self.extra.get(claim)
    }
}
