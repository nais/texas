use super::Error;
use super::key_set::VerifyingKey;
use crate::oauth::assertion::epoch_now_secs;
use crate::oauth::signing_key::SigningKey;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::Value;
use std::collections::HashMap;

pub(super) const ISSUER: &str = "https://issuer.example";

pub(super) const EC_P256_PRIVATE_PEM: &str =
    include_str!("../../../tests/fixtures/ec-p256-private.pem");

pub(super) const EC_P384_PRIVATE_PEM: &str =
    include_str!("../../../tests/fixtures/ec-p384-private.pem");

pub(super) const RSA_PRIVATE_JWK: &str = include_str!("../../../tests/fixtures/rsa-private.jwk");

pub(super) fn valid_claims() -> Value {
    let now = epoch_now_secs();

    serde_json::json!({
        "iss": ISSUER,
        "sub": "subject",
        "iat": now,
        "exp": now + 300,
    })
}

pub(super) fn signed_ec_token(algorithm: Algorithm, claims: &Value) -> (Jwk, String) {
    let pem = match algorithm {
        Algorithm::ES256 => EC_P256_PRIVATE_PEM,
        Algorithm::ES384 => EC_P384_PRIVATE_PEM,
        _ => panic!("expected an EC algorithm"),
    };

    let key = EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
    let mut jwk = Jwk::from_encoding_key(&key, algorithm).unwrap();
    jwk.common.key_id = Some("ec-key".to_string());

    let mut header = Header::new(algorithm);
    header.kid = jwk.common.key_id.clone();
    let token = jsonwebtoken::encode(&header, claims, &key).unwrap();

    (jwk, token)
}

pub(super) fn rsa_public_jwk(alg: Option<&str>) -> Value {
    let private: Value = serde_json::from_str(RSA_PRIVATE_JWK).unwrap();
    let mut jwk = serde_json::json!({
        "kty": "RSA",
        "kid": private["kid"],
        "n": private["n"],
        "e": private["e"],
    });
    if let Some(alg) = alg {
        jwk["alg"] = alg.into();
    }

    jwk
}

pub(super) fn signed_rsa_token(alg: &str) -> String {
    let mut jwk: Value = serde_json::from_str(RSA_PRIVATE_JWK).unwrap();
    jwk["alg"] = alg.into();
    let key: SigningKey = jwk.to_string().parse().unwrap();

    key.sign(&valid_claims()).unwrap()
}

pub(super) fn verifying_key(jwk: impl serde::Serialize) -> Option<VerifyingKey> {
    let jwk: Jwk = serde_json::from_value(serde_json::to_value(jwk).unwrap()).unwrap();

    VerifyingKey::from_jwk(&jwk).unwrap()
}

pub(super) fn assert_rejected(result: Result<HashMap<String, Value>, Error>, expected: &ErrorKind) {
    assert!(
        matches!(&result, Err(Error::InvalidToken(error)) if error.kind() == expected),
        "expected {expected:?}, got {result:?}"
    );
}
