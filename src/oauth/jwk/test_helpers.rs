use super::verification::VerificationKey;
use jsonwebtoken::jwk::Jwk;
use serde_json::Value;

/// Texas's client authentication keys.
// Private scalar 1. Not a real key.
pub(crate) const CLIENT_EC_PRIVATE_JWK: &str =
    include_str!("../../../tests/fixtures/client-auth-ec-p256-private.jwk");
pub(crate) const CLIENT_RSA_PRIVATE_JWK: &str =
    include_str!("../../../tests/fixtures/client-auth-rsa-private.jwk");

/// The identity provider's token signing key.
pub(crate) const IDP_RSA_PRIVATE_JWK: &str =
    include_str!("../../../tests/fixtures/rsa-private.jwk");

pub(crate) fn with_alg(jwk: &str, alg: &str) -> Value {
    let mut jwk: Value = serde_json::from_str(jwk).unwrap();
    jwk["alg"] = alg.into();

    jwk
}

pub(crate) fn rsa_public_jwk(alg: Option<&str>) -> Value {
    let private: Value = serde_json::from_str(IDP_RSA_PRIVATE_JWK).unwrap();
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

pub(crate) fn verification_key(jwk: impl serde::Serialize) -> Option<VerificationKey> {
    let jwk: Jwk = serde_json::from_value(serde_json::to_value(jwk).unwrap()).unwrap();

    VerificationKey::from_jwk(&jwk).unwrap()
}
