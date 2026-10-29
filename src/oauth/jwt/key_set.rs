use crate::http::client::{self, FetchError};
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;

/// How long a key set is reused before it is fetched again.
/// Unknown key IDs trigger an earlier refresh to support key rotation.
pub(super) const KEY_SET_TTL: Duration = Duration::from_hours(1);

/// The identity provider's public keys, by key ID.
#[derive(Clone, Debug)]
pub(super) struct KeySet {
    pub(super) by_kid: Arc<HashMap<String, VerifyingKey>>,
    pub(super) fetched_at: Instant,
}

#[derive(Debug)]
pub(super) struct VerifyingKey {
    pub(super) key: DecodingKey,
    /// The JWK's `alg`, if set.
    algorithm: Option<Algorithm>,
}

/// Failure to obtain the identity provider's public keys.
#[derive(Error, Debug)]
pub enum KeySetError {
    #[error("init client: {0}")]
    Init(reqwest::Error),
    #[error("fetch: {0}")]
    Fetch(#[from] FetchError),
    #[error("jwks has a signature key without key id")]
    MissingKeyId,
    #[error("invalid public jwk: {0}")]
    InvalidJwk(jsonwebtoken::errors::Error),
}

impl KeySet {
    pub(super) async fn fetch(
        client: &client::Client,
        jwks_uri: &str,
    ) -> Result<Self, KeySetError> {
        let response: JwkSet = client.get(jwks_uri).await?;

        Self::from_jwks(&response)
    }

    pub(super) fn from_jwks(jwks: &JwkSet) -> Result<Self, KeySetError> {
        let mut by_kid = HashMap::new();
        for jwk in &jwks.keys {
            let Some(key) = VerifyingKey::from_jwk(jwk).map_err(KeySetError::InvalidJwk)? else {
                continue;
            };

            let key_id = jwk.common.key_id.clone().ok_or(KeySetError::MissingKeyId)?;
            by_kid.insert(key_id, key);
        }

        Ok(Self {
            by_kid: Arc::new(by_kid),
            fetched_at: Instant::now(),
        })
    }

    pub(super) fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() >= KEY_SET_TTL
    }
}

impl VerifyingKey {
    pub(super) fn allows(&self, algorithm: Algorithm) -> bool {
        self.algorithm.is_none_or(|key_algorithm| key_algorithm == algorithm)
    }

    /// Returns `None` for keys that are not for verifying signatures.
    pub(super) fn from_jwk(jwk: &Jwk) -> Result<Option<Self>, jsonwebtoken::errors::Error> {
        let common = &jwk.common;
        let use_allows = common
            .public_key_use
            .as_ref()
            .is_none_or(|key_use| *key_use == PublicKeyUse::Signature);
        let operations_allow = common
            .key_operations
            .as_ref()
            .is_none_or(|operations| operations.contains(&KeyOperations::Verify));
        if !use_allows || !operations_allow {
            return Ok(None);
        }

        let algorithm = match common.key_algorithm {
            None => None,
            Some(algorithm) => match algorithm.to_string().parse() {
                Ok(algorithm) => Some(algorithm),
                // An encryption algorithm, e.g. RSA-OAEP.
                Err(_) => return Ok(None),
            },
        };

        Ok(Some(Self {
            key: DecodingKey::from_jwk(jwk)?,
            algorithm,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::jwt::test_helpers::*;
    use serde_json::Value;

    fn key_set(keys: Vec<Value>) -> Result<KeySet, KeySetError> {
        KeySet::from_jwks(&serde_json::from_value(serde_json::json!({ "keys": keys })).unwrap())
    }

    #[test]
    fn key_set_requires_key_id() {
        let mut jwk = rsa_public_jwk(None);
        jwk.as_object_mut().unwrap().remove("kid");

        assert!(matches!(key_set(vec![jwk]), Err(KeySetError::MissingKeyId)));
    }

    #[test]
    fn key_set_rejects_malformed_key() {
        let mut jwk = rsa_public_jwk(None);
        jwk["n"] = "!".into();

        assert!(matches!(
            key_set(vec![jwk]),
            Err(KeySetError::InvalidJwk(_))
        ));
    }

    #[test]
    fn key_set_skips_encryption_key_without_key_id() {
        let mut encryption_jwk = rsa_public_jwk(None);
        encryption_jwk.as_object_mut().unwrap().remove("kid");
        encryption_jwk["use"] = "enc".into();

        let keys = key_set(vec![encryption_jwk, rsa_public_jwk(None)]).unwrap();

        assert_eq!(keys.by_kid.len(), 1);
    }

    #[rstest::rstest]
    #[case(serde_json::json!({ "use": "sig", "key_ops": ["verify"] }), true)]
    #[case(serde_json::json!({}), true)]
    #[case(serde_json::json!({ "use": "enc" }), false)]
    #[case(serde_json::json!({ "key_ops": ["encrypt"] }), false)]
    #[case(serde_json::json!({ "key_ops": [] }), false)]
    #[case(serde_json::json!({ "alg": "RSA-OAEP" }), false)]
    fn uses_only_keys_for_signature_verification(#[case] metadata: Value, #[case] used: bool) {
        let mut jwk = rsa_public_jwk(None);
        jwk.as_object_mut().unwrap().extend(metadata.as_object().unwrap().clone());

        assert_eq!(verifying_key(jwk).is_some(), used);
    }
}
