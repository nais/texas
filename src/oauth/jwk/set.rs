use super::verification::VerificationKey;
use crate::http::client::{self, FetchError};
use jsonwebtoken::jwk::JwkSet;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;

/// How long a key set is reused before it is fetched again.
/// Unknown key IDs trigger an earlier refresh to support key rotation.
pub(crate) const KEY_SET_TTL: Duration = Duration::from_hours(1);

/// The identity provider's JWKS, cached by key ID.
#[derive(Clone, Debug)]
pub(crate) struct KeySet {
    by_kid: Arc<HashMap<String, VerificationKey>>,
    fetched_at: Instant,
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
    pub(crate) async fn fetch(
        client: &client::Client,
        jwks_uri: &str,
    ) -> Result<Self, KeySetError> {
        let response: JwkSet = client.get(jwks_uri).await?;

        Self::from_jwks(&response)
    }

    pub(crate) fn from_jwks(jwks: &JwkSet) -> Result<Self, KeySetError> {
        let mut by_kid = HashMap::new();
        for jwk in &jwks.keys {
            let Some(key) = VerificationKey::from_jwk(jwk).map_err(KeySetError::InvalidJwk)? else {
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

    pub(crate) fn get(&self, key_id: &str) -> Option<&VerificationKey> {
        self.by_kid.get(key_id)
    }

    pub(crate) fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() >= KEY_SET_TTL
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_kid.len()
    }

    /// Makes the key set look like it was fetched `age` ago.
    #[cfg(test)]
    pub(crate) fn backdate(&mut self, age: Duration) {
        self.fetched_at -= age;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::jwk::test_helpers::*;
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

        assert_eq!(keys.len(), 1);
    }
}
