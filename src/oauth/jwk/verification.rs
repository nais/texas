use jsonwebtoken::jwk::{Jwk, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey};

#[derive(Debug)]
pub(crate) struct VerificationKey {
    key: DecodingKey,
    /// The JWK's `alg`, if set.
    algorithm: Option<Algorithm>,
}

impl VerificationKey {
    /// Returns `None` for keys that are not for verifying signatures.
    pub(crate) fn from_jwk(jwk: &Jwk) -> Result<Option<Self>, jsonwebtoken::errors::Error> {
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

    pub(crate) fn decoding_key(&self) -> &DecodingKey {
        &self.key
    }

    pub(crate) fn allows(&self, algorithm: Algorithm) -> bool {
        self.algorithm.is_none_or(|key_algorithm| key_algorithm == algorithm)
    }
}

#[cfg(test)]
mod tests {
    use crate::oauth::jwk::test_helpers::*;
    use serde_json::Value;

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

        assert_eq!(verification_key(jwk).is_some(), used);
    }
}
