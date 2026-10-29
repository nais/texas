use super::Error;
use super::key_set::VerifyingKey;
use crate::oauth::assertion::epoch_now_secs;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, Validation};
use serde_json::Value;
use std::collections::HashMap;

const SUPPORTED_ALGORITHMS: [Algorithm; 8] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
];

#[derive(Debug)]
pub(super) struct TokenVerifier {
    /// One per algorithm, because jsonwebtoken cannot mix algorithm families in one validation.
    validations: HashMap<Algorithm, Validation>,
}

impl TokenVerifier {
    pub(super) fn new(issuer: &str, audience: Option<String>) -> Self {
        let mut validation = Validation::default();
        validation.validate_aud = true;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["iss", "exp", "iat"]);
        validation.set_issuer(&[issuer]);
        validation.leeway = 60; // 1 minute

        if let Some(audience) = audience {
            validation.set_required_spec_claims(&["iss", "exp", "iat", "aud"]);
            validation.set_audience(&[audience]);
        } else {
            validation.validate_aud = false;
        }

        let validations = SUPPORTED_ALGORITHMS
            .into_iter()
            .map(|algorithm| {
                let mut validation = validation.clone();
                validation.algorithms = vec![algorithm];
                (algorithm, validation)
            })
            .collect();

        Self { validations }
    }

    pub(super) fn check_algorithm(&self, algorithm: Algorithm) -> Result<(), Error> {
        self.validation_for(algorithm).map(|_| ())
    }

    pub(super) fn verify(
        &self,
        token: &str,
        algorithm: Algorithm,
        key: &VerifyingKey,
    ) -> Result<HashMap<String, Value>, Error> {
        let validation = self.validation_for(algorithm)?;
        if !key.allows(algorithm) {
            return Err(invalid_token(ErrorKind::InvalidAlgorithm));
        }

        let claims = jsonwebtoken::decode::<HashMap<String, Value>>(token, &key.key, validation)
            .map_err(Error::InvalidToken)?
            .claims;

        // jsonwebtoken does not check `iat`.
        let iat = claims
            .get("iat")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_token(ErrorKind::MissingRequiredClaim("iat".to_string())))?;
        if iat > epoch_now_secs() + validation.leeway {
            return Err(invalid_token(ErrorKind::ImmatureSignature));
        }

        Ok(claims)
    }

    fn validation_for(&self, algorithm: Algorithm) -> Result<&Validation, Error> {
        self.validations.get(&algorithm).ok_or_else(|| invalid_token(ErrorKind::InvalidAlgorithm))
    }
}

fn invalid_token(kind: ErrorKind) -> Error {
    Error::InvalidToken(kind.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::jwt::test_helpers::*;
    use pretty_assertions::assert_eq;

    fn verify(token: &str, key: &VerifyingKey) -> Result<HashMap<String, Value>, Error> {
        let algorithm = jsonwebtoken::decode_header(token).unwrap().alg;

        TokenVerifier::new(ISSUER, None).verify(token, algorithm, key)
    }

    /// Swaps the first signature character for another base64url character.
    fn corrupt_signature(token: &str) -> String {
        let signature_start = token.rfind('.').unwrap() + 1;
        let mut bytes = token.as_bytes().to_vec();
        bytes[signature_start] = if bytes[signature_start] == b'A' {
            b'B'
        } else {
            b'A'
        };

        String::from_utf8(bytes).unwrap()
    }

    #[rstest::rstest]
    #[case(Algorithm::ES256)]
    #[case(Algorithm::ES384)]
    fn verifies_ec_token(#[case] algorithm: Algorithm) {
        let (jwk, token) = signed_ec_token(algorithm, &valid_claims());

        let claims = verify(&token, &verifying_key(jwk).unwrap()).unwrap();

        assert_eq!(claims["iss"], ISSUER);
        assert_eq!(claims["sub"], "subject");
    }

    #[rstest::rstest]
    #[case(Algorithm::ES256)]
    #[case(Algorithm::ES384)]
    fn rejects_ec_token_with_corrupted_signature(#[case] algorithm: Algorithm) {
        let (jwk, token) = signed_ec_token(algorithm, &valid_claims());

        let result = verify(&corrupt_signature(&token), &verifying_key(jwk).unwrap());

        assert_rejected(result, &ErrorKind::InvalidSignature);
    }

    #[rstest::rstest]
    #[case(Algorithm::ES256, Algorithm::ES384)]
    #[case(Algorithm::ES384, Algorithm::ES256)]
    fn rejects_ec_token_with_key_of_another_curve(
        #[case] algorithm: Algorithm,
        #[case] key_algorithm: Algorithm,
    ) {
        let (_, token) = signed_ec_token(algorithm, &valid_claims());
        let (mut other_jwk, _) = signed_ec_token(key_algorithm, &valid_claims());
        // Otherwise the alg check rejects the token first.
        other_jwk.common.key_algorithm = None;

        let result = verify(&token, &verifying_key(other_jwk).unwrap());

        assert_rejected(result, &ErrorKind::InvalidSignature);
    }

    #[rstest::rstest]
    #[case(Algorithm::ES256)]
    #[case(Algorithm::ES384)]
    fn rejects_ec_token_with_rsa_key(#[case] algorithm: Algorithm) {
        let (_, token) = signed_ec_token(algorithm, &valid_claims());

        let result = verify(&token, &verifying_key(rsa_public_jwk(None)).unwrap());

        assert_rejected(result, &ErrorKind::InvalidKeyFormat);
    }

    #[rstest::rstest]
    #[case(None, "RS256", true)]
    #[case(None, "PS512", true)]
    #[case(Some("PS256"), "PS256", true)]
    #[case(Some("RS256"), "PS256", false)]
    #[case(Some("PS256"), "RS512", false)]
    fn key_with_alg_verifies_only_that_algorithm(
        #[case] jwk_alg: Option<&str>,
        #[case] token_alg: &str,
        #[case] accepted: bool,
    ) {
        let key = verifying_key(rsa_public_jwk(jwk_alg)).unwrap();

        let result = verify(&signed_rsa_token(token_alg), &key);

        if accepted {
            assert_eq!(result.unwrap()["sub"], "subject");
        } else {
            assert_rejected(result, &ErrorKind::InvalidAlgorithm);
        }
    }

    #[test]
    fn rejects_token_without_iat() {
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("iat");
        let (jwk, token) = signed_ec_token(Algorithm::ES256, &claims);

        let result = verify(&token, &verifying_key(jwk).unwrap());

        assert_rejected(result, &ErrorKind::MissingRequiredClaim("iat".to_string()));
    }

    #[test]
    fn rejects_token_issued_beyond_the_leeway() {
        let mut claims = valid_claims();
        claims["iat"] = (epoch_now_secs() + 120).into();
        let (jwk, token) = signed_ec_token(Algorithm::ES256, &claims);

        let result = verify(&token, &verifying_key(jwk).unwrap());

        assert_rejected(result, &ErrorKind::ImmatureSignature);
    }
}
