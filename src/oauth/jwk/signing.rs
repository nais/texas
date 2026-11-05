use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde::Deserialize;
use std::str::FromStr;
use thiserror::Error;

pub struct SigningKey {
    key_id: String,
    algorithm: jwt::Algorithm,
    key: jwt::EncodingKey,
}

#[derive(Debug, Error)]
pub enum SigningKeyError {
    #[error("parse private JWK: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("private JWK is missing key id")]
    MissingKeyId,

    #[error("private JWK is missing algorithm")]
    MissingAlgorithm,

    #[error("symmetric client assertion signing is not supported; use an RSA algorithm or ES256")]
    Symmetric,

    #[error("algorithm {0:?} is not supported for this private JWK")]
    UnsupportedAlgorithm(jwt::Algorithm),

    #[error("private JWK contains only a public key")]
    NotPrivate,

    #[error("convert private JWK: {0}")]
    Conversion(#[from] jwk::ConversionError),

    #[error("decode private JWK: {0}")]
    Decode(#[from] jwt::errors::Error),
}

/// jsonwebkey rejects algorithms other than RS256, ES256 and HS256.
#[derive(Deserialize)]
struct PrivateJwk {
    alg: Option<jwt::Algorithm>,
    #[serde(flatten)]
    jwk: jwk::JsonWebKey,
}

impl FromStr for SigningKey {
    type Err = SigningKeyError;

    fn from_str(private_jwk: &str) -> Result<Self, Self::Err> {
        use jwt::Algorithm::*;

        let PrivateJwk { alg, jwk } = serde_json::from_str(private_jwk)?;

        let alg = alg.ok_or(SigningKeyError::MissingAlgorithm)?;
        let kid = jwk.key_id.ok_or(SigningKeyError::MissingKeyId)?;

        if !jwk.key.is_private() {
            return Err(SigningKeyError::NotPrivate);
        }

        let key = match (alg, jwk.key.as_ref()) {
            (_, jwk::Key::Symmetric { .. }) | (HS256 | HS384 | HS512, _) => {
                return Err(SigningKeyError::Symmetric);
            }
            (RS256 | RS384 | RS512 | PS256 | PS384 | PS512, key @ jwk::Key::RSA { .. }) => {
                jwt::EncodingKey::from_rsa_pem(key.try_to_pem()?.as_bytes())?
            }
            // ES384 needs P-384 keys, which jsonwebkey cannot parse.
            (ES256, key @ jwk::Key::EC { .. }) => {
                jwt::EncodingKey::from_ec_pem(key.try_to_pem()?.as_bytes())?
            }
            _ => return Err(SigningKeyError::UnsupportedAlgorithm(alg)),
        };

        Ok(Self {
            key_id: kid,
            algorithm: alg,
            key,
        })
    }
}

impl SigningKey {
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn algorithm(&self) -> jwt::Algorithm {
        self.algorithm
    }

    pub(crate) fn encoding_key(&self) -> &jwt::EncodingKey {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::jwk::test_helpers::*;
    use pretty_assertions::assert_eq;
    use rstest::rstest;
    use serde_json::Value;

    const SYMMETRIC_JWK: &str = r#"{"kty":"oct","k":"c2VjcmV0","kid":"client-key"}"#;

    #[rstest]
    #[case(SYMMETRIC_JWK, "HS256")]
    #[case(SYMMETRIC_JWK, "HS384")]
    #[case(SYMMETRIC_JWK, "HS512")]
    #[case(SYMMETRIC_JWK, "RS256")]
    #[case(CLIENT_RSA_PRIVATE_JWK, "HS256")]
    fn rejects_symmetric_signing(#[case] jwk: &str, #[case] alg: &str) {
        let result = with_alg(jwk, alg).to_string().parse::<SigningKey>();

        assert!(matches!(result, Err(SigningKeyError::Symmetric)));
    }

    #[rstest]
    #[case(CLIENT_EC_PRIVATE_JWK, "RS256")]
    #[case(CLIENT_EC_PRIVATE_JWK, "PS256")]
    #[case(CLIENT_EC_PRIVATE_JWK, "ES384")]
    #[case(CLIENT_EC_PRIVATE_JWK, "EdDSA")]
    #[case(CLIENT_RSA_PRIVATE_JWK, "ES256")]
    fn rejects_algorithm_unsupported_by_key(#[case] jwk: &str, #[case] alg: &str) {
        let result = with_alg(jwk, alg).to_string().parse::<SigningKey>();

        assert!(matches!(
            result,
            Err(SigningKeyError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let result = with_alg(CLIENT_RSA_PRIVATE_JWK, "none").to_string().parse::<SigningKey>();

        assert!(matches!(result, Err(SigningKeyError::Parse(_))));
    }

    #[rstest]
    #[case("alg", SigningKeyError::MissingAlgorithm)]
    #[case("kid", SigningKeyError::MissingKeyId)]
    #[case("d", SigningKeyError::NotPrivate)]
    fn rejects_incomplete_key(#[case] field: &str, #[case] expected: SigningKeyError) {
        let mut jwk: Value = serde_json::from_str(CLIENT_EC_PRIVATE_JWK).unwrap();
        jwk.as_object_mut().unwrap().remove(field);

        let error = jwk.to_string().parse::<SigningKey>().err().unwrap();

        assert_eq!(error.to_string(), expected.to_string());
    }
}
