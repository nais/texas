use crate::oauth::jwk::signing::SigningKey;
use jsonwebtoken::{Header, errors::Error};
use serde::Serialize;

pub(crate) fn sign(key: &SigningKey, claims: &impl Serialize) -> Result<String, Error> {
    let mut header = Header::new(key.algorithm());
    header.kid = Some(key.key_id().to_string());

    jsonwebtoken::encode(&header, claims, key.encoding_key())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::jwk::test_helpers::{
        CLIENT_EC_PRIVATE_JWK, CLIENT_RSA_PRIVATE_JWK, with_alg,
    };
    use jsonwebtoken as jwt;
    use pretty_assertions::assert_eq;
    use rstest::rstest;
    use serde_json::{Value, json};

    #[rstest]
    #[case(CLIENT_EC_PRIVATE_JWK, "ES256")]
    #[case(CLIENT_RSA_PRIVATE_JWK, "RS256")]
    #[case(CLIENT_RSA_PRIVATE_JWK, "RS384")]
    #[case(CLIENT_RSA_PRIVATE_JWK, "RS512")]
    #[case(CLIENT_RSA_PRIVATE_JWK, "PS256")]
    #[case(CLIENT_RSA_PRIVATE_JWK, "PS384")]
    #[case(CLIENT_RSA_PRIVATE_JWK, "PS512")]
    fn signs_verifiable_tokens(#[case] jwk: &str, #[case] alg: &str) {
        let jwk = with_alg(jwk, alg);
        let key: SigningKey = jwk.to_string().parse().unwrap();

        let token = sign(&key, &json!({ "sub": "client-id" })).unwrap();

        let alg: jwt::Algorithm = alg.parse().unwrap();

        let decoding_key =
            jwt::DecodingKey::from_jwk(&serde_json::from_value(jwk.clone()).unwrap()).unwrap();
        let mut validation = jwt::Validation::new(alg);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let token = jwt::decode::<Value>(&token, &decoding_key, &validation).unwrap();

        assert_eq!(token.header.alg, alg);
        assert_eq!(token.header.kid.as_deref(), jwk["kid"].as_str());
        assert_eq!(token.claims["sub"], "client-id");
    }
}
