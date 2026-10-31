use texas::config::{Config, Provider};

const CLIENT_PRIVATE_JWK: &str = include_str!("../../fixtures/client-auth-rsa-private.jwk");

pub fn mock(host: String, port: u16) -> Config {
    let url_base = format!("http://{host}:{port}");
    Config {
        bind_address: "127.0.0.1:0".to_string(),
        probe_bind_address: Some("127.0.0.1:0".to_string()),
        maskinporten: Some(Provider {
            client_id: "default".to_string(), // expected audience for tokens returned by mock-oauth2-server
            client_jwk: Some(CLIENT_PRIVATE_JWK.to_string()),
            jwks_uri: format!("{url_base}/maskinporten/jwks"),
            issuer: format!("{url_base}/maskinporten"),
            token_endpoint: Some(format!("{url_base}/maskinporten/token")),
        }),
        entra_id: Some(Provider {
            client_id: "default".to_string(), // expected audience for tokens returned by mock-oauth2-server
            client_jwk: Some(CLIENT_PRIVATE_JWK.to_string()),
            jwks_uri: format!("{url_base}/entra_id/jwks"),
            issuer: format!("{url_base}/entra_id"),
            token_endpoint: Some(format!("{url_base}/entra_id/token")),
        }),
        token_x: Some(Provider {
            client_id: "default".to_string(), // expected audience for tokens returned by mock-oauth2-server
            client_jwk: Some(CLIENT_PRIVATE_JWK.to_string()),
            jwks_uri: format!("{url_base}/tokenx/jwks"),
            issuer: format!("{url_base}/tokenx"),
            token_endpoint: Some(format!("{url_base}/tokenx/token")),
        }),
        idporten: Some(Provider {
            client_id: "default".to_string(), // expected audience for tokens returned by mock-oauth2-server
            client_jwk: None,
            jwks_uri: format!("{url_base}/idporten/jwks"),
            issuer: format!("{url_base}/idporten"),
            token_endpoint: None,
        }),
        ansattporten: Some(Provider {
            client_id: "default".to_string(), // expected audience for tokens returned by mock-oauth2-server
            client_jwk: None,
            jwks_uri: format!("{url_base}/ansattporten/jwks"),
            issuer: format!("{url_base}/ansattporten"),
            token_endpoint: None,
        }),
    }
}

pub fn mock_no_providers() -> Config {
    Config {
        bind_address: "127.0.0.1:0".to_string(),
        probe_bind_address: Some("127.0.0.1:0".to_string()),
        maskinporten: None,
        entra_id: None,
        token_x: None,
        idporten: None,
        ansattporten: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebkey as jwk;
    use jsonwebtoken as jwt;
    use serde_json::{Value, json};

    const CLIENT_KID: &str = "test-client-auth-rsa";
    const IDP_PRIVATE_JWK: &str = include_str!("../../fixtures/rsa-private.jwk");

    #[test]
    fn providers_share_client_auth_key_distinct_from_idp_key() {
        let config = mock("localhost".to_string(), 1234);
        for provider in [&config.maskinporten, &config.entra_id, &config.token_x] {
            let provider = provider.as_ref().unwrap();
            assert_eq!(provider.client_jwk.as_deref(), Some(CLIENT_PRIVATE_JWK));
        }

        let client: Value = serde_json::from_str(CLIENT_PRIVATE_JWK).unwrap();
        let idp: Value = serde_json::from_str(IDP_PRIVATE_JWK).unwrap();
        assert_eq!(client["kid"], CLIENT_KID);
        assert_ne!(client["kid"], idp["kid"]);
        assert_ne!(client["n"], idp["n"]);

        // Sign like Texas does for client assertions (RS256 with the kid header),
        // then verify with each public key.
        let private: jwk::JsonWebKey = CLIENT_PRIVATE_JWK.parse().unwrap();
        let encoding_key = jwt::EncodingKey::from_rsa_pem(private.key.to_pem().as_bytes()).unwrap();
        let mut header = jwt::Header::new(jwt::Algorithm::RS256);
        header.kid = Some(CLIENT_KID.to_string());
        let token = jwt::encode(&header, &json!({ "sub": "client-id" }), &encoding_key).unwrap();

        let mut validation = jwt::Validation::new(jwt::Algorithm::RS256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;

        let client_key =
            jwt::DecodingKey::from_jwk(&serde_json::from_str(CLIENT_PRIVATE_JWK).unwrap()).unwrap();
        let verified = jwt::decode::<Value>(&token, &client_key, &validation).unwrap();
        assert_eq!(verified.header.kid.as_deref(), Some(CLIENT_KID));
        assert_eq!(verified.claims["sub"], "client-id");

        let idp_key =
            jwt::DecodingKey::from_jwk(&serde_json::from_str(IDP_PRIVATE_JWK).unwrap()).unwrap();
        let rejected = jwt::decode::<Value>(&token, &idp_key, &validation).unwrap_err();
        assert!(matches!(
            rejected.kind(),
            jwt::errors::ErrorKind::InvalidSignature
        ));
    }
}
