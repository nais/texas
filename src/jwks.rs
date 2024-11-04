use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Jwks {
    endpoint: String,
    issuer: String,
    keys: HashMap<String, jwk::JsonWebKey>,
}

#[derive(Debug)]
pub enum Error {
    Fetch(reqwest::Error),
    JsonDecode(reqwest::Error),
    MissingKeyID,
    InvalidTokenHeader(jwt::errors::Error),
    KeyNotInJWKS,
    InvalidToken(jwt::errors::Error),
}

impl Jwks {
    pub async fn new(issuer: &str, endpoint: &str) -> Result<Jwks, Error> {
        #[derive(Deserialize)]
        struct Response {
            keys: Vec<jwk::JsonWebKey>,
        }

        let client = reqwest::Client::new();
        let request_builder = client.get(endpoint).header("accept", "application/json");

        let response: Response = request_builder
            .send()
            .await
            .map_err(Error::Fetch)?
            .json()
            .await
            .map_err(Error::JsonDecode)?;

        let mut keys: HashMap<String, jwk::JsonWebKey> = HashMap::new();
        for key in response.keys {
            keys.insert(key.key_id.clone().ok_or(Error::MissingKeyID)?, key);
        }

        Ok(Self {
            keys,
            endpoint: endpoint.to_string(),
            issuer: issuer.to_string(),
        })
    }

    /// Pull a new version of the JWKS from the original endpoint.
    pub async fn refresh(&mut self) -> Result<(), Error> {
        let new_jwks = Self::new(&self.issuer, &self.endpoint).await?;
        self.keys = new_jwks.keys;
        Ok(())
    }

    /// Check a JWT against a JWKS.
    /// Returns the JWT's claims on success.
    /// May update the list of signing keys if the key ID is not found.
    pub async fn validate(&mut self, token: &str) -> Result<HashMap<String, Value>, Error> {
        let alg = jwt::Algorithm::RS256;
        let mut validation = jwt::Validation::new(alg);
        validation.set_required_spec_claims(&["iss", "exp", "iat"]);
        validation.set_issuer(&[self.issuer.clone()]);
        validation.validate_nbf = true;

        let key_id = jwt::decode_header(token)
            .map_err(Error::InvalidTokenHeader)?
            .kid
            .ok_or(Error::MissingKeyID)?;

        // Refresh key store if needed before validating.
        let signing_key = match self.keys.get(&key_id) {
            None => {
                self.refresh().await?;
                self.keys.get(&key_id).ok_or(Error::KeyNotInJWKS)?
            }
            Some(key) => key,
        };

        Ok(jwt::decode::<HashMap<String, Value>>(
            token,
            &signing_key.key.to_decoding_key(),
            &validation,
        )
        .map_err(Error::InvalidToken)?
        .claims)
    }
}
