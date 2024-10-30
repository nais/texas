use std::collections::HashMap;
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde::Deserialize;
use serde_json::Value;
use crate::jwks::Error::{InvalidToken, KeyNotInJWKS};

#[derive(Clone, Debug)]
pub struct Jwks {
    endpoint: String,
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
    pub async fn new_from_jwks_endpoint(endpoint: &str) -> Result<Jwks, Error> {
        #[derive(Deserialize)]
        struct Response {
            keys: Vec<jwk::JsonWebKey>,
        }

        let client = reqwest::Client::new();
        let request_builder = client.get(endpoint)
            .header("accept", "application/json");

        let response: Response = request_builder
            .send().await
            .map_err(Error::Fetch)?
            .json().await
            .map_err(Error::JsonDecode)?
            ;

        let mut keys: HashMap<String, jwk::JsonWebKey> = HashMap::new();
        for key in response.keys {
            keys.insert(key.key_id.clone().ok_or(Error::MissingKeyID)?, key);
        }

        Ok(Self {
            keys,
            endpoint: endpoint.to_string(),
        })
    }

    pub async fn refresh(&mut self) -> Result<(), Error> {
        let new_jwks = Self::new_from_jwks_endpoint(&self.endpoint).await?;
        self.keys = new_jwks.keys;
        Ok(())
    }

    /// Check a JWT against a JWKS.
    /// Returns the JWT's claims on success.
    // TODO: ensure all the things are properly validated
    pub fn validate(
        &self,
        token: &str,
    ) -> Result<HashMap<String, Value>, Error> {
        let alg = jwt::Algorithm::RS256;
        let validation = jwt::Validation::new(alg);

        let key_id = jwt::decode_header(&token)
            .map_err(Error::InvalidTokenHeader)?
            .kid.ok_or(Error::MissingKeyID)?
            ;

        let signing_key = self.keys.get(&key_id).ok_or(KeyNotInJWKS)?;

        Ok(jwt::decode::<HashMap<String, Value>>(&token, &signing_key.key.to_decoding_key(), &validation)
            .map_err(InvalidToken)?
            .claims
        )
    }
}
