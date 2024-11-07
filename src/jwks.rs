use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use jsonwebtoken::Validation;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Jwks {
    endpoint: String,
    issuer: String,
    required_audience: Option<String>,
    keys: HashMap<String, jwk::JsonWebKey>,
    validation: Validation,
}

// TODO: some of these errors relate to the keyset itself, some of it relates to validation of a JWT - are we conflating two things here?
#[derive(Error, Debug)]
pub enum Error {
    #[error("fetch: {0}")]
    Fetch(reqwest::Error),
    #[error("decode json: {0}")]
    JsonDecode(reqwest::Error),
    #[error("json web key set has key with blank key id")]
    MissingKeyID,
    #[error("signing key with {0} not in json web key set")]
    KeyNotInJWKS(String),
    #[error("invalid token header: {0}")]
    InvalidTokenHeader(jwt::errors::Error),
    #[error("invalid token: {0}")]
    InvalidToken(jwt::errors::Error),
}

impl Jwks {
    pub async fn new(issuer: &str, endpoint: &str, required_audience: Option<String>) -> Result<Jwks, Error> {
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
            required_audience: required_audience.clone(),
            validation: Self::validate_with(issuer.to_string(), required_audience),
        })
    }

    fn validate_with(issuer: String, audience: Option<String>) -> Validation {
        let alg = jwt::Algorithm::RS256;
        let mut validation = Validation::new(alg);

        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["iss", "exp", "iat"]);
        validation.set_issuer(&[issuer]);

        if let Some(audience) = audience {
            validation.set_required_spec_claims(&["iss", "exp", "iat", "aud"]);
            validation.set_audience(&[audience]);
        }

        validation
    }

    /// Pull a new version of the JWKS from the original endpoint.
    pub async fn refresh(&mut self) -> Result<(), Error> {
        let new_jwks = Self::new(&self.issuer, &self.endpoint, self.required_audience.clone()).await?;
        self.keys = new_jwks.keys;
        Ok(())
    }

    /// Check a JWT against a JWKS.
    /// Returns the JWT's claims on success.
    /// May update the list of signing keys if the key ID is not found.
    pub async fn validate(&mut self, token: &str) -> Result<HashMap<String, Value>, Error> {
        let key_id = jwt::decode_header(token)
            .map_err(Error::InvalidTokenHeader)?
            .kid
            .ok_or(Error::MissingKeyID)?;

        // Refresh key store if needed before validating.
        let signing_key = match self.keys.get(&key_id) {
            None => {
                self.refresh().await?;
                self.keys.get(&key_id).ok_or(Error::KeyNotInJWKS(key_id))?
            }
            Some(key) => key,
        };

        Ok(jwt::decode::<HashMap<String, Value>>(
            token,
            &signing_key.key.to_decoding_key(),
            &self.validation,
        )
        .map_err(Error::InvalidToken)?
        .claims)
    }
}
