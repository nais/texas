use crate::oauth::assertion::epoch_now_secs;
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use jsonwebtoken::Validation;
use reqwest_middleware::ClientBuilder;
use reqwest_retry::{RetryTransientMiddleware, policies};
use reqwest_tracing::{SpanBackendWithUrl, TracingMiddleware};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tracing::instrument;

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
    #[error("init client: {0}")]
    Init(reqwest::Error),
    #[error("fetch: {0}")]
    Fetch(reqwest_middleware::Error),
    #[error("decode json: {0}")]
    JsonDecode(reqwest::Error),
    #[error("json web key set has key with blank key id")]
    MissingKeyID,
    #[error("missing key id from token header")]
    MissingKeyIDInTokenHeader,
    #[error("token can not be validated with this identity provider")]
    KeyNotInJWKS,
    #[error("invalid token header: {0}")]
    InvalidTokenHeader(jwt::errors::Error),
    #[error("invalid token: {0}")]
    InvalidToken(jwt::errors::Error),
}

impl Jwks {
    pub async fn new(
        issuer: &str,
        endpoint: &str,
        required_audience: Option<String>,
    ) -> Result<Jwks, Error> {
        #[derive(Deserialize)]
        struct Response {
            keys: Vec<jwk::JsonWebKey>,
        }

        let timeout = Duration::from_secs(5);
        let retry_policy = policies::ExponentialBackoff::builder()
            .retry_bounds(Duration::from_secs(1), Duration::from_secs(3))
            .build_with_max_retries(10);
        let client = reqwest::Client::builder().timeout(timeout).build().map_err(Error::Init)?;
        let client = ClientBuilder::new(client)
            .with(TracingMiddleware::<SpanBackendWithUrl>::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        let request = client.get(endpoint).header("accept", "application/json");
        let response: Response =
            request.send().await.map_err(Error::Fetch)?.json().await.map_err(Error::JsonDecode)?;

        let mut keys: HashMap<String, jwk::JsonWebKey> = HashMap::new();
        for key in response.keys {
            keys.insert(key.key_id.clone().ok_or(Error::MissingKeyID)?, key);
        }

        Ok(Self {
            keys,
            endpoint: endpoint.to_string(),
            issuer: issuer.to_string(),
            required_audience: required_audience.clone(),
            validation: Self::validator(issuer.to_string(), required_audience),
        })
    }

    fn validator(issuer: String, audience: Option<String>) -> Validation {
        let alg = jwt::Algorithm::RS256;
        let mut validation = Validation::new(alg);

        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["iss", "exp", "iat"]);
        validation.set_issuer(&[issuer]);
        validation.leeway = 60; // 1 minute

        if let Some(audience) = audience {
            validation.set_required_spec_claims(&["iss", "exp", "iat", "aud"]);
            validation.set_audience(&[audience]);
        }

        validation
    }

    /// Pull a new version of the JWKS from the original endpoint.
    #[instrument(skip_all, name = "Refresh JWKS")]
    pub async fn refresh(&mut self) -> Result<(), Error> {
        let new_jwks =
            Self::new(&self.issuer, &self.endpoint, self.required_audience.clone()).await?;
        self.keys = new_jwks.keys;
        Ok(())
    }

    /// Check a JWT against a JWKS.
    /// Returns the JWT's claims on success.
    /// May update the list of signing keys if the key ID is not found.
    #[instrument(skip_all, name = "Validate token signature and claims")]
    pub async fn validate(&mut self, token: &str) -> Result<HashMap<String, Value>, Error> {
        let key_id = jwt::decode_header(token)
            .map_err(Error::InvalidTokenHeader)?
            .kid
            .ok_or(Error::MissingKeyIDInTokenHeader)?;

        // Refresh key store if needed before validating.
        let signing_key = match self.keys.get(&key_id) {
            None => {
                self.refresh().await?;
                self.keys.get(&key_id).ok_or(Error::KeyNotInJWKS)?
            }
            Some(key) => key,
        };

        let claims = jwt::decode::<HashMap<String, Value>>(
            token,
            &signing_key.key.to_decoding_key(),
            &self.validation,
        )
        .map_err(Error::InvalidToken)?
        .claims;

        // validate the `iat` claim manually as the jsonwebtoken crate does not do this
        let iat = claims.get("iat").and_then(Value::as_u64).ok_or_else(|| {
            Error::InvalidToken(
                jwt::errors::ErrorKind::MissingRequiredClaim("iat".to_string()).into(),
            )
        })?;

        if iat > epoch_now_secs() + self.validation.leeway {
            return Err(Error::InvalidToken(
                jwt::errors::ErrorKind::ImmatureSignature.into(),
            ));
        }

        Ok(claims)
    }
}
