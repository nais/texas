mod signing;
#[cfg(test)]
mod test_helpers;

pub use crate::oauth::jwk::set::KeySetError;
pub(crate) use signing::sign;

use crate::http::client;
use crate::oauth::assertion::epoch_now_secs;
use crate::oauth::jwk::set::KeySet;
use crate::oauth::jwk::verification::VerificationKey;
use crate::telemetry;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, Validation};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing::instrument;

/// Shortest interval between two attempts at fetching the key set from the identity provider.
/// Prevents thundering herd for outbound traffic when tokens reference unknown key IDs or the JWKS endpoint is unavailable.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

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

/// Failure to accept a specific token.
#[derive(Error, Debug)]
pub enum Error {
    #[error("missing key id from token header")]
    MissingKeyIdInTokenHeader,
    #[error("token can not be validated with this identity provider")]
    KeyNotInKeySet,
    #[error("invalid token header: {0}")]
    InvalidTokenHeader(jsonwebtoken::errors::Error),
    #[error("invalid token: {0}")]
    InvalidToken(jsonwebtoken::errors::Error),
}

#[derive(Debug)]
pub struct JwtValidator {
    jwks_uri: String,
    issuer: String,
    /// One per algorithm, because jsonwebtoken cannot mix algorithm families in one validation.
    validations: HashMap<Algorithm, Validation>,
    client: client::Client,
    keys: RwLock<KeySet>,
    /// Held across the fetch in [`JwtValidator::refresh_jwks`], so that tasks queueing up behind
    /// an in-flight refresh receive its result rather than starting one of their own. An async
    /// mutex is required for that: a [`std::sync::MutexGuard`] cannot be held across an await,
    /// and releasing the lock before fetching would hand the waiters the outdated key set.
    refresh: Mutex<RefreshState>,
}

#[derive(Debug, Default)]
struct RefreshState {
    /// When the most recent fetch finished, regardless of its outcome.
    last_attempt: Option<Instant>,
}

impl JwtValidator {
    pub async fn new(
        issuer: &str,
        jwks_uri: &str,
        required_audience: Option<String>,
    ) -> Result<Self, KeySetError> {
        let client = client::discovery().map_err(KeySetError::Init)?;
        let initial = KeySet::fetch(&client, jwks_uri).await?;

        Ok(Self::with_keys(
            issuer,
            jwks_uri,
            required_audience,
            client,
            initial,
        ))
    }

    /// Validate verifies the signature and validates standard claims of a JWT against
    /// the identity provider's public keys, returning the claims if valid.
    #[instrument(skip_all, name = "Validate token signature and claims")]
    pub async fn validate(&self, token: &str) -> Result<HashMap<String, Value>, Error> {
        let header = jsonwebtoken::decode_header(token).map_err(Error::InvalidTokenHeader)?;
        let key_id = header.kid.ok_or(Error::MissingKeyIdInTokenHeader)?;

        // Check before the key lookup, where an unknown kid triggers a refresh.
        self.check_algorithm(header.alg)?;

        let mut keys = self.keys().await;
        if keys.is_stale() {
            keys = self.refresh_jwks("expired").await;
        }
        if keys.get(&key_id).is_none() {
            keys = self.refresh_jwks("unknown_kid").await;
        }
        let key = keys.get(&key_id).ok_or(Error::KeyNotInKeySet)?;

        self.verify(token, header.alg, key)
    }

    fn with_keys(
        issuer: &str,
        jwks_uri: &str,
        required_audience: Option<String>,
        client: client::Client,
        keys: KeySet,
    ) -> Self {
        Self {
            jwks_uri: jwks_uri.to_string(),
            issuer: issuer.to_string(),
            validations: validations(issuer, required_audience),
            client,
            keys: RwLock::new(keys),
            refresh: Mutex::new(RefreshState::default()),
        }
    }

    fn check_algorithm(&self, algorithm: Algorithm) -> Result<(), Error> {
        self.validation_for(algorithm).map(|_| ())
    }

    fn verify(
        &self,
        token: &str,
        algorithm: Algorithm,
        key: &VerificationKey,
    ) -> Result<HashMap<String, Value>, Error> {
        let validation = self.validation_for(algorithm)?;
        if !key.allows(algorithm) {
            return Err(invalid_token(ErrorKind::InvalidAlgorithm));
        }

        let claims =
            jsonwebtoken::decode::<HashMap<String, Value>>(token, key.decoding_key(), validation)
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

    async fn keys(&self) -> KeySet {
        self.keys.read().await.clone()
    }

    /// Fetch the key set anew, and return whatever key set is current afterwards.
    /// A mutex lock is used to coalesce concurrent requests.
    ///
    /// A failed fetch keeps the previous keys in place, for as long as the identity provider
    /// stays unavailable.
    #[instrument(skip_all, name = "Refresh JWKS")]
    async fn refresh_jwks(&self, reason: &'static str) -> KeySet {
        let mut refresh = self.refresh.lock().await;

        if refresh.last_attempt.is_some_and(|last| last.elapsed() < MIN_REFRESH_INTERVAL) {
            telemetry::inc_jwks_refresh(&self.issuer, reason, "suppressed");
            return self.keys().await;
        }

        let fetched = KeySet::fetch(&self.client, &self.jwks_uri).await;
        refresh.last_attempt = Some(Instant::now());

        match fetched {
            Ok(keys) => {
                *self.keys.write().await = keys.clone();
                telemetry::inc_jwks_refresh(&self.issuer, reason, "success");
                keys
            }
            Err(error) => {
                telemetry::inc_jwks_refresh(&self.issuer, reason, "failure");
                tracing::warn!(%error, issuer = %self.issuer, "refresh JWKS");
                self.keys().await
            }
        }
    }
}

fn validations(issuer: &str, audience: Option<String>) -> HashMap<Algorithm, Validation> {
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

    SUPPORTED_ALGORITHMS
        .into_iter()
        .map(|algorithm| {
            let mut validation = validation.clone();
            validation.algorithms = vec![algorithm];
            (algorithm, validation)
        })
        .collect()
}

fn invalid_token(kind: ErrorKind) -> Error {
    Error::InvalidToken(kind.into())
}

#[cfg(test)]
mod tests {
    mod startup {
        use crate::http::client::FetchError;

        use crate::oauth::jwk::test_helpers::*;
        use crate::oauth::jwt::test_helpers::*;
        use crate::oauth::jwt::*;

        use pretty_assertions::assert_eq;
        use reqwest::StatusCode;

        #[tokio::test]
        async fn startup_fails_on_unsuccessful_response() {
            let idp = MockIdentityProvider::start().await;
            idp.respond_with(StatusCode::NOT_FOUND, "nope".to_string());

            assert!(matches!(
                idp.connect().await,
                Err(KeySetError::Fetch(FetchError::Status { .. }))
            ));
        }

        #[tokio::test]
        async fn startup_fails_on_body_that_is_not_a_key_set() {
            let idp = MockIdentityProvider::start().await;
            idp.serve(r#"{"keys":"not-a-list"}"#.to_string());

            assert!(matches!(
                idp.connect().await,
                Err(KeySetError::Fetch(FetchError::Decode(_)))
            ));
        }

        #[tokio::test]
        async fn startup_fails_on_key_without_key_id() {
            let idp = MockIdentityProvider::start().await;
            let mut jwk = rsa_public_jwk(Some("RS256"));
            jwk.as_object_mut().unwrap().remove("kid");
            jwk["use"] = "sig".into();
            idp.serve(serde_json::json!({ "keys": [jwk] }).to_string());

            assert!(matches!(
                idp.connect().await,
                Err(KeySetError::MissingKeyId)
            ));
        }

        #[tokio::test]
        async fn startup_fails_on_malformed_key() {
            let idp = MockIdentityProvider::start().await;
            idp.serve(
                r#"{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"key-1","e":"AQAB","n":"!"}]}"#
                    .to_string(),
            );

            assert!(matches!(
                idp.connect().await,
                Err(KeySetError::InvalidJwk(_))
            ));
        }

        #[tokio::test]
        async fn transient_jwks_status_is_retried() {
            let idp = MockIdentityProvider::start().await;
            idp.respond_with(StatusCode::SERVICE_UNAVAILABLE, "temporary".to_string());

            let result = JwtValidator::new(ISSUER, &idp.url, None).await;

            assert!(matches!(
                result,
                Err(KeySetError::Fetch(FetchError::Status { .. }))
            ));
            assert_eq!(idp.hits(), 3);
        }
    }

    mod verification {

        use crate::oauth::jwk::test_helpers::*;
        use crate::oauth::jwt::test_helpers::*;
        use crate::oauth::jwt::*;
        use jsonwebtoken::errors::ErrorKind;
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn validates_token_signed_by_served_key() {
            let idp = MockIdentityProvider::start().await;
            let (jwk, token) = signed_ec_token(Algorithm::ES256, &valid_claims());
            idp.serve(serde_json::json!({ "keys": [jwk] }).to_string());
            let validator = idp.connect().await.unwrap();

            let claims = validator.validate(&token).await.unwrap();

            assert_eq!(claims["sub"], "subject");
            assert_eq!(idp.hits(), 1);
        }

        #[rstest::rstest]
        #[case(Algorithm::ES256)]
        #[case(Algorithm::ES384)]
        fn verifies_ec_token(#[case] algorithm: Algorithm) {
            let (jwk, token) = signed_ec_token(algorithm, &valid_claims());

            let claims = verify(&token, &verification_key(jwk).unwrap()).unwrap();

            assert_eq!(claims["iss"], ISSUER);
            assert_eq!(claims["sub"], "subject");
        }

        #[rstest::rstest]
        #[case(Algorithm::ES256)]
        #[case(Algorithm::ES384)]
        fn rejects_ec_token_with_corrupted_signature(#[case] algorithm: Algorithm) {
            let (jwk, token) = signed_ec_token(algorithm, &valid_claims());

            let result = verify(&corrupt_signature(&token), &verification_key(jwk).unwrap());

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

            let result = verify(&token, &verification_key(other_jwk).unwrap());

            assert_rejected(result, &ErrorKind::InvalidSignature);
        }

        #[rstest::rstest]
        #[case(Algorithm::ES256)]
        #[case(Algorithm::ES384)]
        fn rejects_ec_token_with_rsa_key(#[case] algorithm: Algorithm) {
            let (_, token) = signed_ec_token(algorithm, &valid_claims());

            let result = verify(&token, &verification_key(rsa_public_jwk(None)).unwrap());

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
            let key = verification_key(rsa_public_jwk(jwk_alg)).unwrap();

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

            let result = verify(&token, &verification_key(jwk).unwrap());

            assert_rejected(result, &ErrorKind::MissingRequiredClaim("iat".to_string()));
        }

        #[tokio::test]
        async fn rejects_hs256_token_without_refreshing() {
            let idp = MockIdentityProvider::start().await;
            idp.serve_keys(&["key-1"]);
            let validator = idp.connect().await.unwrap();

            let mut header = Header::new(Algorithm::HS256);
            header.kid = Some("unknown-key".to_string());
            let token = jsonwebtoken::encode(
                &header,
                &HashMap::<String, Value>::new(),
                &EncodingKey::from_secret(b"secret"),
            )
            .unwrap();

            let result = validator.validate(&token).await;

            assert_rejected(result, &ErrorKind::InvalidAlgorithm);
            assert_eq!(idp.hits(), 1);
        }

        #[tokio::test]
        async fn token_without_key_id_is_rejected_without_refreshing() {
            let idp = MockIdentityProvider::start().await;
            idp.serve_keys(&["key-1"]);
            let validator = idp.connect().await.unwrap();

            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
                &HashMap::<String, Value>::new(),
                &jsonwebtoken::EncodingKey::from_secret(b"secret"),
            )
            .unwrap();
            let result = validator.validate(&token).await;

            assert!(matches!(result, Err(Error::MissingKeyIdInTokenHeader)));
            assert_eq!(idp.hits(), 1);
        }

        fn verify(token: &str, key: &VerificationKey) -> Result<HashMap<String, Value>, Error> {
            let algorithm = jsonwebtoken::decode_header(token).unwrap().alg;

            JwtValidator::without_keys().verify(token, algorithm, key)
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
    }

    mod refresh {

        use crate::oauth::jwk::set::KEY_SET_TTL;

        use crate::oauth::jwt::test_helpers::*;
        use crate::oauth::jwt::*;

        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        use pretty_assertions::assert_eq;
        use reqwest::StatusCode;
        use std::sync::Arc;

        #[tokio::test]
        async fn refresh_picks_up_rotated_keys() {
            let idp = MockIdentityProvider::start().await;
            idp.serve_keys(&["key-1"]);
            let validator = idp.connect().await.unwrap();

            idp.serve_keys(&["key-2"]);
            let keys = validator.refresh_jwks("test").await;

            assert!(keys.get("key-2").is_some());
            assert!(keys.get("key-1").is_none());
            assert_eq!(idp.hits(), 2);
        }

        #[tokio::test]
        async fn failed_refresh_keeps_serving_the_previous_keys() {
            let idp = MockIdentityProvider::start().await;
            idp.serve_keys(&["key-1"]);
            let validator = idp.connect().await.unwrap();

            idp.respond_with(StatusCode::BAD_REQUEST, "boom".to_string());
            let keys = validator.refresh_jwks("test").await;

            assert!(keys.get("key-1").is_some());
            assert_eq!(validator.keys().await.len(), 1);
            assert_eq!(idp.hits(), 2);
        }

        #[tokio::test]
        async fn refreshes_within_the_cooldown_are_suppressed() {
            let idp = MockIdentityProvider::start().await;
            idp.serve_keys(&["key-1"]);
            let validator = idp.connect().await.unwrap();

            idp.serve_keys(&["key-2"]);
            validator.refresh_jwks("test").await;
            let keys = validator.refresh_jwks("test").await;

            // The second refresh returned the key set fetched by the first one.
            assert!(keys.get("key-2").is_some());
            assert_eq!(idp.hits(), 2);
        }

        #[tokio::test]
        async fn concurrent_refreshes_result_in_a_single_fetch() {
            let idp = MockIdentityProvider::start().await;
            idp.serve_keys(&["key-1"]);
            let validator = Arc::new(idp.connect().await.unwrap());

            let refreshes = (0..16).map(|_| {
                let validator = validator.clone();
                tokio::spawn(async move { validator.refresh_jwks("test").await })
            });
            for refresh in refreshes {
                refresh.await.unwrap();
            }

            assert_eq!(idp.hits(), 2);
        }

        #[tokio::test]
        async fn key_set_goes_stale_once_its_lifetime_has_passed() {
            let idp = MockIdentityProvider::start().await;
            idp.serve_keys(&["key-1"]);
            let validator = idp.connect().await.unwrap();

            assert!(!validator.keys().await.is_stale());

            validator.age(KEY_SET_TTL).await;

            assert!(validator.keys().await.is_stale());
        }

        #[tokio::test]
        async fn validating_a_stale_key_set_refreshes_it() {
            let idp = MockIdentityProvider::start().await;
            idp.serve_keys(&["key-1"]);
            let validator = idp.connect().await.unwrap();
            validator.age(KEY_SET_TTL).await;

            idp.serve_keys(&["key-1", "key-2"]);
            // The token names a key we already hold, so staleness is the only reason to fetch again.
            let _ = validator.validate(&token_with_kid("key-1")).await;

            assert_eq!(idp.hits(), 2);
            assert!(validator.keys().await.get("key-2").is_some());
        }

        #[tokio::test]
        async fn validating_a_fresh_key_set_does_not_refresh_it() {
            let idp = MockIdentityProvider::start().await;
            idp.serve_keys(&["key-1"]);
            let validator = idp.connect().await.unwrap();

            let _ = validator.validate(&token_with_kid("key-1")).await;

            assert_eq!(idp.hits(), 1);
        }

        #[tokio::test]
        async fn unknown_key_id_refreshes_before_giving_up() {
            let idp = MockIdentityProvider::start().await;
            idp.serve_keys(&["key-1"]);
            let validator = idp.connect().await.unwrap();

            let result = validator.validate(&token_with_kid("absent")).await;

            assert!(matches!(result, Err(Error::KeyNotInKeySet)));
            assert_eq!(idp.hits(), 2);
        }

        fn token_with_kid(key_id: &str) -> String {
            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some(key_id.to_string());
            let key = EncodingKey::from_ec_pem(EC_P256_PRIVATE_PEM.as_bytes()).unwrap();
            jsonwebtoken::encode(&header, &HashMap::<String, Value>::new(), &key).unwrap()
        }

        impl JwtValidator {
            /// Backdate the current key set so that it looks like it was fetched `age` ago.
            /// Also clears the refresh cooldown, which would otherwise suppress the next fetch.
            async fn age(&self, age: Duration) {
                self.keys.write().await.backdate(age);
                if let Some(last_attempt) = self.refresh.lock().await.last_attempt.as_mut() {
                    *last_attempt -= MIN_REFRESH_INTERVAL;
                }
            }
        }
    }
}
