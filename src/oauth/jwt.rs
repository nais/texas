mod key_set;
#[cfg(test)]
mod test_helpers;
mod verifier;

pub use key_set::KeySetError;

use crate::http::client;
use crate::telemetry;
use key_set::KeySet;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing::instrument;
use verifier::TokenVerifier;

/// Shortest interval between two attempts at fetching the key set from the identity provider.
/// Bounds outbound traffic when tokens reference unknown key IDs or the JWKS endpoint is unavailable.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct JwtValidator {
    jwks_uri: String,
    issuer: String,
    verifier: TokenVerifier,
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

impl JwtValidator {
    pub async fn new(
        issuer: &str,
        jwks_uri: &str,
        required_audience: Option<String>,
    ) -> Result<Self, KeySetError> {
        let client = client::discovery().map_err(KeySetError::Init)?;
        let initial = KeySet::fetch(&client, jwks_uri).await?;

        Ok(Self {
            jwks_uri: jwks_uri.to_string(),
            issuer: issuer.to_string(),
            verifier: TokenVerifier::new(issuer, required_audience),
            client,
            keys: RwLock::new(initial),
            refresh: Mutex::new(RefreshState::default()),
        })
    }

    /// Check a JWT against the identity provider's signing keys.
    /// Returns the JWT's claims on success.
    /// Refreshes the key set if it has gone stale or does not contain the token's key ID.
    #[instrument(skip_all, name = "Validate token signature and claims")]
    pub async fn validate(&self, token: &str) -> Result<HashMap<String, Value>, Error> {
        let header = jsonwebtoken::decode_header(token).map_err(Error::InvalidTokenHeader)?;
        let key_id = header.kid.ok_or(Error::MissingKeyIdInTokenHeader)?;

        // Check before the key lookup, where an unknown kid triggers a refresh.
        self.verifier.check_algorithm(header.alg)?;

        let mut keys = self.keys().await;
        if keys.is_stale() {
            keys = self.refresh_jwks("expired").await;
        }
        if !keys.by_kid.contains_key(&key_id) {
            keys = self.refresh_jwks("unknown_kid").await;
        }
        let key = keys.by_kid.get(&key_id).ok_or(Error::KeyNotInKeySet)?;

        self.verifier.verify(token, header.alg, key)
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

#[cfg(test)]
mod tests {
    use super::key_set::KEY_SET_TTL;
    use super::test_helpers::*;
    use super::*;
    use crate::http::client::FetchError;
    use axum::extract::State as AxumState;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use jsonwebtoken::errors::ErrorKind;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use pretty_assertions::assert_eq;
    use reqwest::StatusCode;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
    async fn refresh_picks_up_rotated_keys() {
        let idp = MockIdentityProvider::start().await;
        idp.serve_keys(&["key-1"]);
        let validator = idp.connect().await.unwrap();

        idp.serve_keys(&["key-2"]);
        let keys = validator.refresh_jwks("test").await;

        assert!(keys.by_kid.contains_key("key-2"));
        assert!(!keys.by_kid.contains_key("key-1"));
        assert_eq!(idp.hits(), 2);
    }

    #[tokio::test]
    async fn failed_refresh_keeps_serving_the_previous_keys() {
        let idp = MockIdentityProvider::start().await;
        idp.serve_keys(&["key-1"]);
        let validator = idp.connect().await.unwrap();

        idp.respond_with(StatusCode::BAD_REQUEST, "boom".to_string());
        let keys = validator.refresh_jwks("test").await;

        assert!(keys.by_kid.contains_key("key-1"));
        assert_eq!(validator.keys().await.by_kid.len(), 1);
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
        assert!(keys.by_kid.contains_key("key-2"));
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
        assert!(validator.keys().await.by_kid.contains_key("key-2"));
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
            self.keys.write().await.fetched_at -= age;
            if let Some(last_attempt) = self.refresh.lock().await.last_attempt.as_mut() {
                *last_attempt -= MIN_REFRESH_INTERVAL;
            }
        }
    }

    /// A stand-in for an identity provider's JWKS endpoint, so that tests can rotate keys, fail
    /// requests, and count how often the endpoint was asked for keys.
    struct MockIdentityProvider {
        url: String,
        state: Arc<MockState>,
    }

    struct MockState {
        hits: AtomicUsize,
        response: Mutex<MockResponse>,
    }

    #[derive(Clone)]
    struct MockResponse {
        status: StatusCode,
        body: String,
    }

    impl MockIdentityProvider {
        async fn start() -> Self {
            let state = Arc::new(MockState {
                hits: AtomicUsize::new(0),
                response: Mutex::new(MockResponse {
                    status: StatusCode::OK,
                    body: r#"{"keys":[]}"#.to_string(),
                }),
            });

            let router =
                axum::Router::new().route("/jwks", get(Self::respond)).with_state(state.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let url = format!("http://{address}/jwks");
            tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            });
            Self { url, state }
        }

        async fn respond(AxumState(state): AxumState<Arc<MockState>>) -> impl IntoResponse {
            state.hits.fetch_add(1, Ordering::SeqCst);
            let response = state.response.lock().unwrap().clone();

            (response.status, response.body).into_response()
        }

        async fn connect(&self) -> Result<JwtValidator, KeySetError> {
            JwtValidator::new(ISSUER, &self.url, None).await
        }

        fn hits(&self) -> usize {
            self.state.hits.load(Ordering::SeqCst)
        }

        fn serve(&self, body: String) {
            self.respond_with(StatusCode::OK, body);
        }

        fn serve_keys(&self, key_ids: &[&str]) {
            let keys: Vec<Value> = key_ids
                .iter()
                .map(|kid| {
                    let mut jwk = rsa_public_jwk(Some("RS256"));
                    jwk["kid"] = (*kid).into();
                    jwk
                })
                .collect();
            self.serve(serde_json::json!({ "keys": keys }).to_string());
        }

        fn respond_with(&self, status: StatusCode, body: String) {
            let mut response = self.state.response.lock().unwrap();
            response.status = status;
            response.body = body;
        }
    }
}
