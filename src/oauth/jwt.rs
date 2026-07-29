use crate::http;
use crate::oauth::assertion::epoch_now_secs;
use crate::telemetry;
use jsonwebtoken::{DecodingKey, Validation};
use reqwest_middleware::ClientWithMiddleware;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing::instrument;

/// How long a key set is reused before it is fetched again.
/// Unknown key IDs trigger an earlier refresh to support key rotation.
const KEY_SET_TTL: Duration = Duration::from_hours(1);

/// Shortest interval between two attempts at fetching the key set from the identity provider.
/// Bounds outbound traffic when tokens reference unknown key IDs or the endpoint is unavailable.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct JwtValidator {
    endpoint: String,
    issuer: String,
    validation: Validation,
    client: ClientWithMiddleware,
    keys: RwLock<KeySet>,
    /// Held across the fetch in [`JwtValidator::refresh_jwks`], so that tasks queueing up behind
    /// an in-flight refresh receive its result rather than starting one of their own. An async
    /// mutex is required for that: a [`std::sync::MutexGuard`] cannot be held across an await,
    /// and releasing the lock before fetching would hand the waiters the outdated key set.
    refresh: Mutex<RefreshState>,
}

/// The signing keys currently trusted for an identity provider.
#[derive(Clone, Debug)]
struct KeySet {
    by_kid: Arc<HashMap<String, DecodingKey>>,
    fetched_at: Instant,
}

#[derive(Debug, Default)]
struct RefreshState {
    /// When the most recent fetch finished, regardless of its outcome.
    last_attempt: Option<Instant>,
}

/// Failure to obtain a usable set of signing keys from the identity provider.
#[derive(Error, Debug)]
pub enum KeySetError {
    #[error("init client: {0}")]
    Init(reqwest::Error),
    #[error("fetch: {0:?}")]
    Fetch(reqwest_middleware::Error),
    #[error("unsuccessful response: {0}")]
    HttpStatus(reqwest::Error),
    #[error("decode json: {0}")]
    JsonDecode(reqwest::Error),
    #[error("json web key set has key with blank key id")]
    MissingKeyId,
    #[error("invalid public jwk: {0}")]
    InvalidJwk(jsonwebtoken::errors::Error),
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
        endpoint: &str,
        required_audience: Option<String>,
    ) -> Result<Self, KeySetError> {
        let client = http::client::jwks().map_err(KeySetError::Init)?;
        let initial = fetch_keys(&client, endpoint).await?;
        Ok(Self {
            endpoint: endpoint.to_string(),
            issuer: issuer.to_string(),
            validation: Self::validation(issuer.to_string(), required_audience),
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
        let key_id = jsonwebtoken::decode_header(token)
            .map_err(Error::InvalidTokenHeader)?
            .kid
            .ok_or(Error::MissingKeyIdInTokenHeader)?;

        let mut keys = self.keys().await;
        if keys.is_stale() {
            keys = self.refresh_jwks("expired").await;
        }
        if !keys.by_kid.contains_key(&key_id) {
            keys = self.refresh_jwks("unknown_kid").await;
        }
        let signing_key = keys.by_kid.get(&key_id).ok_or(Error::KeyNotInKeySet)?;

        let claims =
            jsonwebtoken::decode::<HashMap<String, Value>>(token, signing_key, &self.validation)
                .map_err(Error::InvalidToken)?
                .claims;

        // validate the `iat` claim manually as the jsonwebtoken crate does not do this
        let iat = claims.get("iat").and_then(Value::as_u64).ok_or_else(|| {
            Error::InvalidToken(
                jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("iat".to_string()).into(),
            )
        })?;

        if iat > epoch_now_secs() + self.validation.leeway {
            return Err(Error::InvalidToken(
                jsonwebtoken::errors::ErrorKind::ImmatureSignature.into(),
            ));
        }

        Ok(claims)
    }

    // TODO: should allow validation with a selection of asymmetric signing algorithms
    fn validation(issuer: String, audience: Option<String>) -> Validation {
        let alg = jsonwebtoken::AlgorithmFamily::Rsa;
        let mut validation = Validation::new_for_family(alg);

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

        validation
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

        let fetched = fetch_keys(&self.client, &self.endpoint).await;
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

async fn fetch_keys(client: &ClientWithMiddleware, endpoint: &str) -> Result<KeySet, KeySetError> {
    let response = client
        .get(endpoint)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(KeySetError::Fetch)?;
    let response = response.error_for_status().map_err(KeySetError::HttpStatus)?;
    let response: jsonwebtoken::jwk::JwkSet =
        response.json().await.map_err(KeySetError::JsonDecode)?;

    let mut by_kid = HashMap::new();
    for key in &response.keys {
        let key_id = key.common.key_id.clone().ok_or(KeySetError::MissingKeyId)?;
        let decoding_key = DecodingKey::from_jwk(key).map_err(KeySetError::InvalidJwk)?;
        by_kid.insert(key_id, decoding_key);
    }

    Ok(KeySet {
        by_kid: Arc::new(by_kid),
        fetched_at: Instant::now(),
    })
}

impl KeySet {
    fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() >= KEY_SET_TTL
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State as AxumState;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use pretty_assertions::assert_eq;
    use reqwest::StatusCode;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Any valid RSA modulus will do: these tests exercise key lookup and refreshing, and never
    /// get as far as verifying a signature. Copied from key pair used in mock-oauth2-server.
    const MODULUS: &str = "8ZqUp5Cs90XpNn8tJBdUUxdGH4bjqKjFj8lyB3x50RpTuECuwzX1NpVqyFENDiEtMja5fdmJl6SErjnhj6kbhcmfmFibANuG-0WlV5yMysdSbocd75C1JQbiPdpHdXrijmVFMfDnoZTQ-ErNsqqngTNkn5SXBcPenli6Cf9MTSchZuh_qFj_B7Fp3CWKehTiyBcLlNOIjYsXX8WQjZkWKGpQ23AWjZulngWRektLcRWuEKTWaRBtbAr3XAfSmcqTICrebaD3IMWKHDtvzHAt_pt4wnZ06clgeO2Wbc980usnpsF7g8k9p81RcbS4JEZmuuA9NCmOmbyADXwgA9_-Aw";

    const ISSUER: &str = "https://issuer.example";

    #[tokio::test]
    async fn startup_fails_on_unsuccessful_response() {
        let idp = MockIdentityProvider::start().await;
        idp.respond_with(StatusCode::NOT_FOUND, "nope".to_string());

        assert!(matches!(
            idp.connect().await,
            Err(KeySetError::HttpStatus(_))
        ));
    }

    #[tokio::test]
    async fn startup_fails_on_body_that_is_not_a_key_set() {
        let idp = MockIdentityProvider::start().await;
        idp.serve(r#"{"keys":"not-a-list"}"#.to_string());

        assert!(matches!(
            idp.connect().await,
            Err(KeySetError::JsonDecode(_))
        ));
    }

    #[tokio::test]
    async fn startup_fails_on_key_without_key_id() {
        let idp = MockIdentityProvider::start().await;
        idp.serve(format!(
            r#"{{"keys":[{{"kty":"RSA","use":"sig","alg":"RS256","e":"AQAB","n":"{MODULUS}"}}]}}"#
        ));

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
        let _ = validator.validate(&token_signed_with("key-1")).await;

        assert_eq!(idp.hits(), 2);
        assert!(validator.keys().await.by_kid.contains_key("key-2"));
    }

    #[tokio::test]
    async fn validating_a_fresh_key_set_does_not_refresh_it() {
        let idp = MockIdentityProvider::start().await;
        idp.serve_keys(&["key-1"]);
        let validator = idp.connect().await.unwrap();

        let _ = validator.validate(&token_signed_with("key-1")).await;

        assert_eq!(idp.hits(), 1);
    }

    #[tokio::test]
    async fn unknown_key_id_refreshes_before_giving_up() {
        let idp = MockIdentityProvider::start().await;
        idp.serve_keys(&["key-1"]);
        let validator = idp.connect().await.unwrap();

        let result = validator.validate(&token_signed_with("absent")).await;

        assert!(matches!(result, Err(Error::KeyNotInKeySet)));
        assert_eq!(idp.hits(), 2);
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

    /// A syntactically valid JWT that nothing can be signed with; enough to exercise the key
    /// lookup that happens before the signature is checked.
    fn token_signed_with(key_id: &str) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(key_id.to_string());
        jsonwebtoken::encode(
            &header,
            &HashMap::<String, Value>::new(),
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .unwrap()
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
            let url = format!("http://{}/jwks", listener.local_addr().unwrap());
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
            let keys: Vec<String> = key_ids
                .iter()
                .map(|kid| {
                    format!(
                        r#"{{"kty":"RSA","use":"sig","alg":"RS256","kid":"{kid}","e":"AQAB","n":"{MODULUS}"}}"#
                    )
                })
                .collect();
            self.serve(format!(r#"{{"keys":[{}]}}"#, keys.join(",")));
        }

        fn respond_with(&self, status: StatusCode, body: String) {
            let mut response = self.state.response.lock().unwrap();
            response.status = status;
            response.body = body;
        }
    }
}
