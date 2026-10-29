use crate::http::client::{self, FetchError};
use crate::oauth::assertion::epoch_now_secs;
use crate::telemetry;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
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
    verifier: TokenVerifier,
    client: client::Client,
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
    by_kid: Arc<HashMap<String, VerifyingKey>>,
    fetched_at: Instant,
}

#[derive(Debug)]
struct VerifyingKey {
    key: DecodingKey,
    /// From the JWK's `alg`. If set, the key verifies only this algorithm.
    algorithm: Option<Algorithm>,
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
    #[error("fetch: {0}")]
    Fetch(#[from] FetchError),
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
        let client = client::discovery().map_err(KeySetError::Init)?;
        let initial = fetch_keys(&client, endpoint).await?;

        Ok(Self {
            endpoint: endpoint.to_string(),
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

        // Before the key lookup, so these tokens cannot trigger a refresh.
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

async fn fetch_keys(client: &client::Client, endpoint: &str) -> Result<KeySet, KeySetError> {
    let response: JwkSet = client.get(endpoint).await?;

    KeySet::from_jwks(&response)
}

impl VerifyingKey {
    fn allows(&self, algorithm: Algorithm) -> bool {
        self.algorithm.is_none_or(|key_algorithm| key_algorithm == algorithm)
    }

    /// Returns `None` for keys that are not for verifying signatures.
    fn from_jwk(jwk: &Jwk) -> Result<Option<Self>, jsonwebtoken::errors::Error> {
        let common = &jwk.common;
        let use_allows = common
            .public_key_use
            .as_ref()
            .is_none_or(|key_use| *key_use == PublicKeyUse::Signature);
        let operations_allow = common
            .key_operations
            .as_ref()
            .is_none_or(|operations| operations.contains(&KeyOperations::Verify));
        if !use_allows || !operations_allow {
            return Ok(None);
        }

        let algorithm = match common.key_algorithm {
            None => None,
            Some(algorithm) => match algorithm.to_string().parse() {
                Ok(algorithm) => Some(algorithm),
                // Not a signature algorithm, such as RSA-OAEP.
                Err(_) => return Ok(None),
            },
        };

        Ok(Some(Self {
            key: DecodingKey::from_jwk(jwk)?,
            algorithm,
        }))
    }
}

/// What a token must satisfy to be accepted for one issuer.
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

#[derive(Debug)]
struct TokenVerifier {
    /// One per algorithm, because jsonwebtoken cannot mix algorithm families in one validation.
    validations: HashMap<Algorithm, Validation>,
}

impl TokenVerifier {
    fn new(issuer: &str, audience: Option<String>) -> Self {
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

        let validations = SUPPORTED_ALGORITHMS
            .into_iter()
            .map(|algorithm| {
                let mut validation = validation.clone();
                validation.algorithms = vec![algorithm];
                (algorithm, validation)
            })
            .collect();

        Self { validations }
    }

    fn check_algorithm(&self, algorithm: Algorithm) -> Result<(), Error> {
        self.validation_for(algorithm).map(|_| ())
    }

    fn verify(
        &self,
        token: &str,
        algorithm: Algorithm,
        key: &VerifyingKey,
    ) -> Result<HashMap<String, Value>, Error> {
        let validation = self.validation_for(algorithm)?;
        if !key.allows(algorithm) {
            return Err(invalid_token(ErrorKind::InvalidAlgorithm));
        }

        let claims = jsonwebtoken::decode::<HashMap<String, Value>>(token, &key.key, validation)
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
}

fn invalid_token(kind: ErrorKind) -> Error {
    Error::InvalidToken(kind.into())
}

impl KeySet {
    /// Skips keys that are not for verifying signatures.
    fn from_jwks(jwks: &JwkSet) -> Result<Self, KeySetError> {
        let mut by_kid = HashMap::new();
        for jwk in &jwks.keys {
            let Some(key) = VerifyingKey::from_jwk(jwk).map_err(KeySetError::InvalidJwk)? else {
                continue;
            };

            let key_id = jwk.common.key_id.clone().ok_or(KeySetError::MissingKeyId)?;
            by_kid.insert(key_id, key);
        }

        Ok(Self {
            by_kid: Arc::new(by_kid),
            fetched_at: Instant::now(),
        })
    }

    fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() >= KEY_SET_TTL
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::signing_key::SigningKey;
    use axum::extract::State as AxumState;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use jsonwebtoken::{EncodingKey, Header, jwk::Jwk};
    use pretty_assertions::assert_eq;
    use reqwest::StatusCode;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ISSUER: &str = "https://issuer.example";

    const EC_P256_PRIVATE_PEM: &str = include_str!("../../tests/fixtures/ec-p256-private.pem");

    const EC_P384_PRIVATE_PEM: &str = include_str!("../../tests/fixtures/ec-p384-private.pem");

    const RSA_PRIVATE_JWK: &str = include_str!("../../tests/fixtures/rsa-private.jwk");

    fn valid_claims() -> Value {
        let now = epoch_now_secs();

        serde_json::json!({
            "iss": ISSUER,
            "sub": "subject",
            "iat": now,
            "exp": now + 300,
        })
    }

    /// The public JWK and a token signed with the matching EC key.
    fn signed_ec_token(algorithm: Algorithm, claims: &Value) -> (Jwk, String) {
        let pem = match algorithm {
            Algorithm::ES256 => EC_P256_PRIVATE_PEM,
            Algorithm::ES384 => EC_P384_PRIVATE_PEM,
            _ => panic!("expected an EC algorithm"),
        };

        let key = EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
        let mut jwk = Jwk::from_encoding_key(&key, algorithm).unwrap();
        jwk.common.key_id = Some("ec-key".to_string());

        let mut header = Header::new(algorithm);
        header.kid = jwk.common.key_id.clone();
        let token = jsonwebtoken::encode(&header, claims, &key).unwrap();

        (jwk, token)
    }

    /// The public half of the RSA fixture, with the given `alg`.
    fn rsa_public_jwk(alg: Option<&str>) -> Value {
        let private: Value = serde_json::from_str(RSA_PRIVATE_JWK).unwrap();
        let mut jwk = serde_json::json!({
            "kty": "RSA",
            "kid": private["kid"],
            "n": private["n"],
            "e": private["e"],
        });
        if let Some(alg) = alg {
            jwk["alg"] = alg.into();
        }

        jwk
    }

    fn signed_rsa_token(alg: &str) -> String {
        let mut jwk: Value = serde_json::from_str(RSA_PRIVATE_JWK).unwrap();
        jwk["alg"] = alg.into();
        let key: SigningKey = jwk.to_string().parse().unwrap();

        key.sign(&valid_claims()).unwrap()
    }

    fn verifying_key(jwk: impl serde::Serialize) -> Option<VerifyingKey> {
        let jwk: Jwk = serde_json::from_value(serde_json::to_value(jwk).unwrap()).unwrap();

        VerifyingKey::from_jwk(&jwk).unwrap()
    }

    fn verify(token: &str, key: &VerifyingKey) -> Result<HashMap<String, Value>, Error> {
        let algorithm = jsonwebtoken::decode_header(token).unwrap().alg;

        TokenVerifier::new(ISSUER, None).verify(token, algorithm, key)
    }

    fn assert_rejected(result: Result<HashMap<String, Value>, Error>, expected: &ErrorKind) {
        assert!(
            matches!(&result, Err(Error::InvalidToken(error)) if error.kind() == expected),
            "expected {expected:?}, got {result:?}"
        );
    }

    /// Keeps the signature valid base64url, so only verification can fail.
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

        let claims = verify(&token, &verifying_key(jwk).unwrap()).unwrap();

        assert_eq!(claims["iss"], ISSUER);
        assert_eq!(claims["sub"], "subject");
    }

    #[rstest::rstest]
    #[case(Algorithm::ES256)]
    #[case(Algorithm::ES384)]
    fn rejects_ec_token_with_corrupted_signature(#[case] algorithm: Algorithm) {
        let (jwk, token) = signed_ec_token(algorithm, &valid_claims());

        let result = verify(&corrupt_signature(&token), &verifying_key(jwk).unwrap());

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
        // Remove `alg`, so the test reaches the curve check.
        other_jwk.common.key_algorithm = None;

        let result = verify(&token, &verifying_key(other_jwk).unwrap());

        assert_rejected(result, &ErrorKind::InvalidSignature);
    }

    #[rstest::rstest]
    #[case(Algorithm::ES256)]
    #[case(Algorithm::ES384)]
    fn rejects_ec_token_with_rsa_key(#[case] algorithm: Algorithm) {
        let (_, token) = signed_ec_token(algorithm, &valid_claims());

        let result = verify(&token, &verifying_key(rsa_public_jwk(None)).unwrap());

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
        let key = verifying_key(rsa_public_jwk(jwk_alg)).unwrap();

        let result = verify(&signed_rsa_token(token_alg), &key);

        if accepted {
            assert_eq!(result.unwrap()["sub"], "subject");
        } else {
            assert_rejected(result, &ErrorKind::InvalidAlgorithm);
        }
    }

    #[rstest::rstest]
    #[case(serde_json::json!({ "use": "sig", "key_ops": ["verify"] }), true)]
    #[case(serde_json::json!({}), true)]
    #[case(serde_json::json!({ "use": "enc" }), false)]
    #[case(serde_json::json!({ "key_ops": ["encrypt"] }), false)]
    #[case(serde_json::json!({ "key_ops": [] }), false)]
    #[case(serde_json::json!({ "alg": "RSA-OAEP" }), false)]
    fn uses_only_keys_for_signature_verification(#[case] metadata: Value, #[case] used: bool) {
        let mut jwk = rsa_public_jwk(None);
        jwk.as_object_mut().unwrap().extend(metadata.as_object().unwrap().clone());

        assert_eq!(verifying_key(jwk).is_some(), used);
    }

    #[test]
    fn rejects_token_without_iat() {
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("iat");
        let (jwk, token) = signed_ec_token(Algorithm::ES256, &claims);

        let result = verify(&token, &verifying_key(jwk).unwrap());

        assert_rejected(result, &ErrorKind::MissingRequiredClaim("iat".to_string()));
    }

    #[test]
    fn rejects_token_issued_beyond_the_leeway() {
        let mut claims = valid_claims();
        claims["iat"] = (epoch_now_secs() + 120).into();
        let (jwk, token) = signed_ec_token(Algorithm::ES256, &claims);

        let result = verify(&token, &verifying_key(jwk).unwrap());

        assert_rejected(result, &ErrorKind::ImmatureSignature);
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

    fn key_set(keys: Vec<Value>) -> Result<KeySet, KeySetError> {
        KeySet::from_jwks(&serde_json::from_value(serde_json::json!({ "keys": keys })).unwrap())
    }

    #[test]
    fn key_set_requires_key_id() {
        let mut jwk = rsa_public_jwk(None);
        jwk.as_object_mut().unwrap().remove("kid");

        assert!(matches!(key_set(vec![jwk]), Err(KeySetError::MissingKeyId)));
    }

    #[test]
    fn key_set_rejects_malformed_key() {
        let mut jwk = rsa_public_jwk(None);
        jwk["n"] = "!".into();

        assert!(matches!(
            key_set(vec![jwk]),
            Err(KeySetError::InvalidJwk(_))
        ));
    }

    #[test]
    fn key_set_skips_encryption_key_without_key_id() {
        let mut encryption_jwk = rsa_public_jwk(None);
        encryption_jwk.as_object_mut().unwrap().remove("kid");
        encryption_jwk["use"] = "enc".into();

        let keys = key_set(vec![encryption_jwk, rsa_public_jwk(None)]).unwrap();

        assert_eq!(keys.by_kid.len(), 1);
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

    /// A token for key lookup tests. Its signature matches no served key.
    fn token_signed_with(key_id: &str) -> String {
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
