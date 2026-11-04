use super::{Error, JwtValidator, KeySetError};
use crate::http::client;
use crate::oauth::assertion::epoch_now_secs;
use crate::oauth::jwk::set::KeySet;
use crate::oauth::jwk::signing::SigningKey;
use crate::oauth::jwk::test_helpers::rsa_public_jwk;
use crate::oauth::jwk::test_helpers::{IDP_RSA_PRIVATE_JWK, with_alg};
use axum::extract::State as AxumState;
use axum::response::IntoResponse;
use axum::routing::get;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::StatusCode;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub(super) const ISSUER: &str = "https://issuer.example";

pub(super) const EC_P256_PRIVATE_PEM: &str =
    include_str!("../../../tests/fixtures/ec-p256-private.pem");

pub(super) const EC_P384_PRIVATE_PEM: &str =
    include_str!("../../../tests/fixtures/ec-p384-private.pem");

pub(super) fn valid_claims() -> Value {
    let now = epoch_now_secs();

    serde_json::json!({
        "iss": ISSUER,
        "sub": "subject",
        "iat": now,
        "exp": now + 300,
    })
}

pub(super) fn signed_ec_token(algorithm: Algorithm, claims: &Value) -> (Jwk, String) {
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

pub(super) fn signed_rsa_token(alg: &str) -> String {
    let key: SigningKey = with_alg(IDP_RSA_PRIVATE_JWK, alg).to_string().parse().unwrap();

    super::sign(&key, &valid_claims()).unwrap()
}

pub(super) fn assert_rejected(result: Result<HashMap<String, Value>, Error>, expected: &ErrorKind) {
    assert!(
        matches!(&result, Err(Error::InvalidToken(error)) if error.kind() == expected),
        "expected {expected:?}, got {result:?}"
    );
}

impl JwtValidator {
    /// A validator without keys that never fetches any, for checking tokens against a given key.
    pub(super) fn without_keys() -> Self {
        let keys = KeySet::from_jwks(&JwkSet { keys: vec![] }).unwrap();

        Self::with_keys(
            ISSUER,
            "http://jwks.invalid",
            None,
            client::discovery().unwrap(),
            keys,
        )
    }
}

/// A stand-in for an identity provider's JWKS endpoint, so that tests can rotate keys, fail
/// requests, and count how often the endpoint was asked for keys.
pub(super) struct MockIdentityProvider {
    pub(super) url: String,
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
    pub(super) async fn start() -> Self {
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

    pub(super) async fn connect(&self) -> Result<JwtValidator, KeySetError> {
        JwtValidator::new(ISSUER, &self.url, None).await
    }

    pub(super) fn hits(&self) -> usize {
        self.state.hits.load(Ordering::SeqCst)
    }

    pub(super) fn serve(&self, body: String) {
        self.respond_with(StatusCode::OK, body);
    }

    pub(super) fn serve_keys(&self, key_ids: &[&str]) {
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

    pub(super) fn respond_with(&self, status: StatusCode, body: String) {
        let mut response = self.state.response.lock().unwrap();
        response.status = status;
        response.body = body;
    }
}
