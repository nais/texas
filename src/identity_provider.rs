use crate::{jwks, types};
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::marker::PhantomData;
use axum::Json;
use axum::response::IntoResponse;
use log::error;
use reqwest::StatusCode;
use crate::handlers::{ApiError, HandlerState};
use crate::types::{IdentityProvider, TokenExchangeRequest, TokenRequest, TokenResponse};

pub trait TokenRequestFactory {
    fn token_request(config: TokenRequestConfig) -> Option<Self>
    where
        Self: Sized;
}

pub struct TokenRequestConfig {
    target: String,
    assertion: String,
    client_id: Option<String>,
    user_token: Option<String>,
}

#[derive(Clone)]
pub struct Provider<T: Serialize> {
    issuer: String, // unused for now; maskinporten might require this as `aud` in client_assertion
    client_id: String,
    pub token_endpoint: String,
    private_jwk: jwt::EncodingKey,
    client_assertion_header: jwt::Header,
    upstream_jwks: jwks::Jwks,
    _fake: PhantomData<T>,
}

#[derive(Serialize)]
pub struct AzureADClientCredentialsTokenRequest {
    grant_type: String, // client_credentials
    client_id: String,
    client_assertion: String,
    client_assertion_type: String, // urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    scope: String,
}

#[derive(Serialize)]
pub struct AzureADOnBehalfOfTokenRequest {
    grant_type: String, // urn:ietf:params:oauth:grant-type:jwt-bearer
    client_id: String,
    client_assertion: String,
    client_assertion_type: String, // urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    scope: String,
    requested_token_use: String, // on_behalf_of
    assertion: String,
}

#[derive(Serialize)]
pub struct MaskinportenTokenRequest {
    grant_type: String,
    assertion: String,
}

#[derive(Serialize)]
pub struct TokenXTokenRequest {
    grant_type: String, // urn:ietf:params:oauth:grant-type:token-exchange
    client_assertion: String,
    client_assertion_type: String, // urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    subject_token_type: String, // urn:ietf:params:oauth:token-type:jwt
    subject_token: String,
    audience: String,
}

impl TokenRequestFactory for AzureADClientCredentialsTokenRequest {
    fn token_request(config: TokenRequestConfig) -> Option<AzureADClientCredentialsTokenRequest> {
        Some(Self {
            grant_type: "client_credentials".to_string(),
            client_id: config.client_id?,
            client_assertion: config.assertion,
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
            scope: config.target,
        })
    }
}
impl TokenRequestFactory for AzureADOnBehalfOfTokenRequest {
    fn token_request(config: TokenRequestConfig) -> Option<Self> {
        Some(Self {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            client_id: config.client_id?,
            client_assertion: config.assertion,
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                .to_string(),
            scope: config.target,
            requested_token_use: "on_behalf_of".to_string(),
            assertion: config.user_token?,
        })
    }
}

impl TokenRequestFactory for MaskinportenTokenRequest {
    fn token_request(config: TokenRequestConfig) -> Option<Self> {
        Some(Self {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            assertion: config.assertion,
        })
    }
}

impl TokenRequestFactory for TokenXTokenRequest {
    fn token_request(config: TokenRequestConfig) -> Option<Self> {
        Some(Self {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            client_assertion: config.assertion,
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                .to_string(),
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            subject_token: config.user_token?,
            audience: config.target,
        })
    }
}

//impl<T> Provider<T> where T: TokenRequestFactory<T> + Serialize
impl<T> Provider<T>
where
    T: Serialize + TokenRequestFactory,
{
    pub fn new(
        issuer: String,
        client_id: String,
        token_endpoint: String,
        private_jwk: String,
        upstream_jwks: jwks::Jwks,
    ) -> Option<Self> {
        let client_private_jwk: jwk::JsonWebKey = private_jwk.parse().ok()?;
        let alg: jwt::Algorithm = client_private_jwk.algorithm?.into();
        let kid: String = client_private_jwk.key_id.clone()?;
        let mut client_assertion_header = jwt::Header::new(alg);
        client_assertion_header.kid = Some(kid);
        Some(Self {
            issuer,
            client_id,
            token_endpoint,
            client_assertion_header,
            upstream_jwks,
            private_jwk: client_private_jwk.key.to_encoding_key(),
            _fake: Default::default(),
        })
    }

    pub async fn introspect(&mut self, token: String) -> HashMap<String, Value> {
        self.upstream_jwks
            .validate(&token)
            .await
            .map(|mut hashmap| {
                hashmap.insert("active".to_string(), Value::Bool(true));
                hashmap
            })
            .unwrap_or_else(|err| {
                HashMap::from([
                    ("active".to_string(), Value::Bool(false)),
                    ("error".to_string(), Value::String(format!("{:?}", err))),
                ])
            })
    }

    fn create_assertion(&self, ass: AssertionClaimType) -> Result<String, jwt::errors::Error> {
        AssertionClaims::new(
            self.token_endpoint.clone(),
            self.client_id.clone(),
            ass,
        ).serialize(&self.client_assertion_header, &self.private_jwk)
    }

    pub async fn get_token(
        &self,
        _state: HandlerState,
        request: TokenRequest,
    ) -> Result<impl IntoResponse, ApiError> {
        let assertion = match request.identity_provider {
            IdentityProvider::AzureAD => self.create_assertion(AssertionClaimType::WithSub(self.client_id.clone())).unwrap(),
            IdentityProvider::TokenX => self.create_assertion(AssertionClaimType::WithSub(self.client_id.clone())).unwrap(),
            IdentityProvider::Maskinporten => self.create_assertion(AssertionClaimType::WithScope(request.target.clone())).unwrap()
        };

        let params = T::token_request(TokenRequestConfig {
            target: request.target,
            assertion,
            client_id: Some(self.client_id.clone()),
            user_token: None,
        }).unwrap();

        let client = reqwest::Client::new();
        let response = client
            .post(self.token_endpoint.clone())
            .header("accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(ApiError::UpstreamRequest)?;

        if response.status() >= StatusCode::BAD_REQUEST {
            let err: types::ErrorResponse = response.json().await.map_err(ApiError::JSON)?;
            return Err(ApiError::Upstream(err));
        }

        let res: TokenResponse = response
            .json()
            .await
            .inspect_err(|err| error!("Identity provider returned invalid JSON: {:?}", err))
            .map_err(ApiError::JSON)?;

        Ok((StatusCode::OK, Json(res)))
    }

    pub async fn exchange_token(
        &self,
        _state: HandlerState,
        request: TokenExchangeRequest,
    ) -> Result<impl IntoResponse, ApiError> {
        let assertion = match request.identity_provider {
            IdentityProvider::AzureAD => self.create_assertion(AssertionClaimType::WithSub(self.client_id.clone())).unwrap(),
            IdentityProvider::TokenX => self.create_assertion(AssertionClaimType::WithSub(self.client_id.clone())).unwrap(),
            IdentityProvider::Maskinporten => self.create_assertion(AssertionClaimType::WithScope(request.target.clone())).unwrap()
        };

        let params = T::token_request(TokenRequestConfig {
            target: request.target,
            assertion,
            client_id: Some(self.client_id.clone()),
            user_token: Some(request.user_token),
        }).unwrap();

        let client = reqwest::Client::new();
        let response = client
            .post(self.token_endpoint.clone())
            .header("accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(ApiError::UpstreamRequest)?;

        if response.status() >= StatusCode::BAD_REQUEST {
            let err: types::ErrorResponse = response.json().await.map_err(ApiError::JSON)?;
            return Err(ApiError::Upstream(err));
        }

        let res: TokenResponse = response
            .json()
            .await
            .inspect_err(|err| error!("Identity provider returned invalid JSON: {:?}", err))
            .map_err(ApiError::JSON)?;

        Ok((StatusCode::OK, Json(res)))
    }
}

// FIXME: split into client_assertion and jwt_bearer types
#[derive(serde::Serialize, serde::Deserialize)]
struct AssertionClaims {
    exp: usize,
    iat: usize,
    nbf: usize,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    iss: String,
    aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
}

enum AssertionClaimType {
    WithScope(String),
    #[allow(dead_code)]
    WithSub(String),
}

impl AssertionClaims {
    fn new(token_endpoint: String, client_id: String, ass: AssertionClaimType) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jti = uuid::Uuid::new_v4();

        let (scope, sub) = match ass {
            AssertionClaimType::WithScope(scope) => (Some(scope), None),
            AssertionClaimType::WithSub(sub) => (None, Some(sub)),
        };

        AssertionClaims {
            exp: (now + 30) as usize,
            iat: now as usize,
            nbf: now as usize,
            jti: jti.to_string(),
            scope,
            sub,
            iss: client_id, // issuer of the token is the client itself
            aud: token_endpoint, // audience of the token is the issuer
        }
    }

    fn serialize(
        &self,
        client_assertion_header: &jwt::Header,
        key: &jwt::EncodingKey,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        jwt::encode(client_assertion_header, &self, key)
    }
}
