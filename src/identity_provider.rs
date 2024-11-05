use crate::claims::{serialize, Assertion};
use crate::handlers::ApiError;
use crate::jwks;
use axum::response::IntoResponse;
use axum::Json;
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use log::error;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;

// TODO: look into organizing, moving and renaming these structs more appropriately ("types" is a bit vague)

/// This is an upstream RFCXXXX token response.
/// Delivered both from upstream and to Texas clients.
#[derive(Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: TokenType,
    #[serde(rename = "expires_in")]
    pub expires_in_seconds: usize,
}

/// Token type is always Bearer, but this might change in the future.
///
/// This data type exists primarily for forwards API compatibility.
#[derive(Deserialize, Serialize)]
pub enum TokenType {
    Bearer,
}

/// This is an RFCXXXX error response.
/// Delivered both from upstream and to Texas clients.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(rename = "error_description")]
    pub description: String,
}

impl Display for ErrorResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error, self.description)
    }
}

/// Which identity provider do we want to use with token fetch, exchange and validation?
///
/// FIXME: OpenAPI docs
#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum IdentityProvider {
    #[serde(rename = "azuread")]
    AzureAD,
    #[serde(rename = "tokenx")]
    TokenX,
    #[serde(rename = "maskinporten")]
    Maskinporten,
}

/// This is a token request that comes from the application we are serving.
///
/// FIXME: OpenAPI docs
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TokenRequest {
    pub target: String, // typically <cluster>:<namespace>:<app>
    pub identity_provider: IdentityProvider,
}

/// This is a token exchange request that comes from the application we are serving.
///
/// FIXME: OpenAPI docs
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TokenExchangeRequest {
    pub target: String,
    pub identity_provider: IdentityProvider,
    pub user_token: String,
}

/// This is a token introspection/validation request that comes from the application we are serving.
///
/// FIXME: OpenAPI docs
#[derive(Serialize, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
}
pub trait TokenRequestBuilder {
    fn token_request(config: TokenRequestParams) -> Option<Self>
    where
        Self: Sized;
}

pub struct TokenRequestParams {
    target: String,
    assertion: String,
    client_id: Option<String>,
    user_token: Option<String>,
}

// TODO: these might be generic over identity provider "capabilities" (which for a given provider we declare support or preference for), e.g.
//  - GrantTypes (client_credentials, jwt-bearer, token-exchange)
//  - AuthenticationMethods (private_key_jwt, client_secret_post, none)

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

impl TokenRequestBuilder for AzureADClientCredentialsTokenRequest {
    fn token_request(config: TokenRequestParams) -> Option<AzureADClientCredentialsTokenRequest> {
        Some(Self {
            grant_type: "client_credentials".to_string(),
            client_id: config.client_id?,
            client_assertion: config.assertion,
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
            scope: config.target,
        })
    }
}

impl TokenRequestBuilder for AzureADOnBehalfOfTokenRequest {
    fn token_request(config: TokenRequestParams) -> Option<Self> {
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

impl TokenRequestBuilder for MaskinportenTokenRequest {
    fn token_request(config: TokenRequestParams) -> Option<Self> {
        Some(Self {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            assertion: config.assertion,
        })
    }
}

impl TokenRequestBuilder for TokenXTokenRequest {
    fn token_request(config: TokenRequestParams) -> Option<Self> {
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

#[derive(Clone)]
pub struct Provider<R, A> {
    client_id: String,
    pub token_endpoint: String,
    private_jwk: jwt::EncodingKey,
    client_assertion_header: jwt::Header,
    upstream_jwks: jwks::Jwks,
    _fake_request: PhantomData<R>,
    _fake_assertion: PhantomData<A>,
}

impl<R, A> Provider<R, A>
where
    R: Serialize + TokenRequestBuilder,
    A: Serialize + Assertion,
{
    pub fn new(
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
            client_id,
            token_endpoint,
            client_assertion_header,
            upstream_jwks,
            private_jwk: client_private_jwk.key.to_encoding_key(),
            _fake_request: Default::default(),
            _fake_assertion: Default::default(),
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

    async fn get_token_with_config(&self, config: TokenRequestParams,
    ) -> Result<impl IntoResponse, ApiError> {
        let params = R::token_request(config).ok_or(ApiError::Sign)?;

        let client = reqwest::Client::new();
        let response = client
            .post(self.token_endpoint.clone())
            .header("accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(ApiError::UpstreamRequest)?;

        let status = response.status();
        if status >= StatusCode::BAD_REQUEST {
            let err: ErrorResponse = response.json().await.map_err(ApiError::JSON)?;
            let err = ApiError::Upstream {
                status_code: status,
                error: err
            };
            error!("get_token_with_config: {}", err);
            return Err(err);
        }

        let res: TokenResponse = response
            .json()
            .await
            .inspect_err(|err| error!("Identity provider returned invalid JSON: {:?}", err))
            .map_err(ApiError::JSON)?;

        Ok((StatusCode::OK, Json(res)))
    }

    pub async fn get_token(
        &self,
        request: TokenRequest,
    ) -> Result<impl IntoResponse, ApiError> {
        let token_request = TokenRequestParams {
            target: request.target.clone(),
            assertion: self.create_assertion(request.target.clone()),
            client_id: Some(self.client_id.clone()),
            user_token: None,
        };
        self.get_token_with_config(token_request).await
    }

    pub async fn exchange_token(
        &self,
        request: TokenExchangeRequest,
    ) -> Result<impl IntoResponse, ApiError> {
        let token_request = TokenRequestParams {
            target: request.target.clone(),
            assertion: self.create_assertion(request.target.clone()),
            client_id: Some(self.client_id.clone()),
            user_token: Some(request.user_token),
        };
        self.get_token_with_config(token_request).await
    }

    fn create_assertion(&self, target: String) -> String {
        let assertion = A::new(self.token_endpoint.clone(), self.client_id.clone(), target);
        serialize(assertion, &self.client_assertion_header, &self.private_jwk).unwrap()
    }
}
