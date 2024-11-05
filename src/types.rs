use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

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
