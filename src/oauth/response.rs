use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use utoipa::openapi::{ObjectBuilder, RefOr, Schema};
use utoipa::{PartialSchema, ToSchema};

/// RFC 6749 token response from section 5.1.
#[derive(Serialize, Deserialize, ToSchema, Clone, Hash, Debug, PartialEq)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: TokenType,
    /// Token expiry in seconds. Useful for caching purposes.
    #[serde(rename = "expires_in")]
    pub expires_in_seconds: u64,
}

/// Token type is always Bearer, but this might change in the future.
#[derive(Deserialize, Serialize, ToSchema, Clone, Hash, Debug, PartialEq)]
pub enum TokenType {
    Bearer,
}

/// RFC 6749 error response from section 5.2.
#[derive(Serialize, Deserialize, ToSchema, Debug, Clone, PartialEq)]
pub struct ErrorResponse {
    pub error: OAuthErrorCode,
    #[serde(default)]
    #[serde(rename = "error_description")]
    pub description: String,
}

impl Display for ErrorResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err = serde_json::to_string(&self.error)
            .unwrap_or("BUG: unserializable error message".to_string());
        write!(f, "error={}: error_description={}", err, self.description)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum OAuthErrorCode {
    #[serde(rename = "invalid_request")]
    InvalidRequest,
    #[serde(rename = "invalid_client")]
    InvalidClient,
    #[serde(rename = "invalid_grant")]
    InvalidGrant,
    #[serde(rename = "unauthorized_client")]
    UnauthorizedClient,
    #[serde(rename = "unsupported_grant_type")]
    UnsupportedGrantType,
    #[serde(rename = "invalid_scope")]
    InvalidScope,
    #[serde(rename = "server_error")]
    ServerError,
    #[serde(untagged)]
    Unknown(String),
}

impl ToSchema for OAuthErrorCode {
    fn name() -> Cow<'static, str> {
        Cow::Borrowed("OAuthErrorCode")
    }
}

// This is a workaround as the "untagged" enum variant results in a schema type with nested objects, which is undesirable.
impl PartialSchema for OAuthErrorCode {
    fn schema() -> RefOr<Schema> {
        RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .description(Some(
                    "Known OAuth error codes from RFC 6749. Unknown variants may still be returned as these are propagated from the upstream identity provider.",
                ))
                .schema_type(utoipa::openapi::schema::Type::String)
                .enum_values(Some([
                    "invalid_request".to_string(),
                    "invalid_client".to_string(),
                    "invalid_grant".to_string(),
                    "unauthorized_client".to_string(),
                    "unsupported_grant_type".to_string(),
                    "invalid_scope".to_string(),
                    "server_error".to_string(),
                ]))
                .build(),
        ))
    }
}

/// Based on RFC 7662 introspection response from section 2.2.
///
/// Claims from the original token are copied verbatim to the introspection response as additional properties.
/// The claims present depend on the identity provider.
/// Please refer to the Nais documentation for details:
///
/// - [Entra ID](https://doc.nais.io/auth/entra-id/reference/#claims)
/// - [ID-porten](https://doc.nais.io/auth/idporten/reference/#claims)
/// - [Maskinporten](https://doc.nais.io/auth/maskinporten/reference/#claims)
/// - [TokenX](https://doc.nais.io/auth/tokenx/reference/#claims)
///
/// For Ansattporten specifically, please refer to the Digdir documentation for details:
/// - [Ansattporten](https://docs.digdir.no/docs/ansattporten/ansattporten_om.html)
#[derive(Serialize, Deserialize, ToSchema, Debug, PartialEq, Clone)]
pub struct IntrospectResponse {
    /// Indicates whether the token is valid. If this field is _false_,
    /// the token is invalid and *must* be rejected.
    pub active: bool,

    /// If the token is invalid, this field contains the reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Claims from valid tokens are contained in the introspection response, but only if the token is valid.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl IntrospectResponse {
    pub fn new(claims: impl Into<HashMap<String, Value>>) -> Self {
        Self {
            active: true,
            error: None,
            extra: claims.into(),
        }
    }

    pub fn new_invalid(error_message: impl ToString) -> Self {
        Self {
            active: false,
            error: Some(error_message.to_string()),
            extra: HashMap::default(),
        }
    }
}

impl Display for IntrospectResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.error.is_some() {
            return write!(f, "{}", self.error.as_deref().unwrap_or("unknown error"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ErrorResponse, IntrospectResponse, OAuthErrorCode};
    use pretty_assertions::assert_eq;
    use serde_json::Value;

    #[test]
    fn test_introspect_response_serialization_format() {
        let ok = IntrospectResponse::new([("foo".into(), Value::String("bar".into()))]);
        let failed = IntrospectResponse::new_invalid("my error");

        let serialized = serde_json::to_string(&ok).unwrap();
        assert_eq!(serialized, r#"{"active":true,"foo":"bar"}"#);

        let serialized = serde_json::to_string(&failed).unwrap();
        assert_eq!(serialized, r#"{"active":false,"error":"my error"}"#);
    }

    #[test]
    fn test_serde_oauth_error() {
        let known_code_variant =
            r#"{"error":"invalid_request","error_description":"some description"}"#;
        let unknown_code_variant =
            r#"{"error":"unknown_error","error_description":"some description"}"#;

        let serialized = serde_json::from_str::<ErrorResponse>(known_code_variant);
        assert!(serialized.is_ok());
        let error_response = serialized.unwrap();
        assert_eq!(error_response.error, OAuthErrorCode::InvalidRequest);

        let serialized = serde_json::from_str::<ErrorResponse>(unknown_code_variant);
        assert!(serialized.is_ok());
        let error_response = serialized.unwrap();
        assert_eq!(
            error_response.error,
            OAuthErrorCode::Unknown("unknown_error".to_string())
        );
    }
}
