use crate::oauth::identity_provider::IdentityProvider;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use std::hash::{Hash, Hasher};
use utoipa::ToSchema;

/// Use this data type to request a machine token.
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug, Eq)]
pub struct TokenRequest {
    /// Scope or identifier for the target application.
    pub target: String,
    pub identity_provider: IdentityProvider,
    /// Resource indicator for audience-restricted tokens [(RFC 8707)](https://www.rfc-editor.org/rfc/rfc8707.html).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<AuthorizationDetails>,
    /// Force renewal of token. Defaults to false if omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cache: Option<bool>,
}

impl TokenRequest {
    pub(crate) fn with_normalized_target(&self) -> Self {
        Self {
            target: self.identity_provider.normalize_target(self.target.clone()),
            ..self.clone()
        }
    }
}

// Manual PartialEq/Hash so that `skip_cache` does not influence cache lookup keys.
impl PartialEq for TokenRequest {
    fn eq(&self, other: &Self) -> bool {
        self.target == other.target
            && self.identity_provider == other.identity_provider
            && self.resource == other.resource
            && self.authorization_details == other.authorization_details
    }
}

impl Hash for TokenRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.target.hash(state);
        self.identity_provider.hash(state);
        self.resource.hash(state);
        self.authorization_details.hash(state);
    }
}

/// Authorization details for rich authorization requests [(RFC 9396)](https://www.rfc-editor.org/rfc/rfc9396.html).
/// Must be a JSON array of objects, the exact contents of which depend on the identity provider.
/// Texas does not validate this property and only forwards its value to the identity provider.
#[derive(Serialize, ToSchema, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorizationDetails(pub Vec<Map<String, Value>>);

impl<'de> Deserialize<'de> for AuthorizationDetails {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RequestValue {
            Seq(Vec<Map<String, Value>>), // Directly as a JSON array
            Str(String),                  // As a JSON string (for form-encoded data)
        }

        match RequestValue::deserialize(deserializer)? {
            RequestValue::Seq(v) => Ok(AuthorizationDetails::from(v)),
            RequestValue::Str(s) => {
                let v: Vec<Map<String, Value>> = serde_json::from_str(&s).map_err(|e| {
                    serde::de::Error::custom(format!(
                        "failed to parse authorization_details JSON string: {}",
                        e
                    ))
                })?;
                Ok(AuthorizationDetails::from(v))
            }
        }
    }
}

impl From<Vec<Map<String, Value>>> for AuthorizationDetails {
    fn from(v: Vec<Map<String, Value>>) -> Self {
        AuthorizationDetails(v)
    }
}

/// Use this data type to exchange a user token for a machine token.
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug, Eq)]
pub struct TokenExchangeRequest {
    /// Scope or identifier for the target application.
    pub target: String,
    pub identity_provider: IdentityProvider,

    /// The user's access token, usually found in the _Authorization_ header in requests to your application.
    pub user_token: String,
    /// Force renewal of token. Defaults to false if omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cache: Option<bool>,
}

impl TokenExchangeRequest {
    pub(crate) fn with_normalized_target(&self) -> Self {
        Self {
            target: self.identity_provider.normalize_target(self.target.clone()),
            ..self.clone()
        }
    }
}

// Manual PartialEq/Hash so that `skip_cache` does not influence cache lookup keys.
impl PartialEq for TokenExchangeRequest {
    fn eq(&self, other: &Self) -> bool {
        self.target == other.target
            && self.identity_provider == other.identity_provider
            && self.user_token == other.user_token
    }
}

impl Hash for TokenExchangeRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.target.hash(state);
        self.identity_provider.hash(state);
        self.user_token.hash(state);
    }
}

/// This data type holds the OAuth token that will be validated in the introspect endpoint.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct IntrospectRequest {
    pub token: String,
    pub identity_provider: IdentityProvider,
}

#[cfg(test)]
mod tests {
    use super::{AuthorizationDetails, TokenExchangeRequest, TokenRequest};
    use crate::oauth::identity_provider::IdentityProvider;
    use pretty_assertions::assert_eq;
    use rstest::rstest;
    use serde::Deserialize;
    use serde_json::json;
    use std::hash::{DefaultHasher, Hash, Hasher};

    macro_rules! auth_details {
        ( [ $( { $($k:tt : $v:tt),* $(,)? } ),* $(,)? ] ) => {
            AuthorizationDetails::from(vec![
                $({
                    let mut m = ::serde_json::Map::new();
                    $(
                        m.insert($k.to_string(), ::serde_json::json!($v));
                    )*
                    m
                }),*
            ])
        };
    }

    #[derive(Deserialize, Debug)]
    struct AuthorizationDetailsWrapper {
        authorization_details: AuthorizationDetails,
    }

    #[rstest]
    #[case(|mut req: TokenRequest| { req.target = "some_target".to_string(); req }, true)]
    #[case(|mut req: TokenRequest| { req.target = "some_other_target".to_string(); req }, false)]
    #[case(|mut req: TokenRequest| { req.identity_provider = IdentityProvider::Maskinporten; req }, true)]
    #[case(|mut req: TokenRequest| { req.identity_provider = IdentityProvider::TokenX; req }, false)]
    #[case(|mut req: TokenRequest| { req.resource = None; req }, true)]
    #[case(|mut req: TokenRequest| { req.resource = Some("some_resource".to_string()); req }, false)]
    #[case(|mut req: TokenRequest| { req.authorization_details = None; req }, true)]
    #[case(|mut req: TokenRequest| { req.authorization_details = Some(auth_details!([])); req }, false)]
    #[case(|mut req: TokenRequest| { req.authorization_details = Some(auth_details!([ { "type": "some_type" } ])); req }, false)]
    #[case(|mut req: TokenRequest| { req.skip_cache = None; req }, true)]
    #[case(|mut req: TokenRequest| { req.skip_cache = Some(true); req }, true)]
    #[case(|mut req: TokenRequest| { req.skip_cache = Some(false); req }, true)]
    fn token_request_equality_should_work(
        #[case] mutate: fn(TokenRequest) -> TokenRequest,
        #[case] expect_equal: bool,
    ) {
        let original = TokenRequest {
            target: "some_target".to_string(),
            identity_provider: IdentityProvider::Maskinporten,
            resource: None,
            authorization_details: None,
            skip_cache: None,
        };
        let mutated = mutate(original.clone());
        assert_eq!(original == mutated, expect_equal);

        let mut hasher1 = DefaultHasher::new();
        original.hash(&mut hasher1);
        let h1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        mutated.hash(&mut hasher2);
        let h2 = hasher2.finish();

        if expect_equal {
            assert_eq!(h1, h2);
        } else {
            assert_ne!(h1, h2);
        }
    }

    #[rstest]
    #[case(
        r#"[{"type":"some_type"}]"#,
        auth_details!([ { "type": "some_type" } ])
    )]
    #[case(
        r#"[{"type":"some_type"},{"some_array":[{"type": "some_other_type"}]}]"#,
        auth_details!([
            { "type": "some_type" },
            { "some_array": [ { "type": "some_other_type" } ] }
        ])
    )]
    #[case(r#"[]"#, auth_details!([]))]
    fn valid_json_authorization_details_should_deserialize(
        #[case] input: &str,
        #[case] expected: AuthorizationDetails,
    ) {
        let deserialized = serde_json::from_str::<AuthorizationDetails>(input);
        assert!(deserialized.is_ok());
        assert_eq!(deserialized.unwrap(), expected);
    }

    #[rstest]
    #[case("not a json array")]
    #[case(r#"{"type":"some_type"}"#)]
    #[case(r#"[{"type":"some_type"}"#)]
    #[case(r#"42"#)]
    #[case(r#"null"#)]
    #[case(r#"true"#)]
    #[case(r#"false"#)]
    fn invalid_json_authorization_details_should_not_deserialize(#[case] input: &str) {
        let deserialized = serde_json::from_str::<AuthorizationDetails>(input);
        assert!(deserialized.is_err());
    }

    #[test]
    fn normalized_requests_preserve_the_original_target() {
        let token_request = TokenRequest {
            target: "cluster:namespace:application".to_string(),
            identity_provider: IdentityProvider::EntraID,
            resource: None,
            authorization_details: None,
            skip_cache: None,
        };
        let exchange_request = TokenExchangeRequest {
            target: "cluster:namespace:application".to_string(),
            identity_provider: IdentityProvider::EntraID,
            user_token: "user-token".to_string(),
            skip_cache: None,
        };

        let normalized_token_request = token_request.with_normalized_target();
        let normalized_exchange_request = exchange_request.with_normalized_target();

        assert_eq!(
            normalized_token_request.target,
            "api://cluster.namespace.application/.default"
        );
        assert_eq!(
            normalized_exchange_request.target,
            "api://cluster.namespace.application/.default"
        );
        assert_eq!(token_request.target, "cluster:namespace:application");
        assert_eq!(exchange_request.target, "cluster:namespace:application");
    }

    #[rstest]
    #[case(
        "authorization_details=%5B%7B%22type%22%3A%22some_type%22%7D%5D",
        auth_details!([ { "type": "some_type" } ])
    )]
    #[case(
        "authorization_details=%5B%7B%22type%22%3A%22some_type%22%7D%2C%7B%22some_array%22%3A%5B%7B%22type%22%3A%20%22some_other_type%22%7D%5D%7D%5D",
        auth_details!([
            { "type": "some_type"},
            { "some_array": [ { "type": "some_other_type" } ] }
        ])
    )]
    #[case("authorization_details=%5B%5D", auth_details!([]))]
    fn valid_form_authorization_details_should_deserialize(
        #[case] form: &str,
        #[case] expected: AuthorizationDetails,
    ) {
        let res = serde_urlencoded::from_str::<AuthorizationDetailsWrapper>(form).unwrap();
        assert_eq!(res.authorization_details, expected);
    }

    #[rstest]
    #[case("authorization_details=not+a+json+array")]
    #[case("authorization_details=%7B%22type%22%3A%22t%22%7D")]
    #[case("authorization_details=%5B%7B%22type%22%3A%22t%22%7D")]
    fn invalid_form_authorization_details_should_not_deserialize(#[case] form: &str) {
        let res = serde_urlencoded::from_str::<AuthorizationDetailsWrapper>(form);
        assert!(res.is_err());
    }

    #[rstest]
    #[case(auth_details!([]), json!([]))]
    #[case(auth_details!([ { "type": "some_type" } ]), json!([ { "type": "some_type" } ]))]
    fn authorization_details_should_serialize(
        #[case] input: AuthorizationDetails,
        #[case] expected: serde_json::Value,
    ) {
        let serialized = serde_json::to_value(&input).unwrap();
        assert_eq!(serialized, expected);
    }
}
