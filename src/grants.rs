use serde::Serialize;

pub trait TokenRequestBuilder: Send + Sync + Serialize {
    fn token_request(config: TokenRequestBuilderParams) -> Option<Self>
    where
        Self: Sized;
}

pub struct TokenRequestBuilderParams {
    pub target: String,
    pub assertion: String,
    pub client_id: Option<String>,
    pub user_token: Option<String>,
}

// TODO: these might be generic over identity provider "capabilities" (which for a given provider we declare support or preference for), e.g.
//  - GrantTypes (client_credentials, jwt-bearer, token-exchange)
//  - AuthenticationMethods (private_key_jwt, client_secret_post, none)

#[derive(Serialize)]
pub struct ClientCredentials {
    grant_type: String, // client_credentials
    client_id: String,
    client_assertion: String,
    client_assertion_type: String, // urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    scope: String,
}

#[derive(Serialize)]
pub struct OnBehalfOf {
    grant_type: String, // urn:ietf:params:oauth:grant-type:jwt-bearer
    client_id: String,
    client_assertion: String,
    client_assertion_type: String, // urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    scope: String,
    requested_token_use: String, // on_behalf_of
    assertion: String,
}

#[derive(Serialize)]
pub struct JWTBearer {
    grant_type: String,
    assertion: String,
}

#[derive(Serialize)]
pub struct TokenExchange {
    grant_type: String, // urn:ietf:params:oauth:grant-type:token-exchange
    client_assertion: String,
    client_assertion_type: String, // urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    subject_token_type: String,    // urn:ietf:params:oauth:token-type:jwt
    subject_token: String,
    audience: String,
}

impl TokenRequestBuilder for ClientCredentials {
    fn token_request(config: TokenRequestBuilderParams) -> Option<ClientCredentials> {
        Some(Self {
            grant_type: "client_credentials".to_string(),
            client_id: config.client_id?,
            client_assertion: config.assertion,
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                .to_string(),
            scope: config.target,
        })
    }
}

impl TokenRequestBuilder for OnBehalfOf {
    fn token_request(config: TokenRequestBuilderParams) -> Option<Self> {
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

impl TokenRequestBuilder for JWTBearer {
    fn token_request(config: TokenRequestBuilderParams) -> Option<Self> {
        Some(Self {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            assertion: config.assertion,
        })
    }
}

impl TokenRequestBuilder for TokenExchange {
    fn token_request(config: TokenRequestBuilderParams) -> Option<Self> {
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

impl TokenRequestBuilder for () {
    fn token_request(_: TokenRequestBuilderParams) -> Option<Self> {
        None
    }
}
