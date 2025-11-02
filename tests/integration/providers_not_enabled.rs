use crate::helpers::http::{
    introspect_url, test_well_formed_json_request, token_exchange_url, token_url,
};
use crate::helpers::server::TestServer;
use axum::http::StatusCode;
use test_log::test;
use texas::oauth::identity_provider::{
    ErrorResponse, IdentityProvider, IntrospectRequest, IntrospectResponse, OAuthErrorCode,
    TokenExchangeRequest, TokenRequest,
};

/// Test that Texas returns an appropriate error when the identity provider is not supported.
#[test(tokio::test)]
async fn all_providers() {
    let server = TestServer::new_no_providers().await;
    let address = server.address();
    let join_handler = tokio::spawn(async move {
        server.run().await;
    });

    let providers = [
        IdentityProvider::EntraID,
        IdentityProvider::IDPorten,
        IdentityProvider::Maskinporten,
        IdentityProvider::TokenX,
    ];
    for provider in providers {
        test_well_formed_json_request(
            token_url(&address).as_str(),
            TokenRequest {
                target: "some_target".to_string(),
                identity_provider: provider,
                resource: None,
                authorization_details: None,
                skip_cache: None,
            },
            ErrorResponse {
                error: OAuthErrorCode::InvalidRequest,
                description: format!("identity provider '{provider}' is not enabled"),
            },
            StatusCode::BAD_REQUEST,
        )
        .await;

        test_well_formed_json_request(
            token_exchange_url(&address).as_str(),
            TokenExchangeRequest {
                target: "some_target".to_string(),
                identity_provider: provider,
                user_token: "some_token".to_string(),
                skip_cache: None,
            },
            ErrorResponse {
                error: OAuthErrorCode::InvalidRequest,
                description: format!("identity provider '{provider}' is not enabled"),
            },
            StatusCode::BAD_REQUEST,
        )
        .await;

        test_well_formed_json_request(
            introspect_url(&address).as_str(),
            IntrospectRequest {
                token: "some_token".to_string(),
                identity_provider: provider,
            },
            IntrospectResponse::new_invalid(format!(
                "identity provider '{provider}' is not enabled"
            )),
            StatusCode::OK,
        )
        .await;
    }

    join_handler.abort();
}
