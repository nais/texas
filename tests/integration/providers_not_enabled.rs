use crate::helpers::{app, http};
use axum::http::StatusCode;
use test_log::test;
use texas::oauth::identity_provider::{
    ErrorResponse, IdentityProvider, IntrospectRequest, IntrospectResponse, OAuthErrorCode,
    TokenExchangeRequest, TokenRequest,
};

/// Test that Texas returns an appropriate error when the identity provider is not supported.
#[test(tokio::test)]
async fn all_providers() {
    let testapp = app::TestApp::new_no_providers().await;
    let address = testapp.address();
    let join_handler = tokio::spawn(async move {
        testapp.run().await;
    });

    let providers = [
        IdentityProvider::EntraID,
        IdentityProvider::IDPorten,
        IdentityProvider::Maskinporten,
        IdentityProvider::TokenX,
    ];
    for provider in providers {
        http::test_well_formed_json_request(
            app::token_url(&address).as_str(),
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

        http::test_well_formed_json_request(
            app::token_exchange_url(&address).as_str(),
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

        http::test_well_formed_json_request(
            app::introspect_url(&address).as_str(),
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
