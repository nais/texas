use crate::helpers::http::RequestFormat;
use crate::helpers::{app, http, jwt};
use pretty_assertions::{assert_eq, assert_ne};
use reqwest::StatusCode;
use test_log::test;
use texas::oauth::identity_provider::{
    ErrorResponse, IdentityProvider, IntrospectRequest, OAuthErrorCode, TokenExchangeRequest,
    TokenResponse,
};

/// Test a full round-trip of the `/token/exchange` endpoint.
///
/// Content-type encodings tested are both `application/json` and `application/x-www-form-urlencoded`.
///
/// Test token exchange as follows:
///   1. Request an initial token from the mock oauth2 server using the `/token` endpoint
///   2. Exchange that token into a on-behalf-of token using Texas' `/token` endpoint
///   3. Introspect the resulting token and check parameters
#[test(tokio::test)]
async fn all_providers() {
    let testapp = app::TestApp::new().await;
    let address = testapp.address();
    let join_handler = tokio::spawn(async move {
        testapp.app.run().await;
    });
    let docker = testapp.docker.unwrap();
    let identity_provider_address = format!("{}:{}", docker.host.clone(), docker.port);

    // All happy cases
    for format in [RequestFormat::Form, RequestFormat::Json] {
        token_exchange_token(
            &testapp.cfg.azure_ad.clone().unwrap().issuer,
            &testapp.cfg.azure_ad.clone().unwrap().client_id,
            &address,
            &identity_provider_address,
            IdentityProvider::AzureAD,
            format.clone(),
        )
        .await;

        token_exchange_token(
            &testapp.cfg.token_x.clone().unwrap().issuer,
            &testapp.cfg.token_x.clone().unwrap().client_id,
            &address,
            &identity_provider_address,
            IdentityProvider::TokenX,
            format.clone(),
        )
        .await;
    }

    test_token_exchange_missing_or_empty_user_token(&address).await;
    test_token_exchange_unsupported_identity_provider(&address).await;

    join_handler.abort();
}

/// this tests the full token exchange roundtrip:
///  1. fetch user token from mock-oauth2-server
///  2. exchange user token for on-behalf-of token at /token/exchange
///  3. introspect the resulting token at /introspect
async fn token_exchange_token(
    expected_issuer: &str,
    target: &str,
    address: &str,
    identity_provider_address: &str,
    identity_provider: IdentityProvider,
    request_format: RequestFormat,
) {
    let user_token: TokenResponse =
        http::get_user_token(identity_provider_address, identity_provider).await;
    let request = TokenExchangeRequest {
        target: target.to_string(),
        identity_provider,
        user_token: user_token.access_token.clone(),
        skip_cache: None,
    };
    let first_token_response =
        app::test_happy_path_token_exchange(address, request.clone(), request_format.clone()).await;
    let first_token_introspect = app::test_happy_path_introspect(
        address,
        expected_issuer,
        IntrospectRequest {
            token: first_token_response.access_token.clone(),
            identity_provider,
        },
        request_format.clone(),
    )
    .await;

    assert!(jwt::subject(&first_token_introspect).is_some());

    // different target should return a different token
    let different_target_token_response = app::test_happy_path_token_exchange(
        address,
        TokenExchangeRequest {
            target: "different_target".to_string(),
            identity_provider,
            user_token: user_token.access_token.clone(),
            skip_cache: None,
        },
        request_format.clone(),
    )
    .await;
    assert_ne!(
        different_target_token_response.access_token,
        first_token_response.access_token
    );

    // different user token should return a different token
    let user_token_2: TokenResponse =
        http::get_user_token(identity_provider_address, identity_provider).await;
    let different_user_token_response = app::test_happy_path_token_exchange(
        address,
        TokenExchangeRequest {
            target: target.to_string(),
            identity_provider,
            user_token: user_token_2.access_token.clone(),
            skip_cache: None,
        },
        request_format.clone(),
    )
    .await;
    assert_ne!(
        different_user_token_response.access_token,
        first_token_response.access_token
    );
    assert_ne!(
        different_user_token_response.access_token,
        different_target_token_response.access_token
    );

    // second token request with same inputs should return cached token
    let second_token_response =
        app::test_happy_path_token_exchange(address, request, request_format.clone()).await;
    let second_token_introspect = app::test_happy_path_introspect(
        address,
        expected_issuer,
        IntrospectRequest {
            token: second_token_response.access_token.clone(),
            identity_provider,
        },
        request_format.clone(),
    )
    .await;

    assert!(jwt::subject(&second_token_introspect).is_some());

    assert_eq!(
        second_token_response.access_token,
        first_token_response.access_token
    );
    assert_ne!(
        second_token_response.access_token,
        different_target_token_response.access_token
    );
    assert_ne!(
        second_token_response.access_token,
        different_user_token_response.access_token
    );
    assert_eq!(
        jwt::issuer(&second_token_introspect),
        jwt::issuer(&first_token_introspect)
    );
    assert_eq!(
        jwt::jwt_id(&second_token_introspect),
        jwt::jwt_id(&first_token_introspect)
    );
    assert_eq!(
        jwt::subject(&second_token_introspect),
        jwt::subject(&first_token_introspect)
    );

    // third token request with skip_cache=true should return a new token
    let third_token_response = app::test_happy_path_token_exchange(
        address,
        TokenExchangeRequest {
            target: target.to_string(),
            identity_provider,
            user_token: user_token.access_token.clone(),
            skip_cache: Some(true),
        },
        request_format.clone(),
    )
    .await;
    let third_token_introspect = app::test_happy_path_introspect(
        address,
        expected_issuer,
        IntrospectRequest {
            token: third_token_response.access_token.clone(),
            identity_provider,
        },
        request_format.clone(),
    )
    .await;

    assert!(jwt::subject(&third_token_introspect).is_some());

    assert_ne!(
        third_token_response.access_token,
        first_token_response.access_token
    );
    assert_ne!(
        third_token_response.access_token,
        second_token_response.access_token
    );
    assert_ne!(
        third_token_response.access_token,
        different_target_token_response.access_token
    );
    assert_ne!(
        third_token_response.access_token,
        different_user_token_response.access_token
    );

    assert_eq!(
        jwt::issuer(&third_token_introspect),
        jwt::issuer(&first_token_introspect)
    );
    assert_eq!(
        jwt::issuer(&third_token_introspect),
        jwt::issuer(&second_token_introspect)
    );

    assert_ne!(
        jwt::jwt_id(&third_token_introspect),
        jwt::jwt_id(&first_token_introspect)
    );
    assert_ne!(
        jwt::jwt_id(&third_token_introspect),
        jwt::jwt_id(&second_token_introspect)
    );

    assert_eq!(
        jwt::subject(&third_token_introspect),
        jwt::subject(&first_token_introspect)
    );
    assert_eq!(
        jwt::subject(&third_token_introspect),
        jwt::subject(&second_token_introspect)
    );
}

async fn test_token_exchange_missing_or_empty_user_token(address: &str) {
    http::test_well_formed_json_request(
        app::token_exchange_url(address).as_str(),
        TokenExchangeRequest {
            target: "target".to_string(),
            identity_provider: IdentityProvider::AzureAD,
            user_token: "".to_string(),
            skip_cache: None,
        },
        ErrorResponse {
            error: OAuthErrorCode::InvalidRequest,
            description: "invalid request: missing or empty assertion parameter".to_string(),
        },
        StatusCode::BAD_REQUEST,
    )
    .await;
}

async fn test_token_exchange_unsupported_identity_provider(address: &str) {
    http::test_well_formed_json_request(
        app::token_exchange_url(address).as_str(),
        TokenExchangeRequest {
            target: "some_target".to_string(),
            identity_provider: IdentityProvider::IDPorten,
            user_token: "some_token".to_string(),
            skip_cache: None,
        },
        ErrorResponse {
            error: OAuthErrorCode::InvalidRequest,
            description: "identity provider 'idporten' does not support token exchange".to_string(),
        },
        StatusCode::BAD_REQUEST,
    )
    .await;
}
