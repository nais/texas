use crate::helpers::http::RequestFormat;
use crate::helpers::jwt::IntrospectClaims;
use crate::helpers::{app, http};
use pretty_assertions::{assert_eq, assert_ne};
use reqwest::StatusCode;
use serde_json::json;
use std::collections::HashMap;
use test_log::test;
use texas::oauth::identity_provider::{
    ErrorResponse, IdentityProvider, IntrospectRequest, OAuthErrorCode, TokenRequest,
};

/// Test a full round-trip of the `/token` endpoint.
///
/// Content-type encodings tested are both `application/json` and `application/x-www-form-urlencoded`.
///
/// Test client credentials as follows:
///   1. Request a client credentials token using Texas' `/token` endpoint
///   2. Introspect the resulting token and check parameters
#[test(tokio::test)]
async fn all_providers() {
    let testapp = app::TestApp::new().await;
    let address = testapp.address();
    let join_handler = tokio::spawn(async move {
        testapp.app.run().await;
    });

    // All happy cases
    for format in [RequestFormat::Form, RequestFormat::Json] {
        machine_to_machine_token(
            &testapp.cfg.maskinporten.clone().unwrap().issuer,
            "scope",
            &address,
            IdentityProvider::Maskinporten,
            format.clone(),
        )
        .await;

        machine_to_machine_token(
            &testapp.cfg.azure_ad.clone().unwrap().issuer,
            &testapp.cfg.azure_ad.clone().unwrap().client_id,
            &address,
            IdentityProvider::AzureAD,
            format.clone(),
        )
        .await;
    }

    test_token_invalid_identity_provider(&address).await;
    test_token_invalid_content_type(&address).await;
    test_token_unsupported_identity_provider(&address).await;

    join_handler.abort();
}

async fn machine_to_machine_token(
    expected_issuer: &str,
    target: &str,
    address: &str,
    identity_provider: IdentityProvider,
    request_format: RequestFormat,
) {
    let request = TokenRequest {
        target: target.to_string(),
        identity_provider,
        resource: None,
        skip_cache: None,
    };
    let first_token_response =
        app::test_happy_path_token(address, request.clone(), request_format.clone()).await;
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

    // different target should return a different token
    let different_token_response = app::test_happy_path_token(
        address,
        TokenRequest {
            target: "different_target".to_string(),
            identity_provider,
            resource: None,
            skip_cache: None,
        },
        request_format.clone(),
    )
    .await;
    assert_ne!(
        different_token_response.access_token,
        first_token_response.access_token
    );

    // second token request with same inputs should return cached token
    let second_token_response =
        app::test_happy_path_token(address, request, request_format.clone()).await;
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

    assert_eq!(
        second_token_response.access_token,
        first_token_response.access_token
    );
    assert_ne!(
        second_token_response.access_token,
        different_token_response.access_token
    );
    assert_eq!(
        second_token_introspect.issuer(),
        first_token_introspect.issuer()
    );
    assert_eq!(
        second_token_introspect.issuer(),
        first_token_introspect.issuer()
    );

    // third token request with skip_cache=true should return a new token
    let third_token_response = app::test_happy_path_token(
        address,
        TokenRequest {
            target: target.to_string(),
            identity_provider,
            resource: None,
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
        different_token_response.access_token
    );

    assert_eq!(
        third_token_introspect.issuer(),
        first_token_introspect.issuer()
    );
    assert_eq!(
        third_token_introspect.issuer(),
        second_token_introspect.issuer()
    );

    assert_ne!(
        third_token_introspect.jwt_id(),
        first_token_introspect.jwt_id()
    );
    assert_ne!(
        third_token_introspect.jwt_id(),
        second_token_introspect.jwt_id()
    );
}

async fn test_token_invalid_identity_provider(address: &str) {
    let http_response = http::post_request(
        format!("http://{}/api/v1/token", address),
        json!({"target":"dontcare","identity_provider":"invalid"}),
        RequestFormat::Json,
    )
    .await
    .unwrap();
    let error_response =
        http::json_response::<ErrorResponse>(http_response, StatusCode::BAD_REQUEST).await;
    assert_eq!(error_response.error, OAuthErrorCode::InvalidRequest);
    assert_eq!(
        error_response.description,
        "Failed to deserialize the JSON body into the target type: identity_provider: unknown variant `invalid`, expected one of `azuread`, `tokenx`, `maskinporten`, `idporten` at line 1 column 30"
    );

    let http_response = http::post_request(
        format!("http://{}/api/v1/token", address),
        HashMap::from([("target", "dontcare"), ("identity_provider", "invalid")]),
        RequestFormat::Form,
    )
    .await
    .unwrap();
    let error_response =
        http::json_response::<ErrorResponse>(http_response, StatusCode::BAD_REQUEST).await;
    assert_eq!(error_response.error, OAuthErrorCode::InvalidRequest);
    assert_eq!(
        error_response.description,
        "Failed to deserialize form body: identity_provider: unknown variant `invalid`, expected one of `azuread`, `tokenx`, `maskinporten`, `idporten`"
    );
}

async fn test_token_invalid_content_type(address: &str) {
    let client = reqwest::Client::new();
    let request = client
        .post(format!("http://{}/api/v1/token", address))
        .header("accept", "application/json")
        .header("content-type", "text/plain")
        .body("some plain text");
    let http_response = request.send().await.unwrap();

    let error_response =
        http::json_response::<ErrorResponse>(http_response, StatusCode::BAD_REQUEST).await;
    assert_eq!(error_response.error, OAuthErrorCode::InvalidRequest);
    assert_eq!(
        error_response.description,
        "unsupported media type: text/plain: expected one of `application/json`, `application/x-www-form-urlencoded`"
    );
}

async fn test_token_unsupported_identity_provider(address: &str) {
    http::test_well_formed_json_request(
        app::token_url(address).as_str(),
        TokenRequest {
            target: "some_target".to_string(),
            identity_provider: IdentityProvider::IDPorten,
            resource: None,
            skip_cache: None,
        },
        ErrorResponse {
            error: OAuthErrorCode::InvalidRequest,
            description: "identity provider 'idporten' does not support token requests".to_string(),
        },
        StatusCode::BAD_REQUEST,
    )
    .await;
}
