use crate::helpers::http::{
    RequestFormat, json_response, post_request, test_happy_path_introspect, test_happy_path_token,
    test_well_formed_json_request, token_url,
};
use crate::helpers::jwt::IntrospectClaims;
use crate::helpers::server::TestServer;
use pretty_assertions::{assert_eq, assert_ne};
use reqwest::StatusCode;
use serde_json::{from_str, json};
use std::collections::HashMap;
use test_log::test;
use texas::oauth::identity_provider::{
    AuthorizationDetails, ErrorResponse, IdentityProvider, IntrospectRequest, OAuthErrorCode,
    TokenRequest, TokenResponse,
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
    let server = TestServer::new().await;
    let address = server.address();
    let azure_issuer = server.azure_issuer();
    let azure_client_id = server.azure_client_id();
    let maskinporten_issuer = server.maskinporten_issuer();

    let join_handler = tokio::spawn(async move {
        server.run().await;
    });

    // All happy cases
    for format in [RequestFormat::Form, RequestFormat::Json] {
        machine_to_machine_token(
            &maskinporten_issuer,
            "scope",
            &address,
            IdentityProvider::Maskinporten,
            format.clone(),
        )
        .await;

        machine_to_machine_token(
            &azure_issuer,
            &azure_client_id,
            &address,
            IdentityProvider::EntraID,
            format.clone(),
        )
        .await;

        test_token_with_resource(&maskinporten_issuer, &address, format.clone()).await;
    }
    test_token_with_authorization_details_form(&maskinporten_issuer, &address).await;
    test_token_with_authorization_details_json(&maskinporten_issuer, &address).await;

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
        authorization_details: None,
        skip_cache: None,
    };
    let first_token_response =
        test_happy_path_token(address, request.clone(), request_format.clone()).await;
    let first_token_introspect = test_happy_path_introspect(
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
    let different_token_response = test_happy_path_token(
        address,
        TokenRequest {
            target: "different_target".to_string(),
            identity_provider,
            resource: None,
            authorization_details: None,
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
        test_happy_path_token(address, request, request_format.clone()).await;
    let second_token_introspect = test_happy_path_introspect(
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
    let third_token_response = test_happy_path_token(
        address,
        TokenRequest {
            target: target.to_string(),
            identity_provider,
            resource: None,
            authorization_details: None,
            skip_cache: Some(true),
        },
        request_format.clone(),
    )
    .await;
    let third_token_introspect = test_happy_path_introspect(
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
    let http_response = post_request(
        format!("http://{}/api/v1/token", address),
        json!({"target":"dontcare","identity_provider":"invalid"}),
        RequestFormat::Json,
    )
    .await
    .unwrap();
    let error_response =
        json_response::<ErrorResponse>(http_response, StatusCode::BAD_REQUEST).await;
    assert_eq!(error_response.error, OAuthErrorCode::InvalidRequest);
    assert_eq!(
        error_response.description,
        "Failed to deserialize the JSON body into the target type: identity_provider: unknown variant `invalid`, expected one of `azuread`, `entra_id`, `tokenx`, `maskinporten`, `idporten` at line 1 column 30"
    );

    let http_response = post_request(
        format!("http://{}/api/v1/token", address),
        HashMap::from([("target", "dontcare"), ("identity_provider", "invalid")]),
        RequestFormat::Form,
    )
    .await
    .unwrap();
    let error_response =
        json_response::<ErrorResponse>(http_response, StatusCode::BAD_REQUEST).await;
    assert_eq!(error_response.error, OAuthErrorCode::InvalidRequest);
    assert_eq!(
        error_response.description,
        "Failed to deserialize form body: identity_provider: unknown variant `invalid`, expected one of `azuread`, `entra_id`, `tokenx`, `maskinporten`, `idporten`"
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
        json_response::<ErrorResponse>(http_response, StatusCode::BAD_REQUEST).await;
    assert_eq!(error_response.error, OAuthErrorCode::InvalidRequest);
    assert_eq!(
        error_response.description,
        "unsupported media type: text/plain: expected one of `application/json`, `application/x-www-form-urlencoded`"
    );
}

async fn test_token_unsupported_identity_provider(address: &str) {
    test_well_formed_json_request(
        token_url(address).as_str(),
        TokenRequest {
            target: "some_target".to_string(),
            identity_provider: IdentityProvider::IDPorten,
            resource: None,
            authorization_details: None,
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

async fn test_token_with_resource(
    expected_issuer: &str,
    address: &str,
    request_format: RequestFormat,
) {
    let target = "scope";
    let resource = "some_resource";
    let identity_provider = IdentityProvider::Maskinporten;

    let token_response = test_happy_path_token(
        address,
        TokenRequest {
            target: target.to_string(),
            identity_provider,
            resource: Some(resource.to_string()),
            authorization_details: None,
            skip_cache: None,
        },
        request_format.clone(),
    )
    .await;

    let introspect_response = test_happy_path_introspect(
        address,
        expected_issuer,
        IntrospectRequest {
            token: token_response.access_token.clone(),
            identity_provider,
        },
        request_format.clone(),
    )
    .await;

    assert_eq!(introspect_response.get_string_claim("resource"), resource);
}

async fn test_token_with_authorization_details_form(expected_issuer: &str, address: &str) {
    let authorization_details = r#"[{
        "type": "customer_information",
        "locations": [
            "https://example.com/customers"
        ],
        "actions": [
            "read",
            "write"
        ],
        "datatypes": [
            "contacts",
            "photos"
        ]
    }]"#;

    let http_response = post_request(
        token_url(address),
        HashMap::from([
            ("target", "some_target"),
            (
                "identity_provider",
                IdentityProvider::Maskinporten.to_string().as_str(),
            ),
            ("authorization_details", authorization_details),
        ]),
        RequestFormat::Form,
    )
    .await
    .unwrap();

    let token_response = json_response::<TokenResponse>(http_response, StatusCode::OK).await;
    assert!(token_response.expires_in_seconds > 0);
    assert!(!token_response.access_token.is_empty());

    let introspect_response = test_happy_path_introspect(
        address,
        expected_issuer,
        IntrospectRequest {
            token: token_response.access_token,
            identity_provider: IdentityProvider::Maskinporten,
        },
        RequestFormat::Form,
    )
    .await;

    let actual = introspect_response.get_authorization_details();
    let expected: AuthorizationDetails = from_str(authorization_details).unwrap();
    assert_eq!(actual, expected);
}

async fn test_token_with_authorization_details_json(expected_issuer: &str, address: &str) {
    let authorization_details = r#"[{
        "type": "customer_information",
        "locations": [
            "https://example.com/customers"
        ],
        "actions": [
            "read",
            "write"
        ],
        "datatypes": [
            "contacts",
            "photos"
        ]
    }]"#;

    let http_response = post_request(
        token_url(address),
        json!({
            "target": "some_target",
            "identity_provider": IdentityProvider::Maskinporten,
            "authorization_details": authorization_details
        }),
        RequestFormat::Json,
    )
    .await
    .unwrap();

    let token_response = json_response::<TokenResponse>(http_response, StatusCode::OK).await;
    assert!(token_response.expires_in_seconds > 0);
    assert!(!token_response.access_token.is_empty());

    let introspect_response = test_happy_path_introspect(
        address,
        expected_issuer,
        IntrospectRequest {
            token: token_response.access_token,
            identity_provider: IdentityProvider::Maskinporten,
        },
        RequestFormat::Json,
    )
    .await;

    let actual = introspect_response.get_authorization_details();
    let expected: AuthorizationDetails = from_str(authorization_details).unwrap();
    assert_eq!(actual, expected);
}

/// Test that concurrent token exchange requests for the same key are coalesced
/// into a single upstream call (via moka's try_get_with behavior).
#[test(tokio::test)]
async fn token_exchange_concurrent_requests_are_coalesced() {
    let server = TestServer::new().await;
    let address = server.address();
    let join_handler = tokio::spawn(async move {
        server.run().await;
    });

    let request = TokenRequest {
        target: "scope".to_string(),
        identity_provider: IdentityProvider::Maskinporten,
        resource: None,
        authorization_details: None,
        skip_cache: None,
    };

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..10 {
        let address = address.clone();
        let request = request.clone();
        set.spawn(
            async move { test_happy_path_token(&address, request, RequestFormat::Json).await },
        );
    }

    let mut results = Vec::new();
    while let Some(result) = set.join_next().await {
        results.push(result.unwrap());
    }

    // All responses should be identical (same cached token)
    let first_token = &results[0].access_token;
    for result in &results[1..] {
        assert_eq!(
            &result.access_token, first_token,
            "concurrent requests should return the same cached token"
        );
    }

    join_handler.abort();
}
