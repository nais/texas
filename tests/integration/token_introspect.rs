use crate::helpers::http::RequestFormat;
use crate::helpers::jwt::{IntrospectClaims, Token, TokenClaims};
use crate::helpers::{app, http, jwt};
use reqwest::StatusCode;
use serde_json::Value;
use test_log::test;
use texas::oauth::assertion::epoch_now_secs;
use texas::oauth::identity_provider::{
    IdentityProvider, IntrospectRequest, IntrospectResponse, TokenRequest, TokenResponse,
};

/// Test a full round-trip of the `/introspect` endpoint.
///
/// Content-type encodings tested are both `application/json` and `application/x-www-form-urlencoded`.
#[test(tokio::test)]
async fn all_providers() {
    let testapp = app::TestApp::new().await;
    let address = testapp.address();
    let identity_provider_address = testapp.identity_provider_address();
    let azure_issuer = testapp.azure_issuer();
    let idporten_issuer = testapp.idporten_issuer();
    let maskinporten_issuer = testapp.maskinporten_issuer();
    let token_x_issuer = testapp.token_x_issuer();

    let join_handler = tokio::spawn(async move {
        testapp.run().await;
    });

    // All happy cases
    for format in [RequestFormat::Form, RequestFormat::Json] {
        introspect_token(
            &azure_issuer,
            &address,
            &identity_provider_address,
            IdentityProvider::EntraID,
            format.clone(),
        )
        .await;

        introspect_token(
            &idporten_issuer,
            &address,
            &identity_provider_address,
            IdentityProvider::IDPorten,
            format.clone(),
        )
        .await;

        introspect_token(
            &maskinporten_issuer,
            &address,
            &identity_provider_address,
            IdentityProvider::Maskinporten,
            format.clone(),
        )
        .await;

        introspect_token(
            &token_x_issuer,
            &address,
            &identity_provider_address,
            IdentityProvider::TokenX,
            format.clone(),
        )
        .await;
    }

    test_introspect_token_has_not_before_in_the_future(&address, &identity_provider_address).await;
    test_introspect_token_invalid_audience(&address).await;
    test_introspect_token_is_expired(&address, &identity_provider_address).await;
    test_introspect_token_is_issued_in_the_future(&address, &identity_provider_address).await;
    test_introspect_token_is_not_a_jwt(&address).await;
    test_introspect_token_issuer_mismatch(&address, &identity_provider_address).await;
    test_introspect_token_missing_issuer(&address).await;
    test_introspect_token_missing_key_in_jwks(&address, &identity_provider_address).await;
    test_introspect_token_missing_kid(&address, &identity_provider_address).await;
    test_introspect_token_unrecognized_issuer(&address).await;

    join_handler.abort();
}

async fn introspect_token(
    expected_issuer: &str,
    address: &str,
    identity_provider_address: &str,
    identity_provider: IdentityProvider,
    request_format: RequestFormat,
) {
    let user_token: TokenResponse =
        http::get_user_token(identity_provider_address, identity_provider).await;
    let introspect_response = app::test_happy_path_introspect(
        address,
        expected_issuer,
        IntrospectRequest {
            token: user_token.access_token.clone(),
            identity_provider,
        },
        request_format,
    )
    .await;

    assert!(!introspect_response.subject().is_empty());
}

async fn test_introspect_token_has_not_before_in_the_future(
    address: &str,
    identity_provider_address: &str,
) {
    let token = Token::sign_with_kid(
        TokenClaims::from([
            (
                "iss".into(),
                format!("http://{}/maskinporten", identity_provider_address).into(),
            ),
            ("nbf".into(), (epoch_now_secs() + 120).into()),
            ("iat".into(), epoch_now_secs().into()),
            ("exp".into(), (epoch_now_secs() + 300).into()),
        ]),
        "maskinporten",
    );

    http::test_well_formed_json_request(
        app::introspect_url(address).as_str(),
        IntrospectRequest {
            token,
            identity_provider: IdentityProvider::Maskinporten,
        },
        IntrospectResponse::new_invalid("invalid token: ImmatureSignature"),
        StatusCode::OK,
    )
    .await;
}

async fn test_introspect_token_invalid_audience(address: &str) {
    let token_response = app::test_happy_path_token(
        address,
        TokenRequest {
            target: "invalid".to_string(),
            identity_provider: IdentityProvider::EntraID,
            resource: None,
            authorization_details: None,
            skip_cache: None,
        },
        RequestFormat::Json,
    )
    .await;

    http::test_well_formed_json_request(
        app::introspect_url(address).as_str(),
        IntrospectRequest {
            token: token_response.access_token.clone(),
            identity_provider: IdentityProvider::EntraID,
        },
        IntrospectResponse::new_invalid("invalid token: InvalidAudience"),
        StatusCode::OK,
    )
    .await;
}

async fn test_introspect_token_is_expired(address: &str, identity_provider_address: &str) {
    let token = Token::sign_with_kid(
        TokenClaims::from([
            (
                "iss".into(),
                format!("http://{}/maskinporten", identity_provider_address).into(),
            ),
            ("nbf".into(), epoch_now_secs().into()),
            ("iat".into(), epoch_now_secs().into()),
            ("exp".into(), (epoch_now_secs() - 120).into()),
        ]),
        "maskinporten",
    );

    http::test_well_formed_json_request(
        app::introspect_url(address).as_str(),
        IntrospectRequest {
            token,
            identity_provider: IdentityProvider::Maskinporten,
        },
        IntrospectResponse::new_invalid("invalid token: ExpiredSignature"),
        StatusCode::OK,
    )
    .await;
}

async fn test_introspect_token_is_issued_in_the_future(
    address: &str,
    identity_provider_address: &str,
) {
    let token = Token::sign_with_kid(
        TokenClaims::from([
            (
                "iss".into(),
                format!("http://{}/maskinporten", identity_provider_address).into(),
            ),
            ("nbf".into(), epoch_now_secs().into()),
            ("iat".into(), (epoch_now_secs() + 120).into()),
            ("exp".into(), (epoch_now_secs() + 300).into()),
        ]),
        "maskinporten",
    );

    http::test_well_formed_json_request(
        app::introspect_url(address).as_str(),
        IntrospectRequest {
            token,
            identity_provider: IdentityProvider::Maskinporten,
        },
        IntrospectResponse::new_invalid("invalid token: ImmatureSignature"),
        StatusCode::OK,
    )
    .await;
}

async fn test_introspect_token_is_not_a_jwt(address: &str) {
    http::test_well_formed_json_request(
        app::introspect_url(address).as_str(),
        IntrospectRequest {
            token: "not a jwt".to_string(),
            identity_provider: IdentityProvider::EntraID,
        },
        IntrospectResponse::new_invalid("invalid token header: InvalidToken"),
        StatusCode::OK,
    )
    .await;
}

async fn test_introspect_token_issuer_mismatch(address: &str, identity_provider_address: &str) {
    let iss = format!("http://{}/maskinporten", identity_provider_address);
    let token = Token::sign_with_kid(
        TokenClaims::from([
            ("iss".into(), Value::String(iss)),
            ("nbf".into(), epoch_now_secs().into()),
            ("iat".into(), epoch_now_secs().into()),
            ("exp".into(), (epoch_now_secs() + 120).into()),
        ]),
        &IdentityProvider::Maskinporten.to_string(),
    );

    http::test_well_formed_json_request(
        app::introspect_url(address).as_str(),
        IntrospectRequest {
            token,
            identity_provider: IdentityProvider::EntraID,
        },
        IntrospectResponse::new_invalid("token can not be validated with this identity provider"),
        StatusCode::OK,
    )
    .await;
}

async fn test_introspect_token_missing_issuer(address: &str) {
    let token = Token::sign_with_kid(
        TokenClaims::from([
            ("nbf".into(), epoch_now_secs().into()),
            ("iat".into(), epoch_now_secs().into()),
            ("exp".into(), (epoch_now_secs() + 120).into()),
        ]),
        &IdentityProvider::Maskinporten.to_string(),
    );

    http::test_well_formed_json_request(
        app::introspect_url(address).as_str(),
        IntrospectRequest {
            token,
            identity_provider: IdentityProvider::Maskinporten,
        },
        IntrospectResponse::new_invalid("invalid token: Missing required claim: iss"),
        StatusCode::OK,
    )
    .await;
}

async fn test_introspect_token_missing_key_in_jwks(address: &str, identity_provider_address: &str) {
    let token = Token::sign_with_kid(
        TokenClaims::from([(
            "iss".into(),
            format!("http://{}/maskinporten", identity_provider_address).into(),
        )]),
        "missing-key",
    );

    http::test_well_formed_json_request(
        app::introspect_url(address).as_str(),
        IntrospectRequest {
            token,
            identity_provider: IdentityProvider::Maskinporten,
        },
        IntrospectResponse::new_invalid("token can not be validated with this identity provider"),
        StatusCode::OK,
    )
    .await;
}

async fn test_introspect_token_missing_kid(address: &str, identity_provider_address: &str) {
    let token = Token::sign(jwt::TokenClaims::from([(
        "iss".into(),
        format!("http://{}/maskinporten", identity_provider_address).into(),
    )]));

    http::test_well_formed_json_request(
        app::introspect_url(address).as_str(),
        IntrospectRequest {
            token,
            identity_provider: IdentityProvider::EntraID,
        },
        IntrospectResponse::new_invalid("missing key id from token header"),
        StatusCode::OK,
    )
    .await;
}

async fn test_introspect_token_unrecognized_issuer(address: &str) {
    let token = Token::sign_with_kid(
        TokenClaims::from([
            ("iss".into(), Value::String("snafu".into())),
            ("nbf".into(), epoch_now_secs().into()),
            ("iat".into(), epoch_now_secs().into()),
            ("exp".into(), (epoch_now_secs() + 120).into()),
        ]),
        &IdentityProvider::Maskinporten.to_string(),
    );
    http::test_well_formed_json_request(
        app::introspect_url(address).as_str(),
        IntrospectRequest {
            token,
            identity_provider: IdentityProvider::Maskinporten,
        },
        IntrospectResponse::new_invalid("invalid token: InvalidIssuer"),
        StatusCode::OK,
    )
    .await;
}
