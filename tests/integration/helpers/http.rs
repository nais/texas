use crate::helpers::jwt::IntrospectClaims;
use axum::http::StatusCode;
use pretty_assertions::assert_eq;
use reqwest::{Error, Response, Url, redirect::Policy};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use texas::oauth::identity_provider::IdentityProvider;
use texas::oauth::request::{IntrospectRequest, TokenExchangeRequest, TokenRequest};
use texas::oauth::response::{IntrospectResponse, TokenResponse};

#[derive(Clone)]
pub enum RequestFormat {
    Json,
    Form,
}

pub async fn post_request(
    url: String,
    params: impl Serialize,
    format: RequestFormat,
) -> Result<Response, Error> {
    let client = reqwest::Client::new();
    let request = client.post(url).header("accept", "application/json");
    let request = match format {
        RequestFormat::Json => request.json(&params),
        RequestFormat::Form => request.form(&params),
    };
    request.send().await
}

pub async fn json_response<U: DeserializeOwned + PartialEq + Debug + Clone>(
    response: Response,
    status_code: StatusCode,
) -> U {
    let response_status = response.status();
    let response_body = response.json::<U>().await.unwrap();
    assert_eq!(
        response_status, status_code,
        "response body: {:?}",
        response_body
    );
    response_body
}

pub async fn test_well_formed_request<
    T: Serialize,
    U: DeserializeOwned + PartialEq + Debug + Clone,
>(
    url: &str,
    request: T,
    request_format: RequestFormat,
    status_code: StatusCode,
    assert_response: impl FnOnce(U),
) -> U {
    let http_response = post_request(url.to_string(), request, request_format).await.unwrap();
    let actual_response = json_response::<U>(http_response, status_code).await;
    assert_response(actual_response.clone());
    actual_response
}

pub async fn test_well_formed_json_request<
    T: Serialize,
    U: DeserializeOwned + PartialEq + Debug + Clone,
>(
    url: &str,
    request: T,
    expected_response: U,
    status_code: StatusCode,
) -> U {
    test_well_formed_request(
        url,
        request,
        RequestFormat::Json,
        status_code,
        |response: U| {
            assert_eq!(response, expected_response);
        },
    )
    .await
}

#[derive(Serialize)]
struct AuthorizeRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
}

#[derive(Serialize)]
struct AuthorizeCodeRequest {
    grant_type: String,
    code: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

pub async fn get_user_token(
    identity_provider_address: &str,
    identity_provider: IdentityProvider,
) -> TokenResponse {
    let client = reqwest::Client::builder().redirect(Policy::none()).build().unwrap();
    let redirect_uri = "http://localhost/callback";
    let authorize_response = client
        .get(format!(
            "http://{}/{}/authorize",
            identity_provider_address, identity_provider
        ))
        .query(&AuthorizeRequest {
            response_type: "code".to_string(),
            client_id: "myclientid".to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: "openid".to_string(),
            state: "test-state".to_string(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(authorize_response.status(), StatusCode::FOUND);

    let callback_url = Url::parse(
        authorize_response.headers().get(reqwest::header::LOCATION).unwrap().to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        callback_url.query_pairs().find(|(key, _)| key == "state"),
        Some(("state".into(), "test-state".into()))
    );
    let code = callback_url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .unwrap();

    let user_token_response = client
        .post(format!(
            "http://{}/{}/token",
            identity_provider_address, identity_provider
        ))
        .form(&AuthorizeCodeRequest {
            grant_type: "authorization_code".to_string(),
            code,
            client_id: "myclientid".to_string(),
            client_secret: "myclientsecret".to_string(),
            redirect_uri: redirect_uri.to_string(),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(user_token_response.status(), 200);
    user_token_response.json::<TokenResponse>().await.unwrap()
}

pub fn token_url(address: &str) -> String {
    format!("http://{}/api/v1/token", address)
}

pub fn token_exchange_url(address: &str) -> String {
    format!("http://{}/api/v1/token/exchange", address)
}

pub fn introspect_url(address: &str) -> String {
    format!("http://{}/api/v1/introspect", address)
}

pub async fn test_happy_path_token(
    address: &str,
    request: TokenRequest,
    request_format: RequestFormat,
) -> TokenResponse {
    test_well_formed_request(
        token_url(address).as_str(),
        request,
        request_format,
        StatusCode::OK,
        |resp: TokenResponse| {
            assert!(resp.expires_in_seconds > 0);
            assert!(!resp.access_token.is_empty());
        },
    )
    .await
}

pub async fn test_happy_path_token_exchange(
    address: &str,
    request: TokenExchangeRequest,
    request_format: RequestFormat,
) -> TokenResponse {
    test_well_formed_request(
        token_exchange_url(address).as_str(),
        request,
        request_format,
        StatusCode::OK,
        |resp: TokenResponse| {
            assert!(resp.expires_in_seconds > 0);
            assert!(!resp.access_token.is_empty());
        },
    )
    .await
}

pub async fn test_happy_path_introspect(
    address: &str,
    expected_issuer: &str,
    request: IntrospectRequest,
    request_format: RequestFormat,
) -> IntrospectResponse {
    test_well_formed_request(
        introspect_url(address).as_str(),
        request,
        request_format,
        StatusCode::OK,
        |resp: IntrospectResponse| {
            assert!(resp.active);
            assert!(resp.error.is_none());
            assert!(resp.has_claims());
            assert!(!resp.issuer().is_empty());
            assert!(!resp.jwt_id().is_empty());
            assert_eq!(resp.issuer(), expected_issuer);
        },
    )
    .await
}
