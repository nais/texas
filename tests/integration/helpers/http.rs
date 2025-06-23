use axum::http::StatusCode;
use pretty_assertions::assert_eq;
use reqwest::{Error, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use texas::identity_provider::{IdentityProvider, TokenResponse};

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
    grant_type: String,
    code: String,
    client_id: String,
    client_secret: String,
}

pub async fn get_user_token(
    identity_provider_address: &str,
    identity_provider: IdentityProvider,
) -> TokenResponse {
    // This request goes directly to the mock oauth2 server, which only accepts form encoding
    let user_token_response = post_request(
        format!(
            "http://{}/{}/token",
            identity_provider_address, identity_provider
        ),
        AuthorizeRequest {
            grant_type: "authorization_code".to_string(),
            code: "mycode".to_string(),
            client_id: "myclientid".to_string(),
            client_secret: "myclientsecret".to_string(),
        },
        RequestFormat::Form,
    )
    .await
    .unwrap();

    assert_eq!(user_token_response.status(), 200);
    user_token_response.json::<TokenResponse>().await.unwrap()
}
