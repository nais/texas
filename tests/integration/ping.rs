use crate::helpers::app;
use axum::http::StatusCode;
use pretty_assertions::assert_eq;
use test_log::test;

#[test(tokio::test)]
async fn ping() {
    let testapp = app::TestApp::new().await;
    let address = testapp.address();
    let join_handler = tokio::spawn(async move {
        testapp.run().await;
    });

    let client = reqwest::Client::new();
    let response = client.get(format!("http://{}/ping", address)).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "pong");

    join_handler.abort();
}
