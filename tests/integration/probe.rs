use crate::helpers::app;
use axum::http::StatusCode;
use pretty_assertions::assert_eq;
use test_log::test;

#[test(tokio::test)]
async fn probe() {
    let testapp = app::TestApp::new().await;
    let probe_address = testapp.probe_address().expect("Probe address is not set");
    let join_handler = tokio::spawn(async move {
        testapp.run().await;
    });

    let client = reqwest::Client::new();
    let response = client.get(format!("http://{}/healthz", probe_address)).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "ok");

    join_handler.abort();
}
