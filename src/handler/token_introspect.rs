use crate::handler;
use crate::handler::{JsonOrForm, State};
use crate::oauth::identity_provider::{IdentityProvider, IntrospectRequest, IntrospectResponse};
use crate::tracing::inc_token_introspections;
use axum::Json;
use axum::extract::State as AxumState;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::Value;
use std::collections::HashMap;
use tracing::instrument;

#[utoipa::path(
    post,
    path = "/api/v1/introspect",
    tag = "Endpoints",
    request_body(
        content(
            (IntrospectRequest = "application/json"),
            (IntrospectRequest = "application/x-www-form-urlencoded"),
        ),
        description = "Validate a token and return its claims and metadata. The response object's _active_ field will be set to either true or false for valid and invalid tokens, respectively. The identity provider determines which claims are returned. Please see the examples and/or Nais documentation for details.",
        examples(
            ("Token introspection" = (value = json!(IntrospectRequest{
                token: "eyJraWQiOiJ0b2tlbngiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJlMDE1NTQyYy0wZjgxLTQwZjUtYmJkOS03YzNkOTM2NjI5OGYiLCJhdWQiOiJteS10YXJnZXQiLCJuYmYiOjE3MzA5NzcyOTMsImF6cCI6InlvbG8iLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdG9rZW54IiwiZXhwIjoxNzMwOTgwODkzLCJpYXQiOjE3MzA5NzcyOTMsImp0aSI6ImU3Y2JhZGMzLTZiZGEtNDljMC1hMTk2LWM0NzMyOGRhODgwZSIsInRpZCI6InRva2VueCJ9.SIme9o5YE6pZXT9IMAx5upV3V4ww_TnDlqZG203pkySPBd_VqNGBXzOKHeOasIDpXEMlf8Yc-1nKgySjGOT3c46PIHEUrhQFXF6s9OpJAYAwy7L2n2DIFfEOLt8EpwSpM5hWDwnGpSdvebWlmoaA3ImFEB5dtnxLrVG-7dYEEzZjMfBOKFWrPp03FTO4qKOJUqCZR0tmZRmcPzymPWFIMjP2FTj6iz9zai93dhQmdvNVMGL9HBXF6ewKf_CTlUIx9XpwI2M-dhlyH2PIxyhix7Amuff_mHuEHTuCAFqMfjon-F438uyZmgicyrvhoUGxV8W1PfZEiLIv0RBeWRJ9gw".to_string(),
                identity_provider: IdentityProvider::TokenX,
            })))
        ),
    ),
    responses(
        (status = OK, description = "Success", body = IntrospectResponse, content_type = "application/json",
        examples(
                ("Valid token" = (value = json!(IntrospectResponse::new(HashMap::from(
                    [
                    ("aud".to_string(), Value::String("my-target".into())),
                    ("azp".to_string(), Value::String("yolo".into())),
                    ("exp".to_string(), Value::Number(1730980893.into())),
                    ("iat".to_string(), Value::Number(1730977293.into())),
                    ("iss".to_string(), Value::String("http://localhost:8080/tokenx".into())),
                    ("jti".to_string(), Value::String("e7cbadc3-6bda-49c0-a196-c47328da880e".into())),
                    ("nbf".to_string(), Value::Number(1730977293.into())),
                    ("sub".to_string(), Value::String("e015542c-0f81-40f5-bbd9-7c3d9366298f".into())),
                    ("tid".to_string(), Value::String("tokenx".into())),
                    ],
                ))))),
                ("Invalid token" = (value = json!(IntrospectResponse::new_invalid("token is expired".to_string())))),
            )
        ),
    )
)]
#[instrument(skip_all, name = "Handle /api/v1/introspect", err, fields(
    texas.identity_provider = %request.identity_provider
))]
pub async fn token_introspect(
    AxumState(state): AxumState<State>,
    JsonOrForm(request): JsonOrForm<IntrospectRequest>,
) -> IntrospectResult {
    const PATH: &str = "/api/v1/introspect";
    inc_token_introspections(PATH, request.identity_provider);

    let mut provider_enabled = false;
    for provider in state.providers {
        if provider.read().await.identity_provider_matches(request.identity_provider) {
            provider_enabled = true;
        }
        if !provider.read().await.should_handle_introspect_request(&request) {
            continue;
        }
        // We need to acquire a write lock here because introspect
        // might refresh its JWKS in-flight.
        return Ok(provider.write().await.introspect(request.token).await);
    }

    if !provider_enabled {
        return Err(IntrospectResponse::new_invalid(
            handler::identity_provider_not_enabled_error(PATH, request.identity_provider),
        ));
    }

    let error_message = format!(
        "identity provider '{}' does not support introspection",
        request.identity_provider
    );
    Err(IntrospectResponse::new_invalid(error_message))
}

type IntrospectResult = Result<IntrospectResponse, IntrospectResponse>;

// This allows us to use the `err` attribute for the `instrument` macro,
// as we can't implement the `Display` trait for Json<IntrospectResponse>.
impl IntoResponse for IntrospectResponse {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        (StatusCode::OK, Json(self)).into_response()
    }
}
