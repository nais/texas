use crate::cache::CachedTokenResponse;
use crate::handler;
use crate::handler::{ApiError, JsonOrForm, State};
use crate::oauth::identity_provider::{
    AuthorizationDetails, ErrorResponse, IdentityProvider, TokenRequest, TokenResponse, TokenType,
};
use crate::tracing::{inc_handler_errors, inc_token_cache_hits, inc_token_requests};
use axum::Json;
use axum::extract::State as AxumState;
use axum::response::IntoResponse;
use tracing::instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[utoipa::path(
    post,
    path = "/api/v1/token",
    tag = "Endpoints",
    request_body(
        content(
            (TokenRequest = "application/json"),
            (TokenRequest = "application/x-www-form-urlencoded"),
        ),
        description = "Request a machine-to-machine token from the specified identity provider and for a given target.",
        examples(
            ("Generate a token for Maskinporten with resource indicator" = (value = json!(TokenRequest{
                identity_provider: IdentityProvider::Maskinporten,
                target: "altinn:serviceowner/rolesandrights".to_string(),
                resource: Some("http://resource.example/api".to_string()),
                authorization_details: None,
                skip_cache: None,
            }))),
            ("Generate a token for Maskinporten with authorization details" = (value = json!(TokenRequest{
                identity_provider: IdentityProvider::Maskinporten,
                target: "skatteetaten:skattekorttilarbeidsgiver".to_string(),
                resource: None,
                authorization_details: Some(AuthorizationDetails(serde_json::from_str(r#"[{
                    "type": "urn:altinn:systemuser",
                    "systemuser_org": {
                        "authority": "iso6523-actorid-upis",
                        "ID": "0192:313367002"
                    },
                    "systemuser_id": [
                        "33a0911a-5459-456f-bc57-3d37ef9a016c"
                    ],
                    "system_id": "974761076_skatt_demo_system"
                }]"#).unwrap())),
                skip_cache: None,
            }))),
            ("Generate a token for Entra ID" = (value = json!(TokenRequest{
                identity_provider: IdentityProvider::EntraID,
                target: "api://cluster.namespace.application/.default".to_string(),
                resource: None,
                authorization_details: None,
                skip_cache: None,
            }))),
            ("Force renewal of token for Entra ID" = (value = json!(TokenRequest{
                identity_provider: IdentityProvider::EntraID,
                target: "api://cluster.namespace.application/.default".to_string(),
                resource: None,
                authorization_details: None,
                skip_cache: Some(true),
            }))),
        ),
    ),
    responses(
        (status = OK, description = "Success", body = TokenResponse, content_type = "application/json",
            examples(
                ("Token response" = (value = json!(TokenResponse{
                    // This token comes from mock-oauth2-server and is not a security issue
                    access_token: "eyJraWQiOiJ0b2tlbngiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyZjNjM2Y4YS03NTYwLTRjNWMtYmM4My0yNzVhY2Q1MWU1N2YiLCJhdWQiOiJteS10YXJnZXQiLCJuYmYiOjE3MzA5NzYxODQsImF6cCI6InlvbG8iLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdG9rZW54IiwiZXhwIjoxNzMwOTc5Nzg0LCJpYXQiOjE3MzA5NzYxODQsImp0aSI6IjBmNTM3M2YyLThjYmUtNDczOS05ZDU1LWY5MzE4YmFiNWQ2NyIsInRpZCI6InRva2VueCJ9.aQ-2TcdDRkWXbi3en6eMwzjSkYLH-S6aiAyss8MkkAPT_RGlZF_eCKFFsaKJ9YwQAzs4BN_d13W-xejPf6B_3Mn7xasDX_5r-M5ZwXxPWkRe5daqdqznF-vPAnIIjmqynjEYgijn79Rajorcu1sgW4bsrByp1lXNhntHar-8x62S_5oY40tEjIAHv7q2zKRxoKxKlcNpnLpKnZWrkJj7SboiCpGWc-W4JtcnNTHgKRXcFVfXSGD6EhHQ2HLDtmWJkk8NHTnjLI8IRt0mrkOs_nt2jNDDpH9ViqlWi7FOwi4C0OSfGHGukDYOeRc3vICgFGHyi0G6Avq9YXtuAP62_A".to_string(),
                    token_type: TokenType::Bearer,
                    expires_in_seconds: 3599,
                }))),
        )),
        (status = BAD_REQUEST, description = "Bad request", body = ErrorResponse, content_type = "application/json"),
        (status = INTERNAL_SERVER_ERROR, description = "Server error", body = ErrorResponse, content_type = "application/json"),
    )
)]
#[instrument(skip_all, name = "Handle /api/v1/token", err, fields(
    texas.cache_force_skipped,
    texas.cache_hit,
    texas.cache_ttl_seconds,
    texas.identity_provider = %request.identity_provider,
    texas.target = %request.target,
    texas.token_expires_in_seconds,
))]
pub async fn token(
    AxumState(state): AxumState<State>,
    JsonOrForm(request): JsonOrForm<TokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    const PATH: &str = "/api/v1/token";
    let span = tracing::Span::current();
    inc_token_requests(PATH, request.identity_provider);

    if let Some(ref resource) = request.resource {
        span.set_attribute("texas.resource", resource.clone());
    }
    if let Some(ref authorization_details) = request.authorization_details {
        span.set_attribute(
            "texas.authorization_details",
            serde_json::to_string_pretty(authorization_details).unwrap_or_default(),
        );
    }

    if request.skip_cache.unwrap_or(false) {
        span.set_attribute("texas.cache_force_skipped", true);
        state.token_cache.invalidate(&request).await;
    } else if let Some(cached_response) = state.token_cache.get(&request).await {
        inc_token_cache_hits(PATH, request.identity_provider);
        span.set_attribute(
            "texas.cache_ttl_seconds",
            cached_response.ttl().as_secs_f64(),
        );
        span.set_attribute(
            "texas.token_expires_in_seconds",
            cached_response.expires_in().as_secs_f64(),
        );

        return Ok(Json(TokenResponse::from(cached_response)));
    } else {
        span.set_attribute("texas.cache_hit", false);
    }

    let mut provider_enabled = false;
    for provider in state.providers {
        if provider.read().await.identity_provider_matches(request.identity_provider) {
            provider_enabled = true;
        }
        if !provider.read().await.should_handle_token_request(&request) {
            continue;
        }
        let response: TokenResponse = provider
            .read()
            .await
            .get_token(request.clone())
            .await
            .inspect_err(|e| inc_handler_errors(PATH, request.identity_provider, e.as_ref()))?;

        span.set_attribute(
            "texas.token_expires_in_seconds",
            response.expires_in_seconds.cast_signed(),
        );
        state.token_cache.insert(request, CachedTokenResponse::from(response.clone())).await;
        return Ok(Json(response));
    }

    if !provider_enabled {
        return Err(handler::identity_provider_not_enabled_error(
            PATH,
            request.identity_provider,
        ));
    }

    let err = ApiError::TokenRequestUnsupported(request.identity_provider);
    inc_handler_errors(PATH, request.identity_provider, err.as_ref());
    Err(err)
}
