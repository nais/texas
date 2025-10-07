use crate::cache::CachedTokenResponse;
use crate::handler;
use crate::handler::{ApiError, JsonOrForm, State};
use crate::oauth::identity_provider::{
    ErrorResponse, IdentityProvider, TokenExchangeRequest, TokenResponse, TokenType,
};
use crate::tracing::{inc_handler_errors, inc_token_cache_hits, inc_token_exchanges};
use axum::Json;
use axum::extract::State as AxumState;
use axum::response::IntoResponse;
use tracing::instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[utoipa::path(
    post,
    path = "/api/v1/token/exchange",
    tag = "Endpoints",
    request_body(
        content(
            (TokenExchangeRequest = "application/json"),
            (TokenExchangeRequest = "application/x-www-form-urlencoded"),
        ),
        description = "Exchange a user's token for a machine token, scoped to the given target. The returned token allows your application to act on behalf of the user.",
        examples(
            ("Exchange a token using TokenX" = (value = json!(TokenExchangeRequest{
                identity_provider: IdentityProvider::TokenX,
                target: "cluster:namespace:application".to_string(),
                user_token: "eyJraWQiOiJpZHBvcnRlbiIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIxOTQyMmVhNC04ZWUwLTQ0YTYtOThjNi0zODc0MjAyN2YyYWQiLCJhdWQiOiJkZWZhdWx0IiwibmJmIjoxNzMwOTc4MzgwLCJhenAiOiJ5b2xvIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2lkcG9ydGVuIiwiZXhwIjoxNzMwOTgxOTgwLCJpYXQiOjE3MzA5NzgzODAsImp0aSI6IjBhMDU5MDc3LTQwNzEtNDdlYS04MmM2LTU2NTY2OTk3Nzg3MiIsInRpZCI6ImlkcG9ydGVuIn0.JwgvrhPMRMaNJngiR6hzHfhg5Qy-yV4zuAtxRRvdjX4g2cBmsWj305U-lHJGsozjFhpGpA0lAn16bD3l1Z6x7CsO6kbQEwKQiJE9gB61RwSUEjV4-RbpVrKMJwppQg8gPLrb4SbTjjkylD7B9CfPiIZYtCNr6d-J0lupYiB7IlK7anUImCv7RqXTuhH0aklVpVmxOZRhzHJ6_WfhWS54MysZmeRZwOsSO-ofkrcznFFaArS1ODfrYgHx4dgVBjkE7RTcLP7nuwNtvbLg9ZVvIAT4Xh-3fu0pCL9NXoDiqBsQ0SukBAlBFfWQBFu1-34-bXkfRz2RgCR964WbKUQ8gQ".to_string(),
                skip_cache: None,
            }))),
            ("Exchange a token using Entra ID" = (value = json!(TokenExchangeRequest{
                identity_provider: IdentityProvider::EntraID,
                target: "api://cluster.namespace.application/.default".to_string(),
                user_token: "eyJraWQiOiJhenVyZWFkIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI1ZDYzMDliNi05OGUzLTQ1ODAtYTQwNS02MDExYzhhNjExYzgiLCJhdWQiOiJkZWZhdWx0IiwibmJmIjoxNzMwOTc4MjQyLCJhenAiOiJ5b2xvIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F6dXJlYWQiLCJleHAiOjE3MzA5ODE4NDIsImlhdCI6MTczMDk3ODI0MiwianRpIjoiZTU4ZGM2ZjctZjQ0NC00YzcxLThlNzAtNzRhNWY1MTRlZDAwIiwidGlkIjoiYXp1cmVhZCJ9.KhySKFTJVaE6tYhsxCZonYMXv4fKwjtOI4YIAIoOs3DwaXoynTvy2lgiHSfisq-jLTJFGf9eGNbvwc3jUtypclVpYy_8d3xbvuu6jrOA1zWYagZjYr1FNN1g8tlF0SXjtkK_Bg-eZusLnEEbrZK1KnQRWN0I5fXqS7-IVe07hKTOE1teg7of2nCjfJ-iOXhf1mkXqCoUfSbJuUX2PEUs0b9yXAh_J-5P75T6130KBfRw5T5gYI0Kab3u2vm6t-ihT2Kz0aMkUGv_39myDgiwP4TV2vt4PhUiwefPo7KD-4_dkHc7Q5xUv-DWgTLUfXL2lOWf2d0C5tVExLB86jq8hw".to_string(),
                skip_cache: None,
            }))),
            ("Force renewal of token using Entra ID" = (value = json!(TokenExchangeRequest{
                identity_provider: IdentityProvider::EntraID,
                target: "api://cluster.namespace.application/.default".to_string(),
                user_token: "eyJraWQiOiJhenVyZWFkIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI1ZDYzMDliNi05OGUzLTQ1ODAtYTQwNS02MDExYzhhNjExYzgiLCJhdWQiOiJkZWZhdWx0IiwibmJmIjoxNzMwOTc4MjQyLCJhenAiOiJ5b2xvIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F6dXJlYWQiLCJleHAiOjE3MzA5ODE4NDIsImlhdCI6MTczMDk3ODI0MiwianRpIjoiZTU4ZGM2ZjctZjQ0NC00YzcxLThlNzAtNzRhNWY1MTRlZDAwIiwidGlkIjoiYXp1cmVhZCJ9.KhySKFTJVaE6tYhsxCZonYMXv4fKwjtOI4YIAIoOs3DwaXoynTvy2lgiHSfisq-jLTJFGf9eGNbvwc3jUtypclVpYy_8d3xbvuu6jrOA1zWYagZjYr1FNN1g8tlF0SXjtkK_Bg-eZusLnEEbrZK1KnQRWN0I5fXqS7-IVe07hKTOE1teg7of2nCjfJ-iOXhf1mkXqCoUfSbJuUX2PEUs0b9yXAh_J-5P75T6130KBfRw5T5gYI0Kab3u2vm6t-ihT2Kz0aMkUGv_39myDgiwP4TV2vt4PhUiwefPo7KD-4_dkHc7Q5xUv-DWgTLUfXL2lOWf2d0C5tVExLB86jq8hw".to_string(),
                skip_cache: Some(true),
            }))),
        ),
    ),
    responses(
        (status = OK, description = "Success", body = TokenResponse, content_type = "application/json",
            examples(
                ("Token response" = (value = json!(TokenResponse{
                    access_token: "eyJraWQiOiJhenVyZWFkIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI1ZDYzMDliNi05OGUzLTQ1ODAtYTQwNS02MDExYzhhNjExYzgiLCJhdWQiOiJteS10YXJnZXQiLCJuYmYiOjE3MzA5NzgyNDIsImF6cCI6InlvbG8iLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXp1cmVhZCIsImV4cCI6MTczMDk4MTg0MiwiaWF0IjoxNzMwOTc4MjQyLCJqdGkiOiJkNDQ4NTRjNC1iYmZhLTRmZTMtYTMyNC0xZDQyNjdkZjdjZjYiLCJ0aWQiOiJhenVyZWFkIn0.fqTw40aXkzGqet7mMRfK-8cUICzBW7SKIb5UOh6sTvrqprJEtF1HG8MLRcjgjEVwShNkYzJiUZzOC7GSxcuYSiDFg9rboR0QPvTtYsPHWjBGCpvo7lJl27oyqS7QUS83Gsc3oGbCYxc_f4TWOVP8j6pVVZjHAietUd7A-KSwck_YkhmJxKpx7HUhK11AOLjcUlJzb_GpAf1zbog9aIsg9gg9DvWIXtyGqmmBAjr69faFzg7s6KssAQS6A3Qcn19nHC2-J_Ic5q-b8gIDGTq2w62GukbYjyjI7pMYYE04QPPmFI1jdKS9QygW8zX2wQ-10Tc4o4BmMMRjp1RvMm3t6Q".to_string(),
                    token_type: TokenType::Bearer,
                    expires_in_seconds: 3599,
                }))),
        )),
        (status = BAD_REQUEST, description = "Bad request", body = ErrorResponse, content_type = "application/json"),
        (status = INTERNAL_SERVER_ERROR, description = "Server error", body = ErrorResponse, content_type = "application/json"),
    )
)]
#[instrument(skip_all, name = "Handle /api/v1/token/exchange", err, fields(
    texas.cache_force_skipped,
    texas.cache_hit,
    texas.cache_ttl_seconds,
    texas.identity_provider = %request.identity_provider,
    texas.target = %request.target,
    texas.token_expires_in_seconds,
))]
pub async fn token_exchange(
    AxumState(state): AxumState<State>,
    JsonOrForm(request): JsonOrForm<TokenExchangeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    const PATH: &str = "/api/v1/token/exchange";
    let span = tracing::Span::current();
    inc_token_exchanges(PATH, request.identity_provider);

    if request.skip_cache.unwrap_or(false) {
        span.set_attribute("texas.cache_force_skipped", true);
        state.token_exchange_cache.invalidate(&request).await;
    } else if let Some(cached_response) = state.token_exchange_cache.get(&request).await {
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
        if !provider.read().await.should_handle_token_exchange_request(&request) {
            continue;
        }
        let response: TokenResponse =
            provider
                .read()
                .await
                .exchange_token(request.clone())
                .await
                .inspect_err(|e| inc_handler_errors(PATH, request.identity_provider, e.as_ref()))?;

        span.set_attribute(
            "texas.token_expires_in_seconds",
            response.expires_in_seconds.cast_signed(),
        );
        state
            .token_exchange_cache
            .insert(request, CachedTokenResponse::from(response.clone()))
            .await;
        return Ok(Json(response));
    }

    if !provider_enabled {
        return Err(handler::identity_provider_not_enabled_error(
            PATH,
            request.identity_provider,
        ));
    }

    let err = ApiError::TokenExchangeUnsupported(request.identity_provider);
    inc_handler_errors(PATH, request.identity_provider, err.as_ref());
    Err(err)
}
