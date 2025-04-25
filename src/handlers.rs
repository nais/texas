use crate::cache::{CachedTokenResponse, TokenResponseExpiry};
use crate::claims::{Assertion, ClientAssertion, JWTBearerAssertion};
use crate::config::Config;
use crate::grants::{ClientCredentials, JWTBearer, OnBehalfOf, TokenExchange, TokenRequestBuilder};
use crate::identity_provider::*;
use crate::tracing::{inc_handler_errors, inc_token_cache_hits, inc_token_exchanges, inc_token_introspections, inc_token_requests};
use crate::{config, jwks};
use axum::extract::rejection::{FormRejection, JsonRejection};
use axum::extract::FromRequest;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Form;
use axum::Json;
use log::{error, info};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use strum_macros::AsRefStr;
use thiserror::Error;
use tokio::sync::RwLock;
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
            ("Generate a token for Maskinporten" = (value = json!(TokenRequest{
                identity_provider: IdentityProvider::Maskinporten,
                target: "altinn:serviceowner/rolesandrights".to_string(),
                resource: Some("http://resource.example/api".to_string()),
                skip_cache: None,
            }))),
            ("Generate a token for Azure AD" = (value = json!(TokenRequest{
                identity_provider: IdentityProvider::AzureAD,
                target: "api://cluster.namespace.application/.default".to_string(),
                resource: None,
                skip_cache: None,
            }))),
            ("Force renewal of token for Azure AD" = (value = json!(TokenRequest{
                identity_provider: IdentityProvider::AzureAD,
                target: "api://cluster.namespace.application/.default".to_string(),
                resource: None,
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
#[instrument(skip_all, name = "Handle /api/v1/token", fields(texas.cache_hit, texas.cache_skipped, texas.resource, texas.identity_provider = %request.identity_provider, texas.target = %request.target))]
pub async fn token(State(state): State<HandlerState>, JsonOrForm(request): JsonOrForm<TokenRequest>) -> Result<impl IntoResponse, ApiError> {
    const PATH: &str = "/api/v1/token";
    let span = tracing::Span::current();

    if let Some(ref resource) = request.resource {
        span.set_attribute("texas.resource", resource.clone());
    };

    let skip_cache = request.skip_cache.unwrap_or(false);
    if !skip_cache {
        if let Some(cached_response) = state.token_cache.get(&request).await {
            inc_token_cache_hits(PATH, request.identity_provider);
            inc_token_requests(PATH, request.identity_provider);
            return Ok(Json(cached_response.into()));
        }
    }
    tracing::Span::current().set_attribute("texas.cache_skipped", skip_cache);
    inc_token_requests(PATH, request.identity_provider);

    let mut provider_enabled = false;
    for provider in state.providers {
        if provider.read().await.identity_provider_matches(request.identity_provider) {
            provider_enabled = true;
        }
        if !provider.read().await.should_handle_token_request(&request) {
            continue;
        }
        let response = provider
            .read()
            .await
            .get_token(request.clone())
            .await
            .inspect_err(|e| inc_handler_errors(PATH, request.identity_provider, e.as_ref()))?;
        state.token_cache.insert(request, response.clone().into()).await;
        return Ok(Json(response));
    }

    if !provider_enabled {
        return Err(identity_provider_not_enabled_error(PATH, request.identity_provider));
    }

    let err = ApiError::TokenRequestUnsupported(request.identity_provider);
    inc_handler_errors(PATH, request.identity_provider, err.as_ref());
    Err(err)
}

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
            ("Exchange a token using Azure AD" = (value = json!(TokenExchangeRequest{
                identity_provider: IdentityProvider::AzureAD,
                target: "api://cluster.namespace.application/.default".to_string(),
                user_token: "eyJraWQiOiJhenVyZWFkIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI1ZDYzMDliNi05OGUzLTQ1ODAtYTQwNS02MDExYzhhNjExYzgiLCJhdWQiOiJkZWZhdWx0IiwibmJmIjoxNzMwOTc4MjQyLCJhenAiOiJ5b2xvIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F6dXJlYWQiLCJleHAiOjE3MzA5ODE4NDIsImlhdCI6MTczMDk3ODI0MiwianRpIjoiZTU4ZGM2ZjctZjQ0NC00YzcxLThlNzAtNzRhNWY1MTRlZDAwIiwidGlkIjoiYXp1cmVhZCJ9.KhySKFTJVaE6tYhsxCZonYMXv4fKwjtOI4YIAIoOs3DwaXoynTvy2lgiHSfisq-jLTJFGf9eGNbvwc3jUtypclVpYy_8d3xbvuu6jrOA1zWYagZjYr1FNN1g8tlF0SXjtkK_Bg-eZusLnEEbrZK1KnQRWN0I5fXqS7-IVe07hKTOE1teg7of2nCjfJ-iOXhf1mkXqCoUfSbJuUX2PEUs0b9yXAh_J-5P75T6130KBfRw5T5gYI0Kab3u2vm6t-ihT2Kz0aMkUGv_39myDgiwP4TV2vt4PhUiwefPo7KD-4_dkHc7Q5xUv-DWgTLUfXL2lOWf2d0C5tVExLB86jq8hw".to_string(),
                skip_cache: None,
            }))),
            ("Force renewal of token using Azure AD" = (value = json!(TokenExchangeRequest{
                identity_provider: IdentityProvider::AzureAD,
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
#[instrument(skip_all, name = "Handle /api/v1/token/exchange", fields(texas.cache_hit, texas.cache_skipped, texas.identity_provider = %request.identity_provider, texas.target = %request.target))]
pub async fn token_exchange(State(state): State<HandlerState>, JsonOrForm(request): JsonOrForm<TokenExchangeRequest>) -> Result<impl IntoResponse, ApiError> {
    const PATH: &str = "/api/v1/token/exchange";

    let skip_cache = request.skip_cache.unwrap_or(false);
    if !skip_cache {
        if let Some(cached_response) = state.token_exchange_cache.get(&request).await {
            inc_token_cache_hits(PATH, request.identity_provider);
            inc_token_exchanges(PATH, request.identity_provider);
            return Ok(Json(cached_response.into()));
        }
    }
    tracing::Span::current().set_attribute("texas.cache_skipped", skip_cache);
    inc_token_exchanges(PATH, request.identity_provider);

    let mut provider_enabled = false;
    for provider in state.providers {
        if provider.read().await.identity_provider_matches(request.identity_provider) {
            provider_enabled = true;
        }
        if !provider.read().await.should_handle_token_exchange_request(&request) {
            continue;
        }
        let response = provider
            .read()
            .await
            .exchange_token(request.clone())
            .await
            .inspect_err(|e| inc_handler_errors(PATH, request.identity_provider, e.as_ref()))?;
        state.token_exchange_cache.insert(request, response.clone().into()).await;
        return Ok(Json(response));
    }

    if !provider_enabled {
        return Err(identity_provider_not_enabled_error(PATH, request.identity_provider));
    }

    let err = ApiError::TokenExchangeUnsupported(request.identity_provider);
    inc_handler_errors(PATH, request.identity_provider, err.as_ref());
    Err(err)
}

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
#[instrument(skip_all, name = "Handle /api/v1/introspect", fields(texas.identity_provider = %request.identity_provider))]
pub async fn introspect(State(state): State<HandlerState>, JsonOrForm(request): JsonOrForm<IntrospectRequest>) -> Result<impl IntoResponse, Json<IntrospectResponse>> {
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
        return Ok(Json(provider.write().await.introspect(request.token).await));
    }

    if !provider_enabled {
        return Err(Json(IntrospectResponse::new_invalid(identity_provider_not_enabled_error(PATH, request.identity_provider))));
    }

    let error_message = match request.issuer() {
        None => "token is invalid".to_string(),
        Some(iss) => format!("unrecognized issuer: '{iss}'"),
    };

    Err(Json(IntrospectResponse::new_invalid(error_message)))
}

#[derive(Error, Debug)]
pub enum InitError {
    #[error("invalid private JWK format: {0}")]
    Jwk(ProviderError),

    #[error("fetch JWKS from remote endpoint: {0}")]
    Jwks(#[from] jwks::Error),
}

async fn new<R, A>(kind: IdentityProvider, provider_cfg: &config::Provider, audience: Option<String>) -> Result<Arc<RwLock<Box<dyn ProviderHandler>>>, InitError>
where
    R: TokenRequestBuilder + 'static,
    A: Assertion + 'static,
    Provider<R, A>: ShouldHandler,
{
    Ok(Arc::new(RwLock::new(Box::new(
        Provider::<R, A>::new(
            kind,
            provider_cfg.client_id.clone(),
            provider_cfg.token_endpoint.clone(),
            provider_cfg.client_jwk.clone(),
            jwks::Jwks::new(&provider_cfg.issuer.clone(), &provider_cfg.jwks_uri.clone(), audience)
                .await
                .map_err(InitError::Jwks)?,
        )
        .map_err(InitError::Jwk)?,
    ))))
}

#[derive(Clone)]
pub struct HandlerState {
    pub cfg: Config,
    pub providers: Vec<Arc<RwLock<Box<dyn ProviderHandler>>>>,
    pub token_cache: moka::future::Cache<TokenRequest, CachedTokenResponse>,
    pub token_exchange_cache: moka::future::Cache<TokenExchangeRequest, CachedTokenResponse>,
}

impl HandlerState {
    pub async fn from_config(cfg: Config) -> Result<Self, InitError> {
        let mut providers: Vec<Arc<RwLock<Box<dyn ProviderHandler>>>> = vec![];

        if let Some(provider_cfg) = &cfg.maskinporten {
            info!("Fetch JWKS for Maskinporten from '{}'...", provider_cfg.jwks_uri);
            let provider = new::<JWTBearer, JWTBearerAssertion>(IdentityProvider::Maskinporten, provider_cfg, None).await?;
            providers.push(provider);
        }

        if let Some(provider_cfg) = &cfg.azure_ad {
            info!("Fetch JWKS for Azure AD (on behalf of) from '{}'...", provider_cfg.jwks_uri);
            let provider = new::<OnBehalfOf, ClientAssertion>(IdentityProvider::AzureAD, provider_cfg, Some(provider_cfg.client_id.clone())).await?;
            providers.push(provider);

            info!("Fetch JWKS for Azure AD (client credentials) from '{}'...", provider_cfg.jwks_uri);
            let provider = new::<ClientCredentials, ClientAssertion>(IdentityProvider::AzureAD, provider_cfg, Some(provider_cfg.client_id.clone())).await?;
            providers.push(provider);
        }

        if let Some(provider_cfg) = &cfg.token_x {
            info!("Fetch JWKS for TokenX from '{}'...", provider_cfg.jwks_uri);
            let provider = new::<TokenExchange, ClientAssertion>(IdentityProvider::TokenX, provider_cfg, Some(provider_cfg.client_id.clone())).await?;
            providers.push(provider);
        }

        if let Some(provider_cfg) = &cfg.idporten {
            info!("Fetch JWKS for ID-porten from '{}'...", provider_cfg.jwks_uri);
            let provider = new::<(), ()>(IdentityProvider::IDPorten, provider_cfg, Some(provider_cfg.client_id.clone())).await?;
            providers.push(provider);
        }

        const CACHE_MAX_CAPACITY: u64 = 262144;

        let token_cache = moka::future::CacheBuilder::default()
            .max_capacity(CACHE_MAX_CAPACITY)
            .expire_after(TokenResponseExpiry)
            .build();

        let token_exchange_cache = moka::future::CacheBuilder::default()
            .max_capacity(CACHE_MAX_CAPACITY)
            .expire_after(TokenResponseExpiry)
            .build();

        Ok(Self {
            cfg,
            token_cache,
            token_exchange_cache,
            providers,
        })
    }
}

#[derive(Debug, AsRefStr, Error)]
pub enum ApiError {
    #[error("identity provider error: {0}")]
    UpstreamRequest(reqwest_middleware::Error),

    #[error("upstream: status code {status_code}: {error}")]
    Upstream { status_code: StatusCode, error: ErrorResponse },

    #[error("invalid JSON in token response: {0}")]
    JSON(reqwest::Error),

    #[error("cannot sign JWT claims")]
    Sign,

    #[error("{0}")]
    UnsupportedMediaType(String),

    #[error("{0}")]
    UnprocessableContent(String),

    #[error("identity provider '{0}' does not support token exchange")]
    TokenExchangeUnsupported(IdentityProvider),

    #[error("identity provider '{0}' does not support token requests")]
    TokenRequestUnsupported(IdentityProvider),

    #[error("identity provider '{0}' is not enabled")]
    IdentityProviderNotEnabled(IdentityProvider),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        let (status_code, error_response) = match self {
            // Upstream OAuth errors may differ between providers.
            //
            // They range from things we're in control of (such as assertions) to things we cannot
            // control (such as access to scopes, invalid downstream-supplied values, and so on).
            //
            // We propagate the error response as-is from the upstream instead of trying to handle
            // these ambiguities.
            ApiError::Upstream { status_code, error } => (status_code, error),
            ApiError::Sign => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse {
                    error: OAuthErrorCode::ServerError,
                    description: "Failed to sign assertion".to_string(),
                },
            ),
            ApiError::JSON(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse {
                    error: OAuthErrorCode::ServerError,
                    description: format!("Failed to parse JSON: {}", err),
                },
            ),
            ApiError::UpstreamRequest(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse {
                    error: OAuthErrorCode::ServerError,
                    description: format!("Upstream request failed: {}", err),
                },
            ),
            ApiError::TokenExchangeUnsupported(_) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse {
                    error: OAuthErrorCode::InvalidRequest,
                    description: self.to_string(),
                },
            ),
            ApiError::TokenRequestUnsupported(_) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse {
                    error: OAuthErrorCode::InvalidRequest,
                    description: self.to_string(),
                },
            ),
            ApiError::IdentityProviderNotEnabled(_) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse {
                    error: OAuthErrorCode::InvalidRequest,
                    description: self.to_string(),
                },
            ),
            ApiError::UnprocessableContent(_) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse {
                    error: OAuthErrorCode::InvalidRequest,
                    description: self.to_string(),
                },
            ),
            ApiError::UnsupportedMediaType(_) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse {
                    error: OAuthErrorCode::InvalidRequest,
                    description: self.to_string(),
                },
            ),
        };
        (status_code, Json(error_response)).into_response()
    }
}

pub struct JsonOrForm<T>(pub T);

impl<S, T> FromRequest<S> for JsonOrForm<T>
where
    S: Send + Sync,
    T: 'static,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    Form<T>: FromRequest<S, Rejection = FormRejection>,
{
    type Rejection = ApiError;

    #[instrument(skip_all, name = "Deserialize request")]
    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let content_type_header = req.headers().get(CONTENT_TYPE);
        let content_type = content_type_header.and_then(|value| value.to_str().ok());

        if let Some(content_type) = content_type {
            if content_type.starts_with("application/json") {
                return match Json::<T>::from_request(req, state).await {
                    Ok(payload) => Ok(Self(payload.0)),
                    Err(rejection) => Err(match rejection {
                        JsonRejection::MissingJsonContentType(err) => ApiError::UnsupportedMediaType(err.body_text()),
                        JsonRejection::JsonDataError(err) => ApiError::UnprocessableContent(err.body_text()),
                        JsonRejection::JsonSyntaxError(err) => ApiError::UnprocessableContent(err.body_text()),
                        JsonRejection::BytesRejection(err) => ApiError::UnprocessableContent(err.body_text()),
                        err => ApiError::UnprocessableContent(err.body_text()),
                    }),
                };
            }

            if content_type.starts_with("application/x-www-form-urlencoded") {
                return match Form::<T>::from_request(req, state).await {
                    Ok(payload) => Ok(Self(payload.0)),
                    Err(rejection) => Err(match rejection {
                        FormRejection::InvalidFormContentType(err) => ApiError::UnsupportedMediaType(err.body_text()),
                        FormRejection::FailedToDeserializeForm(err) => ApiError::UnprocessableContent(err.body_text()),
                        FormRejection::FailedToDeserializeFormBody(err) => ApiError::UnprocessableContent(err.body_text()),
                        FormRejection::BytesRejection(err) => ApiError::UnprocessableContent(err.body_text()),
                        err => ApiError::UnprocessableContent(err.body_text()),
                    }),
                };
            }
        }

        Err(ApiError::UnsupportedMediaType(format!(
            "unsupported media type: {}: expected one of `application/json`, `application/x-www-form-urlencoded`",
            content_type.unwrap_or("")
        )))
    }
}

fn identity_provider_not_enabled_error(path: &str, provider: IdentityProvider) -> ApiError {
    let err = ApiError::IdentityProviderNotEnabled(provider);
    tracing::Span::current().set_attribute("texas.identity_provider.enabled", false);
    inc_handler_errors(path, provider, err.as_ref());
    err
}
