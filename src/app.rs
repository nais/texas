use crate::app::Error::LocalAddress;
use crate::config::Config;
use crate::handlers::__path_introspect;
use crate::handlers::__path_token;
use crate::handlers::__path_token_exchange;
use crate::handlers::{HandlerState, introspect, token, token_exchange};
use crate::{config, handlers};
use axum::Router;
use axum::extract::MatchedPath;
use axum::http::Request;
use axum::response::Response;
use log::{debug, info};
use opentelemetry::KeyValue;
use opentelemetry::baggage::BaggageExt;
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_http::HeaderExtractor;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing::{Span, error, info_span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use utoipa::{OpenApi, openapi};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

pub struct App {
    router: Router,
    listener: TcpListener,
}

#[derive(OpenApi)]
#[openapi(info(
    title = "Token Exchange as a Service (Texas)",
    description = "Texas implements OAuth token fetch, exchange, and validation, so that you don't have to.",
    contact(name = "Nais", url = "https://nais.io")
))]
pub struct ApiDoc;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("set up listening socket: {0}")]
    BindAddress(std::io::Error),
    #[error("describe socket local address: {0}")]
    LocalAddress(std::io::Error),
    #[error("{0}")]
    InitHandlerState(handlers::InitError),
    #[error("invalid configuration: {0}")]
    Configuration(config::Error),
}

impl App {
    pub async fn new_from_env() -> Result<Self, Error> {
        let cfg = Config::new_from_env().map_err(Error::Configuration)?;
        Self::new_from_config(cfg).await
    }

    pub async fn new_from_config(cfg: Config) -> Result<Self, Error> {
        let bind_address = cfg.bind_address.clone();
        let listener = TcpListener::bind(bind_address).await.map_err(Error::BindAddress)?;

        let state = HandlerState::from_config(cfg).await.map_err(Error::InitHandlerState)?;
        let app = Self::router(state);

        let local_addr = listener.local_addr().map_err(LocalAddress)?;
        info!("Serving on http://{local_addr:?}");
        #[cfg(feature = "openapi")]
        info!("Swagger API documentation: http://{:?}/swagger-ui", local_addr);

        Ok(Self { router: app, listener })
    }

    pub async fn run(self) {
        // Although this future resolves to `io::Result<()>`,
        // it will never actually complete or return an error.
        axum::serve(self.listener, self.router)
            .with_graceful_shutdown(Self::shutdown_signal())
            .await
            .unwrap();
    }

    async fn shutdown_signal() {
        let ctrl_c = async {
            signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler")
                .recv()
                .await;
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            () = ctrl_c => debug!{"Received Ctrl+C / SIGINT"},
            () = terminate => debug!{"Received SIGTERM"},
        }
    }

    #[cfg(test)]
    pub fn address(&self) -> Option<String> {
        self.listener.local_addr().map(|addr| addr.to_string()).ok()
    }

    pub fn routes(state: HandlerState) -> (Router, openapi::OpenApi) {
        OpenApiRouter::with_openapi(ApiDoc::openapi())
            .routes(routes!(token))
            .routes(routes!(token_exchange))
            .routes(routes!(introspect))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(move |request: &Request<_>| {
                        // Log the matched route's path (with placeholders not filled in).
                        // Use request.uri() or OriginalUri if you want the real path.
                        let path = request.extensions().get::<MatchedPath>().map(MatchedPath::as_str);

                        // get tracing context from request
                        let parent_context = TraceContextPropagator::new().extract(&HeaderExtractor(request.headers()));

                        let root_span = info_span!(
                            "Handle incoming request",
                            method = ?request.method(),
                            path,
                            "otel.kind" = "server",
                        );

                        let context = parent_context.with_baggage(vec![KeyValue::new("path".to_string(), path.unwrap_or_default().to_string())]);
                        root_span.set_parent(context.clone());
                        root_span
                    })
                    .on_response(move |response: &Response, latency: Duration, span: &Span| {
                        let path = span.context().baggage().get("path").map(ToString::to_string).unwrap_or_default();
                        crate::tracing::record_http_response_secs(&path, latency, response.status());
                    }),
            )
            .with_state(state)
            .split_for_parts()
    }

    #[cfg(not(feature = "openapi"))]
    fn router(state: HandlerState) -> Router {
        let (router, _) = Self::routes(state);
        router
    }

    #[cfg(feature = "openapi")]
    fn router(state: HandlerState) -> Router {
        use utoipa_swagger_ui::SwaggerUi;
        let (router, openapi) = Self::routes(state);
        router.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi.clone()))
    }
}

#[cfg(test)]
mod tests {
    use crate::app::App;
    use crate::claims::epoch_now_secs;
    use crate::config::Config;
    use crate::identity_provider::{ErrorResponse, IdentityProvider, IntrospectRequest, IntrospectResponse, OAuthErrorCode, TokenExchangeRequest, TokenRequest, TokenResponse};
    use jsonwebkey as jwk;
    use jsonwebtoken as jwt;
    use log::info;
    use reqwest::{Error, Response, StatusCode};
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::fmt::Debug;
    use testcontainers::{ContainerAsync, GenericImage};

    /// Test a full round-trip of the `/token`, `/token/exchange`, and `/introspect` endpoints.
    ///
    /// Content-type encodings tested are both `application/json` and `application/x-www-form-urlencoded`.
    ///
    /// Test token exchange as follows:
    ///   1. Request an initial token from the mock oauth2 server using the `/token` endpoint
    ///   2. Exchange that token into a on-behalf-of token using Texas' `/token` endpoint
    ///   3. Introspect the resulting token and check parameters
    ///
    /// Test client credentials as follows:
    ///   1. Request a client credentials token using Texas' `/token` endpoint
    ///   2. Introspect the resulting token and check parameters
    #[tokio::test]
    async fn test_all_providers_integration_tests() {
        let testapp = TestApp::new().await;
        let address = testapp.app.address().unwrap();
        let join_handler = tokio::spawn(async move {
            testapp.app.run().await;
        });
        let docker = testapp.docker.unwrap();
        let identity_provider_address = format!("{}:{}", docker.host.clone(), docker.port);

        // All happy cases
        for format in [RequestFormat::Form, RequestFormat::Json] {
            machine_to_machine_token(&testapp.cfg.maskinporten.clone().unwrap().issuer, "scope", &address, IdentityProvider::Maskinporten, format.clone()).await;

            machine_to_machine_token(
                &testapp.cfg.azure_ad.clone().unwrap().issuer,
                &testapp.cfg.azure_ad.clone().unwrap().client_id,
                &address,
                IdentityProvider::AzureAD,
                format.clone(),
            )
            .await;

            token_exchange_token(
                &testapp.cfg.azure_ad.clone().unwrap().issuer,
                &testapp.cfg.azure_ad.clone().unwrap().client_id,
                &address,
                &identity_provider_address,
                IdentityProvider::AzureAD,
                format.clone(),
            )
            .await;

            token_exchange_token(
                &testapp.cfg.token_x.clone().unwrap().issuer,
                &testapp.cfg.token_x.clone().unwrap().client_id,
                &address,
                &identity_provider_address,
                IdentityProvider::TokenX,
                format.clone(),
            )
            .await;

            introspect_token(
                &testapp.cfg.azure_ad.clone().unwrap().issuer,
                &address,
                &identity_provider_address,
                IdentityProvider::AzureAD,
                format.clone(),
            )
            .await;

            introspect_token(
                &testapp.cfg.idporten.clone().unwrap().issuer,
                &address,
                &identity_provider_address,
                IdentityProvider::IDPorten,
                format.clone(),
            )
            .await;

            introspect_token(
                &testapp.cfg.maskinporten.clone().unwrap().issuer,
                &address,
                &identity_provider_address,
                IdentityProvider::Maskinporten,
                format.clone(),
            )
            .await;

            introspect_token(
                &testapp.cfg.token_x.clone().unwrap().issuer,
                &address,
                &identity_provider_address,
                IdentityProvider::TokenX,
                format.clone(),
            )
            .await;
        }

        test_token_invalid_identity_provider(&address).await;
        test_token_invalid_content_type(&address).await;
        test_token_exchange_missing_or_empty_user_token(&address).await;
        test_introspect_token_is_not_a_jwt(&address).await;
        test_introspect_token_missing_issuer(&address).await;
        test_introspect_token_unrecognized_issuer(&address).await;
        test_introspect_token_issuer_mismatch(&address, &identity_provider_address).await;
        test_introspect_token_missing_kid(&address, &identity_provider_address).await;
        test_introspect_token_missing_key_in_jwks(&address, &identity_provider_address).await;
        test_introspect_token_is_expired(&address, &identity_provider_address).await;
        test_introspect_token_is_issued_in_the_future(&address, &identity_provider_address).await;
        test_introspect_token_has_not_before_in_the_future(&address, &identity_provider_address).await;
        test_introspect_token_invalid_audience(&address).await;
        test_token_unsupported_identity_provider(&address).await;
        test_token_exchange_unsupported_identity_provider(&address).await;

        join_handler.abort();
    }

    /// Test that Texas returns an appropriate error when the identity provider is not supported.
    #[tokio::test]
    async fn test_non_enabled_providers_integration_tests() {
        let testapp = TestApp::new_no_providers().await;
        let address = testapp.app.address().unwrap();
        let join_handler = tokio::spawn(async move {
            testapp.app.run().await;
        });

        let providers = [IdentityProvider::AzureAD, IdentityProvider::IDPorten, IdentityProvider::Maskinporten, IdentityProvider::TokenX];
        for provider in providers {
            test_well_formed_json_request(
                token_url(&address).as_str(),
                TokenRequest {
                    target: "some_target".to_string(),
                    identity_provider: provider,
                    resource: None,
                    skip_cache: None,
                },
                ErrorResponse {
                    error: OAuthErrorCode::InvalidRequest,
                    description: format!("identity provider '{provider}' is not enabled"),
                },
                StatusCode::BAD_REQUEST,
            )
            .await;

            test_well_formed_json_request(
                token_exchange_url(&address).as_str(),
                TokenExchangeRequest {
                    target: "some_target".to_string(),
                    identity_provider: provider,
                    user_token: "some_token".to_string(),
                    skip_cache: None,
                },
                ErrorResponse {
                    error: OAuthErrorCode::InvalidRequest,
                    description: format!("identity provider '{provider}' is not enabled"),
                },
                StatusCode::BAD_REQUEST,
            )
            .await;

            test_well_formed_json_request(
                introspect_url(&address).as_str(),
                IntrospectRequest {
                    token: "some_token".to_string(),
                    identity_provider: provider,
                },
                IntrospectResponse::new_invalid(format!("identity provider '{provider}' is not enabled")),
                StatusCode::OK,
            )
            .await;
        }

        join_handler.abort();
    }

    async fn machine_to_machine_token(expected_issuer: &str, target: &str, address: &str, identity_provider: IdentityProvider, request_format: RequestFormat) {
        let request = TokenRequest {
            target: target.to_string(),
            identity_provider,
            resource: None,
            skip_cache: None,
        };
        let first_token_response = test_happy_path_token(address, request.clone(), request_format.clone()).await;
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
                skip_cache: None,
            },
            request_format.clone(),
        )
        .await;
        assert_ne!(different_token_response.access_token, first_token_response.access_token);

        // second token request with same inputs should return cached token
        let second_token_response = test_happy_path_token(address, request, request_format.clone()).await;
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

        assert_eq!(second_token_response.access_token, first_token_response.access_token);
        assert_ne!(second_token_response.access_token, different_token_response.access_token);
        assert_eq!(second_token_introspect.issuer(), first_token_introspect.issuer());
        assert_eq!(second_token_introspect.jwt_id(), first_token_introspect.jwt_id());

        // third token request with skip_cache=true should return a new token
        let third_token_response = test_happy_path_token(
            address,
            TokenRequest {
                target: target.to_string(),
                identity_provider,
                resource: None,
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

        assert_ne!(third_token_response.access_token, first_token_response.access_token);
        assert_ne!(third_token_response.access_token, second_token_response.access_token);
        assert_ne!(third_token_response.access_token, different_token_response.access_token);

        assert_eq!(third_token_introspect.issuer(), first_token_introspect.issuer());
        assert_eq!(third_token_introspect.issuer(), second_token_introspect.issuer());

        assert_ne!(third_token_introspect.jwt_id(), first_token_introspect.jwt_id());
        assert_ne!(third_token_introspect.jwt_id(), second_token_introspect.jwt_id());
    }

    /// this tests the full token exchange roundtrip:
    ///  1. fetch user token from mock-oauth2-server
    ///  2. exchange user token for on-behalf-of token at /token/exchange
    ///  3. introspect the resulting token at /introspect
    async fn token_exchange_token(expected_issuer: &str, target: &str, address: &str, identity_provider_address: &str, identity_provider: IdentityProvider, request_format: RequestFormat) {
        let user_token: TokenResponse = get_user_token(identity_provider_address, identity_provider).await;
        let request = TokenExchangeRequest {
            target: target.to_string(),
            identity_provider,
            user_token: user_token.access_token.clone(),
            skip_cache: None,
        };
        let first_token_response = test_happy_path_token_exchange(address, request.clone(), request_format.clone()).await;
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

        assert!(first_token_introspect.subject().is_some());

        // different target should return a different token
        let different_target_token_response = test_happy_path_token_exchange(
            address,
            TokenExchangeRequest {
                target: "different_target".to_string(),
                identity_provider,
                user_token: user_token.access_token.clone(),
                skip_cache: None,
            },
            request_format.clone(),
        )
        .await;
        assert_ne!(different_target_token_response.access_token, first_token_response.access_token);

        // different user token should return a different token
        let user_token_2: TokenResponse = get_user_token(identity_provider_address, identity_provider).await;
        let different_user_token_response = test_happy_path_token_exchange(
            address,
            TokenExchangeRequest {
                target: target.to_string(),
                identity_provider,
                user_token: user_token_2.access_token.clone(),
                skip_cache: None,
            },
            request_format.clone(),
        )
        .await;
        assert_ne!(different_user_token_response.access_token, first_token_response.access_token);
        assert_ne!(different_user_token_response.access_token, different_target_token_response.access_token);

        // second token request with same inputs should return cached token
        let second_token_response = test_happy_path_token_exchange(address, request, request_format.clone()).await;
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

        assert!(second_token_introspect.subject().is_some());

        assert_eq!(second_token_response.access_token, first_token_response.access_token);
        assert_ne!(second_token_response.access_token, different_target_token_response.access_token);
        assert_ne!(second_token_response.access_token, different_user_token_response.access_token);
        assert_eq!(second_token_introspect.issuer(), first_token_introspect.issuer());
        assert_eq!(second_token_introspect.jwt_id(), first_token_introspect.jwt_id());
        assert_eq!(second_token_introspect.subject(), first_token_introspect.subject());

        // third token request with skip_cache=true should return a new token
        let third_token_response = test_happy_path_token_exchange(
            address,
            TokenExchangeRequest {
                target: target.to_string(),
                identity_provider,
                user_token: user_token.access_token.clone(),
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

        assert!(third_token_introspect.subject().is_some());

        assert_ne!(third_token_response.access_token, first_token_response.access_token);
        assert_ne!(third_token_response.access_token, second_token_response.access_token);
        assert_ne!(third_token_response.access_token, different_target_token_response.access_token);
        assert_ne!(third_token_response.access_token, different_user_token_response.access_token);

        assert_eq!(third_token_introspect.issuer(), first_token_introspect.issuer());
        assert_eq!(third_token_introspect.issuer(), second_token_introspect.issuer());

        assert_ne!(third_token_introspect.jwt_id(), first_token_introspect.jwt_id());
        assert_ne!(third_token_introspect.jwt_id(), second_token_introspect.jwt_id());

        assert_eq!(third_token_introspect.subject(), first_token_introspect.subject());
        assert_eq!(third_token_introspect.subject(), second_token_introspect.subject());
    }

    async fn introspect_token(expected_issuer: &str, address: &str, identity_provider_address: &str, identity_provider: IdentityProvider, request_format: RequestFormat) {
        let user_token: TokenResponse = get_user_token(identity_provider_address, identity_provider).await;
        let introspect_response = test_happy_path_introspect(
            address,
            expected_issuer,
            IntrospectRequest {
                token: user_token.access_token.clone(),
                identity_provider,
            },
            request_format,
        )
        .await;

        assert!(introspect_response.subject().is_some());
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
        test_well_formed_json_request(
            introspect_url(address).as_str(),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::Maskinporten,
            },
            IntrospectResponse::new_invalid("invalid token: InvalidIssuer"),
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

        test_well_formed_json_request(
            introspect_url(address).as_str(),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::AzureAD,
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

        test_well_formed_json_request(
            introspect_url(address).as_str(),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::Maskinporten,
            },
            IntrospectResponse::new_invalid("invalid token: Missing required claim: iss"),
            StatusCode::OK,
        )
        .await;
    }

    async fn test_introspect_token_is_not_a_jwt(address: &str) {
        test_well_formed_json_request(
            introspect_url(address).as_str(),
            IntrospectRequest {
                token: "not a jwt".to_string(),
                identity_provider: IdentityProvider::AzureAD,
            },
            IntrospectResponse::new_invalid("invalid token header: InvalidToken"),
            StatusCode::OK,
        )
        .await;
    }

    async fn test_introspect_token_missing_kid(address: &str, identity_provider_address: &str) {
        let token = Token::sign(TokenClaims::from([("iss".into(), format!("http://{}/maskinporten", identity_provider_address).into())]));

        test_well_formed_json_request(
            introspect_url(address).as_str(),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::AzureAD,
            },
            IntrospectResponse::new_invalid("missing key id from token header"),
            StatusCode::OK,
        )
        .await;
    }

    async fn test_introspect_token_missing_key_in_jwks(address: &str, identity_provider_address: &str) {
        let token = Token::sign_with_kid(TokenClaims::from([("iss".into(), format!("http://{}/maskinporten", identity_provider_address).into())]), "missing-key");

        test_well_formed_json_request(
            introspect_url(address).as_str(),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::Maskinporten,
            },
            IntrospectResponse::new_invalid("token can not be validated with this identity provider"),
            StatusCode::OK,
        )
        .await;
    }

    async fn test_introspect_token_is_expired(address: &str, identity_provider_address: &str) {
        let token = Token::sign_with_kid(
            TokenClaims::from([
                ("iss".into(), format!("http://{}/maskinporten", identity_provider_address).into()),
                ("nbf".into(), epoch_now_secs().into()),
                ("iat".into(), epoch_now_secs().into()),
                ("exp".into(), (epoch_now_secs() - 120).into()),
            ]),
            "maskinporten",
        );

        test_well_formed_json_request(
            introspect_url(address).as_str(),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::Maskinporten,
            },
            IntrospectResponse::new_invalid("invalid token: ExpiredSignature"),
            StatusCode::OK,
        )
        .await;
    }

    async fn test_introspect_token_is_issued_in_the_future(address: &str, identity_provider_address: &str) {
        let token = Token::sign_with_kid(
            TokenClaims::from([
                ("iss".into(), format!("http://{}/maskinporten", identity_provider_address).into()),
                ("nbf".into(), epoch_now_secs().into()),
                ("iat".into(), (epoch_now_secs() + 120).into()),
                ("exp".into(), (epoch_now_secs() + 300).into()),
            ]),
            "maskinporten",
        );

        test_well_formed_json_request(
            introspect_url(address).as_str(),
            IntrospectRequest {
                token,
                identity_provider: IdentityProvider::Maskinporten,
            },
            IntrospectResponse::new_invalid("invalid token: ImmatureSignature"),
            StatusCode::OK,
        )
        .await;
    }

    async fn test_introspect_token_has_not_before_in_the_future(address: &str, identity_provider_address: &str) {
        let token = Token::sign_with_kid(
            TokenClaims::from([
                ("iss".into(), format!("http://{}/maskinporten", identity_provider_address).into()),
                ("nbf".into(), (epoch_now_secs() + 120).into()),
                ("iat".into(), epoch_now_secs().into()),
                ("exp".into(), (epoch_now_secs() + 300).into()),
            ]),
            "maskinporten",
        );

        test_well_formed_json_request(
            introspect_url(address).as_str(),
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
        let token_response = test_happy_path_token(
            address,
            TokenRequest {
                target: "invalid".to_string(),
                identity_provider: IdentityProvider::AzureAD,
                resource: None,
                skip_cache: None,
            },
            RequestFormat::Json,
        )
        .await;

        test_well_formed_json_request(
            introspect_url(address).as_str(),
            IntrospectRequest {
                token: token_response.access_token.clone(),
                identity_provider: IdentityProvider::AzureAD,
            },
            IntrospectResponse::new_invalid("invalid token: InvalidAudience"),
            StatusCode::OK,
        )
        .await;
    }

    async fn test_token_exchange_missing_or_empty_user_token(address: &str) {
        test_well_formed_json_request(
            token_exchange_url(address).as_str(),
            TokenExchangeRequest {
                target: "target".to_string(),
                identity_provider: IdentityProvider::AzureAD,
                user_token: "".to_string(),
                skip_cache: None,
            },
            ErrorResponse {
                error: OAuthErrorCode::InvalidRequest,
                description: "invalid request: missing or empty assertion parameter".to_string(),
            },
            StatusCode::BAD_REQUEST,
        )
        .await;
    }

    async fn test_token_invalid_identity_provider(address: &str) {
        let http_response = post_request(
            format!("http://{}/api/v1/token", address),
            json!({"target":"dontcare","identity_provider":"invalid"}),
            RequestFormat::Json,
        )
        .await
        .unwrap();
        let error_response = json_response::<ErrorResponse>(http_response, StatusCode::BAD_REQUEST).await;
        assert_eq!(error_response.error, OAuthErrorCode::InvalidRequest);
        assert_eq!(
            error_response.description,
            "Failed to deserialize the JSON body into the target type: identity_provider: unknown variant `invalid`, expected one of `azuread`, `tokenx`, `maskinporten`, `idporten` at line 1 column 30"
        );

        let http_response = post_request(
            format!("http://{}/api/v1/token", address),
            HashMap::from([("target", "dontcare"), ("identity_provider", "invalid")]),
            RequestFormat::Form,
        )
        .await
        .unwrap();
        let error_response = json_response::<ErrorResponse>(http_response, StatusCode::BAD_REQUEST).await;
        assert_eq!(error_response.error, OAuthErrorCode::InvalidRequest);
        assert_eq!(
            error_response.description,
            "Failed to deserialize form body: identity_provider: unknown variant `invalid`, expected one of `azuread`, `tokenx`, `maskinporten`, `idporten`"
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

        let error_response = json_response::<ErrorResponse>(http_response, StatusCode::BAD_REQUEST).await;
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

    async fn test_token_exchange_unsupported_identity_provider(address: &str) {
        test_well_formed_json_request(
            token_exchange_url(address).as_str(),
            TokenExchangeRequest {
                target: "some_target".to_string(),
                identity_provider: IdentityProvider::IDPorten,
                user_token: "some_token".to_string(),
                skip_cache: None,
            },
            ErrorResponse {
                error: OAuthErrorCode::InvalidRequest,
                description: "identity provider 'idporten' does not support token exchange".to_string(),
            },
            StatusCode::BAD_REQUEST,
        )
        .await;
    }

    #[derive(Clone)]
    enum RequestFormat {
        Json,
        Form,
    }

    async fn post_request(url: String, params: impl Serialize, format: RequestFormat) -> Result<Response, Error> {
        let client = reqwest::Client::new();
        let request = client.post(url).header("accept", "application/json");
        let request = match format {
            RequestFormat::Json => request.json(&params),
            RequestFormat::Form => request.form(&params),
        };
        request.send().await
    }

    async fn json_response<U: DeserializeOwned + PartialEq + Debug + Clone>(response: Response, status_code: StatusCode) -> U {
        assert_eq!(response.status(), status_code);
        response.json::<U>().await.unwrap()
    }

    async fn test_well_formed_request<T: Serialize, U: DeserializeOwned + PartialEq + Debug + Clone>(
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

    async fn test_well_formed_json_request<T: Serialize, U: DeserializeOwned + PartialEq + Debug + Clone>(url: &str, request: T, expected_response: U, status_code: StatusCode) -> U {
        test_well_formed_request(url, request, RequestFormat::Json, status_code, |response: U| {
            assert_eq!(response, expected_response);
        })
        .await
    }

    async fn test_happy_path_token(address: &str, request: TokenRequest, request_format: RequestFormat) -> TokenResponse {
        test_well_formed_request(token_url(address).as_str(), request, request_format, StatusCode::OK, |resp: TokenResponse| {
            assert!(resp.expires_in_seconds > 0);
            assert!(!resp.access_token.is_empty());
        })
        .await
    }

    async fn test_happy_path_token_exchange(address: &str, request: TokenExchangeRequest, request_format: RequestFormat) -> TokenResponse {
        test_well_formed_request(token_exchange_url(address).as_str(), request, request_format, StatusCode::OK, |resp: TokenResponse| {
            assert!(resp.expires_in_seconds > 0);
            assert!(!resp.access_token.is_empty());
        })
        .await
    }

    async fn test_happy_path_introspect(address: &str, expected_issuer: &str, request: IntrospectRequest, request_format: RequestFormat) -> IntrospectResponse {
        test_well_formed_request(introspect_url(address).as_str(), request, request_format, StatusCode::OK, |resp: IntrospectResponse| {
            assert!(resp.active);
            assert!(resp.error.is_none());
            assert!(resp.has_claims());
            assert!(resp.issuer().is_some());
            assert!(resp.jwt_id().is_some());
            assert_eq!(resp.issuer().unwrap(), expected_issuer);
        })
        .await
    }

    async fn get_user_token(identity_provider_address: &str, identity_provider: IdentityProvider) -> TokenResponse {
        #[derive(Serialize)]
        struct AuthorizeRequest {
            grant_type: String,
            code: String,
            client_id: String,
            client_secret: String,
        }

        // This request goes directly to the mock oauth2 server, which only accepts form encoding
        let user_token_response = post_request(
            format!("http://{}/{}/token", identity_provider_address, identity_provider),
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

    fn token_url(address: &str) -> String {
        format!("http://{}/api/v1/token", address)
    }

    fn token_exchange_url(address: &str) -> String {
        format!("http://{}/api/v1/token/exchange", address)
    }

    fn introspect_url(address: &str) -> String {
        format!("http://{}/api/v1/introspect", address)
    }

    struct TestApp {
        app: App,
        cfg: Config,
        docker: Option<DockerRuntimeParams>,
    }

    impl TestApp {
        async fn new() -> Self {
            let docker = DockerRuntimeParams::init().await;

            match docker.container {
                None => info!("Expecting mock-oauth2-server natively in docker-compose on localhost:8080"),
                Some(_) => info!("Running mock-oauth2-server on {}:{}", docker.host, docker.port,),
            }

            // Set up Texas
            let cfg = Config::mock(docker.host.clone(), docker.port);
            let app = App::new_from_config(cfg.clone()).await.unwrap();

            Self { app, cfg, docker: Some(docker) }
        }

        async fn new_no_providers() -> Self {
            // Set up Texas
            let cfg = Config::mock_no_providers();
            let app = App::new_from_config(cfg.clone()).await.unwrap();

            Self { app, cfg, docker: None }
        }
    }

    type TokenClaims = HashMap<String, Value>;

    struct Token {
        header: jwt::Header,
        claims: TokenClaims,
    }

    impl Token {
        /// Matches signing key used in mock-oauth2-server
        const SIGNING_KEY: &'static str = r#"{"p":"_LNnIjBshCrFuxtjUC2KKzg_NTVv26UZh5j12_9r5mYTxb8yW047jOYFEGvIdMkTRLGOBig6fLWzgd62lnLainzV35J6K6zr4jQfTldLondlkldMR6nQrp1KfnNUuRbKvzpNKkhl12-f1l91l0tCx3s4blztvWgdzN2xBfvWV68","kty":"RSA","q":"9MIWsbIA3WjiR_Ful5FM8NCgb6JdS2D6ySHVepoNI-iAPilcltF_J2orjfLqAxeztTskPi45wtF_-eV4GIYSzvMo-gFiXLMrvEa7WaWizMi_7Bu9tEk3m_f3IDLN9lwULYoebkDbiXx6GOiuj0VkuKz8ckYFNKLCMP9QRLFff-0","d":"J6UX848X8tNz-09PFvcFDUVqak32GXzoPjnuDjBsxNUvG7LxenLmM_i8tvYl0EW9Ztn4AiCqJUoHw5cX3jz_mSqGl7ciaDedpKm_AetcZwHiEuT1EpSKRPMmOMQSqcJqXrdbbWB8gdUrnTKZIlJCfj7yqgT16ypC43TnwjA0UwxhG5pHaYjKI3pPdoHg2BzA-iubHjVn15Sz7-pnjBmeGDbEFa7ADY-1yPHCmqqvPKTNhoCNW6RpG34Id9hXslPa3X-7pAhJrDBd0_NPlktSA2rUkifYiZURhHR5ijhe0v3uw6kYP8f_foVm_C8O1ExkxXh9Dg8KDZ89dbsSOtBc0Q","e":"AQAB","use":"sig","kid":"l7C_WJgbZ_6e59vPrFETAehX7Dsp7fIyvSV4XhotsGs","qi":"cQFN5q5WhYkzgd1RS0rGqvpX1AkmZMrLv2MW04gSfu0dDwpbsSAu8EUCQW9oA4pr6V7R9CBSu9kdN2iY5SR-hZvEad5nDKPV1F3TMQYv5KpRiS_0XhfV5PcolUJVO_4p3h8d-mo2hh1Sw2fairAKOzvnwJCQ6DFkiY7H1cqwA54","dp":"YTql9AGtvyy158gh7jeXcgmySEbHQzvDFulDr-IXIg8kjHGEbp0rTIs0Z50RA95aC5RFkRjpaBKBfvaySjDm5WIi6GLzntpp6B8l7H6qG1jVO_la4Df2kzjx8LVvY8fhOrKz_hDdHodUeKdCF3RdvWMr00ruLnJhBPJHqoW7cwE","alg":"RS256","dq":"IZA4AngRbEtEtG7kJn6zWVaSmZxfRMXwvgIYvy4-3Qy2AVA0tS3XTPVfMaD8_B2U9CY_CxPVseR-sysHc_12uNBZbycfcOzU84WTjXCMSZ7BysPnGMDtkkLHra-p1L29upz1HVNhh5H9QEswHM98R2LZX2ZAsn4bORLZ1AGqweU","n":"8ZqUp5Cs90XpNn8tJBdUUxdGH4bjqKjFj8lyB3x50RpTuECuwzX1NpVqyFENDiEtMja5fdmJl6SErjnhj6kbhcmfmFibANuG-0WlV5yMysdSbocd75C1JQbiPdpHdXrijmVFMfDnoZTQ-ErNsqqngTNkn5SXBcPenli6Cf9MTSchZuh_qFj_B7Fp3CWKehTiyBcLlNOIjYsXX8WQjZkWKGpQ23AWjZulngWRektLcRWuEKTWaRBtbAr3XAfSmcqTICrebaD3IMWKHDtvzHAt_pt4wnZ06clgeO2Wbc980usnpsF7g8k9p81RcbS4JEZmuuA9NCmOmbyADXwgA9_-Aw"}"#;

        fn new(claims: TokenClaims) -> Self {
            Self {
                header: jwt::Header::new(jwt::Algorithm::RS256),
                claims,
            }
        }

        fn sign(claims: TokenClaims) -> String {
            Self::new(claims).encode()
        }

        fn sign_with_kid(claims: TokenClaims, kid: &str) -> String {
            let mut token = Self::new(claims);
            token.header.kid = Some(kid.to_string());
            token.encode()
        }

        fn encode(&self) -> String {
            let key = Self::get_signing_key();
            jwt::encode(&self.header, &self.claims, &key.key.to_encoding_key()).unwrap()
        }

        fn get_signing_key() -> jwk::JsonWebKey {
            Self::SIGNING_KEY.parse().unwrap()
        }
    }

    struct DockerRuntimeParams {
        container: Option<ContainerAsync<GenericImage>>,
        host: String,
        port: u16,
    }

    impl DockerRuntimeParams {
        #[cfg(feature = "docker")]
        const MOCK_OAUTH_SERVER_JSON_CONFIG: &'static str = r#"{
        "tokenProvider" : {
            "keyProvider" : {
               "initialKeys" : "{\"p\":\"_LNnIjBshCrFuxtjUC2KKzg_NTVv26UZh5j12_9r5mYTxb8yW047jOYFEGvIdMkTRLGOBig6fLWzgd62lnLainzV35J6K6zr4jQfTldLondlkldMR6nQrp1KfnNUuRbKvzpNKkhl12-f1l91l0tCx3s4blztvWgdzN2xBfvWV68\",\"kty\":\"RSA\",\"q\":\"9MIWsbIA3WjiR_Ful5FM8NCgb6JdS2D6ySHVepoNI-iAPilcltF_J2orjfLqAxeztTskPi45wtF_-eV4GIYSzvMo-gFiXLMrvEa7WaWizMi_7Bu9tEk3m_f3IDLN9lwULYoebkDbiXx6GOiuj0VkuKz8ckYFNKLCMP9QRLFff-0\",\"d\":\"J6UX848X8tNz-09PFvcFDUVqak32GXzoPjnuDjBsxNUvG7LxenLmM_i8tvYl0EW9Ztn4AiCqJUoHw5cX3jz_mSqGl7ciaDedpKm_AetcZwHiEuT1EpSKRPMmOMQSqcJqXrdbbWB8gdUrnTKZIlJCfj7yqgT16ypC43TnwjA0UwxhG5pHaYjKI3pPdoHg2BzA-iubHjVn15Sz7-pnjBmeGDbEFa7ADY-1yPHCmqqvPKTNhoCNW6RpG34Id9hXslPa3X-7pAhJrDBd0_NPlktSA2rUkifYiZURhHR5ijhe0v3uw6kYP8f_foVm_C8O1ExkxXh9Dg8KDZ89dbsSOtBc0Q\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"l7C_WJgbZ_6e59vPrFETAehX7Dsp7fIyvSV4XhotsGs\",\"qi\":\"cQFN5q5WhYkzgd1RS0rGqvpX1AkmZMrLv2MW04gSfu0dDwpbsSAu8EUCQW9oA4pr6V7R9CBSu9kdN2iY5SR-hZvEad5nDKPV1F3TMQYv5KpRiS_0XhfV5PcolUJVO_4p3h8d-mo2hh1Sw2fairAKOzvnwJCQ6DFkiY7H1cqwA54\",\"dp\":\"YTql9AGtvyy158gh7jeXcgmySEbHQzvDFulDr-IXIg8kjHGEbp0rTIs0Z50RA95aC5RFkRjpaBKBfvaySjDm5WIi6GLzntpp6B8l7H6qG1jVO_la4Df2kzjx8LVvY8fhOrKz_hDdHodUeKdCF3RdvWMr00ruLnJhBPJHqoW7cwE\",\"alg\":\"RS256\",\"dq\":\"IZA4AngRbEtEtG7kJn6zWVaSmZxfRMXwvgIYvy4-3Qy2AVA0tS3XTPVfMaD8_B2U9CY_CxPVseR-sysHc_12uNBZbycfcOzU84WTjXCMSZ7BysPnGMDtkkLHra-p1L29upz1HVNhh5H9QEswHM98R2LZX2ZAsn4bORLZ1AGqweU\",\"n\":\"8ZqUp5Cs90XpNn8tJBdUUxdGH4bjqKjFj8lyB3x50RpTuECuwzX1NpVqyFENDiEtMja5fdmJl6SErjnhj6kbhcmfmFibANuG-0WlV5yMysdSbocd75C1JQbiPdpHdXrijmVFMfDnoZTQ-ErNsqqngTNkn5SXBcPenli6Cf9MTSchZuh_qFj_B7Fp3CWKehTiyBcLlNOIjYsXX8WQjZkWKGpQ23AWjZulngWRektLcRWuEKTWaRBtbAr3XAfSmcqTICrebaD3IMWKHDtvzHAt_pt4wnZ06clgeO2Wbc980usnpsF7g8k9p81RcbS4JEZmuuA9NCmOmbyADXwgA9_-Aw\"}",
               "algorithm" : "RS256"
            }
          }
        }"#;

        /// Runs Docker from Rust, no external setup needed
        #[cfg(feature = "docker")]
        async fn init() -> DockerRuntimeParams {
            use reqwest::StatusCode;
            use testcontainers::core::wait::HttpWaitStrategy;
            use testcontainers::core::{ImageExt, IntoContainerPort, WaitFor};
            use testcontainers::runners::AsyncRunner;

            // Set up Docker container
            let container = GenericImage::new("ghcr.io/navikt/mock-oauth2-server", "2.2.1")
                .with_exposed_port(8080.tcp())
                .with_wait_for(WaitFor::Http(Box::new(
                    HttpWaitStrategy::new("/maskinporten/.well-known/openid-configuration").with_expected_status_code(StatusCode::OK),
                )))
                .with_env_var("JSON_CONFIG", Self::MOCK_OAUTH_SERVER_JSON_CONFIG)
                .start()
                .await
                .unwrap();
            let host = container.get_host().await.unwrap().to_string();
            let port = container.get_host_port_ipv4(8080).await.unwrap();
            Self {
                container: Some(container),
                host,
                port,
            }
        }

        /// Requires docker-compose up to be running.
        #[cfg(not(feature = "docker"))]
        async fn init() -> DockerRuntimeParams {
            Self {
                container: None,
                host: "localhost".to_string(),
                port: 8080,
            }
        }
    }
}
