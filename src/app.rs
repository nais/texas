use crate::app::Error::LocalAddress;
use crate::config::Config;
use crate::handlers::__path_introspect;
use crate::handlers::__path_token;
use crate::handlers::__path_token_exchange;
use crate::handlers::{HandlerState, introspect, token, token_exchange};
use crate::{config, handlers};
use axum::Router;
use axum::extract::MatchedPath;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::get;
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
use tracing::{Span, error, field, info_span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use utoipa::{OpenApi, openapi};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

pub struct App {
    router: Router,
    pub listener: TcpListener,
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
        info!(
            "Swagger API documentation: http://{:?}/swagger-ui",
            local_addr
        );

        Ok(Self {
            router: app,
            listener,
        })
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

    pub fn routes(state: HandlerState) -> (Router, openapi::OpenApi) {
        let trace_layer = TraceLayer::new_for_http()
            .make_span_with(move |request: &Request<_>| {
                // Log the matched route's path (with placeholders not filled in).
                // Use request.uri() or OriginalUri if you want the real path.
                let path = request.extensions().get::<MatchedPath>().map(MatchedPath::as_str);

                // get tracing context from request
                let parent_context =
                    TraceContextPropagator::new().extract(&HeaderExtractor(request.headers()));

                let root_span = info_span!(
                    "Handle incoming request",
                    "http.request.method" = ?request.method(),
                    "http.response.status_code" = field::Empty, // to be populated in on_response
                    "http.route" = path,
                    "http.version" = ?request.version(),
                    "otel.kind" = "server",
                );

                let context = parent_context.with_baggage(vec![KeyValue::new(
                    "path".to_string(),
                    path.unwrap_or_default().to_string(),
                )]);
                root_span.set_parent(context.clone());
                root_span
            })
            .on_response(move |response: &Response, latency: Duration, span: &Span| {
                let path = span
                    .context()
                    .baggage()
                    .get("path")
                    .map(ToString::to_string)
                    .unwrap_or_default();
                span.record("http.response.status_code", response.status().as_u16());
                crate::tracing::record_http_response_secs(&path, latency, response.status());
            });
        let probes =
            OpenApiRouter::default().route("/ping", get(|| async { (StatusCode::OK, "pong") }));
        let api = OpenApiRouter::default()
            .routes(routes!(token))
            .routes(routes!(token_exchange))
            .routes(routes!(introspect))
            .layer(trace_layer)
            .with_state(state);

        OpenApiRouter::with_openapi(ApiDoc::openapi()).merge(api).merge(probes).split_for_parts()
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
