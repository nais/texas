use crate::handler;
use crate::http::server::Server;
use crate::telemetry::record_http_response_latency;
use axum::Router;
use axum::extract::{MatchedPath, Request};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use opentelemetry::global;
use opentelemetry_http::HeaderExtractor;
use std::time::Instant;
use tracing::{Instrument, field, info_span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use utoipa::{OpenApi, openapi};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

pub fn api(state: handler::State) -> (Router, openapi::OpenApi) {
    let api = OpenApiRouter::default()
        .routes(routes!(handler::token))
        .routes(routes!(handler::token_exchange))
        .routes(routes!(handler::token_introspect))
        .layer(middleware::from_fn(trace_request))
        .with_state(state);

    OpenApiRouter::with_openapi(Server::openapi()).merge(api).split_for_parts()
}

/// Root server span for each API request. Propagates incoming trace context
/// and records response status code and latency after the handler completes.
async fn trace_request(request: Request, next: Next) -> Response {
    let path = request.extensions().get::<MatchedPath>().map(|p| p.as_str().to_owned());

    let span = info_span!(
        "Handle incoming request",
        "http.request.method" = ?request.method(),
        "http.response.status_code" = field::Empty,
        "http.route" = path.as_deref(),
        "http.version" = ?request.version(),
        "otel.kind" = "server",
    );

    let parent_context = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(request.headers()))
    });
    let _ = span.set_parent(parent_context);

    let start = Instant::now();
    let response = next.run(request).instrument(span.clone()).await;
    let latency = start.elapsed();

    span.record(
        "http.response.status_code",
        i64::from(response.status().as_u16()),
    );
    record_http_response_latency(path.as_deref().unwrap_or(""), latency, response.status());

    response
}

pub(super) fn probe() -> Router {
    async fn healthz() -> (StatusCode, &'static str) {
        (StatusCode::OK, "ok")
    }

    Router::new().route("/", get(healthz)).route("/healthz", get(healthz))
}
