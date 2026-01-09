use crate::handler;
use crate::http::server::Server;
use crate::telemetry::record_http_response_latency;
use axum::Router;
use axum::extract::MatchedPath;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::get;
use opentelemetry::baggage::BaggageExt;
use opentelemetry::{KeyValue, global};
use opentelemetry_http::HeaderExtractor;
use std::time::Duration;
use tower_http::trace::TraceLayer;
use tracing::{Span, field, info_span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use utoipa::{OpenApi, openapi};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

pub fn api(state: handler::State) -> (Router, openapi::OpenApi) {
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(move |request: &Request<_>| {
            // Log the matched route's path (with placeholders not filled in).
            // Use request.uri() or OriginalUri if you want the real path.
            let path = request.extensions().get::<MatchedPath>().map(MatchedPath::as_str);

            let root_span = info_span!(
                "Handle incoming request",
                "http.request.method" = ?request.method(),
                "http.response.status_code" = field::Empty, // to be populated in on_response
                "http.route" = path,
                "http.version" = ?request.version(),
                "otel.kind" = "server",
            );

            let parent_context = global::get_text_map_propagator(|propagator| {
                propagator.extract(&HeaderExtractor(request.headers()))
            });
            let context = parent_context.with_baggage(vec![KeyValue::new(
                "path".to_string(),
                path.unwrap_or_default().to_string(),
            )]);
            root_span.set_parent(context.clone());
            root_span
        })
        .on_response(move |response: &Response, latency: Duration, span: &Span| {
            let path =
                span.context().baggage().get("path").map(ToString::to_string).unwrap_or_default();
            span.record("http.response.status_code", response.status().as_u16());
            record_http_response_latency(&path, latency, response.status());
        });

    let api = OpenApiRouter::default()
        .routes(routes!(handler::token))
        .routes(routes!(handler::token_exchange))
        .routes(routes!(handler::token_introspect))
        .layer(trace_layer)
        .with_state(state);

    OpenApiRouter::with_openapi(Server::openapi()).merge(api).split_for_parts()
}

pub(super) fn probe() -> Router {
    async fn healthz() -> (StatusCode, &'static str) {
        (StatusCode::OK, "ok")
    }

    Router::new().route("/", get(healthz)).route("/healthz", get(healthz))
}
