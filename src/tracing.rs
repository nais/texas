use std::collections::HashMap;
use axum::http::{HeaderName, HeaderValue};
use opentelemetry::trace::TracerProvider;
use opentelemetry::{global, KeyValue};
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_sdk::metrics::reader::DefaultTemporalitySelector;
use opentelemetry_sdk::metrics::{MeterProviderBuilder, PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::{BatchConfig, RandomIdGenerator, Sampler, Tracer};
use opentelemetry_sdk::{runtime, Resource};
use opentelemetry_semantic_conventions::{
    attribute::{SERVICE_NAME, SERVICE_VERSION},
    SCHEMA_URL,
};
use reqwest::header::HeaderMap;
use tracing::{Level};
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer, OpenTelemetrySpanExt};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing;
use crate::config::DownstreamApp;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("init opentelemetry metrics: {0}")]
    Metrics(#[from] opentelemetry::metrics::MetricsError),

    #[error("init opentelemetry tracing: {0}")]
    Tracing(#[from] opentelemetry::trace::TraceError),
}

/// Initialize tracing-subscriber and return OtelGuard for opentelemetry-related termination processing
pub fn init_tracing_subscriber() -> Result<OtelGuard, Error> {
    let meter_provider = init_meter_provider()?;
    let tracer = init_tracer()?;
    tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::from_level(Level::INFO))
        .with(MetricsLayer::new(meter_provider.clone()))
        .with(tracing_subscriber::fmt::layer())
        .with(OpenTelemetryLayer::new(tracer))
        .init();

    Ok(OtelGuard { meter_provider })
}

/// Extract trace data from the current span in order to
/// generate the `traceparent` and `tracestate` headers,
/// which can be sent with outgoing HTTP requests.
pub fn trace_headers_from_current_span() -> HeaderMap {
    let span = tracing::Span::current();
    let context = span.context();
    let propagator = opentelemetry_sdk::propagation::TraceContextPropagator::new();
    let mut fields = HashMap::new();
    propagator.inject_context(&context, &mut fields);
    fields
        .into_iter()
        .map(|(k, v)| {
            (
                HeaderName::try_from(k).unwrap(),
                HeaderValue::try_from(v).unwrap(),
            )
        })
        .collect()
}

pub fn inc_cache_hits(path: &str, downstream_app: DownstreamApp) {
    let meter = global::meter("texas");
    let counter = meter
        .u64_counter("texas_token_cache_hits")
        .with_description(format!("Number of {path} cache hits"))
        .init();
    counter.add(1, &[
        KeyValue::new("path", path.to_string()),
        KeyValue::new("downstream_app_name", downstream_app.name),
        KeyValue::new("downstream_app_namespace", downstream_app.namespace),
        KeyValue::new("downstream_app_cluster", downstream_app.cluster),
        KeyValue::new("pod_name", downstream_app.pod_name),
    ]);
}

pub struct OtelGuard {
    meter_provider: SdkMeterProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(err) = self.meter_provider.shutdown() {
            eprintln!("{err:?}");
        }
        global::shutdown_tracer_provider();
    }
}

// Construct MeterProvider for MetricsLayer
fn init_meter_provider() -> Result<SdkMeterProvider, Error> {
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .build_metrics_exporter(Box::new(DefaultTemporalitySelector::new()))?;

    let reader = PeriodicReader::builder(exporter, runtime::Tokio)
        .with_interval(std::time::Duration::from_secs(2))
        .build();

    let meter_provider = MeterProviderBuilder::default()
        .with_resource(resource())
        .with_reader(reader)
        .build();

    global::set_meter_provider(meter_provider.clone());

    Ok(meter_provider)
}

fn init_tracer() -> Result<Tracer, Error> {
    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_trace_config(
            opentelemetry_sdk::trace::Config::default()
                // Customize sampling strategy
                .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(1.0))))
                // If export trace to AWS X-Ray, you can use XrayIdGenerator
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(resource()),
        )
        .with_batch_config(BatchConfig::default())
        .with_exporter(opentelemetry_otlp::new_exporter().tonic())
        .install_batch(runtime::Tokio)?;

    global::set_tracer_provider(provider.clone());
    Ok(provider.tracer("tracing-otel-subscriber"))
}

fn resource() -> Resource {
    Resource::from_schema_url(
        [
            KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
            KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
            KeyValue::new("service.build_time", env!("BUILD_TIME")),
            //KeyValue::new(DEPLOYMENT_ENVIRONMENT_NAME, "develop"),
        ],
        SCHEMA_URL,
    )
}
