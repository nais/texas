use crate::oauth::identity_provider::IdentityProvider;
use axum::http::StatusCode;
use log::debug;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{InstrumentationScope, KeyValue, global};
use opentelemetry_otlp::{MetricExporter, SpanExporter};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{
    MeterProviderBuilder, PeriodicReader, SdkMeterProvider, Temporality,
};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_semantic_conventions::attribute::SERVICE_VERSION;
use std::env;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::Duration;
use tracing;
use tracing::metadata::LevelFilter;
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer, OpenTelemetrySpanExt};
use tracing_subscriber::filter::Directive;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("init opentelemetry exporter: {0}")]
    Exporter(#[from] opentelemetry_otlp::ExporterBuildError),
    #[error("init env filter: {0}")]
    EnvFilter(#[from] tracing_subscriber::filter::ParseError),
}

/// Initialize tracing-subscriber and return `OtelGuard` for opentelemetry-related termination processing
pub fn init_tracing_subscriber() -> Result<OtelGuard, Error> {
    let meter_provider = init_meter_provider()?;
    let tracer_provider = init_tracing_provider()?;

    global::set_text_map_propagator(TraceContextPropagator::new());

    let tracer = tracer_provider.tracer("tracing-otel-subscriber");

    #[cfg(not(feature = "local"))]
    let fmt_layer = json_subscriber::layer()
        .flatten_event(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_opentelemetry_ids(true)
        .boxed();
    #[cfg(feature = "local")]
    let fmt_layer = tracing_subscriber::fmt::layer().with_thread_names(true).boxed();

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        // we don't care about internal opentelemetry logs
        // (there's an internal-logs feature for these crates that can be excluded, though doesn't quite work)
        // see https://github.com/open-telemetry/opentelemetry-rust/issues/2972
        .add_directive(Directive::from_str("opentelemetry=off")?);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(MetricsLayer::new(meter_provider.clone()))
        .with(fmt_layer)
        .with(OpenTelemetryLayer::new(tracer))
        .init();

    Ok(OtelGuard {
        meter_provider,
        tracer_provider,
    })
}

pub struct OtelGuard {
    meter_provider: SdkMeterProvider,
    tracer_provider: SdkTracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        let _ = self.meter_provider.shutdown();
        let _ = self.tracer_provider.shutdown();

        debug!("Shut down all OpenTelemetry providers");
    }
}

// Construct MeterProvider for MetricsLayer
fn init_meter_provider() -> Result<SdkMeterProvider, Error> {
    let exporter =
        MetricExporter::builder().with_tonic().with_temporality(Temporality::default()).build()?;

    let reader = PeriodicReader::builder(exporter).build();

    // TODO: Resource attributes aren't propagated to the metrics for some reason
    //  Creating a meter with an explicit InstrumentScope also doesn't work...
    let meter_provider =
        MeterProviderBuilder::default().with_resource(resource()).with_reader(reader).build();

    global::set_meter_provider(meter_provider.clone());

    Ok(meter_provider)
}

fn init_tracing_provider() -> Result<SdkTracerProvider, Error> {
    let exporter = SpanExporter::builder().with_tonic().build()?;

    let provider = SdkTracerProvider::builder()
        .with_resource(resource())
        .with_batch_exporter(exporter)
        .build();

    global::set_tracer_provider(provider.clone());

    Ok(provider)
}

fn resource() -> Resource {
    Resource::builder()
        .with_service_name(env!("CARGO_PKG_NAME"))
        .with_attributes([
            KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
            KeyValue::new("service.build_time", env!("BUILD_TIME")),
        ])
        .build()
}

static RESOURCE_ATTRIBUTES: LazyLock<Vec<KeyValue>> = LazyLock::new(|| {
    let extract_key_value = |entry: &str| {
        entry.split_once('=').and_then(|(k, v)| {
            if v.contains('=') {
                None
            } else {
                Some(KeyValue::new(
                    k.trim().replace('.', "_"),
                    v.trim().to_owned(),
                ))
            }
        })
    };

    match env::var("OTEL_RESOURCE_ATTRIBUTES") {
        Ok(s) if !s.is_empty() => s.split_terminator(',').filter_map(extract_key_value).collect(),
        Ok(_) | Err(_) => vec![],
    }
});

// TODO: this manually appends resource attributes because they aren't being propagated by the MeterProvider
fn with_resource_attributes(additional_attributes: Vec<KeyValue>) -> Vec<KeyValue> {
    [RESOURCE_ATTRIBUTES.clone(), additional_attributes].concat()
}

static METER: LazyLock<Meter> = LazyLock::new(|| {
    global::meter_with_scope(
        InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
            .with_version(env!("CARGO_PKG_VERSION"))
            .build(),
    )
});

static COUNTER_TOKEN_CACHE_HITS: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("texas_token_cache_hits")
        .with_description("Number of token cache hits")
        .build()
});

pub fn inc_token_cache_hits(path: &str, identity_provider: IdentityProvider) {
    tracing::Span::current().set_attribute("texas.cache_hit", true);
    COUNTER_TOKEN_CACHE_HITS.add(
        1,
        with_resource_attributes(vec![
            KeyValue::new("path", path.to_string()),
            KeyValue::new("identity_provider", identity_provider.to_string()),
        ])
        .as_slice(),
    );
}

static COUNTER_HANDLER_REQUESTS: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("texas_handler_requests")
        .with_description("Number of processed requests")
        .build()
});

pub fn inc_token_requests(path: &str, identity_provider: IdentityProvider) {
    COUNTER_HANDLER_REQUESTS.add(
        1,
        with_resource_attributes(vec![
            KeyValue::new("path", path.to_string()),
            KeyValue::new("identity_provider", identity_provider.to_string()),
            KeyValue::new("request_type", "token".to_string()),
        ])
        .as_slice(),
    );
}

pub fn inc_token_exchanges(path: &str, identity_provider: IdentityProvider) {
    COUNTER_HANDLER_REQUESTS.add(
        1,
        with_resource_attributes(vec![
            KeyValue::new("path", path.to_string()),
            KeyValue::new("identity_provider", identity_provider.to_string()),
            KeyValue::new("request_type", "token_exchange".to_string()),
        ])
        .as_slice(),
    );
}

pub fn inc_token_introspections(path: &str, identity_provider: IdentityProvider) {
    COUNTER_HANDLER_REQUESTS.add(
        1,
        with_resource_attributes(vec![
            KeyValue::new("path", path.to_string()),
            KeyValue::new("identity_provider", identity_provider.to_string()),
            KeyValue::new("request_type", "token_introspection".to_string()),
        ])
        .as_slice(),
    );
}

static COUNTER_HANDLER_ERRORS: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER.u64_counter("texas_handler_errors").with_description("Number of handler errors").build()
});

pub fn inc_handler_errors(path: &str, identity_provider: IdentityProvider, error_kind: &str) {
    COUNTER_HANDLER_ERRORS.add(
        1,
        with_resource_attributes(vec![
            KeyValue::new("path", path.to_string()),
            KeyValue::new("identity_provider", identity_provider.to_string()),
            KeyValue::new("error_kind", error_kind.to_string()),
        ])
        .as_slice(),
    );
}

static HISTOGRAM_HTTP_RESPONSE_SECS: LazyLock<Histogram<f64>> = LazyLock::new(|| {
    METER
        .f64_histogram("http_response_secs")
        .with_description("Response time in seconds")
        .with_boundaries(vec![
            0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009, 0.01, 0.02, 0.03, 0.04,
            0.05, 0.06, 0.07, 0.08, 0.09, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 2.0,
            5.0, 10.0,
        ])
        .build()
});

pub fn record_http_response_latency(path: &str, latency: Duration, status_code: StatusCode) {
    HISTOGRAM_HTTP_RESPONSE_SECS.record(
        latency.as_secs_f64(),
        with_resource_attributes(vec![
            KeyValue::new("status_code", status_code.as_str().to_string()),
            KeyValue::new("path", path.to_string()),
        ])
        .as_slice(),
    );
}

static HISTOGRAM_IDENTITY_PROVIDER_LATENCY_SECS: LazyLock<Histogram<f64>> = LazyLock::new(|| {
    METER
        .f64_histogram("texas_identity_provider_latency_secs")
        .with_description("Latency to identity provider in seconds")
        .with_boundaries(vec![
            0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009, 0.01, 0.02, 0.03, 0.04,
            0.05, 0.06, 0.07, 0.08, 0.09, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 2.0,
            5.0, 10.0,
        ])
        .build()
});

pub fn record_identity_provider_latency(identity_provider: IdentityProvider, latency: Duration) {
    HISTOGRAM_IDENTITY_PROVIDER_LATENCY_SECS.record(
        latency.as_secs_f64(),
        with_resource_attributes(vec![KeyValue::new(
            "identity_provider",
            identity_provider.to_string(),
        )])
        .as_slice(),
    );
}
