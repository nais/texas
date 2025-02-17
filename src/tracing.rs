use axum::http::{HeaderName, HeaderValue, StatusCode};
use crate::identity_provider::IdentityProvider;
use opentelemetry::metrics::Meter;
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::trace::{TracerProvider as _};
use opentelemetry::{global, InstrumentationScope, KeyValue};
use opentelemetry_otlp::{MetricExporter, SpanExporter};
use opentelemetry_sdk::metrics::{MeterProviderBuilder, PeriodicReader, SdkMeterProvider, Temporality};
use opentelemetry_sdk::trace::TracerProvider;
use opentelemetry_sdk::{runtime, Resource};
use opentelemetry_semantic_conventions::{attribute::{SERVICE_NAME, SERVICE_VERSION}};
use reqwest::header::HeaderMap;
use std::collections::HashMap;
use std::env;
use std::fmt::Debug;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::Level;
use tracing;
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer, OpenTelemetrySpanExt};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

static METER: OnceLock<Meter> = OnceLock::new();
static RESOURCE_ATTRIBUTES: OnceLock<Vec<KeyValue>> = OnceLock::new();

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("init opentelemetry metrics: {0}")]
    Metrics(#[from] opentelemetry_sdk::metrics::MetricError),

    #[error("init opentelemetry tracing: {0}")]
    Tracing(#[from] opentelemetry::trace::TraceError),
}

/// Initialize tracing-subscriber and return OtelGuard for opentelemetry-related termination processing
pub fn init_tracing_subscriber() -> Result<OtelGuard, Error> {
    let meter_provider = init_meter_provider()?;
    let tracer_provider = init_tracing_provider()?;

    let tracer = tracer_provider.tracer("tracing-otel-subscriber");

    tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::from_level(Level::INFO))
        .with(MetricsLayer::new(meter_provider.clone()))
        .with(tracing_subscriber::fmt::layer())
        .with(OpenTelemetryLayer::new(tracer))
        .init();

    Ok(OtelGuard { meter_provider, tracer_provider })
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

pub fn inc_cache_hits(path: &str, identity_provider: IdentityProvider) {
    let counter = get_meter()
        .u64_counter("texas_token_cache_hits")
        .with_description(format!("Number of {path} cache hits"))
        .build();

    counter.add(1, with_resource_attributes(vec![
        KeyValue::new("path", path.to_string()),
        KeyValue::new("identity_provider", identity_provider.to_string()),
    ]).as_slice());
}

pub fn record_http_response_secs(path: &str, latency: Duration, status_code: StatusCode) {
    let histogram = get_meter()
        .f64_histogram("http_response_secs")
        .with_description("Response time in seconds")
        // Setting boundaries is optional. By default, the boundaries are set to
        // [0.0, 5.0, 10.0, 25.0, 50.0, 75.0, 100.0, 250.0, 500.0, 750.0, 1000.0, 2500.0, 5000.0, 7500.0, 10000.0]
        .with_boundaries(vec![
            0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009,
            0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09,
            0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9,
            1.0
        ])
        .build();

    histogram.record(latency.as_secs_f64(), with_resource_attributes(vec![
        KeyValue::new("status_code", status_code.as_str().to_string()),
        KeyValue::new("path", path.to_string()),
    ]).as_slice());
}

pub struct OtelGuard {
    meter_provider: SdkMeterProvider,
    tracer_provider: TracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(err) = self.meter_provider.shutdown() {
            eprintln!("{err:?}");
        }

        if let Err(err) = self.tracer_provider.shutdown() {
            eprintln!("{err:?}");
        }
    }
}

// Construct MeterProvider for MetricsLayer
fn init_meter_provider() -> Result<SdkMeterProvider, Error> {
    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_temporality(Temporality::default())
        .build()?;

    let reader = PeriodicReader::builder(exporter, runtime::Tokio)
        .with_interval(Duration::from_secs(10))
        .build();

    // TODO: Resource attributes aren't propagated to the metrics for some reason
    //  Creating a meter with an explicit InstrumentScope also doesn't work...
    let meter_provider = MeterProviderBuilder::default()
        .with_resource(resource())
        .with_reader(reader)
        .build();

    global::set_meter_provider(meter_provider.clone());

    Ok(meter_provider)
}

fn init_tracing_provider() -> Result<TracerProvider, Error> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .build()?;

    let provider = TracerProvider::builder()
        .with_resource(resource())
        .with_batch_exporter(exporter, runtime::Tokio)
        .build();

    global::set_tracer_provider(provider.clone());

    Ok(provider)
}

fn resource() -> Resource {
    Resource::new_with_defaults(vec![
        KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
        KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
        KeyValue::new("service.build_time", env!("BUILD_TIME")),
    ])
}

fn get_meter() -> &'static Meter {
    METER.get_or_init(|| global::meter_with_scope(InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .build())
    )
}

fn get_resource_attributes() -> &'static Vec<KeyValue> {
    RESOURCE_ATTRIBUTES.get_or_init(|| {
        match env::var("OTEL_RESOURCE_ATTRIBUTES") {
            Ok(s) if !s.is_empty() => {
                let kvs = s.split_terminator(',').filter_map(|entry| {
                    let mut parts = entry.splitn(2, '=');
                    let key = parts.next()?.trim().replace(".", "_");
                    let value = parts.next()?.trim();
                    if value.find('=').is_some() {
                        return None;
                    }

                    Some(KeyValue::new(key.to_owned(), value.to_owned()))
                }).collect();
                kvs
            },
            Ok(_) | Err(_) => vec![],
        }
    })
}

// TODO: this manually appends resource attributes because they aren't being propagated by the MeterProvider
fn with_resource_attributes(additional_attributes: Vec<KeyValue>) -> Vec<KeyValue> {
    [get_resource_attributes().clone(), additional_attributes].concat()
}
