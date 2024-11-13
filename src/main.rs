mod app;
mod claims;
mod config;
mod grants;
pub mod handlers;
pub mod identity_provider;
pub mod jwks;

use std::time::Duration;
use crate::app::App;
use config::Config;
use dotenv::dotenv;
use log::{error, info, LevelFilter};
use opentelemetry::trace::Tracer;
use opentelemetry_otlp::{WithExportConfig};
use opentelemetry_sdk::trace::TracerProvider;
#[allow(unused_imports)]
use opentelemetry::trace::TracerProvider as _;

fn test() {
    let trac = opentelemetry::global::tracer("tracer");
    let span = trac.span_builder("more stuff");
    let _guard = span.start(&trac);
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Debug)
        .init();

    config::print_texas_logo();
    info!("Starting up");

    // in main
    let exp = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint("http://localhost:4317")
        .build()
        .unwrap();

    // in main
    let metexp = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint("http://localhost:4317")
        .build()
        .unwrap();

    let perred = opentelemetry_sdk::metrics::PeriodicReader::builder(metexp, opentelemetry_sdk::runtime::Tokio)
        .with_interval(Duration::from_secs(3))
        .with_timeout(Duration::from_secs(10))
        .build()
        ;

    //let exp = opentelemetry_stdout::SpanExporter::default();
    let prov = TracerProvider::builder()
        .with_simple_exporter(exp)
        .with_config(
            opentelemetry_sdk::trace::Config::default()
                .with_resource(opentelemetry_sdk::Resource::new(vec![opentelemetry::KeyValue::new("service.name", "texas")]))
        )
        .build();

    let metpro = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(perred)
        .with_resource(opentelemetry_sdk::Resource::new(vec![opentelemetry::KeyValue::new("service.name", "texas")]))
        .build();

    opentelemetry::global::set_tracer_provider(prov);
    opentelemetry::global::set_meter_provider(metpro);

    // in functions
    let trac = opentelemetry::global::tracer("tracer");
    let span = trac.span_builder("span");
    {
        let _guard = span.start(&trac);
        test();
    }

    let met = opentelemetry::global::meter("meter");
    let metric = met.u64_counter("mycounter").with_description("bare en test").build();
    metric.add(1, &[]);

    let _ = dotenv(); // load .env if present

    let cfg = match Config::new_from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            error!("configuration: {}", err);
            return;
        }
    };

    let app = App::new(cfg).await;
    app.run().await.unwrap()
}
