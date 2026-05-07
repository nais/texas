use http::Extensions;
use log::debug;
use opentelemetry::trace::Status;
use reqwest::{Request, Response};
use reqwest_middleware::ClientWithMiddleware;
use reqwest_retry::{Jitter, RetryTransientMiddleware, policies};
use reqwest_tracing::{
    ReqwestOtelSpanBackend, SpanBackendWithUrl, TracingMiddleware, default_on_request_end,
};
use std::time::Duration;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub fn new(config: Config) -> Result<ClientWithMiddleware, reqwest::Error> {
    let retry_policy = policies::ExponentialBackoff::builder()
        .retry_bounds(config.retry_min_interval, config.retry_max_interval)
        .jitter(Jitter::None)
        .build_with_max_retries(config.retry_max_attempts);

    let client = reqwest::Client::builder()
        .connect_timeout(config.timeout_connect)
        .read_timeout(config.timeout_read)
        .timeout(config.timeout_overall)
        .pool_max_idle_per_host(config.pool_max_idle_per_host)
        .pool_idle_timeout(config.pool_idle_timeout)
        .build()?;

    let client = reqwest_middleware::ClientBuilder::new(client)
        .with(TracingMiddleware::<StatusAwareSpanBackend>::new())
        .with(
            RetryTransientMiddleware::new_with_policy(retry_policy)
                .with_retry_log_level(tracing::Level::INFO),
        )
        .build();

    Ok(client)
}

/// Extends [`SpanBackendWithUrl`] to mark the client span as errored on HTTP 4xx/5xx
/// responses. `default_on_request_end` only does this for transport failures, but
/// OTel HTTP client semconv expects error status for unsuccessful response codes too.
pub struct StatusAwareSpanBackend;

impl ReqwestOtelSpanBackend for StatusAwareSpanBackend {
    fn on_request_start(req: &Request, ext: &mut Extensions) -> Span {
        SpanBackendWithUrl::on_request_start(req, ext)
    }

    fn on_request_end(
        span: &Span,
        outcome: &Result<Response, reqwest_middleware::Error>,
        _ext: &mut Extensions,
    ) {
        default_on_request_end(span, outcome);
        if let Ok(response) = outcome
            && (response.status().is_client_error() || response.status().is_server_error())
        {
            span.set_status(Status::error(format!(
                "HTTP {}",
                response.status().as_u16()
            )));
        }
    }
}

pub fn jwks() -> Result<ClientWithMiddleware, reqwest::Error> {
    new(Config::jwks())
}

pub fn token() -> Result<ClientWithMiddleware, reqwest::Error> {
    new(Config::token())
}

pub struct Config {
    pool_max_idle_per_host: usize,
    pool_idle_timeout: Duration,
    retry_max_attempts: u32,
    retry_min_interval: Duration,
    retry_max_interval: Duration,
    timeout_connect: Duration,
    timeout_read: Duration,
    timeout_overall: Duration,
}

impl Config {
    pub fn jwks() -> Self {
        Self {
            pool_max_idle_per_host: env_or_default::<usize>("TEXAS_HTTP_POOL_MAX_IDLE", 100),
            pool_idle_timeout: Duration::from_secs(10),
            retry_max_attempts: env_or_default::<u32>("TEXAS_HTTP_MAX_RETRIES", 10),
            retry_min_interval: Duration::from_millis(100),
            retry_max_interval: Duration::from_secs(2),
            timeout_connect: Duration::from_millis(env_or_default::<u64>(
                "TEXAS_HTTP_CONNECT_TIMEOUT_MILLIS",
                5_000,
            )),
            timeout_read: Duration::from_millis(env_or_default::<u64>(
                "TEXAS_HTTP_READ_TIMEOUT_MILLIS",
                5_000,
            )),
            timeout_overall: Duration::from_millis(env_or_default::<u64>(
                "TEXAS_HTTP_OVERALL_TIMEOUT_MILLIS",
                10_000,
            )),
        }
    }

    pub fn token() -> Self {
        Self {
            pool_max_idle_per_host: env_or_default::<usize>("TEXAS_HTTP_POOL_MAX_IDLE", 100),
            pool_idle_timeout: Duration::from_secs(10),
            retry_max_attempts: env_or_default::<u32>("TEXAS_HTTP_MAX_RETRIES", 3),
            retry_min_interval: Duration::ZERO,
            retry_max_interval: Duration::ZERO,
            timeout_connect: Duration::from_millis(env_or_default::<u64>(
                "TEXAS_HTTP_CONNECT_TIMEOUT_MILLIS",
                1_000,
            )),
            timeout_read: Duration::from_millis(env_or_default::<u64>(
                "TEXAS_HTTP_READ_TIMEOUT_MILLIS",
                1_000,
            )),
            timeout_overall: Duration::from_millis(env_or_default::<u64>(
                "TEXAS_HTTP_OVERALL_TIMEOUT_MILLIS",
                2_000,
            )),
        }
    }
}

fn env_or_default<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr + Copy + std::fmt::Display,
{
    let val = std::env::var(key).ok().and_then(|v| v.parse::<T>().ok()).unwrap_or(default);

    debug!("Using {key}={val}");
    val
}
