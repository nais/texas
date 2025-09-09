use log::debug;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{Jitter, RetryTransientMiddleware, policies};
use reqwest_tracing::{SpanBackendWithUrl, TracingMiddleware};
use std::time::Duration;

pub fn new_client(retry: Retry) -> Result<ClientWithMiddleware, reqwest::Error> {
    let retry_policy = policies::ExponentialBackoff::builder()
        .retry_bounds(retry.min_interval, retry.max_interval)
        .jitter(Jitter::None)
        .build_with_max_retries(retry.max_retries);

    let connect_timeout_millis = env_or_default::<u64>("TEXAS_HTTP_CONNECT_TIMEOUT_MILLIS", 200);
    let read_timeout_millis = env_or_default::<u64>("TEXAS_HTTP_READ_TIMEOUT_MILLIS", 500);
    let overall_timeout_millis = env_or_default::<u64>("TEXAS_HTTP_OVERALL_TIMEOUT_MILLIS", 1_000);
    let pool_max_idle = env_or_default::<usize>("TEXAS_HTTP_POOL_MAX_IDLE", 10_000);

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(connect_timeout_millis))
        .read_timeout(Duration::from_millis(read_timeout_millis))
        .timeout(Duration::from_millis(overall_timeout_millis))
        .pool_max_idle_per_host(pool_max_idle)
        .pool_idle_timeout(Duration::from_secs(30))
        .build()?;

    let client_with_middleware = ClientBuilder::new(client)
        .with(TracingMiddleware::<SpanBackendWithUrl>::new())
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build();

    Ok(client_with_middleware)
}

pub fn new_default_client() -> Result<ClientWithMiddleware, reqwest::Error> {
    new_client(Retry::default())
}

pub struct Retry {
    max_retries: u32,
    min_interval: Duration,
    max_interval: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        let max_retries = env_or_default::<u32>("TEXAS_HTTP_MAX_RETRIES", 5);

        Self {
            max_retries,
            min_interval: Duration::from_millis(10),
            max_interval: Duration::from_millis(100),
        }
    }
}

impl Retry {
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }
    pub fn min_interval(mut self, min_interval: Duration) -> Self {
        self.min_interval = min_interval;
        self
    }
    pub fn max_interval(mut self, max_interval: Duration) -> Self {
        self.max_interval = max_interval;
        self
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
