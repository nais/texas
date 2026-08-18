use http::Extensions;
use log::debug;
use opentelemetry::trace::Status;
use reqwest::header::ACCEPT;
use reqwest::{Request, Response};
use reqwest_middleware::{ClientWithMiddleware, RequestBuilder};
use reqwest_tracing::{
    ReqwestOtelSpanBackend, SpanBackendWithUrl, TracingMiddleware, default_on_request_end,
};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::{self, Debug};
use std::time::Duration;
use thiserror::Error;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Upper bound on a buffered upstream response body. The largest realistic body is a JWKS
/// document, which is orders of magnitude smaller.
pub const MAX_BODY_BYTES: usize = 1 << 20;
pub const BODY_PREVIEW_LIMIT: usize = 256;

pub fn body_preview(body: &[u8]) -> String {
    let truncated = body.len() > BODY_PREVIEW_LIMIT;
    let mut preview =
        String::from_utf8_lossy(&body[..body.len().min(BODY_PREVIEW_LIMIT)]).into_owned();
    if truncated {
        preview.push('…');
    }
    preview
}

#[derive(Debug)]
pub struct Client {
    inner: ClientWithMiddleware,
    max_retries: u32,
}

pub struct ClientConfig {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub request_timeout: Duration,
    pub pool_max_idle_per_host: usize,
    pub pool_idle_timeout: Duration,
    pub max_retries: u32,
}

pub fn token() -> Result<Client, reqwest::Error> {
    Client::new(ClientConfig {
        connect_timeout: timeout_from_env("TEXAS_HTTP_CONNECT_TIMEOUT_MILLIS", 2_000),
        read_timeout: timeout_from_env("TEXAS_HTTP_READ_TIMEOUT_MILLIS", 3_000),
        request_timeout: timeout_from_env("TEXAS_HTTP_OVERALL_TIMEOUT_MILLIS", 5_000),
        pool_max_idle_per_host: env_or_default("TEXAS_HTTP_POOL_MAX_IDLE", 100),
        pool_idle_timeout: Duration::from_secs(10),
        max_retries: env_or_default("TEXAS_HTTP_MAX_RETRIES", 1),
    })
}

pub fn discovery() -> Result<Client, reqwest::Error> {
    Client::new(ClientConfig {
        connect_timeout: timeout_from_env("TEXAS_HTTP_CONNECT_TIMEOUT_MILLIS", 5_000),
        read_timeout: timeout_from_env("TEXAS_HTTP_READ_TIMEOUT_MILLIS", 5_000),
        request_timeout: timeout_from_env("TEXAS_HTTP_OVERALL_TIMEOUT_MILLIS", 10_000),
        pool_max_idle_per_host: env_or_default("TEXAS_HTTP_POOL_MAX_IDLE", 100),
        pool_idle_timeout: Duration::from_secs(10),
        max_retries: env_or_default("TEXAS_HTTP_MAX_RETRIES", 2),
    })
}

fn timeout_from_env(key: &str, default_millis: u64) -> Duration {
    Duration::from_millis(env_or_default(key, default_millis))
}

fn env_or_default<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr + fmt::Display,
{
    match std::env::var(key).ok().and_then(|value| value.parse().ok()) {
        Some(value) => {
            debug!("Using {key}={value}");
            value
        }
        None => default,
    }
}

impl Client {
    pub fn new(config: ClientConfig) -> Result<Self, reqwest::Error> {
        let inner = reqwest::Client::builder()
            // OpenID Connect Discovery and RFC 8414 both mandate 200 OK, and token endpoints
            // never redirect. A 3xx means a misconfigured or hijacked upstream, so surface it.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(config.connect_timeout)
            .read_timeout(config.read_timeout)
            .timeout(config.request_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .pool_idle_timeout(config.pool_idle_timeout)
            .build()?;
        let inner = reqwest_middleware::ClientBuilder::new(inner)
            .with(TracingMiddleware::<StatusAwareSpanBackend>::new())
            .build();

        Ok(Self {
            inner,
            max_retries: config.max_retries,
        })
    }

    pub async fn get<T>(&self, url: &str) -> Result<T, FetchError>
    where
        T: DeserializeOwned,
    {
        self.fetch(
            || Ok(self.inner.get(url).header(ACCEPT, "application/json")),
            |_| {},
        )
        .await
    }

    /// `on_attempt` receives the duration of every attempt, whether it succeeded or failed.
    pub async fn post<T, E, P, Prepare, OnAttempt>(
        &self,
        url: &str,
        mut prepare: Prepare,
        on_attempt: OnAttempt,
    ) -> Result<T, E>
    where
        T: DeserializeOwned,
        E: From<FetchError>,
        P: Serialize,
        Prepare: FnMut() -> Result<P, E>,
        OnAttempt: FnMut(Duration),
    {
        self.fetch(
            || {
                let form = prepare()?;
                Ok(self.inner.post(url).header(ACCEPT, "application/json").form(&form))
            },
            on_attempt,
        )
        .await
    }

    async fn fetch<T, E, Prepare, OnAttempt>(
        &self,
        mut prepare: Prepare,
        mut on_attempt: OnAttempt,
    ) -> Result<T, E>
    where
        T: DeserializeOwned,
        Prepare: FnMut() -> Result<RequestBuilder, E>,
        E: From<FetchError>,
        OnAttempt: FnMut(Duration),
    {
        for retry in 0..=self.max_retries {
            let request = prepare()?;
            let start = std::time::Instant::now();
            let result = async {
                let mut response = request.send().await.map_err(FetchError::Send)?;
                let status = response.status();
                let mut body = Vec::new();
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|source| FetchError::BodyRead { status, source })?
                {
                    if body.len() + chunk.len() > MAX_BODY_BYTES {
                        return Err(FetchError::BodyTooLarge {
                            status,
                            limit: MAX_BODY_BYTES,
                        });
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok::<_, FetchError>((status, body))
            }
            .await;
            on_attempt(start.elapsed());

            let result = result.and_then(|(status, body)| {
                if !status.is_success() {
                    return Err(FetchError::Status { status, body });
                }
                serde_json::from_slice(&body).map_err(|source| {
                    tracing::warn!(
                        error = %source,
                        body_preview = %body_preview(&body),
                        "upstream returned invalid JSON"
                    );
                    FetchError::Decode(source)
                })
            });

            match result {
                Ok(value) => return Ok(value),
                Err(failure) if retry < self.max_retries && is_retryable(&failure) => {
                    tracing::info!(attempt = retry + 1, error = %failure, "retrying upstream request");
                }
                Err(failure) => {
                    if !matches!(failure, FetchError::Status { .. }) {
                        tracing::info!(
                            error = %failure,
                            error.cause_chain = ?failure,
                            "upstream request failed"
                        );
                    }
                    return Err(E::from(failure));
                }
            }
        }

        unreachable!("request loop always returns from its body")
    }
}

#[derive(Error)]
pub enum FetchError {
    #[error("request failed before response headers: {0}")]
    Send(reqwest_middleware::Error),
    #[error("request returned HTTP {status}")]
    Status {
        status: reqwest::StatusCode,
        body: Vec<u8>,
    },
    #[error("response body read failed after HTTP {status}: {source}")]
    BodyRead {
        status: reqwest::StatusCode,
        source: reqwest::Error,
    },
    #[error("response body exceeded {limit} bytes after HTTP {status}")]
    BodyTooLarge {
        status: reqwest::StatusCode,
        limit: usize,
    },
    #[error("response JSON decode failed: {0}")]
    Decode(serde_json::Error),
}

impl Debug for FetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(source) => formatter.debug_tuple("Send").field(source).finish(),
            Self::Status { status, .. } => {
                formatter.debug_struct("Status").field("status", status).finish()
            }
            Self::BodyRead { status, source } => formatter
                .debug_struct("BodyRead")
                .field("status", status)
                .field("source", source)
                .finish(),
            Self::BodyTooLarge { status, limit } => formatter
                .debug_struct("BodyTooLarge")
                .field("status", status)
                .field("limit", limit)
                .finish(),
            Self::Decode(source) => formatter.debug_tuple("Decode").field(source).finish(),
        }
    }
}

fn is_retryable(failure: &FetchError) -> bool {
    match failure {
        FetchError::Send(error) => error.is_timeout() || error.is_connect() || error.is_request(),
        FetchError::BodyRead { .. } => true,
        FetchError::BodyTooLarge { .. } => false,
        FetchError::Status { status, .. } => {
            status.is_server_error()
                || *status == reqwest::StatusCode::REQUEST_TIMEOUT
                || *status == reqwest::StatusCode::TOO_MANY_REQUESTS
        }
        FetchError::Decode(_) => false,
    }
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

#[cfg(test)]
mod tests {
    use super::{
        BODY_PREVIEW_LIMIT, Client, ClientConfig, FetchError, MAX_BODY_BYTES, body_preview,
        is_retryable,
    };
    use axum::Router;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use reqwest::StatusCode;
    use serde_json::Value;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn client(max_retries: u32) -> Client {
        Client::new(ClientConfig {
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(10),
            pool_max_idle_per_host: 100,
            pool_idle_timeout: Duration::from_secs(10),
            max_retries,
        })
        .unwrap()
    }

    /// Serves the given router on a loopback port. The task is aborted when the guard drops.
    async fn serve(router: Router) -> (String, AbortOnDrop) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        (url, AbortOnDrop(server))
    }

    struct AbortOnDrop(tokio::task::JoinHandle<()>);

    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let hits = Arc::new(AtomicUsize::new(0));
        let target_hits = hits.clone();
        let router = Router::new()
            .route(
                "/redirect",
                get(|| async { (StatusCode::FOUND, [("location", "/target")]).into_response() }),
            )
            .route(
                "/target",
                get(move || {
                    target_hits.fetch_add(1, Ordering::Relaxed);
                    async { (StatusCode::OK, "{}").into_response() }
                }),
            );
        let (url, _server) = serve(router).await;

        let error = client(1).get::<Value>(&format!("{url}/redirect")).await.unwrap_err();

        assert!(matches!(
            error,
            FetchError::Status {
                status: StatusCode::FOUND,
                ..
            }
        ));
        assert_eq!(hits.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn oversized_response_body_is_rejected_without_retrying() {
        let hits = Arc::new(AtomicUsize::new(0));
        let served = hits.clone();
        let router = Router::new().route(
            "/big",
            get(move || {
                served.fetch_add(1, Ordering::Relaxed);
                async { (StatusCode::OK, vec![b'x'; MAX_BODY_BYTES + 1]).into_response() }
            }),
        );
        let (url, _server) = serve(router).await;

        let error = client(3).get::<Value>(&format!("{url}/big")).await.unwrap_err();

        assert!(matches!(
            error,
            FetchError::BodyTooLarge {
                status: StatusCode::OK,
                limit: MAX_BODY_BYTES,
            }
        ));
        assert_eq!(hits.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn attempt_observer_runs_once_per_attempt() {
        let router = Router::new().route(
            "/token",
            axum::routing::post(|| async {
                (StatusCode::SERVICE_UNAVAILABLE, "{}").into_response()
            }),
        );
        let (url, _server) = serve(router).await;
        let mut attempts = Vec::new();

        let error = client(2)
            .post::<Value, FetchError, _, _, _>(
                &format!("{url}/token"),
                || Ok([("grant_type", "client_credentials")]),
                |elapsed| attempts.push(elapsed),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            FetchError::Status {
                status: StatusCode::SERVICE_UNAVAILABLE,
                ..
            }
        ));
        assert_eq!(attempts.len(), 3);
    }

    #[test]
    fn retries_transient_statuses_only() {
        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            assert!(is_retryable(&FetchError::Status {
                status,
                body: Vec::new(),
            }));
        }
        assert!(!is_retryable(&FetchError::Status {
            status: StatusCode::BAD_REQUEST,
            body: Vec::new(),
        }));
    }

    #[test]
    fn body_preview_is_bounded() {
        let body = vec![b'x'; BODY_PREVIEW_LIMIT + 1];

        assert_eq!(
            body_preview(&body).len(),
            BODY_PREVIEW_LIMIT + '…'.len_utf8()
        );
        assert!(body_preview(&body).ends_with('…'));
    }

    #[test]
    fn debug_does_not_include_error_response_body() {
        let error = FetchError::Status {
            status: StatusCode::BAD_GATEWAY,
            body: b"secret response".to_vec(),
        };

        assert!(!format!("{error:?}").contains("secret response"));
    }
}
