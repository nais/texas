use crate::oauth::identity_provider::TokenResponse;
use moka::Expiry;
use moka::notification::RemovalCause;
use std::hash::Hash;
use std::time::Duration;

use crate::telemetry;
#[cfg(test)]
use mock_instant::thread_local::Instant;
#[cfg(not(test))]
use std::time::Instant;
use tracing_opentelemetry::OpenTelemetrySpanExt;

const MAX_CAPACITY: u64 = 262144;

#[derive(Clone)]
pub struct TokenCache<K> {
    inner: moka::future::Cache<K, CachedTokenResponse>,
    kind: &'static str,
}

impl<K> TokenCache<K>
where
    K: Eq + Hash + Send + Sync + 'static,
{
    pub fn new(kind: &'static str) -> Self {
        let listener = |_k, _v, cause| match cause {
            RemovalCause::Expired | RemovalCause::Size | RemovalCause::Explicit => {
                telemetry::dec_token_cache(kind);
            }
            RemovalCause::Replaced => {
                // The entry itself was not actually removed, but its value was replaced.
            }
        };

        Self {
            inner: moka::future::Cache::builder()
                .max_capacity(MAX_CAPACITY)
                .expire_after(TokenResponseExpiry)
                .eviction_listener(listener)
                .build(),
            kind,
        }
    }

    pub async fn get(&self, key: &K) -> Option<TokenResponse> {
        let span = tracing::Span::current();
        let response = self.inner.get(key).await;

        match &response {
            Some(cached_response) => {
                span.set_attribute("texas.cache_hit", true);
                span.set_attribute(
                    "texas.cache_ttl_seconds",
                    cached_response.ttl().as_secs().cast_signed(),
                );
                span.set_attribute(
                    "texas.token_expires_in_seconds",
                    cached_response.expires_in().as_secs().cast_signed(),
                );
            }
            None => {
                span.set_attribute("texas.cache_hit", false);
            }
        }

        response.map(TokenResponse::from)
    }

    pub async fn insert(&self, key: K, response: TokenResponse) {
        let span = tracing::Span::current();
        span.set_attribute(
            "texas.token_expires_in_seconds",
            response.expires_in_seconds.cast_signed(),
        );

        self.inner.insert(key, CachedTokenResponse::from(response)).await;
        telemetry::inc_token_cache(self.kind)
    }

    pub async fn invalidate(&self, key: &K) {
        let span = tracing::Span::current();
        span.set_attribute("texas.cache_force_skipped", true);

        self.inner.invalidate(key).await
    }
}

#[derive(Clone)]
pub struct CachedTokenResponse {
    response: TokenResponse,
    expires_at: Option<Instant>,
}

impl CachedTokenResponse {
    // expires_in calculates the actual time left until the token expires.
    pub fn expires_in(&self) -> Duration {
        if let Some(expires_at) = self.expires_at {
            expires_at.saturating_duration_since(Instant::now())
        } else {
            Duration::ZERO
        }
    }

    // ttl calculates the remaining time to live (TTL) for preemptive cache expiration,
    // i.e. cache entries should be removed before the token expires.
    pub fn ttl(&self) -> Duration {
        const EXPIRY_LEEWAY: Duration = Duration::from_secs(60);

        let expires_in = self.expires_in();
        if expires_in > EXPIRY_LEEWAY {
            expires_in.saturating_sub(EXPIRY_LEEWAY)
        } else {
            expires_in / 2
        }
    }
}

impl From<CachedTokenResponse> for TokenResponse {
    fn from(mut cached: CachedTokenResponse) -> Self {
        cached.response.expires_in_seconds = cached.expires_in().as_secs();
        cached.response
    }
}

impl From<TokenResponse> for CachedTokenResponse {
    fn from(response: TokenResponse) -> Self {
        Self {
            expires_at: Instant::now()
                .checked_add(Duration::from_secs(response.expires_in_seconds)),
            response,
        }
    }
}

pub struct TokenResponseExpiry;

impl<R> Expiry<R, CachedTokenResponse> for TokenResponseExpiry {
    // Sets TTL per cache entry on creation/insertion.
    // Returning `Some(duration)` sets expiration to `created_at + duration`.
    // Returning `None` disables expiration for the entry.
    fn expire_after_create(
        &self,
        _key: &R,
        value: &CachedTokenResponse,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(value.ttl())
    }

    fn expire_after_update(
        &self,
        _key: &R,
        value: &CachedTokenResponse,
        _updated_at: std::time::Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::identity_provider::TokenType;
    use mock_instant::thread_local::MockClock;
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    #[rstest]
    #[case(3_600, 3_595)]
    #[case(180, 175)]
    #[case(1, 0)]
    #[case(0, 0)]
    fn test_token_response_from_cached_token_response(
        #[case] expires_in: u64,
        #[case] expected_after_advance: u64,
    ) {
        setup_clock();

        let expires_in = Duration::from_secs(expires_in);
        let cached = CachedTokenResponse {
            response: token_response(expires_in),
            expires_at: Instant::now().checked_add(expires_in),
        };

        let token_response = TokenResponse::from(cached.clone());
        assert_eq!(token_response.expires_in_seconds, expires_in.as_secs());

        MockClock::advance(Duration::from_secs(5));
        let token_response = TokenResponse::from(cached.clone());
        assert_eq!(token_response.expires_in_seconds, expected_after_advance);

        MockClock::advance(expires_in);
        let token_response = TokenResponse::from(cached);
        assert_eq!(token_response.expires_in_seconds, 0);
    }

    #[rstest]
    #[case(Duration::from_secs(3_600), Duration::from_secs(3_595))]
    #[case(Duration::from_secs(180), Duration::from_secs(175))]
    #[case(Duration::from_secs(30), Duration::from_secs(25))]
    #[case(Duration::from_secs(1), Duration::from_secs(0))]
    #[case(Duration::from_secs(0), Duration::from_secs(0))]
    fn test_cached_token_response_from_token_response(
        #[case] expires_in: Duration,
        #[case] expected_after_advance: Duration,
    ) {
        setup_clock();

        let cached = CachedTokenResponse::from(token_response(expires_in));
        assert_eq!(cached.expires_in(), expires_in);
        assert_eq!(cached.response.expires_in_seconds, expires_in.as_secs());

        MockClock::advance(Duration::from_secs(5));
        assert_eq!(cached.expires_in(), expected_after_advance);
        // the response struct should not change after advancing the clock
        assert_eq!(cached.response.expires_in_seconds, expires_in.as_secs());

        MockClock::advance(expires_in);
        assert_eq!(cached.expires_in(), Duration::ZERO);
        assert_eq!(cached.response.expires_in_seconds, expires_in.as_secs());
    }

    #[rstest]
    // expected = expires_in - 60 seconds leeway
    #[case(
        Duration::from_secs(3_600),
        Duration::from_secs(3_540),
        Duration::from_secs(3_535)
    )]
    #[case(
        Duration::from_secs(180),
        Duration::from_secs(120),
        Duration::from_secs(115)
    )]
    #[case(
        Duration::from_secs(61),
        Duration::from_secs(1),
        Duration::from_secs(28)
    )]
    // expires_in < leeway -> expected = expires_in / 2
    #[case(
        Duration::from_secs(60),
        Duration::from_secs(30),
        Duration::from_millis(27_500)
    )]
    #[case(
        Duration::from_secs(30),
        Duration::from_secs(15),
        Duration::from_millis(12_500)
    )]
    #[case(
        Duration::from_secs(1),
        Duration::from_millis(500),
        Duration::from_secs(0)
    )]
    #[case(Duration::from_secs(0), Duration::from_secs(0), Duration::from_secs(0))]
    fn test_cached_token_response_ttl(
        #[case] expires_in: Duration,
        #[case] expected: Duration,
        #[case] expected_after_advance: Duration,
    ) {
        setup_clock();

        let cached = CachedTokenResponse::from(token_response(expires_in));
        assert_eq!(cached.ttl(), expected);

        MockClock::advance(Duration::from_secs(5));
        assert_eq!(cached.ttl(), expected_after_advance);

        MockClock::advance(expires_in);
        assert_eq!(cached.ttl(), Duration::ZERO);
    }

    #[test]
    fn test_expires_in_seconds_overflow_should_not_cache() {
        setup_clock();

        let expires_in = Duration::MAX;
        let cached = CachedTokenResponse::from(token_response(expires_in));
        assert_eq!(cached.expires_in(), Duration::ZERO);
        assert_eq!(cached.ttl(), Duration::ZERO);

        let token_response = TokenResponse::from(cached);
        assert_eq!(token_response.expires_in_seconds, 0);
    }

    fn setup_clock() {
        MockClock::set_time(Duration::from_secs(100_000))
    }

    fn token_response(expires_in: Duration) -> TokenResponse {
        TokenResponse {
            access_token: "some-token".to_string(),
            expires_in_seconds: expires_in.as_secs(),
            token_type: TokenType::Bearer,
        }
    }
}
