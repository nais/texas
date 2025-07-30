use crate::oauth::identity_provider::TokenResponse;
use moka::Expiry;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct CachedTokenResponse {
    response: TokenResponse,
    created_at: Instant,
}

impl From<CachedTokenResponse> for TokenResponse {
    fn from(mut cached: CachedTokenResponse) -> Self {
        // Subtract the elapsed time since insertion to get the actual remaining seconds to expiry.
        cached.response.expires_in_seconds = cached
            .response
            .expires_in_seconds
            .saturating_sub(cached.created_at.elapsed().as_secs());
        cached.response
    }
}

#[test]
fn test_cached_token_response_from_token_response() {
    use crate::oauth::identity_provider::TokenType;
    use pretty_assertions::assert_eq;

    let cached_response = CachedTokenResponse {
        created_at: Instant::now().checked_sub(Duration::from_secs(3601)).unwrap(),
        response: TokenResponse {
            access_token: "some-token".to_string(),
            expires_in_seconds: 3600,
            token_type: TokenType::Bearer,
        },
    };

    let token_response: TokenResponse = cached_response.into();
    assert_eq!(token_response.expires_in_seconds, 0);
}

impl From<TokenResponse> for CachedTokenResponse {
    fn from(response: TokenResponse) -> Self {
        Self {
            response,
            created_at: Instant::now(),
        }
    }
}

/// Make sure tokens expire from the cache when their validity expires.
///
/// We subtract a leeway of 60 seconds from the actual expiry to ensure that we don't
/// return an expired token from the cache.
///
/// If the expiry is less than the leeway, we expire at the half-life instead.
pub struct TokenResponseExpiry;

impl<R> Expiry<R, CachedTokenResponse> for TokenResponseExpiry {
    fn expire_after_create(
        &self,
        _key: &R,
        value: &CachedTokenResponse,
        _created_at: Instant,
    ) -> Option<Duration> {
        const EXPIRY_LEEWAY_SECS: u64 = 60;
        let expiry_secs = value.response.expires_in_seconds;
        let expiry_secs = if expiry_secs > EXPIRY_LEEWAY_SECS {
            expiry_secs - EXPIRY_LEEWAY_SECS
        } else {
            expiry_secs / 2
        };

        Some(Duration::from_secs(expiry_secs))
    }
}
