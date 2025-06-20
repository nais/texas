use crate::identity_provider::TokenResponse;
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
        cached.response.expires_in_seconds -= cached.created_at.elapsed().as_secs();
        cached.response
    }
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
