//! Consul intention authorization middleware for Axum.
//!
//! [`IntentionAuthorizer`] verifies that the peer's SPIFFE ID is allowed
//! to connect based on Consul Connect intentions. Results are cached to
//! reduce API calls.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;

use crate::client::ConsulClient;

/// A cached intention check result.
struct CachedIntention {
    allowed: bool,
    expires_at: Instant,
}

/// Axum middleware that checks Consul Connect intentions.
///
/// Extracts the peer SPIFFE ID from the TLS client certificate and
/// verifies it against Consul intentions. Defaults to **deny** when
/// Consul is unreachable (fail-closed).
///
/// Cache entries expire after `cache_ttl`.
pub struct IntentionAuthorizer {
    client: Arc<ConsulClient>,
    service_name: String,
    cache: DashMap<String, CachedIntention>,
    cache_ttl: Duration,
}

impl IntentionAuthorizer {
    /// Create a new intention authorizer.
    pub fn new(client: Arc<ConsulClient>, service_name: String, cache_ttl: Duration) -> Self {
        Self {
            client,
            service_name,
            cache: DashMap::new(),
            cache_ttl,
        }
    }

    /// Check whether a source SPIFFE ID is allowed to connect.
    async fn check_allowed(&self, source_spiffe_id: &str) -> bool {
        // Check cache.
        if let Some(entry) = self.cache.get(source_spiffe_id) {
            if entry.expires_at > Instant::now() {
                return entry.allowed;
            }
        }

        // Extract service name from SPIFFE ID.
        // Format: spiffe://<domain>/ns/<ns>/dc/<dc>/svc/<service>
        let source_service = extract_service_from_spiffe(source_spiffe_id)
            .unwrap_or_else(|| source_spiffe_id.to_string());

        let allowed = match self
            .client
            .intention_check(&source_service, &self.service_name)
            .await
        {
            Ok(allowed) => allowed,
            Err(e) => {
                // Fail-closed: deny when Consul is unreachable.
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    source = %source_spiffe_id,
                    error = %e,
                    "intention check failed, defaulting to deny"
                );
                false
            },
        };

        // Cache the result.
        self.cache.insert(source_spiffe_id.to_string(), CachedIntention {
            allowed,
            expires_at: Instant::now() + self.cache_ttl,
        });

        allowed
    }
}

/// Extract the service name from a SPIFFE ID.
///
/// Handles the format: `spiffe://<domain>/ns/<ns>/dc/<dc>/svc/<service>`
fn extract_service_from_spiffe(spiffe_id: &str) -> Option<String> {
    let path = spiffe_id.strip_prefix("spiffe://")?;
    // Find the service component after `/svc/`.
    let svc_idx = path.find("/svc/")?;
    let after_svc = &path[svc_idx + 5..];
    // Take until next `/` or end.
    let service = after_svc.split('/').next()?;
    if service.is_empty() {
        return None;
    }
    Some(service.to_string())
}

/// Axum middleware function for intention-based authorization.
///
/// This should be used with `axum::middleware::from_fn_with_state`.
///
/// In native mTLS mode, the peer SPIFFE ID is extracted from the client
/// certificate's SAN URI. This must be set as a request extension by the
/// TLS termination layer.
pub async fn intention_middleware(
    axum::extract::State(authorizer): axum::extract::State<Arc<IntentionAuthorizer>>,
    request: Request,
    next: Next,
) -> Response {
    // Look for the peer SPIFFE ID in request extensions.
    // This would be set by the mTLS layer when validating client certs.
    let peer_spiffe = request
        .extensions()
        .get::<PeerSpiffeId>()
        .map(|p| p.0.clone());

    if let Some(ref spiffe_id) = peer_spiffe {
        if !authorizer.check_allowed(spiffe_id).await {
            #[cfg(feature = "tracing")]
            tracing::warn!(peer = %spiffe_id, "intention denied");
            return (StatusCode::FORBIDDEN, "intention denied").into_response();
        }
    }
    // If no SPIFFE ID is present (e.g. non-mTLS request), skip the check.
    // The auth middleware will handle authentication separately.

    next.run(request).await
}

/// Request extension containing the peer's SPIFFE ID.
///
/// Set by the mTLS termination layer after verifying the client certificate.
#[derive(Debug, Clone)]
pub struct PeerSpiffeId(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_service_from_standard_spiffe() {
        let id = "spiffe://dc1/ns/default/dc/dc1/svc/web-frontend";
        assert_eq!(
            extract_service_from_spiffe(id).as_deref(),
            Some("web-frontend")
        );
    }

    #[test]
    fn extract_service_from_simple_spiffe() {
        let id = "spiffe://example.com/svc/my-service";
        assert_eq!(
            extract_service_from_spiffe(id).as_deref(),
            Some("my-service")
        );
    }

    #[test]
    fn extract_service_no_svc_returns_none() {
        let id = "spiffe://example.com/gateway";
        assert_eq!(extract_service_from_spiffe(id), None);
    }

    #[test]
    fn extract_service_invalid_spiffe() {
        assert_eq!(extract_service_from_spiffe("not-a-spiffe-id"), None);
    }
}
