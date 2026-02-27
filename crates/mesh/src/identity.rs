//! Workload identity abstraction.
//!
//! Defines [`WorkloadIdentity`] — a trait for resolving the SPIFFE identity
//! of the current workload. Used by mTLS and authorization components.

use async_trait::async_trait;

use crate::error::Result;

/// Trait for resolving workload identity.
///
/// In a service mesh, each workload has a cryptographic identity expressed
/// as a SPIFFE ID (e.g. `spiffe://example.com/ns/default/sa/moltis`).
/// This trait abstracts how that identity is obtained — from Consul Connect
/// leaf certs, Vault PKI, environment variables, etc.
#[async_trait]
pub trait WorkloadIdentity: Send + Sync {
    /// Return the SPIFFE ID of this workload.
    ///
    /// Format: `spiffe://<trust-domain>/<path>`
    ///
    /// Returns `None` if no identity is available (e.g. standalone mode).
    async fn spiffe_id(&self) -> Result<Option<String>>;

    /// Return the trust domain this workload belongs to.
    ///
    /// Extracted from the SPIFFE ID (the authority component).
    /// Returns `None` if no identity is available.
    async fn trust_domain(&self) -> Result<Option<String>> {
        let id = self.spiffe_id().await?;
        Ok(id.and_then(|s| {
            s.strip_prefix("spiffe://")
                .and_then(|rest| rest.split('/').next())
                .map(ToString::to_string)
        }))
    }

    /// Validate that a peer's SPIFFE ID belongs to the same trust domain.
    ///
    /// Returns `true` if the peer's trust domain matches this workload's.
    /// Returns `false` if either identity is unavailable.
    async fn is_same_trust_domain(&self, peer_spiffe_id: &str) -> Result<bool> {
        let our_domain = self.trust_domain().await?;
        let peer_domain = peer_spiffe_id
            .strip_prefix("spiffe://")
            .and_then(|rest| rest.split('/').next())
            .map(ToString::to_string);
        Ok(our_domain.is_some() && our_domain == peer_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestIdentity {
        id: Option<String>,
    }

    #[async_trait]
    impl WorkloadIdentity for TestIdentity {
        async fn spiffe_id(&self) -> Result<Option<String>> {
            Ok(self.id.clone())
        }
    }

    #[tokio::test]
    async fn trust_domain_extraction() {
        let id = TestIdentity {
            id: Some("spiffe://example.com/ns/default/sa/moltis".into()),
        };
        assert_eq!(
            id.trust_domain().await.ok().flatten().as_deref(),
            Some("example.com")
        );
    }

    #[tokio::test]
    async fn trust_domain_none_when_no_identity() {
        let id = TestIdentity { id: None };
        assert_eq!(id.trust_domain().await.ok().flatten(), None);
    }

    #[tokio::test]
    async fn same_trust_domain_check() {
        let id = TestIdentity {
            id: Some("spiffe://prod.example.com/gateway".into()),
        };
        assert!(id
            .is_same_trust_domain("spiffe://prod.example.com/sandbox")
            .await
            .unwrap_or(false));
        assert!(!id
            .is_same_trust_domain("spiffe://staging.example.com/sandbox")
            .await
            .unwrap_or(true));
    }
}
