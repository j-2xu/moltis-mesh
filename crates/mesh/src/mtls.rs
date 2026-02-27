//! mTLS certificate management abstraction.
//!
//! Defines [`MtlsCertManager`] — a trait for managing mutual TLS certificates
//! backed by any certificate authority (self-signed, Consul Connect, Vault PKI, etc.).
//!
//! # Certificate lifecycle
//!
//! Implementations should:
//! 1. Fetch leaf certificates (SPIFFE x509-SVIDs or equivalent) on startup.
//! 2. Build `rustls` configs for both server and client roles.
//! 3. Periodically refresh certificates before expiry (e.g. at 70% of TTL).
//! 4. Swap the active `ServerConfig` atomically via `Arc` to avoid disrupting
//!    in-flight connections.

use async_trait::async_trait;

use crate::error::Result;

/// Trait for mTLS certificate management.
///
/// Implementations provide rustls configurations that enforce mutual TLS
/// authentication. The server config verifies client certificates; the client
/// config presents the workload's own certificate.
///
/// # Thread safety
///
/// Implementations must be `Send + Sync`. Certificate rotation should use
/// interior mutability (e.g. `Arc<ArcSwap<ServerConfig>>`) to avoid blocking
/// the TLS acceptor.
#[async_trait]
pub trait MtlsCertManager: Send + Sync {
    /// Build a `rustls::ServerConfig` configured for mutual TLS.
    ///
    /// The returned config:
    /// - Presents the workload's leaf certificate to clients.
    /// - Requires and verifies client certificates against the trust bundle.
    /// - Uses ALPN `["h2", "http/1.1"]`.
    async fn build_mtls_server_config(&self) -> Result<rustls::ServerConfig>;

    /// Build a `rustls::ClientConfig` for outgoing mTLS connections.
    ///
    /// The returned config:
    /// - Presents the workload's leaf certificate to servers.
    /// - Verifies server certificates against the trust bundle.
    async fn build_mtls_client_config(&self) -> Result<rustls::ClientConfig>;

    /// Return the SPIFFE ID of this workload, if available.
    ///
    /// Format: `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`
    /// or `spiffe://<trust-domain>/<service-name>`.
    fn spiffe_id(&self) -> Option<String>;

    /// Refresh certificates from the CA.
    ///
    /// Called periodically by a background task. Implementations should:
    /// 1. Fetch new leaf certs from the CA.
    /// 2. Rebuild the server/client configs.
    /// 3. Atomically swap the active configs.
    ///
    /// Returns `Ok(())` even if certs are still valid (no-op refresh).
    async fn refresh_certs(&self) -> Result<()>;
}
