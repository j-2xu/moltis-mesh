//! Consul Connect mTLS certificate manager.
//!
//! Implements [`MtlsCertManager`] using Consul Connect CA leaf certificates.
//! Certificates are SPIFFE x509-SVIDs that identify the workload.

use std::{io::BufReader, sync::Arc};

use async_trait::async_trait;
use rustls::ServerConfig;
use tokio::sync::RwLock;

use moltis_mesh::{MtlsCertManager, error::Result as MeshResult};

use crate::{
    client::ConsulClient,
    error::{ConsulError, Result},
};

/// Consul Connect certificate manager.
///
/// Fetches SPIFFE x509-SVIDs from Consul's Connect CA and builds
/// `rustls` server/client configs for mutual TLS.
///
/// Certificate rotation happens via [`refresh_certs`](MtlsCertManager::refresh_certs)
/// which atomically swaps the active configs.
pub struct ConsulConnectCertManager {
    client: Arc<ConsulClient>,
    /// Cached SPIFFE ID from the last leaf cert.
    spiffe_id: RwLock<Option<String>>,
    /// Current server config (atomic swap on rotation).
    server_config: RwLock<Option<Arc<ServerConfig>>>,
    /// Current client config.
    client_config: RwLock<Option<Arc<rustls::ClientConfig>>>,
    /// Shutdown signal for the rotation task.
    shutdown: tokio::sync::watch::Receiver<bool>,
}

impl std::fmt::Debug for ConsulConnectCertManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsulConnectCertManager")
            .field("client", &self.client)
            .finish()
    }
}

impl ConsulConnectCertManager {
    /// Create a new cert manager.
    pub fn new(
        client: Arc<ConsulClient>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Self {
        Self {
            client,
            spiffe_id: RwLock::new(None),
            server_config: RwLock::new(None),
            client_config: RwLock::new(None),
            shutdown,
        }
    }

    /// Initialize certificates. Must be called before `build_mtls_*` methods.
    pub async fn init(&self) -> Result<()> {
        self.do_refresh().await
    }

    /// Spawn a background cert rotation task at 70% of cert TTL.
    pub fn spawn_rotation(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.rotation_loop().await;
        })
    }

    async fn rotation_loop(&self) {
        // Default rotation interval: 6 hours (Consul default leaf TTL is 72h).
        let default_interval = std::time::Duration::from_secs(6 * 3600);

        loop {
            let mut shutdown_rx = self.shutdown.clone();
            tokio::select! {
                _ = tokio::time::sleep(default_interval) => {},
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && *shutdown_rx.borrow() {
                        #[cfg(feature = "tracing")]
                        tracing::info!("consul cert rotation shutting down");
                        return;
                    }
                },
            }

            if let Err(e) = self.do_refresh().await {
                #[cfg(feature = "tracing")]
                tracing::warn!("consul cert rotation failed: {e}");
            } else {
                #[cfg(feature = "tracing")]
                tracing::debug!("consul certs rotated successfully");
            }
        }
    }

    async fn do_refresh(&self) -> Result<()> {
        // Fetch CA roots for trust bundle.
        let roots = self.client.connect_ca_roots().await?;
        let mut root_store = rustls::RootCertStore::empty();
        for root in &roots.roots {
            if !root.active {
                continue;
            }
            let certs: Vec<_> =
                rustls_pemfile::certs(&mut BufReader::new(root.root_cert_pem.as_bytes()))
                    .filter_map(|r| r.ok())
                    .collect();
            for cert in certs {
                root_store
                    .add(cert)
                    .map_err(|e| ConsulError::Certificate(format!("add CA root: {e}")))?;
            }
        }

        // Fetch leaf cert (SPIFFE x509-SVID).
        let leaf = self.client.connect_ca_leaf().await?;

        // Parse leaf cert chain.
        let cert_chain: Vec<_> =
            rustls_pemfile::certs(&mut BufReader::new(leaf.certificate_pem.as_bytes()))
                .filter_map(|r| r.ok())
                .collect();
        if cert_chain.is_empty() {
            return Err(ConsulError::Certificate("empty leaf cert chain".into()));
        }

        // Parse private key.
        let key = rustls_pemfile::private_key(&mut BufReader::new(
            leaf.private_key_pem.as_bytes(),
        ))
        .map_err(|e| ConsulError::Certificate(format!("parse leaf key: {e}")))?
        .ok_or_else(|| ConsulError::Certificate("no private key in leaf response".into()))?;

        // Ensure a crypto provider is installed.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Build server config with client cert verification.
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store.clone()))
            .build()
            .map_err(|e| ConsulError::Tls(format!("build client verifier: {e}")))?;

        let mut server_cfg = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert_chain.clone(), key.clone_key())
            .map_err(|e| ConsulError::Tls(format!("build server config: {e}")))?;
        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        // Build client config.
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, key)
            .map_err(|e| ConsulError::Tls(format!("build client config: {e}")))?;

        // Atomically swap.
        *self.server_config.write().await = Some(Arc::new(server_cfg));
        *self.client_config.write().await = Some(Arc::new(client_cfg));
        *self.spiffe_id.write().await = Some(leaf.service_u_r_i);

        #[cfg(feature = "tracing")]
        tracing::info!("consul Connect certs loaded");

        Ok(())
    }
}

#[async_trait]
impl MtlsCertManager for ConsulConnectCertManager {
    async fn build_mtls_server_config(&self) -> MeshResult<ServerConfig> {
        let guard = self.server_config.read().await;
        let config = guard.as_ref().ok_or_else(|| {
            moltis_mesh::MeshError::Tls("consul certs not initialized — call init() first".into())
        })?;
        // Return a clone of the inner ServerConfig.
        Ok(config.as_ref().clone())
    }

    async fn build_mtls_client_config(&self) -> MeshResult<rustls::ClientConfig> {
        let guard = self.client_config.read().await;
        let config = guard.as_ref().ok_or_else(|| {
            moltis_mesh::MeshError::Tls("consul certs not initialized — call init() first".into())
        })?;
        Ok(config.as_ref().clone())
    }

    fn spiffe_id(&self) -> Option<String> {
        // Non-async helper. Use try_read to avoid blocking.
        self.spiffe_id
            .try_read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    async fn refresh_certs(&self) -> MeshResult<()> {
        self.do_refresh().await.map_err(Into::into)
    }
}
