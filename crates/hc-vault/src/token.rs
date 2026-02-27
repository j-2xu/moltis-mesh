//! Token lifecycle management for HC Vault.
//!
//! [`TokenManager`] handles automatic token renewal before expiry and
//! re-authentication when tokens can't be renewed.

use std::sync::Arc;

use secrecy::{ExposeSecret, Secret};

use crate::{
    client::VaultClient,
    config::{HcVaultAuth, HcVaultConfig},
    error::Result,
};

/// Manages Vault token lifecycle: initial auth, periodic renewal, and
/// re-authentication on renewal failure.
pub struct TokenManager {
    client: Arc<VaultClient>,
    config: HcVaultConfig,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

impl TokenManager {
    /// Create a token manager.
    ///
    /// Call [`TokenManager::authenticate`] to perform initial authentication,
    /// then [`TokenManager::spawn_renewal`] to start background renewal.
    pub fn new(
        client: Arc<VaultClient>,
        config: HcVaultConfig,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Self {
        Self {
            client,
            config,
            shutdown,
        }
    }

    /// Perform initial authentication based on the configured auth method.
    ///
    /// For `Token` auth, validates the token is usable.
    /// For `AppRole` / `Kubernetes`, performs a login and stores the resulting token.
    pub async fn authenticate(&self) -> Result<()> {
        match &self.config.auth {
            HcVaultAuth::Token { token } => {
                // Validate the token by looking it up.
                self.client.set_token(Secret::new(token.expose_secret().clone())).await;
                let _ = self.client.token_lookup_self().await?;
                #[cfg(feature = "tracing")]
                tracing::info!("vault token authentication successful");
                Ok(())
            },
            HcVaultAuth::AppRole {
                role_id,
                secret_id,
                mount,
            } => {
                let (ttl, renewable) = self.client.login_approle(role_id, secret_id, mount).await?;
                #[cfg(feature = "tracing")]
                tracing::info!(ttl, renewable, "vault AppRole authentication successful");
                Ok(())
            },
            HcVaultAuth::Kubernetes {
                role,
                token_path,
                mount,
            } => {
                let jwt = tokio::fs::read_to_string(token_path).await.map_err(|e| {
                    crate::error::HcVaultError::Config(format!(
                        "failed to read K8s service account token from {}: {e}",
                        token_path.display()
                    ))
                })?;
                let (ttl, renewable) =
                    self.client.login_kubernetes(role, jwt.trim(), mount).await?;
                #[cfg(feature = "tracing")]
                tracing::info!(ttl, renewable, "vault Kubernetes authentication successful");
                Ok(())
            },
        }
    }

    /// Spawn a background task that renews the token at 50% of its TTL.
    ///
    /// The task runs until the shutdown signal is received.
    pub fn spawn_renewal(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.renewal_loop().await;
        })
    }

    async fn renewal_loop(&self) {
        loop {
            // Look up current TTL.
            let (ttl, renewable) = match self.client.token_lookup_self().await {
                Ok(info) => info,
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("vault token lookup failed: {e}");
                    // Try re-authenticating.
                    if let Err(e) = self.authenticate().await {
                        #[cfg(feature = "tracing")]
                        tracing::error!("vault re-authentication failed: {e}");
                    }
                    (60, true)
                },
            };

            // Sleep until 50% of TTL, minimum 5 seconds.
            let sleep_secs = (ttl / 2).max(5);
            let sleep_duration = std::time::Duration::from_secs(sleep_secs as u64);

            let mut shutdown_rx = self.shutdown.clone();
            tokio::select! {
                _ = tokio::time::sleep(sleep_duration) => {},
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && *shutdown_rx.borrow() {
                        #[cfg(feature = "tracing")]
                        tracing::info!("vault token renewal shutting down");
                        return;
                    }
                },
            }

            if !renewable {
                // Non-renewable token — try re-authentication.
                if let Err(e) = self.authenticate().await {
                    #[cfg(feature = "tracing")]
                    tracing::error!("vault re-authentication failed (non-renewable token): {e}");
                }
                continue;
            }

            match self.client.token_renew_self().await {
                Ok((new_ttl, _)) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(new_ttl, "vault token renewed");
                },
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("vault token renewal failed, re-authenticating: {e}");
                    if let Err(e) = self.authenticate().await {
                        #[cfg(feature = "tracing")]
                        tracing::error!("vault re-authentication failed: {e}");
                    }
                },
            }
        }
    }
}
