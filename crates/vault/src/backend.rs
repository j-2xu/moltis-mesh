//! [`SecretBackend`] implementation backed by the local encryption vault.
//!
//! Wraps the existing [`Vault<C>`](crate::Vault) to provide the mesh-agnostic
//! secret storage interface. Secrets are encrypted with the vault's DEK and
//! stored in the `vault_secrets` SQLite table.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::SqlitePool;

use moltis_mesh::{
    SecretBackend, SecretBackendStatus,
    error::Result as MeshResult,
};

use crate::{
    error::VaultError,
    traits::Cipher,
    vault::Vault,
};

/// Local secret backend wrapping the existing Moltis vault.
///
/// Uses the vault's [`encrypt_string`](Vault::encrypt_string) /
/// [`decrypt_string`](Vault::decrypt_string) for encryption and stores
/// the encrypted blobs in the `vault_secrets` table.
pub struct LocalSecretBackend<C: Cipher = crate::xchacha20::XChaCha20Poly1305Cipher> {
    vault: Arc<Vault<C>>,
    pool: SqlitePool,
}

impl<C: Cipher> std::fmt::Debug for LocalSecretBackend<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSecretBackend").finish()
    }
}

impl<C: Cipher> LocalSecretBackend<C> {
    /// Create a new local secret backend.
    ///
    /// The vault must already be initialized and unsealed.
    pub fn new(vault: Arc<Vault<C>>, pool: SqlitePool) -> Self {
        Self { vault, pool }
    }

    /// Map a logical path to an AAD value for authenticated encryption.
    fn aad_for_path(path: &str) -> String {
        format!("secret:{path}")
    }
}

#[async_trait]
impl<C: Cipher + 'static> SecretBackend for LocalSecretBackend<C> {
    async fn put_secret(&self, path: &str, value: &str, metadata: Option<&str>) -> MeshResult<()> {
        let aad = Self::aad_for_path(path);
        let encrypted = self
            .vault
            .encrypt_string(value, &aad)
            .await
            .map_err(|e| moltis_mesh::MeshError::Internal(anyhow::anyhow!("{e}")))?;

        sqlx::query(
            "INSERT INTO vault_secrets (path, value, metadata, updated_at)
             VALUES (?, ?, ?, datetime('now'))
             ON CONFLICT(path) DO UPDATE SET
                value = excluded.value,
                metadata = excluded.metadata,
                updated_at = datetime('now')",
        )
        .bind(path)
        .bind(&encrypted)
        .bind(metadata)
        .execute(&self.pool)
        .await
        .map_err(|e| moltis_mesh::MeshError::Internal(anyhow::anyhow!("{e}")))?;

        Ok(())
    }

    async fn get_secret(&self, path: &str) -> MeshResult<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM vault_secrets WHERE path = ?")
                .bind(path)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| moltis_mesh::MeshError::Internal(anyhow::anyhow!("{e}")))?;

        let Some((encrypted,)) = row else {
            return Ok(None);
        };

        let aad = Self::aad_for_path(path);
        let decrypted = self
            .vault
            .decrypt_string(&encrypted, &aad)
            .await
            .map_err(|e| match e {
                VaultError::Sealed => moltis_mesh::MeshError::BackendUnavailable {
                    reason: "vault is sealed".into(),
                },
                other => moltis_mesh::MeshError::Internal(anyhow::anyhow!("{other}")),
            })?;

        Ok(Some(decrypted))
    }

    async fn delete_secret(&self, path: &str) -> MeshResult<()> {
        sqlx::query("DELETE FROM vault_secrets WHERE path = ?")
            .bind(path)
            .execute(&self.pool)
            .await
            .map_err(|e| moltis_mesh::MeshError::Internal(anyhow::anyhow!("{e}")))?;
        Ok(())
    }

    async fn list_secrets(&self, prefix: &str) -> MeshResult<Vec<String>> {
        let prefix_pattern = if prefix.ends_with('/') {
            format!("{prefix}%")
        } else if prefix.is_empty() {
            "%".into()
        } else {
            format!("{prefix}/%")
        };

        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT path FROM vault_secrets WHERE path LIKE ? ORDER BY path",
        )
        .bind(&prefix_pattern)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| moltis_mesh::MeshError::Internal(anyhow::anyhow!("{e}")))?;

        // Return only direct children (not nested paths).
        let prefix_depth = if prefix.is_empty() {
            0
        } else {
            prefix.trim_end_matches('/').matches('/').count() + 1
        };

        let mut results = Vec::new();
        for (path,) in rows {
            let path_depth = path.matches('/').count();
            // Direct child: depth is exactly prefix_depth.
            if path_depth == prefix_depth {
                results.push(path);
            }
        }

        Ok(results)
    }

    async fn status(&self) -> SecretBackendStatus {
        if self.vault.is_unsealed().await {
            SecretBackendStatus::Available
        } else {
            match self.vault.status().await {
                Ok(crate::vault::VaultStatus::Uninitialized) => SecretBackendStatus::Unavailable {
                    reason: "vault not initialized".into(),
                },
                Ok(crate::vault::VaultStatus::Sealed) => SecretBackendStatus::Sealed,
                Ok(crate::vault::VaultStatus::Unsealed) => SecretBackendStatus::Available,
                Err(e) => SecretBackendStatus::Unavailable {
                    reason: e.to_string(),
                },
            }
        }
    }

    fn backend_name(&self) -> &'static str {
        "local"
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::xchacha20::XChaCha20Poly1305Cipher;

    async fn test_setup() -> (Arc<Vault<XChaCha20Poly1305Cipher>>, SqlitePool) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS vault_metadata (
                id                   INTEGER PRIMARY KEY CHECK (id = 1),
                version              INTEGER NOT NULL DEFAULT 1,
                kdf_salt             TEXT NOT NULL,
                kdf_params           TEXT NOT NULL,
                wrapped_dek          TEXT NOT NULL,
                recovery_wrapped_dek TEXT,
                recovery_key_hash    TEXT,
                created_at           TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at           TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS vault_secrets (
                path        TEXT PRIMARY KEY NOT NULL,
                value       TEXT NOT NULL,
                metadata    TEXT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        let vault = Arc::new(
            Vault::with_cipher(pool.clone(), XChaCha20Poly1305Cipher)
                .await
                .unwrap(),
        );
        vault.initialize("testpassword").await.unwrap();
        (vault, pool)
    }

    #[tokio::test]
    async fn put_get_roundtrip() {
        let (vault, pool) = test_setup().await;
        let backend = LocalSecretBackend::new(vault, pool);

        backend
            .put_secret("provider/openai/api_key", "sk-test123", Some("OpenAI"))
            .await
            .unwrap();
        let result = backend.get_secret("provider/openai/api_key").await.unwrap();
        assert_eq!(result.as_deref(), Some("sk-test123"));
    }

    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        let (vault, pool) = test_setup().await;
        let backend = LocalSecretBackend::new(vault, pool);

        let result = backend.get_secret("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_secret() {
        let (vault, pool) = test_setup().await;
        let backend = LocalSecretBackend::new(vault, pool);

        backend
            .put_secret("env/MY_KEY", "value", None)
            .await
            .unwrap();
        backend.delete_secret("env/MY_KEY").await.unwrap();
        let result = backend.get_secret("env/MY_KEY").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_is_noop() {
        let (vault, pool) = test_setup().await;
        let backend = LocalSecretBackend::new(vault, pool);

        // Should not error.
        backend.delete_secret("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn list_secrets() {
        let (vault, pool) = test_setup().await;
        let backend = LocalSecretBackend::new(vault, pool);

        backend
            .put_secret("provider/openai", "val1", None)
            .await
            .unwrap();
        backend
            .put_secret("provider/anthropic", "val2", None)
            .await
            .unwrap();
        backend
            .put_secret("env/MY_KEY", "val3", None)
            .await
            .unwrap();

        let providers = backend.list_secrets("provider").await.unwrap();
        assert_eq!(providers.len(), 2);
        assert!(providers.contains(&"provider/openai".to_string()));
        assert!(providers.contains(&"provider/anthropic".to_string()));

        let env_vars = backend.list_secrets("env").await.unwrap();
        assert_eq!(env_vars.len(), 1);
        assert!(env_vars.contains(&"env/MY_KEY".to_string()));
    }

    #[tokio::test]
    async fn put_overwrites_existing() {
        let (vault, pool) = test_setup().await;
        let backend = LocalSecretBackend::new(vault, pool);

        backend
            .put_secret("env/KEY", "old", None)
            .await
            .unwrap();
        backend
            .put_secret("env/KEY", "new", None)
            .await
            .unwrap();
        let result = backend.get_secret("env/KEY").await.unwrap();
        assert_eq!(result.as_deref(), Some("new"));
    }

    #[tokio::test]
    async fn status_available_when_unsealed() {
        let (vault, pool) = test_setup().await;
        let backend = LocalSecretBackend::new(vault, pool);
        assert_eq!(backend.status().await, SecretBackendStatus::Available);
    }

    #[tokio::test]
    async fn status_sealed_when_sealed() {
        let (vault, pool) = test_setup().await;
        vault.seal().await;
        let backend = LocalSecretBackend::new(vault, pool);
        assert_eq!(backend.status().await, SecretBackendStatus::Sealed);
    }

    #[tokio::test]
    async fn backend_name() {
        let (vault, pool) = test_setup().await;
        let backend = LocalSecretBackend::new(vault, pool);
        assert_eq!(backend.backend_name(), "local");
    }
}
