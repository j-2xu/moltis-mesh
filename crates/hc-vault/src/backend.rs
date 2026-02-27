//! [`SecretBackend`] implementation backed by HashiCorp Vault KV v2.

use std::sync::Arc;

use async_trait::async_trait;

use moltis_mesh::{
    SecretBackend, SecretBackendStatus,
    error::Result as MeshResult,
};

use crate::client::VaultClient;

/// HC Vault implementation of [`SecretBackend`].
///
/// Maps logical paths to Vault KV v2 paths:
/// - `provider/openai/api_key` → `secret/data/moltis/provider/openai/api_key`
///
/// Secrets are stored as `{"value": "<secret>"}` in KV v2 with optional
/// `metadata` field.
pub struct HcVaultBackend {
    client: Arc<VaultClient>,
}

impl std::fmt::Debug for HcVaultBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HcVaultBackend")
            .field("client", &self.client)
            .finish()
    }
}

impl HcVaultBackend {
    /// Create a new backend wrapping a Vault client.
    pub fn new(client: Arc<VaultClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl SecretBackend for HcVaultBackend {
    async fn put_secret(&self, path: &str, value: &str, metadata: Option<&str>) -> MeshResult<()> {
        let mut data = serde_json::json!({ "value": value });
        if let Some(meta) = metadata {
            data["metadata"] = serde_json::Value::String(meta.to_string());
        }
        self.client.kv_write(path, data).await.map_err(Into::into)
    }

    async fn get_secret(&self, path: &str) -> MeshResult<Option<String>> {
        let data = self.client.kv_read(path).await.map_err(moltis_mesh::MeshError::from)?;
        Ok(data.and_then(|d| {
            d.get("value")
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        }))
    }

    async fn delete_secret(&self, path: &str) -> MeshResult<()> {
        self.client.kv_delete(path).await.map_err(Into::into)
    }

    async fn list_secrets(&self, prefix: &str) -> MeshResult<Vec<String>> {
        let keys = self.client.kv_list(prefix).await.map_err(moltis_mesh::MeshError::from)?;
        // Vault LIST returns trailing `/` for directories — strip them and
        // prepend the prefix for a consistent API.
        let prefix_normalized = if prefix.ends_with('/') {
            prefix.to_string()
        } else if prefix.is_empty() {
            String::new()
        } else {
            format!("{prefix}/")
        };
        Ok(keys
            .into_iter()
            .map(|k| {
                let k = k.trim_end_matches('/');
                format!("{prefix_normalized}{k}")
            })
            .collect())
    }

    async fn status(&self) -> SecretBackendStatus {
        match self.client.token_lookup_self().await {
            Ok((ttl, _)) if ttl > 0 => SecretBackendStatus::Available,
            Ok(_) => SecretBackendStatus::Unavailable {
                reason: "token TTL is zero".into(),
            },
            Err(crate::error::HcVaultError::Sealed) => SecretBackendStatus::Sealed,
            Err(e) => SecretBackendStatus::Unavailable {
                reason: e.to_string(),
            },
        }
    }

    fn backend_name(&self) -> &'static str {
        "hashicorp-vault"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;

    #[tokio::test]
    async fn put_and_get_roundtrip() {
        let mut server = mockito::Server::new_async().await;

        let write_mock = server
            .mock("POST", "/v1/secret/data/moltis/env/MY_KEY")
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let read_mock = server
            .mock("GET", "/v1/secret/data/moltis/env/MY_KEY")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"data":{"value":"my-secret","metadata":"test"},"metadata":{"version":1}}}"#)
            .create_async()
            .await;

        let config = crate::config::HcVaultConfig {
            address: server.url(),
            auth: crate::config::HcVaultAuth::Token {
                token: Secret::new("test".into()),
            },
            mount_path: "secret".into(),
            path_prefix: "moltis".into(),
            transit_mount: None,
            namespace: None,
            tls_ca_cert: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        let client = Arc::new(VaultClient::new(config, Secret::new("test".into())).unwrap());
        let backend = HcVaultBackend::new(client);

        backend
            .put_secret("env/MY_KEY", "my-secret", Some("test"))
            .await
            .unwrap();
        let result = backend.get_secret("env/MY_KEY").await.unwrap();

        assert_eq!(result.as_deref(), Some("my-secret"));
        write_mock.assert_async().await;
        read_mock.assert_async().await;
    }

    #[tokio::test]
    async fn get_returns_none_on_missing() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/secret/data/moltis/env/MISSING")
            .with_status(404)
            .create_async()
            .await;

        let config = crate::config::HcVaultConfig {
            address: server.url(),
            auth: crate::config::HcVaultAuth::Token {
                token: Secret::new("test".into()),
            },
            mount_path: "secret".into(),
            path_prefix: "moltis".into(),
            transit_mount: None,
            namespace: None,
            tls_ca_cert: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        let client = Arc::new(VaultClient::new(config, Secret::new("test".into())).unwrap());
        let backend = HcVaultBackend::new(client);

        let result = backend.get_secret("env/MISSING").await.unwrap();
        assert!(result.is_none());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn backend_name() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server.mock("GET", "/").create_async().await;

        let config = crate::config::HcVaultConfig {
            address: server.url(),
            auth: crate::config::HcVaultAuth::Token {
                token: Secret::new("test".into()),
            },
            mount_path: "secret".into(),
            path_prefix: "moltis".into(),
            transit_mount: None,
            namespace: None,
            tls_ca_cert: None,
            tls_client_cert: None,
            tls_client_key: None,
        };
        let client = Arc::new(VaultClient::new(config, Secret::new("test".into())).unwrap());
        let backend = HcVaultBackend::new(client);

        assert_eq!(backend.backend_name(), "hashicorp-vault");
    }
}
