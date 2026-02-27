//! HashiCorp Vault HTTP client.
//!
//! Implements KV v2 CRUD, Transit encrypt/decrypt, and token operations
//! against the Vault HTTP API.

use std::sync::Arc;

use secrecy::{ExposeSecret, Secret};
use tokio::sync::RwLock;

use crate::{
    config::HcVaultConfig,
    error::{HcVaultError, Result},
};

/// Response wrapper for KV v2 read operations.
#[derive(Debug, serde::Deserialize)]
struct KvReadResponse {
    data: KvReadData,
}

#[derive(Debug, serde::Deserialize)]
struct KvReadData {
    data: serde_json::Map<String, serde_json::Value>,
    metadata: KvMetadata,
}

#[derive(Debug, serde::Deserialize)]
struct KvMetadata {
    #[allow(dead_code)]
    version: u64,
}

/// Response wrapper for KV v2 list operations.
#[derive(Debug, serde::Deserialize)]
struct KvListResponse {
    data: KvListData,
}

#[derive(Debug, serde::Deserialize)]
struct KvListData {
    keys: Vec<String>,
}

/// Response wrapper for Transit operations.
#[derive(Debug, serde::Deserialize)]
struct TransitResponse {
    data: TransitData,
}

#[derive(Debug, serde::Deserialize)]
struct TransitData {
    ciphertext: Option<String>,
    plaintext: Option<String>,
}

/// Response for token lookup.
#[derive(Debug, serde::Deserialize)]
struct TokenLookupResponse {
    data: TokenLookupData,
}

#[derive(Debug, serde::Deserialize)]
struct TokenLookupData {
    ttl: i64,
    renewable: bool,
}

/// Response for auth login.
#[derive(Debug, serde::Deserialize)]
struct AuthResponse {
    auth: AuthData,
}

#[derive(Debug, serde::Deserialize)]
struct AuthData {
    client_token: String,
    lease_duration: i64,
    renewable: bool,
}

/// HTTP client for HashiCorp Vault.
///
/// Thread-safe. The current token is held behind a `RwLock` to support
/// background renewal.
pub struct VaultClient {
    config: HcVaultConfig,
    http: reqwest::Client,
    token: Arc<RwLock<Secret<String>>>,
}

impl std::fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultClient")
            .field("address", &self.config.address)
            .field("mount_path", &self.config.mount_path)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl VaultClient {
    /// Create a new client with the given configuration and initial token.
    pub fn new(config: HcVaultConfig, initial_token: Secret<String>) -> Result<Self> {
        let mut builder = reqwest::Client::builder();

        if let Some(ref ca_path) = config.tls_ca_cert {
            let ca_bytes = std::fs::read(ca_path).map_err(|e| {
                HcVaultError::Config(format!("failed to read TLS CA cert: {e}"))
            })?;
            let ca_cert = reqwest::Certificate::from_pem(&ca_bytes)
                .map_err(|e| HcVaultError::Config(format!("invalid TLS CA cert: {e}")))?;
            builder = builder.add_root_certificate(ca_cert);
        }

        let http = builder
            .build()
            .map_err(|e| HcVaultError::Config(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            config,
            http,
            token: Arc::new(RwLock::new(initial_token)),
        })
    }

    /// Build a request with Vault token and optional namespace headers.
    async fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let token = self.token.read().await;
        let mut req = self
            .http
            .request(method, url)
            .header("X-Vault-Token", token.expose_secret());

        if let Some(ref ns) = self.config.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }

        req
    }

    /// Map a Vault HTTP response to a result.
    async fn check_response(&self, resp: reqwest::Response) -> Result<reqwest::Response> {
        let status = resp.status().as_u16();
        match status {
            200..=299 => Ok(resp),
            403 => {
                let body = resp.text().await.unwrap_or_default();
                Err(HcVaultError::AuthFailed(body))
            },
            503 => Err(HcVaultError::Sealed),
            _ => {
                let body = resp.text().await.unwrap_or_default();
                Err(HcVaultError::Http {
                    status,
                    message: body,
                })
            },
        }
    }

    // ── KV v2 ──────────────────────────────────────────────────────────

    /// Read a secret from KV v2.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), fields(path)))]
    pub async fn kv_read(&self, path: &str) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
        let url = self.config.kv_data_url(path);
        let resp = self.request(reqwest::Method::GET, &url).await.send().await?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        let resp = self.check_response(resp).await?;
        let kv: KvReadResponse = resp.json().await?;
        Ok(Some(kv.data.data))
    }

    /// Write a secret to KV v2.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, data), fields(path)))]
    pub async fn kv_write(&self, path: &str, data: serde_json::Value) -> Result<()> {
        let url = self.config.kv_data_url(path);
        let body = serde_json::json!({ "data": data });
        let resp = self
            .request(reqwest::Method::POST, &url)
            .await
            .json(&body)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Delete a secret from KV v2 (soft delete — marks latest version as deleted).
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), fields(path)))]
    pub async fn kv_delete(&self, path: &str) -> Result<()> {
        let url = self.config.kv_data_url(path);
        let resp = self
            .request(reqwest::Method::DELETE, &url)
            .await
            .send()
            .await?;

        // 404 is fine — secret didn't exist.
        if resp.status().as_u16() == 404 {
            return Ok(());
        }
        self.check_response(resp).await?;
        Ok(())
    }

    /// List secrets under a prefix in KV v2.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), fields(prefix)))]
    pub async fn kv_list(&self, prefix: &str) -> Result<Vec<String>> {
        let url = self.config.kv_metadata_url(prefix);
        let resp = self
            .request(reqwest::Method::from_bytes(b"LIST").unwrap_or(reqwest::Method::GET), &url)
            .await
            .send()
            .await?;

        if resp.status().as_u16() == 404 {
            return Ok(Vec::new());
        }

        let resp = self.check_response(resp).await?;
        let list: KvListResponse = resp.json().await?;
        Ok(list.data.keys)
    }

    // ── Transit ────────────────────────────────────────────────────────

    /// Encrypt data using the Transit engine.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, plaintext)))]
    pub async fn transit_encrypt(&self, key_name: &str, plaintext: &[u8]) -> Result<String> {
        let url = self
            .config
            .transit_encrypt_url(key_name)
            .ok_or_else(|| HcVaultError::Config("transit_mount not configured".into()))?;

        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, plaintext);
        let body = serde_json::json!({ "plaintext": b64 });

        let resp = self
            .request(reqwest::Method::POST, &url)
            .await
            .json(&body)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        let transit: TransitResponse = resp.json().await?;
        transit
            .data
            .ciphertext
            .ok_or_else(|| HcVaultError::Internal(anyhow::anyhow!("no ciphertext in response")))
    }

    /// Decrypt data using the Transit engine.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, ciphertext)))]
    pub async fn transit_decrypt(&self, key_name: &str, ciphertext: &str) -> Result<Vec<u8>> {
        let url = self
            .config
            .transit_decrypt_url(key_name)
            .ok_or_else(|| HcVaultError::Config("transit_mount not configured".into()))?;

        let body = serde_json::json!({ "ciphertext": ciphertext });
        let resp = self
            .request(reqwest::Method::POST, &url)
            .await
            .json(&body)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        let transit: TransitResponse = resp.json().await?;

        let b64 = transit
            .data
            .plaintext
            .ok_or_else(|| HcVaultError::Internal(anyhow::anyhow!("no plaintext in response")))?;
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
            .map_err(|e| HcVaultError::Internal(anyhow::anyhow!("base64 decode: {e}")))
    }

    // ── Token operations ───────────────────────────────────────────────

    /// Look up the current token's TTL and renewability.
    pub async fn token_lookup_self(&self) -> Result<(i64, bool)> {
        let url = format!(
            "{}/v1/auth/token/lookup-self",
            self.config.address.trim_end_matches('/')
        );
        let resp = self.request(reqwest::Method::GET, &url).await.send().await?;
        let resp = self.check_response(resp).await?;
        let lookup: TokenLookupResponse = resp.json().await?;
        Ok((lookup.data.ttl, lookup.data.renewable))
    }

    /// Renew the current token.
    pub async fn token_renew_self(&self) -> Result<(i64, bool)> {
        let url = format!(
            "{}/v1/auth/token/renew-self",
            self.config.address.trim_end_matches('/')
        );
        let resp = self
            .request(reqwest::Method::POST, &url)
            .await
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        let auth: AuthResponse = resp.json().await?;
        Ok((auth.auth.lease_duration, auth.auth.renewable))
    }

    /// Authenticate via AppRole and update the stored token.
    pub async fn login_approle(&self, role_id: &str, secret_id: &Secret<String>, mount: &str) -> Result<(i64, bool)> {
        let url = format!(
            "{}/v1/auth/{}/login",
            self.config.address.trim_end_matches('/'),
            mount
        );
        let body = serde_json::json!({
            "role_id": role_id,
            "secret_id": secret_id.expose_secret(),
        });
        let resp = self.http.post(&url).json(&body).send().await?;
        let resp = self.check_response(resp).await?;
        let auth: AuthResponse = resp.json().await?;

        *self.token.write().await = Secret::new(auth.auth.client_token);
        Ok((auth.auth.lease_duration, auth.auth.renewable))
    }

    /// Authenticate via Kubernetes service account and update the stored token.
    pub async fn login_kubernetes(&self, role: &str, jwt: &str, mount: &str) -> Result<(i64, bool)> {
        let url = format!(
            "{}/v1/auth/{}/login",
            self.config.address.trim_end_matches('/'),
            mount
        );
        let body = serde_json::json!({
            "role": role,
            "jwt": jwt,
        });
        let resp = self.http.post(&url).json(&body).send().await?;
        let resp = self.check_response(resp).await?;
        let auth: AuthResponse = resp.json().await?;

        *self.token.write().await = Secret::new(auth.auth.client_token);
        Ok((auth.auth.lease_duration, auth.auth.renewable))
    }

    /// Replace the current token (used by `TokenManager` after renewal).
    pub async fn set_token(&self, token: Secret<String>) {
        *self.token.write().await = token;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(address: &str) -> HcVaultConfig {
        HcVaultConfig {
            address: address.into(),
            auth: crate::config::HcVaultAuth::Token {
                token: Secret::new("test-token".into()),
            },
            mount_path: "secret".into(),
            path_prefix: "moltis".into(),
            transit_mount: Some("transit".into()),
            namespace: None,
            tls_ca_cert: None,
        }
    }

    #[tokio::test]
    async fn kv_read_returns_none_on_404() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/secret/data/moltis/nonexistent")
            .with_status(404)
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = VaultClient::new(config, Secret::new("test".into())).unwrap();
        let result = client.kv_read("nonexistent").await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn kv_read_returns_data() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/secret/data/moltis/provider/openai")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"data":{"api_key":"sk-test"},"metadata":{"version":1}}}"#)
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = VaultClient::new(config, Secret::new("test".into())).unwrap();
        let result = client.kv_read("provider/openai").await.unwrap();

        assert!(result.is_some());
        let data = result.unwrap();
        assert_eq!(data.get("api_key").and_then(|v| v.as_str()), Some("sk-test"));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn kv_write_sends_data() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v1/secret/data/moltis/provider/openai")
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = VaultClient::new(config, Secret::new("test".into())).unwrap();
        let result = client
            .kv_write(
                "provider/openai",
                serde_json::json!({"api_key": "sk-new"}),
            )
            .await;

        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn kv_delete_ok_on_404() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("DELETE", "/v1/secret/data/moltis/nonexistent")
            .with_status(404)
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = VaultClient::new(config, Secret::new("test".into())).unwrap();
        let result = client.kv_delete("nonexistent").await;

        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn auth_failed_on_403() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/secret/data/moltis/test")
            .with_status(403)
            .with_body("permission denied")
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = VaultClient::new(config, Secret::new("bad-token".into())).unwrap();
        let result = client.kv_read("test").await;

        assert!(matches!(result, Err(HcVaultError::AuthFailed(_))));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn sealed_on_503() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/secret/data/moltis/test")
            .with_status(503)
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = VaultClient::new(config, Secret::new("test".into())).unwrap();
        let result = client.kv_read("test").await;

        assert!(matches!(result, Err(HcVaultError::Sealed)));
        mock.assert_async().await;
    }
}
