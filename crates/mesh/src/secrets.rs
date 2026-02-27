//! Secret backend abstraction.
//!
//! Defines [`SecretBackend`] — a trait for storing and retrieving secrets
//! from any backend (local encrypted vault, HashiCorp Vault, etc.).
//!
//! # Path conventions
//!
//! Secrets are addressed by slash-separated paths:
//! - `provider/<name>/api_key` — LLM provider API keys
//! - `env/<key>` — user-defined environment variables
//! - `oauth/<provider>/access_token` — OAuth tokens
//! - `oauth/<provider>/refresh_token` — OAuth refresh tokens
//!
//! Backends map these logical paths to their native storage (e.g. HC Vault
//! maps to `secret/data/moltis/<path>`).

use async_trait::async_trait;

use crate::error::Result;

/// Health/availability status of a secret backend.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretBackendStatus {
    /// Backend is available and ready.
    Available,
    /// Backend exists but is sealed / locked (e.g. local vault needs password).
    Sealed,
    /// Backend is unreachable or misconfigured.
    Unavailable { reason: String },
}

/// Trait for secret storage backends.
///
/// Implementations must be safe to share across tasks (`Send + Sync`).
/// All methods are async to support network-backed stores.
///
/// # Invariants
///
/// - `put_secret` followed by `get_secret` on the same path must return the
///   stored value (assuming no concurrent deletion).
/// - `delete_secret` on a nonexistent path is a no-op (not an error).
/// - `list_secrets` returns only direct children of the prefix, not nested
///   paths (like a single directory listing, not recursive).
/// - Implementations must wrap sensitive values with [`secrecy::Secret`]
///   internally and only expose plaintext at consumption boundaries.
#[async_trait]
pub trait SecretBackend: Send + Sync {
    /// Store a secret value at the given path.
    ///
    /// `metadata` is an optional human-readable label (e.g. provider name).
    /// Overwrites any existing value at the same path.
    async fn put_secret(&self, path: &str, value: &str, metadata: Option<&str>) -> Result<()>;

    /// Retrieve a secret value by path.
    ///
    /// Returns `None` if no secret exists at the path.
    async fn get_secret(&self, path: &str) -> Result<Option<String>>;

    /// Delete a secret at the given path.
    ///
    /// No-op if the path does not exist.
    async fn delete_secret(&self, path: &str) -> Result<()>;

    /// List secret paths under a prefix.
    ///
    /// Returns direct children only (not recursive). For example,
    /// listing `"provider/"` might return `["provider/openai", "provider/anthropic"]`.
    async fn list_secrets(&self, prefix: &str) -> Result<Vec<String>>;

    /// Check the health/availability of this backend.
    async fn status(&self) -> SecretBackendStatus;

    /// Human-readable name for this backend (e.g. `"local"`, `"hashicorp-vault"`).
    fn backend_name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the status enum serializes correctly.
    #[test]
    fn status_serializes() {
        let available = serde_json::to_string(&SecretBackendStatus::Available).ok();
        assert_eq!(available.as_deref(), Some("\"available\""));

        let sealed = serde_json::to_string(&SecretBackendStatus::Sealed).ok();
        assert_eq!(sealed.as_deref(), Some("\"sealed\""));

        let unavailable = serde_json::to_string(&SecretBackendStatus::Unavailable {
            reason: "connection refused".into(),
        })
        .ok();
        assert!(unavailable
            .as_deref()
            .is_some_and(|s| s.contains("connection refused")));
    }
}
