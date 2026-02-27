//! Error types for the HashiCorp Vault client.

/// Errors from HC Vault operations.
#[derive(Debug, thiserror::Error)]
pub enum HcVaultError {
    /// Vault returned an HTTP error.
    #[error("vault HTTP {status}: {message}")]
    Http { status: u16, message: String },

    /// Authentication failed (403).
    #[error("vault authentication failed: {0}")]
    AuthFailed(String),

    /// Vault is sealed (503).
    #[error("vault is sealed")]
    Sealed,

    /// Token has expired and renewal failed.
    #[error("token expired: {0}")]
    TokenExpired(String),

    /// Network or transport error.
    #[error("vault transport: {0}")]
    Transport(#[from] reqwest::Error),

    /// JSON parsing error.
    #[error("vault json: {0}")]
    Json(#[from] serde_json::Error),

    /// Configuration error.
    #[error("vault config: {0}")]
    Config(String),

    /// Generic internal error.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<HcVaultError> for moltis_mesh::MeshError {
    fn from(e: HcVaultError) -> Self {
        match e {
            HcVaultError::AuthFailed(msg) => Self::Auth(msg),
            HcVaultError::Sealed => Self::BackendUnavailable {
                reason: "vault is sealed".into(),
            },
            HcVaultError::TokenExpired(msg) => Self::Auth(msg),
            HcVaultError::Config(msg) => Self::Config(msg),
            HcVaultError::Transport(e) => Self::Transport(e.to_string()),
            other => Self::Internal(anyhow::anyhow!("{other}")),
        }
    }
}

pub type Result<T> = std::result::Result<T, HcVaultError>;
