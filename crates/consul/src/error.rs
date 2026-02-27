//! Error types for the Consul client.

/// Errors from Consul operations.
#[derive(Debug, thiserror::Error)]
pub enum ConsulError {
    /// Consul returned an HTTP error.
    #[error("consul HTTP {status}: {message}")]
    Http { status: u16, message: String },

    /// Authentication failed.
    #[error("consul auth failed: {0}")]
    AuthFailed(String),

    /// Certificate error (Connect CA, leaf cert parsing).
    #[error("consul cert error: {0}")]
    Certificate(String),

    /// Intention check failed (authorization denied or Consul unreachable).
    #[error("intention denied: {0}")]
    IntentionDenied(String),

    /// Service registration failed.
    #[error("registration failed: {0}")]
    Registration(String),

    /// Network or transport error.
    #[error("consul transport: {0}")]
    Transport(#[from] reqwest::Error),

    /// JSON parsing error.
    #[error("consul json: {0}")]
    Json(#[from] serde_json::Error),

    /// Configuration error.
    #[error("consul config: {0}")]
    Config(String),

    /// TLS/rustls error.
    #[error("tls error: {0}")]
    Tls(String),

    /// Generic internal error.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<ConsulError> for moltis_mesh::MeshError {
    fn from(e: ConsulError) -> Self {
        match e {
            ConsulError::AuthFailed(msg) => Self::Auth(msg),
            ConsulError::Certificate(msg) => Self::Tls(msg),
            ConsulError::IntentionDenied(msg) => Self::IntentionDenied { reason: msg },
            ConsulError::Registration(msg) => Self::Registration(msg),
            ConsulError::Config(msg) => Self::Config(msg),
            ConsulError::Tls(msg) => Self::Tls(msg),
            ConsulError::Transport(e) => Self::Transport(e.to_string()),
            other => Self::Internal(anyhow::anyhow!("{other}")),
        }
    }
}

pub type Result<T> = std::result::Result<T, ConsulError>;
