//! Error types for the mesh abstraction layer.

/// Errors that can occur in mesh operations.
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    /// Secret not found at the given path.
    #[error("secret not found: {path}")]
    SecretNotFound { path: String },

    /// Secret backend is sealed or unavailable.
    #[error("secret backend unavailable: {reason}")]
    BackendUnavailable { reason: String },

    /// Authentication/authorization failure.
    #[error("auth error: {0}")]
    Auth(String),

    /// Network or transport error.
    #[error("transport error: {0}")]
    Transport(String),

    /// TLS/certificate error.
    #[error("tls error: {0}")]
    Tls(String),

    /// Service registration error.
    #[error("registration error: {0}")]
    Registration(String),

    /// Configuration error.
    #[error("config error: {0}")]
    Config(String),

    /// Intention/authorization policy denied.
    #[error("intention denied: {reason}")]
    IntentionDenied { reason: String },

    /// Generic internal error.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, MeshError>;
