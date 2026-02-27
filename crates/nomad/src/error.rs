//! Error types for the Nomad client.

/// Errors from Nomad operations.
#[derive(Debug, thiserror::Error)]
pub enum NomadError {
    /// Nomad returned an HTTP error.
    #[error("nomad HTTP {status}: {message}")]
    Http { status: u16, message: String },

    /// Authentication failed (403).
    #[error("nomad auth failed: {0}")]
    AuthFailed(String),

    /// Job submission failed.
    #[error("job submission failed: {0}")]
    JobFailed(String),

    /// Allocation scheduling failed.
    #[error("allocation failed: {reason}")]
    AllocationFailed { reason: String },

    /// Allocation exec failed.
    #[error("exec failed: {0}")]
    ExecFailed(String),

    /// Timeout waiting for allocation.
    #[error("allocation timeout: waited {seconds}s for {job_id}")]
    AllocationTimeout { job_id: String, seconds: u64 },

    /// Network or transport error.
    #[error("nomad transport: {0}")]
    Transport(#[from] reqwest::Error),

    /// JSON parsing error.
    #[error("nomad json: {0}")]
    Json(#[from] serde_json::Error),

    /// Configuration error.
    #[error("nomad config: {0}")]
    Config(String),

    /// Generic internal error.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, NomadError>;
