//! Nomad orchestration for Moltis sandbox containers.
//!
//! Provides a Nomad HTTP client, job spec builder, and allocation lifecycle
//! management. The `Sandbox` trait adapter lives in `moltis-tools` (behind
//! the `nomad` feature) to avoid circular dependencies.
//!
//! # Feature flags
//!
//! | Flag | Effect |
//! |------|--------|
//! | `tracing` | Enables `tracing::instrument` on API methods |
//! | `metrics` | Enables metric recording |

pub mod alloc;
pub mod client;
pub mod config;
pub mod error;
pub mod job;
pub mod registry;

pub use client::NomadClient;
pub use config::NomadConfig;
pub use error::NomadError;
pub use job::SandboxJobOpts;
