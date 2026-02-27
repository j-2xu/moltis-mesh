//! Mesh-agnostic abstractions for service mesh integration.
//!
//! This crate defines traits for secret management, mutual TLS, service
//! registration, and workload identity. Concrete implementations live in
//! dedicated crates (`moltis-hc-vault`, `moltis-consul`, `moltis-nomad`).
//!
//! # Feature flags
//!
//! | Flag | Effect |
//! |------|--------|
//! | `tracing` | Enables `tracing::instrument` on key methods |
//! | `metrics` | Enables metric recording |

pub mod error;
pub mod identity;
pub mod mode;
pub mod mtls;
pub mod registry;
pub mod secrets;

pub use error::{MeshError, Result};
pub use identity::WorkloadIdentity;
pub use mode::MeshMode;
pub use mtls::MtlsCertManager;
pub use registry::{HealthStatus, ServiceInstance, ServiceRegistration, ServiceRegistry};
pub use secrets::{SecretBackend, SecretBackendStatus};
