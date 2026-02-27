//! Service registry abstraction.
//!
//! Defines [`ServiceRegistry`] — a trait for registering services with a
//! service mesh (Consul, Kubernetes, etc.) and discovering peer services.
//!
//! # Lifecycle
//!
//! 1. Call [`ServiceRegistry::register`] after the gateway binds its listener.
//! 2. Periodically call [`ServiceRegistry::report_health`] (or rely on the
//!    registry's built-in health checks).
//! 3. Call [`ServiceRegistry::deregister`] during graceful shutdown.

use async_trait::async_trait;

use crate::error::Result;

/// Health status for reporting to the service registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Service is healthy and ready to accept traffic.
    Passing,
    /// Service is degraded but still operational.
    Warning,
    /// Service is unhealthy and should not receive traffic.
    Critical,
}

/// Information needed to register a service instance.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceRegistration {
    /// Unique service name (e.g. `"moltis-gateway"`).
    pub name: String,
    /// Instance ID (unique across instances of the same service).
    pub id: String,
    /// Address this instance is reachable at.
    pub address: String,
    /// Port this instance listens on.
    pub port: u16,
    /// Key-value tags for routing/filtering.
    pub tags: Vec<String>,
    /// Metadata key-value pairs.
    pub meta: std::collections::HashMap<String, String>,
}

/// A discovered service instance.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceInstance {
    /// Instance ID.
    pub id: String,
    /// Service name.
    pub service: String,
    /// Reachable address.
    pub address: String,
    /// Reachable port.
    pub port: u16,
    /// Current health status.
    pub status: HealthStatus,
    /// Tags from registration.
    pub tags: Vec<String>,
    /// Metadata from registration.
    pub meta: std::collections::HashMap<String, String>,
}

/// Trait for service registration and discovery.
///
/// Implementations handle the specifics of each service mesh (Consul catalog,
/// Kubernetes service, etc.).
#[async_trait]
pub trait ServiceRegistry: Send + Sync {
    /// Register this service instance with the registry.
    ///
    /// Should be called once after the gateway listener is bound. Subsequent
    /// calls update the registration (idempotent).
    async fn register(&self, reg: ServiceRegistration) -> Result<()>;

    /// Deregister this service instance.
    ///
    /// Called during graceful shutdown. No-op if not registered.
    async fn deregister(&self) -> Result<()>;

    /// Discover healthy instances of a named service.
    ///
    /// Returns only instances with `HealthStatus::Passing` by default.
    async fn discover(&self, service_name: &str) -> Result<Vec<ServiceInstance>>;

    /// Report the current health status.
    ///
    /// For TTL-based health checks, this updates the check status.
    /// For HTTP-based checks, the registry polls `/health` directly and
    /// this method is a no-op.
    async fn report_health(&self, status: HealthStatus) -> Result<()>;
}
