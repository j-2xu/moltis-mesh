//! Consul service registration and discovery.
//!
//! Implements [`ServiceRegistry`] for Consul.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use moltis_mesh::{
    HealthStatus, ServiceInstance, ServiceRegistration, ServiceRegistry,
    error::Result as MeshResult,
};

use crate::client::{AgentServiceCheck, AgentServiceConnect, AgentServiceRegistration, ConsulClient};
use crate::config::ConsulConfig;

/// Consul implementation of [`ServiceRegistry`].
pub struct ConsulServiceRegistry {
    client: Arc<ConsulClient>,
    config: ConsulConfig,
    /// The service ID we registered under (set after register()).
    registered_id: RwLock<Option<String>>,
    /// TTL check ID (derived from service ID).
    check_id: RwLock<Option<String>>,
}

impl ConsulServiceRegistry {
    /// Create a new registry from config.
    pub fn new(client: Arc<ConsulClient>, config: ConsulConfig) -> Self {
        Self {
            client,
            config,
            registered_id: RwLock::new(None),
            check_id: RwLock::new(None),
        }
    }

    /// The service name this registry registers under.
    pub fn service_name(&self) -> &str {
        &self.config.service_name
    }

    /// Whether Connect native mode is enabled.
    fn connect_native(&self) -> bool {
        self.config.mesh_mode == moltis_mesh::MeshMode::Native
    }
}

#[async_trait]
impl ServiceRegistry for ConsulServiceRegistry {
    async fn register(&self, reg: ServiceRegistration) -> MeshResult<()> {
        let check_id = format!("service:{}", reg.id);

        let consul_reg = AgentServiceRegistration {
            id: reg.id.clone(),
            name: reg.name,
            address: reg.address,
            port: reg.port,
            tags: reg.tags,
            meta: reg.meta,
            check: Some(AgentServiceCheck {
                ttl: Some("15s".into()),
                http: None,
                interval: None,
                deregister_critical_service_after: Some("1m".into()),
            }),
            connect: if self.connect_native() {
                Some(AgentServiceConnect { native: true })
            } else {
                None
            },
        };

        self.client
            .register_service(&consul_reg)
            .await
            .map_err(moltis_mesh::MeshError::from)?;

        *self.registered_id.write().await = Some(reg.id);
        *self.check_id.write().await = Some(check_id);

        #[cfg(feature = "tracing")]
        tracing::info!("registered with consul");

        Ok(())
    }

    async fn deregister(&self) -> MeshResult<()> {
        let id = self.registered_id.read().await.clone();
        if let Some(id) = id {
            self.client
                .deregister_service(&id)
                .await
                .map_err(moltis_mesh::MeshError::from)?;
            *self.registered_id.write().await = None;
            *self.check_id.write().await = None;

            #[cfg(feature = "tracing")]
            tracing::info!("deregistered from consul");
        }
        Ok(())
    }

    async fn discover(&self, service_name: &str) -> MeshResult<Vec<ServiceInstance>> {
        let entries = self
            .client
            .health_service(service_name, true)
            .await
            .map_err(moltis_mesh::MeshError::from)?;

        Ok(entries
            .into_iter()
            .map(|e| ServiceInstance {
                id: e.service.id,
                service: e.service.service,
                address: e.service.address,
                port: e.service.port,
                status: HealthStatus::Passing,
                tags: e.service.tags,
                meta: e.service.meta,
            })
            .collect())
    }

    async fn report_health(&self, status: HealthStatus) -> MeshResult<()> {
        let check_id = self.check_id.read().await.clone();
        let Some(check_id) = check_id else {
            return Ok(());
        };

        let (consul_status, note) = match status {
            HealthStatus::Passing => ("passing", "moltis gateway healthy"),
            HealthStatus::Warning => ("warning", "moltis gateway degraded"),
            HealthStatus::Critical => ("critical", "moltis gateway unhealthy"),
        };

        self.client
            .update_ttl_check(&check_id, consul_status, note)
            .await
            .map_err(moltis_mesh::MeshError::from)?;

        Ok(())
    }
}
