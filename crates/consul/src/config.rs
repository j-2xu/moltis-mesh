//! Configuration for the Consul client.

use std::path::PathBuf;

use moltis_mesh::MeshMode;
use secrecy::Secret;

/// Consul client configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsulConfig {
    /// Consul agent address (e.g. `http://127.0.0.1:8500`).
    #[serde(default = "default_address")]
    pub address: String,

    /// Consul ACL token for API access.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_redacted"
    )]
    pub token: Option<Secret<String>>,

    /// Consul datacenter.
    #[serde(default)]
    pub datacenter: Option<String>,

    /// Service name to register as (default: `"moltis-gateway"`).
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// How often to report health status (seconds). Default: 10.
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval: u64,

    /// mTLS mesh mode: `none`, `native`, or `proxy`.
    #[serde(default)]
    pub mesh_mode: MeshMode,

    /// Path to CA cert for verifying Consul's TLS cert.
    pub tls_ca_cert: Option<PathBuf>,

    /// Path to client certificate for mTLS authentication to Consul.
    pub tls_client_cert: Option<PathBuf>,

    /// Path to client private key for mTLS authentication to Consul.
    pub tls_client_key: Option<PathBuf>,

    /// How long to cache intention results (seconds). Default: 30.
    #[serde(default = "default_intention_cache_ttl")]
    pub intention_cache_ttl: u64,
}

fn default_address() -> String {
    "http://127.0.0.1:8500".into()
}

fn default_service_name() -> String {
    "moltis-gateway".into()
}

fn default_health_check_interval() -> u64 {
    10
}

fn default_intention_cache_ttl() -> u64 {
    30
}

fn serialize_opt_redacted<S: serde::Serializer>(
    secret: &Option<Secret<String>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match secret {
        Some(_) => serializer.serialize_str("[REDACTED]"),
        None => serializer.serialize_none(),
    }
}

impl Default for ConsulConfig {
    fn default() -> Self {
        Self {
            address: default_address(),
            token: None,
            datacenter: None,
            service_name: default_service_name(),
            health_check_interval: default_health_check_interval(),
            mesh_mode: MeshMode::default(),
            tls_ca_cert: None,
            tls_client_cert: None,
            tls_client_key: None,
            intention_cache_ttl: default_intention_cache_ttl(),
        }
    }
}

impl ConsulConfig {
    /// Construct from a `ConsulSection` parsed from `moltis.toml`.
    pub fn try_from_config_section(
        section: &moltis_config::schema::ConsulSection,
    ) -> anyhow::Result<Self> {
        let mesh_mode = match section.mesh_mode.as_deref() {
            Some("native") => MeshMode::Native,
            Some("proxy") => MeshMode::Proxy,
            Some("none") | None => MeshMode::None,
            Some(other) => anyhow::bail!("unsupported consul.mesh_mode: {other}"),
        };

        Ok(Self {
            address: section.address.clone().unwrap_or_else(default_address),
            token: section.token.as_ref().map(|t| Secret::new(t.clone())),
            datacenter: section.datacenter.clone(),
            service_name: section
                .service_name
                .clone()
                .unwrap_or_else(default_service_name),
            health_check_interval: section
                .health_check_interval
                .unwrap_or_else(default_health_check_interval),
            mesh_mode,
            tls_ca_cert: section.tls_ca_cert.as_ref().map(PathBuf::from),
            tls_client_cert: section.tls_client_cert.as_ref().map(PathBuf::from),
            tls_client_key: section.tls_client_key.as_ref().map(PathBuf::from),
            intention_cache_ttl: section
                .intention_cache_ttl
                .unwrap_or_else(default_intention_cache_ttl),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = ConsulConfig::default();
        assert_eq!(config.address, "http://127.0.0.1:8500");
        assert_eq!(config.service_name, "moltis-gateway");
        assert_eq!(config.mesh_mode, MeshMode::None);
    }

    #[test]
    fn serde_roundtrip() {
        let json = r#"{"address":"http://consul:8500","service_name":"my-svc","mesh_mode":"native"}"#;
        let config: ConsulConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.address, "http://consul:8500");
        assert_eq!(config.mesh_mode, MeshMode::Native);
    }
}
