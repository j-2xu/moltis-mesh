//! Configuration for the Nomad client.

use std::path::PathBuf;

use secrecy::Secret;

/// Nomad client configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NomadConfig {
    /// Nomad server address (e.g. `http://127.0.0.1:4646`).
    #[serde(default = "default_address")]
    pub address: String,

    /// Nomad ACL token.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_redacted"
    )]
    pub token: Option<Secret<String>>,

    /// Nomad namespace (Enterprise feature).
    #[serde(default)]
    pub namespace: Option<String>,

    /// Nomad region.
    #[serde(default)]
    pub region: Option<String>,

    /// Nomad datacenter for job placement.
    #[serde(default)]
    pub datacenter: Option<String>,

    /// Task driver: `"docker"` or `"podman"`. Default: `"docker"`.
    #[serde(default = "default_task_driver")]
    pub task_driver: String,

    /// Container registry URL for pulling sandbox images.
    #[serde(default)]
    pub registry: Option<String>,

    /// Prefix for Nomad job IDs. Default: `"moltis-sandbox"`.
    #[serde(default = "default_job_prefix")]
    pub job_prefix: String,

    /// Path to CA cert for verifying Nomad's TLS cert.
    pub tls_ca_cert: Option<PathBuf>,
}

fn default_address() -> String {
    "http://127.0.0.1:4646".into()
}

fn default_task_driver() -> String {
    "docker".into()
}

fn default_job_prefix() -> String {
    "moltis-sandbox".into()
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

impl Default for NomadConfig {
    fn default() -> Self {
        Self {
            address: default_address(),
            token: None,
            namespace: None,
            region: None,
            datacenter: None,
            task_driver: default_task_driver(),
            registry: None,
            job_prefix: default_job_prefix(),
            tls_ca_cert: None,
        }
    }
}

impl NomadConfig {
    /// Build a Nomad config with the given job prefix.
    ///
    /// Use this when constructing from sandbox config fields. If `prefix`
    /// is `None`, the default prefix `"moltis-sandbox"` is used.
    #[must_use]
    pub fn with_job_prefix(prefix: Option<&str>) -> Self {
        Self {
            job_prefix: prefix.map_or_else(default_job_prefix, Into::into),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = NomadConfig::default();
        assert_eq!(config.address, "http://127.0.0.1:4646");
        assert_eq!(config.task_driver, "docker");
        assert_eq!(config.job_prefix, "moltis-sandbox");
    }

    #[test]
    fn serde_roundtrip() {
        let json = r#"{"address":"http://nomad:4646","task_driver":"podman","job_prefix":"test-sandbox"}"#;
        let config: NomadConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.task_driver, "podman");
        assert_eq!(config.job_prefix, "test-sandbox");
    }
}
