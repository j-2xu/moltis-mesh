//! Configuration for the HashiCorp Vault client.

use std::path::PathBuf;

use secrecy::Secret;

/// Authentication method for HC Vault.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum HcVaultAuth {
    /// Static token (e.g. root token for dev, wrapped token for prod).
    Token {
        #[serde(serialize_with = "crate::config::serialize_redacted")]
        token: Secret<String>,
    },
    /// AppRole authentication.
    AppRole {
        role_id: String,
        #[serde(serialize_with = "crate::config::serialize_redacted")]
        secret_id: Secret<String>,
        /// Mount path for the AppRole auth method (default: `"approle"`).
        #[serde(default = "default_approle_mount")]
        mount: String,
    },
    /// Kubernetes service account token authentication.
    Kubernetes {
        role: String,
        /// Path to the service account token file.
        /// Default: `/var/run/secrets/kubernetes.io/serviceaccount/token`.
        #[serde(default = "default_k8s_token_path")]
        token_path: PathBuf,
        /// Mount path for the Kubernetes auth method (default: `"kubernetes"`).
        #[serde(default = "default_k8s_mount")]
        mount: String,
    },
}

fn default_approle_mount() -> String {
    "approle".into()
}

fn default_k8s_token_path() -> PathBuf {
    PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token")
}

fn default_k8s_mount() -> String {
    "kubernetes".into()
}

fn serialize_redacted<S: serde::Serializer>(
    _secret: &Secret<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str("[REDACTED]")
}

/// HC Vault client configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HcVaultConfig {
    /// Vault server address (e.g. `https://vault.example.com:8200`).
    pub address: String,

    /// Authentication configuration.
    pub auth: HcVaultAuth,

    /// KV v2 mount path (default: `"secret"`).
    #[serde(default = "default_mount_path")]
    pub mount_path: String,

    /// Path prefix for all secrets (default: `"moltis"`).
    /// Secrets are stored at `<mount_path>/data/<path_prefix>/<path>`.
    #[serde(default = "default_path_prefix")]
    pub path_prefix: String,

    /// Transit engine mount path for envelope encryption (optional).
    /// When set, bulk data is encrypted via Transit before storage.
    pub transit_mount: Option<String>,

    /// Vault namespace (Enterprise feature). Optional.
    pub namespace: Option<String>,

    /// Path to a CA certificate for verifying the Vault server's TLS cert.
    pub tls_ca_cert: Option<PathBuf>,
}

fn default_mount_path() -> String {
    "secret".into()
}

fn default_path_prefix() -> String {
    "moltis".into()
}

impl HcVaultConfig {
    /// Build the full KV v2 data URL for a logical path.
    ///
    /// Example: `https://vault:8200/v1/secret/data/moltis/provider/openai/api_key`
    #[must_use]
    pub fn kv_data_url(&self, path: &str) -> String {
        format!(
            "{}/v1/{}/data/{}/{}",
            self.address.trim_end_matches('/'),
            self.mount_path,
            self.path_prefix,
            path.trim_start_matches('/')
        )
    }

    /// Build the full KV v2 metadata URL for listing.
    #[must_use]
    pub fn kv_metadata_url(&self, prefix: &str) -> String {
        format!(
            "{}/v1/{}/metadata/{}/{}",
            self.address.trim_end_matches('/'),
            self.mount_path,
            self.path_prefix,
            prefix.trim_start_matches('/').trim_end_matches('/')
        )
    }

    /// Build the Transit encrypt URL.
    #[must_use]
    pub fn transit_encrypt_url(&self, key_name: &str) -> Option<String> {
        self.transit_mount.as_ref().map(|mount| {
            format!(
                "{}/v1/{}/encrypt/{}",
                self.address.trim_end_matches('/'),
                mount,
                key_name
            )
        })
    }

    /// Build the Transit decrypt URL.
    #[must_use]
    pub fn transit_decrypt_url(&self, key_name: &str) -> Option<String> {
        self.transit_mount.as_ref().map(|mount| {
            format!(
                "{}/v1/{}/decrypt/{}",
                self.address.trim_end_matches('/'),
                mount,
                key_name
            )
        })
    }

    /// Construct from a `HcVaultSection` parsed from `moltis.toml`.
    ///
    /// Validates that required fields are present and returns a concrete config.
    pub fn try_from_config_section(
        section: &moltis_config::schema::HcVaultSection,
    ) -> anyhow::Result<Self> {
        let address = section
            .address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("hc_vault.address is required"))?
            .clone();

        let auth_method = section.auth_method.as_deref().unwrap_or("token");
        let auth = match auth_method {
            "token" => {
                let token = section
                    .token
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("hc_vault.token is required for token auth"))?;
                HcVaultAuth::Token {
                    token: Secret::new(token.clone()),
                }
            },
            "approle" => {
                let role_id = section
                    .role_id
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("hc_vault.role_id is required for approle auth"))?
                    .clone();
                let secret_id = section
                    .secret_id
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow::anyhow!("hc_vault.secret_id is required for approle auth")
                    })?;
                HcVaultAuth::AppRole {
                    role_id,
                    secret_id: Secret::new(secret_id.clone()),
                    mount: default_approle_mount(),
                }
            },
            "kubernetes" => {
                let role = section
                    .role
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow::anyhow!("hc_vault.role is required for kubernetes auth")
                    })?
                    .clone();
                HcVaultAuth::Kubernetes {
                    role,
                    token_path: default_k8s_token_path(),
                    mount: default_k8s_mount(),
                }
            },
            other => {
                anyhow::bail!("unsupported hc_vault.auth_method: {other}");
            },
        };

        Ok(Self {
            address,
            auth,
            mount_path: section
                .mount_path
                .clone()
                .unwrap_or_else(default_mount_path),
            path_prefix: section
                .path_prefix
                .clone()
                .unwrap_or_else(default_path_prefix),
            transit_mount: section.transit_mount.clone(),
            namespace: section.namespace.clone(),
            tls_ca_cert: section.tls_ca_cert.as_ref().map(PathBuf::from),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_data_url_construction() {
        let config = HcVaultConfig {
            address: "https://vault.example.com:8200".into(),
            auth: HcVaultAuth::Token {
                token: Secret::new("test".into()),
            },
            mount_path: "secret".into(),
            path_prefix: "moltis".into(),
            transit_mount: None,
            namespace: None,
            tls_ca_cert: None,
        };

        assert_eq!(
            config.kv_data_url("provider/openai/api_key"),
            "https://vault.example.com:8200/v1/secret/data/moltis/provider/openai/api_key"
        );
    }

    #[test]
    fn kv_metadata_url_construction() {
        let config = HcVaultConfig {
            address: "https://vault:8200/".into(),
            auth: HcVaultAuth::Token {
                token: Secret::new("test".into()),
            },
            mount_path: "secret".into(),
            path_prefix: "moltis".into(),
            transit_mount: None,
            namespace: None,
            tls_ca_cert: None,
        };

        assert_eq!(
            config.kv_metadata_url("provider/"),
            "https://vault:8200/v1/secret/metadata/moltis/provider"
        );
    }

    #[test]
    fn transit_urls() {
        let config = HcVaultConfig {
            address: "https://vault:8200".into(),
            auth: HcVaultAuth::Token {
                token: Secret::new("test".into()),
            },
            mount_path: "secret".into(),
            path_prefix: "moltis".into(),
            transit_mount: Some("transit".into()),
            namespace: None,
            tls_ca_cert: None,
        };

        assert_eq!(
            config.transit_encrypt_url("moltis-key").as_deref(),
            Some("https://vault:8200/v1/transit/encrypt/moltis-key")
        );
    }
}
