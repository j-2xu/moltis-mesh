//! Mesh mode configuration.
//!
//! [`MeshMode`] determines how the gateway integrates with the service mesh
//! for mutual TLS. This allows the same binary to work in standalone, native
//! mTLS, or sidecar-proxy deployments.

/// How the gateway participates in the service mesh for mTLS.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MeshMode {
    /// No service mesh. Uses self-signed certs from `FsCertManager` (current
    /// standalone behaviour). This is the default.
    #[default]
    None,

    /// Native mTLS — the gateway fetches SPIFFE x509-SVIDs from the mesh CA
    /// and terminates TLS itself. Requires an `MtlsCertManager` implementation.
    Native,

    /// Sidecar proxy mode — a mesh proxy (Envoy, Consul Connect proxy) handles
    /// mTLS on behalf of the gateway. The gateway serves plaintext on localhost
    /// but still registers with the `ServiceRegistry` for health checks and
    /// service discovery.
    Proxy,
}

impl MeshMode {
    /// Whether the gateway should set up its own TLS termination.
    #[must_use]
    pub fn needs_tls(&self) -> bool {
        matches!(self, Self::Native)
    }

    /// Whether the gateway should register with a service registry.
    #[must_use]
    pub fn needs_registry(&self) -> bool {
        matches!(self, Self::Native | Self::Proxy)
    }

    /// Whether the gateway should skip TLS entirely (proxy handles it).
    #[must_use]
    pub fn is_proxy(&self) -> bool {
        matches!(self, Self::Proxy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_none() {
        assert_eq!(MeshMode::default(), MeshMode::None);
    }

    #[test]
    fn native_needs_tls() {
        assert!(MeshMode::Native.needs_tls());
        assert!(!MeshMode::None.needs_tls());
        assert!(!MeshMode::Proxy.needs_tls());
    }

    #[test]
    fn registry_needed() {
        assert!(MeshMode::Native.needs_registry());
        assert!(MeshMode::Proxy.needs_registry());
        assert!(!MeshMode::None.needs_registry());
    }

    #[test]
    fn serde_roundtrip() {
        let mode = MeshMode::Native;
        let json = serde_json::to_string(&mode).ok();
        assert_eq!(json.as_deref(), Some("\"native\""));

        let deserialized: MeshMode = serde_json::from_str("\"proxy\"").unwrap_or_default();
        assert_eq!(deserialized, MeshMode::Proxy);
    }
}
