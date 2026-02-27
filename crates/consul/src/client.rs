//! Consul HTTP API client.
//!
//! Covers service registration, health, Connect CA leaf certs, and intentions.

use secrecy::ExposeSecret;

use crate::{
    config::ConsulConfig,
    error::{ConsulError, Result},
};

/// Response from `/v1/agent/connect/ca/leaf/:service`.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LeafCertResponse {
    /// PEM-encoded certificate chain (leaf + intermediates).
    pub certificate_pem: String,
    /// PEM-encoded private key.
    pub private_key_pem: String,
    /// SPIFFE service identity (e.g. `spiffe://dc1/ns/default/dc/dc1/svc/moltis-gateway`).
    pub service_u_r_i: String,
    /// When the cert becomes valid (RFC 3339).
    pub valid_after: String,
    /// When the cert expires (RFC 3339).
    pub valid_before: String,
}

/// Response from `/v1/agent/connect/ca/roots`.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CaRootsResponse {
    /// Trust domain for SPIFFE ID validation.
    pub trust_domain: String,
    pub roots: Vec<CaRoot>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CaRoot {
    pub root_cert_pem: String,
    pub active: bool,
}

/// Service registration payload.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AgentServiceRegistration {
    #[serde(rename = "ID")]
    pub id: String,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub tags: Vec<String>,
    pub meta: std::collections::HashMap<String, String>,
    pub check: Option<AgentServiceCheck>,
    pub connect: Option<AgentServiceConnect>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AgentServiceCheck {
    /// TTL-based check: e.g. `"15s"`.
    #[serde(rename = "TTL", skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// HTTP check URL.
    #[serde(rename = "HTTP", skip_serializing_if = "Option::is_none")]
    pub http: Option<String>,
    /// Check interval (e.g. `"10s"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// Deregister after this duration of critical state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deregister_critical_service_after: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AgentServiceConnect {
    pub native: bool,
}

/// Intention check result.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IntentionCheckResponse {
    pub allowed: bool,
}

/// HTTP client for the Consul API.
pub struct ConsulClient {
    config: ConsulConfig,
    http: reqwest::Client,
}

impl std::fmt::Debug for ConsulClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsulClient")
            .field("address", &self.config.address)
            .field("service_name", &self.config.service_name)
            .finish()
    }
}

impl ConsulClient {
    /// Create a new Consul client.
    pub fn new(config: ConsulConfig) -> Result<Self> {
        let mut builder = reqwest::Client::builder();

        if let Some(ref ca_path) = config.tls_ca_cert {
            let ca_bytes = std::fs::read(ca_path).map_err(|e| {
                ConsulError::Config(format!("failed to read TLS CA cert: {e}"))
            })?;
            let ca_cert = reqwest::Certificate::from_pem(&ca_bytes)
                .map_err(|e| ConsulError::Config(format!("invalid TLS CA cert: {e}")))?;
            builder = builder.add_root_certificate(ca_cert);
        }

        let http = builder
            .build()
            .map_err(|e| ConsulError::Config(format!("failed to build HTTP client: {e}")))?;

        Ok(Self { config, http })
    }

    /// Build a request with optional ACL token.
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!(
            "{}/v1/{}",
            self.config.address.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut req = self.http.request(method, &url);

        if let Some(ref token) = self.config.token {
            req = req.header("X-Consul-Token", token.expose_secret());
        }
        if let Some(ref dc) = self.config.datacenter {
            req = req.query(&[("dc", dc)]);
        }

        req
    }

    /// Map a Consul HTTP response to a result.
    async fn check_response(&self, resp: reqwest::Response) -> Result<reqwest::Response> {
        let status = resp.status().as_u16();
        match status {
            200..=299 => Ok(resp),
            403 => {
                let body = resp.text().await.unwrap_or_default();
                Err(ConsulError::AuthFailed(body))
            },
            _ => {
                let body = resp.text().await.unwrap_or_default();
                Err(ConsulError::Http {
                    status,
                    message: body,
                })
            },
        }
    }

    // ── Service registration ───────────────────────────────────────────

    /// Register a service with the local agent.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, reg)))]
    pub async fn register_service(&self, reg: &AgentServiceRegistration) -> Result<()> {
        let resp = self
            .request(reqwest::Method::PUT, "agent/service/register")
            .json(reg)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Deregister a service by ID.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn deregister_service(&self, service_id: &str) -> Result<()> {
        let path = format!("agent/service/deregister/{service_id}");
        let resp = self
            .request(reqwest::Method::PUT, &path)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Update TTL check status.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn update_ttl_check(
        &self,
        check_id: &str,
        status: &str,
        note: &str,
    ) -> Result<()> {
        let path = format!("agent/check/update/{check_id}");
        let body = serde_json::json!({
            "Status": status,
            "Output": note,
        });
        let resp = self
            .request(reqwest::Method::PUT, &path)
            .json(&body)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    // ── Connect CA ─────────────────────────────────────────────────────

    /// Fetch Connect CA root certificates.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn connect_ca_roots(&self) -> Result<CaRootsResponse> {
        let resp = self
            .request(reqwest::Method::GET, "agent/connect/ca/roots")
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    /// Fetch a Connect leaf certificate for this service.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn connect_ca_leaf(&self) -> Result<LeafCertResponse> {
        let path = format!("agent/connect/ca/leaf/{}", self.config.service_name);
        let resp = self
            .request(reqwest::Method::GET, &path)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    // ── Intentions ─────────────────────────────────────────────────────

    /// Check whether a source service is allowed to connect to a destination.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn intention_check(
        &self,
        source: &str,
        destination: &str,
    ) -> Result<bool> {
        let path = format!("connect/intentions/check?source={source}&destination={destination}");
        let resp = self
            .request(reqwest::Method::GET, &path)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        let check: IntentionCheckResponse = resp.json().await?;
        Ok(check.allowed)
    }

    // ── Health ──────────────────────────────────────────────────────────

    /// List healthy instances of a service.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn health_service(
        &self,
        service_name: &str,
        passing_only: bool,
    ) -> Result<Vec<HealthServiceEntry>> {
        let mut path = format!("health/service/{service_name}");
        if passing_only {
            path.push_str("?passing=true");
        }
        let resp = self
            .request(reqwest::Method::GET, &path)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }
}

/// Entry from the health service endpoint.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HealthServiceEntry {
    pub service: HealthService,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HealthService {
    #[serde(rename = "ID")]
    pub id: String,
    pub service: String,
    pub address: String,
    pub port: u16,
    pub tags: Vec<String>,
    pub meta: std::collections::HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;

    fn test_config(address: &str) -> ConsulConfig {
        ConsulConfig {
            address: address.into(),
            token: Some(Secret::new("test-token".into())),
            datacenter: None,
            service_name: "moltis-gateway".into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn register_service_ok() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PUT", "/v1/agent/service/register")
            .with_status(200)
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = ConsulClient::new(config).unwrap();
        let reg = AgentServiceRegistration {
            id: "moltis-1".into(),
            name: "moltis-gateway".into(),
            address: "10.0.0.1".into(),
            port: 3443,
            tags: vec!["moltis".into()],
            meta: Default::default(),
            check: None,
            connect: Some(AgentServiceConnect { native: true }),
        };

        client.register_service(&reg).await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn deregister_service_ok() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PUT", "/v1/agent/service/deregister/moltis-1")
            .with_status(200)
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = ConsulClient::new(config).unwrap();
        client.deregister_service("moltis-1").await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn connect_ca_leaf_ok() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/agent/connect/ca/leaf/moltis-gateway")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "CertificatePem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
                    "PrivateKeyPem": "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----",
                    "ServiceURI": "spiffe://dc1/ns/default/dc/dc1/svc/moltis-gateway",
                    "ValidAfter": "2025-01-01T00:00:00Z",
                    "ValidBefore": "2025-01-02T00:00:00Z"
                }"#,
            )
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = ConsulClient::new(config).unwrap();
        let leaf = client.connect_ca_leaf().await.unwrap();

        assert!(leaf.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(leaf.service_u_r_i.starts_with("spiffe://"));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn intention_check_allowed() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "GET",
                "/v1/connect/intentions/check?source=web&destination=moltis-gateway",
            )
            .with_status(200)
            .with_body(r#"{"Allowed": true}"#)
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = ConsulClient::new(config).unwrap();
        let allowed = client.intention_check("web", "moltis-gateway").await.unwrap();
        assert!(allowed);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn auth_failed_on_403() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/agent/connect/ca/roots")
            .with_status(403)
            .with_body("ACL not found")
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = ConsulClient::new(config).unwrap();
        let result = client.connect_ca_roots().await;
        assert!(matches!(result, Err(ConsulError::AuthFailed(_))));
        mock.assert_async().await;
    }
}
