//! Nomad HTTP API client.
//!
//! Covers job submission, allocation status, alloc exec, and log streaming.

use secrecy::ExposeSecret;

use crate::{
    config::NomadConfig,
    error::{NomadError, Result},
};

/// Job submission response.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct JobRegisterResponse {
    #[serde(rename = "EvalID")]
    pub eval_id: String,
}

/// Job status response.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Job {
    #[serde(rename = "ID")]
    pub id: String,
    pub status: String,
}

/// Evaluation response.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Evaluation {
    #[serde(rename = "ID")]
    pub id: String,
    pub status: String,
    pub blocked_eval: Option<String>,
}

/// Allocation summary.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Allocation {
    #[serde(rename = "ID")]
    pub id: String,
    pub eval_id: String,
    pub job_id: String,
    pub client_status: String,
    pub desired_status: String,
    pub task_states: Option<std::collections::HashMap<String, TaskState>>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TaskState {
    pub state: String,
    pub failed: bool,
    pub restarts: u64,
    pub events: Option<Vec<TaskEvent>>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TaskEvent {
    #[serde(rename = "Type")]
    pub event_type: String,
    pub display_message: Option<String>,
}

/// Exec response frame (WebSocket or HTTP streaming).
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecFrame {
    pub stdout: Option<ExecData>,
    pub stderr: Option<ExecData>,
    pub exited: Option<bool>,
    pub result: Option<ExecResult>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecData {
    pub data: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecResult {
    pub exit_code: i32,
}

/// HTTP client for the Nomad API.
pub struct NomadClient {
    config: NomadConfig,
    http: reqwest::Client,
}

impl std::fmt::Debug for NomadClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NomadClient")
            .field("address", &self.config.address)
            .field("job_prefix", &self.config.job_prefix)
            .finish()
    }
}

impl NomadClient {
    /// Create a new Nomad client.
    pub fn new(config: NomadConfig) -> Result<Self> {
        let mut builder = reqwest::Client::builder();

        if let Some(ref ca_path) = config.tls_ca_cert {
            let ca_bytes = std::fs::read(ca_path).map_err(|e| {
                NomadError::Config(format!("failed to read TLS CA cert: {e}"))
            })?;
            let ca_cert = reqwest::Certificate::from_pem(&ca_bytes)
                .map_err(|e| NomadError::Config(format!("invalid TLS CA cert: {e}")))?;
            builder = builder.add_root_certificate(ca_cert);
        }

        let http = builder
            .build()
            .map_err(|e| NomadError::Config(format!("failed to build HTTP client: {e}")))?;

        Ok(Self { config, http })
    }

    /// Build a request with optional auth token and namespace.
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!(
            "{}/v1/{}",
            self.config.address.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut req = self.http.request(method, &url);

        if let Some(ref token) = self.config.token {
            req = req.header("X-Nomad-Token", token.expose_secret());
        }
        if let Some(ref ns) = self.config.namespace {
            req = req.query(&[("namespace", ns)]);
        }
        if let Some(ref region) = self.config.region {
            req = req.query(&[("region", region)]);
        }

        req
    }

    async fn check_response(&self, resp: reqwest::Response) -> Result<reqwest::Response> {
        let status = resp.status().as_u16();
        match status {
            200..=299 => Ok(resp),
            403 => {
                let body = resp.text().await.unwrap_or_default();
                Err(NomadError::AuthFailed(body))
            },
            _ => {
                let body = resp.text().await.unwrap_or_default();
                Err(NomadError::Http {
                    status,
                    message: body,
                })
            },
        }
    }

    // ── Jobs ───────────────────────────────────────────────────────────

    /// Submit (register) a job.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, job_spec)))]
    pub async fn register_job(&self, job_spec: &serde_json::Value) -> Result<JobRegisterResponse> {
        let body = serde_json::json!({ "Job": job_spec });
        let resp = self
            .request(reqwest::Method::POST, "jobs")
            .json(&body)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    /// Get job status.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn get_job(&self, job_id: &str) -> Result<Job> {
        let path = format!("job/{job_id}");
        let resp = self
            .request(reqwest::Method::GET, &path)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    /// Stop a job. If `purge` is true, removes it from Nomad entirely.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn stop_job(&self, job_id: &str, purge: bool) -> Result<()> {
        let mut path = format!("job/{job_id}");
        if purge {
            path.push_str("?purge=true");
        }
        let resp = self
            .request(reqwest::Method::DELETE, &path)
            .send()
            .await?;
        // 404 means job doesn't exist — treat as success.
        if resp.status().as_u16() == 404 {
            return Ok(());
        }
        self.check_response(resp).await?;
        Ok(())
    }

    // ── Evaluations ────────────────────────────────────────────────────

    /// Get an evaluation by ID.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn get_evaluation(&self, eval_id: &str) -> Result<Evaluation> {
        let path = format!("evaluation/{eval_id}");
        let resp = self
            .request(reqwest::Method::GET, &path)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    // ── Allocations ────────────────────────────────────────────────────

    /// List allocations for a job.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn job_allocations(&self, job_id: &str) -> Result<Vec<Allocation>> {
        let path = format!("job/{job_id}/allocations");
        let resp = self
            .request(reqwest::Method::GET, &path)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    /// Execute a command in an allocation.
    ///
    /// Uses the HTTP API exec endpoint. For simple commands,
    /// this posts to `/v1/client/allocation/{alloc_id}/exec` with a
    /// command array.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn alloc_exec(
        &self,
        alloc_id: &str,
        task: &str,
        command: &[&str],
        tty: bool,
    ) -> Result<(String, String, i32)> {
        let path = format!("client/allocation/{alloc_id}/exec");
        let body = serde_json::json!({
            "command": command,
            "task": task,
            "tty": tty,
        });

        let resp = self
            .request(reqwest::Method::POST, &path)
            .json(&body)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;

        // Parse the streaming response. Each line is a JSON frame.
        let body_text = resp.text().await?;
        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut exit_code = -1i32;

        for line in body_text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(frame) = serde_json::from_str::<ExecFrame>(line) {
                if let Some(ref data) = frame.stdout {
                    if let Some(ref b64) = data.data {
                        if let Ok(bytes) = base64::Engine::decode(
                            &base64::engine::general_purpose::STANDARD,
                            b64,
                        ) {
                            stdout.push_str(&String::from_utf8_lossy(&bytes));
                        }
                    }
                }
                if let Some(ref data) = frame.stderr {
                    if let Some(ref b64) = data.data {
                        if let Ok(bytes) = base64::Engine::decode(
                            &base64::engine::general_purpose::STANDARD,
                            b64,
                        ) {
                            stderr.push_str(&String::from_utf8_lossy(&bytes));
                        }
                    }
                }
                if let Some(ref result) = frame.result {
                    exit_code = result.exit_code;
                }
            }
        }

        Ok((stdout, stderr, exit_code))
    }

    /// Fetch allocation logs (stdout or stderr).
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn alloc_logs(
        &self,
        alloc_id: &str,
        task: &str,
        log_type: &str,
    ) -> Result<String> {
        let path = format!(
            "client/fs/logs/{alloc_id}?task={task}&type={log_type}&plain=true"
        );
        let resp = self
            .request(reqwest::Method::GET, &path)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.text().await?)
    }

    // ── Utility ────────────────────────────────────────────────────────

    /// List all jobs matching a prefix.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn list_jobs(&self, prefix: &str) -> Result<Vec<Job>> {
        let path = format!("jobs?prefix={prefix}");
        let resp = self
            .request(reqwest::Method::GET, &path)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;

    fn test_config(address: &str) -> NomadConfig {
        NomadConfig {
            address: address.into(),
            token: Some(Secret::new("test-token".into())),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn register_job_ok() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v1/jobs")
            .with_status(200)
            .with_body(r#"{"EvalID":"eval-123"}"#)
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = NomadClient::new(config).unwrap();
        let job_spec = serde_json::json!({"ID": "test-job"});
        let result = client.register_job(&job_spec).await.unwrap();

        assert_eq!(result.eval_id, "eval-123");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn stop_job_ok_on_404() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("DELETE", "/v1/job/nonexistent?purge=true")
            .with_status(404)
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = NomadClient::new(config).unwrap();
        let result = client.stop_job("nonexistent", true).await;

        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_jobs_with_prefix() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/jobs?prefix=moltis-sandbox")
            .with_status(200)
            .with_body(r#"[{"ID":"moltis-sandbox-abc","Status":"running"}]"#)
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = NomadClient::new(config).unwrap();
        let jobs = client.list_jobs("moltis-sandbox").await.unwrap();

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, "moltis-sandbox-abc");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn auth_failed_on_403() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/jobs?prefix=test")
            .with_status(403)
            .with_body("ACL token not found")
            .create_async()
            .await;

        let config = test_config(&server.url());
        let client = NomadClient::new(config).unwrap();
        let result = client.list_jobs("test").await;

        assert!(matches!(result, Err(NomadError::AuthFailed(_))));
        mock.assert_async().await;
    }
}
