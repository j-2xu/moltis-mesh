//! Nomad implementation of the [`Sandbox`] trait.
//!
//! Bridges `moltis-nomad` (HTTP client, job builder, allocation lifecycle)
//! with the `Sandbox` trait defined in this crate.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use moltis_nomad::{
    NomadClient, NomadConfig, SandboxJobOpts,
    alloc::wait_for_running,
    job::build_sandbox_job,
};

use crate::exec::{ExecOpts, ExecResult};
use crate::sandbox::{BuildImageResult, Sandbox, SandboxConfig, SandboxId};

/// Sandbox backend that schedules containers as Nomad batch jobs.
pub struct NomadSandbox {
    sandbox_config: SandboxConfig,
    nomad_config: NomadConfig,
    client: Arc<NomadClient>,
    /// Maps SandboxId keys → (job_id, alloc_id) for running sandboxes.
    running: RwLock<std::collections::HashMap<String, (String, String)>>,
}

impl NomadSandbox {
    /// Create a new Nomad sandbox backend.
    pub fn new(sandbox_config: SandboxConfig, nomad_config: NomadConfig) -> Self {
        let client = Arc::new(
            NomadClient::new(nomad_config.clone())
                .unwrap_or_else(|e| panic!("failed to create Nomad client: {e}")),
        );
        Self {
            sandbox_config,
            nomad_config,
            client,
            running: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Build a job ID from a sandbox ID.
    fn job_id(&self, id: &SandboxId) -> String {
        format!("{}-{}", self.nomad_config.job_prefix, id.key)
    }

    /// Resolve the container image to use.
    fn resolve_image(&self, image_override: Option<&str>) -> String {
        image_override
            .map(ToString::to_string)
            .or_else(|| self.sandbox_config.image.clone())
            .unwrap_or_else(|| "ubuntu:22.04".into())
    }

    /// Convert the local [`SandboxConfig`] to [`SandboxJobOpts`] for the job builder.
    fn job_opts(&self) -> SandboxJobOpts {
        SandboxJobOpts {
            no_network: self.sandbox_config.no_network,
            workspace_mount: self.sandbox_config.workspace_mount.to_string(),
            cpu_quota: self.sandbox_config.resource_limits.cpu_quota,
            memory_limit: self.sandbox_config.resource_limits.memory_limit.clone(),
        }
    }
}

#[async_trait]
impl Sandbox for NomadSandbox {
    fn backend_name(&self) -> &'static str {
        "nomad"
    }

    async fn ensure_ready(
        &self,
        id: &SandboxId,
        image_override: Option<&str>,
    ) -> anyhow::Result<()> {
        // Check if already running.
        if self.running.read().await.contains_key(&id.key) {
            return Ok(());
        }

        let job_id = self.job_id(id);
        let image = self.resolve_image(image_override);

        tracing::info!(
            job_id = %job_id,
            image = %image,
            "submitting nomad sandbox job"
        );

        // Build and submit the job.
        let opts = self.job_opts();
        let job_spec = build_sandbox_job(&job_id, &image, &opts, &self.nomad_config);
        let register_resp = self
            .client
            .register_job(&job_spec)
            .await
            .map_err(|e| anyhow::anyhow!("nomad job submission failed: {e}"))?;

        // Wait for the allocation to be running.
        let alloc = wait_for_running(&self.client, &job_id, &register_resp.eval_id)
            .await
            .map_err(|e| anyhow::anyhow!("nomad allocation failed: {e}"))?;

        // Track the running allocation.
        self.running
            .write()
            .await
            .insert(id.key.clone(), (job_id, alloc.id));

        tracing::info!(
            sandbox = %id.key,
            "nomad sandbox ready"
        );

        Ok(())
    }

    async fn exec(
        &self,
        id: &SandboxId,
        command: &str,
        opts: &ExecOpts,
    ) -> anyhow::Result<ExecResult> {
        let running = self.running.read().await;
        let (_job_id, alloc_id) = running.get(&id.key).ok_or_else(|| {
            anyhow::anyhow!("sandbox {} not running — call ensure_ready first", id.key)
        })?;

        // Build the command array: ["/bin/sh", "-c", command]
        let cmd = vec!["/bin/sh", "-c", command];

        // Execute with timeout.
        let exec_fut = self.client.alloc_exec(alloc_id, "sandbox", &cmd, false);
        let (stdout, stderr, exit_code) =
            match tokio::time::timeout(opts.timeout, exec_fut).await {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("nomad exec failed: {e}"));
                },
                Err(_) => {
                    return Ok(ExecResult {
                        stdout: String::new(),
                        stderr: format!("command timed out after {:?}", opts.timeout),
                        exit_code: 124, // Convention: 124 = timeout
                    });
                },
            };

        // Truncate output to max_output_bytes.
        let stdout = truncate_output(&stdout, opts.max_output_bytes);
        let stderr = truncate_output(&stderr, opts.max_output_bytes);

        Ok(ExecResult {
            stdout,
            stderr,
            exit_code,
        })
    }

    async fn cleanup(&self, id: &SandboxId) -> anyhow::Result<()> {
        let entry = self.running.write().await.remove(&id.key);
        if let Some((job_id, _alloc_id)) = entry {
            #[cfg(feature = "tracing")]
            tracing::info!(
                job_id = %job_id,
                "stopping nomad sandbox job"
            );
            self.client
                .stop_job(&job_id, true)
                .await
                .map_err(|e| anyhow::anyhow!("nomad job stop failed: {e}"))?;
        }
        Ok(())
    }

    fn is_real(&self) -> bool {
        true
    }

    async fn build_image(
        &self,
        _base: &str,
        _packages: &[String],
    ) -> anyhow::Result<Option<BuildImageResult>> {
        // Nomad cannot build images locally — they must be in a registry.
        tracing::info!(
            "nomad sandbox does not support local image builds; \
             images must be available in a container registry"
        );
        Ok(None)
    }
}

/// Truncate a string to at most `max_bytes` bytes (on a UTF-8 boundary).
fn truncate_output(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = s[..end].to_string();
    truncated.push_str("\n... (output truncated)");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_output_short() {
        assert_eq!(truncate_output("hello", 100), "hello");
    }

    #[test]
    fn truncate_output_long() {
        let long = "a".repeat(1000);
        let result = truncate_output(&long, 100);
        assert!(result.len() < 200); // truncated + suffix
        assert!(result.contains("truncated"));
    }

    #[test]
    fn job_id_construction() {
        let config = SandboxConfig::default();
        let nomad_config = NomadConfig::default();
        let sandbox = NomadSandbox::new(config, nomad_config);

        let id = SandboxId {
            key: "session-abc".into(),
        };
        assert_eq!(sandbox.job_id(&id), "moltis-sandbox-session-abc");
    }
}
