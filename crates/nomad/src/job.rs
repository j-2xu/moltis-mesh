//! Nomad job specification builder.
//!
//! Creates Nomad job JSON from [`SandboxJobOpts`] for running sandbox
//! containers as batch jobs.

use crate::config::NomadConfig;

/// Parameters for building a Nomad sandbox job.
///
/// Decoupled from any specific config crate type so the nomad crate
/// doesn't depend on the caller's config structures.
#[derive(Debug, Clone)]
pub struct SandboxJobOpts {
    /// Whether to disable networking in the sandbox.
    pub no_network: bool,
    /// Workspace mount mode: `"ro"`, `"rw"`, or `"none"`.
    pub workspace_mount: String,
    /// CPU quota as a fraction of one core (e.g. 0.5 = half a core).
    pub cpu_quota: Option<f64>,
    /// Memory limit (e.g. `"512m"`, `"1g"`).
    pub memory_limit: Option<String>,
}

/// Build a Nomad job specification for a sandbox container.
///
/// Creates a `batch` type job with a single task group containing
/// the sandbox container. Resource limits are mapped from the
/// [`SandboxJobOpts`] to Nomad resources.
#[must_use]
pub fn build_sandbox_job(
    job_id: &str,
    image: &str,
    opts: &SandboxJobOpts,
    nomad_config: &NomadConfig,
) -> serde_json::Value {
    let task_driver = &nomad_config.task_driver;

    // Map resource limits.
    let cpu_mhz = opts
        .cpu_quota
        .map(|q| (q as u64 * 100).max(100)) // Convert fraction to MHz (rough)
        .unwrap_or(500);

    let memory_mb = opts
        .memory_limit
        .as_ref()
        .and_then(|m| parse_memory_mb(m))
        .unwrap_or(512);

    // Build network config.
    let network_mode = if opts.no_network { "none" } else { "bridge" };

    // Build task config.
    let mut task_config = serde_json::json!({
        "image": image,
        "command": "/bin/sh",
        "args": ["-c", "sleep infinity"],
    });

    // Add volumes for workspace mount.
    let mut volumes = Vec::new();
    match opts.workspace_mount.as_str() {
        "ro" | "rw" => {
            let mode = &opts.workspace_mount;
            if let Ok(cwd) = std::env::current_dir() {
                volumes.push(format!("{}:/workspace:{mode}", cwd.display()));
            }
        },
        // "none" or any other value — no mount.
        _ => {},
    }
    if !volumes.is_empty() {
        task_config["volumes"] = serde_json::json!(volumes);
    }

    let mut datacenters = vec!["dc1".to_string()];
    if let Some(ref dc) = nomad_config.datacenter {
        datacenters = vec![dc.clone()];
    }

    serde_json::json!({
        "ID": job_id,
        "Name": job_id,
        "Type": "batch",
        "Datacenters": datacenters,
        "TaskGroups": [{
            "Name": "sandbox",
            "Count": 1,
            "RestartPolicy": {
                "Attempts": 0,
                "Mode": "fail",
            },
            "Networks": [{
                "Mode": network_mode,
            }],
            "Tasks": [{
                "Name": "sandbox",
                "Driver": task_driver,
                "Config": task_config,
                "Resources": {
                    "CPU": cpu_mhz,
                    "MemoryMB": memory_mb,
                },
                "KillTimeout": 5_000_000_000_u64, // 5s in nanoseconds
            }],
        }],
    })
}

/// Parse a memory limit string (e.g. "512m", "1g", "256mb") to megabytes.
fn parse_memory_mb(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    if let Some(val) = s.strip_suffix("gb").or_else(|| s.strip_suffix('g')) {
        val.trim().parse::<u64>().ok().map(|v| v * 1024)
    } else if let Some(val) = s.strip_suffix("mb").or_else(|| s.strip_suffix('m')) {
        val.trim().parse::<u64>().ok()
    } else if let Some(val) = s.strip_suffix("kb").or_else(|| s.strip_suffix('k')) {
        val.trim().parse::<u64>().ok().map(|v| v / 1024)
    } else {
        // Assume bytes, convert to MB.
        s.parse::<u64>().ok().map(|v| v / (1024 * 1024))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_opts() -> SandboxJobOpts {
        SandboxJobOpts {
            no_network: false,
            workspace_mount: "ro".into(),
            cpu_quota: None,
            memory_limit: None,
        }
    }

    #[test]
    fn parse_memory_mb_values() {
        assert_eq!(parse_memory_mb("512m"), Some(512));
        assert_eq!(parse_memory_mb("1g"), Some(1024));
        assert_eq!(parse_memory_mb("256mb"), Some(256));
        assert_eq!(parse_memory_mb("2gb"), Some(2048));
    }

    #[test]
    fn build_basic_job() {
        let opts = default_opts();
        let nomad_config = NomadConfig::default();

        let job = build_sandbox_job("moltis-sandbox-test", "ubuntu:22.04", &opts, &nomad_config);

        assert_eq!(job["ID"].as_str(), Some("moltis-sandbox-test"));
        assert_eq!(job["Type"].as_str(), Some("batch"));
        assert_eq!(
            job["TaskGroups"][0]["Tasks"][0]["Driver"].as_str(),
            Some("docker")
        );
    }

    #[test]
    fn build_job_with_podman_driver() {
        let opts = default_opts();
        let mut nomad_config = NomadConfig::default();
        nomad_config.task_driver = "podman".into();

        let job = build_sandbox_job("test-job", "alpine:3", &opts, &nomad_config);

        assert_eq!(
            job["TaskGroups"][0]["Tasks"][0]["Driver"].as_str(),
            Some("podman")
        );
    }

    #[test]
    fn build_job_no_network() {
        let mut opts = default_opts();
        opts.no_network = true;
        let nomad_config = NomadConfig::default();

        let job = build_sandbox_job("test", "alpine:3", &opts, &nomad_config);

        assert_eq!(
            job["TaskGroups"][0]["Networks"][0]["Mode"].as_str(),
            Some("none")
        );
    }
}
