//! Allocation lifecycle management.
//!
//! Provides polling with exponential backoff for waiting on allocations to
//! reach the `running` state, and handles placement failures.

use std::time::Duration;

use crate::{
    client::{Allocation, NomadClient},
    error::{NomadError, Result},
};

/// Maximum time to wait for an allocation to be running.
const MAX_WAIT: Duration = Duration::from_secs(120);

/// Initial backoff between polls.
const INITIAL_BACKOFF: Duration = Duration::from_millis(500);

/// Maximum backoff between polls.
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Wait for an allocation to reach the `running` state.
///
/// Polls the Nomad API with exponential backoff. Returns the allocation
/// once it's running, or an error if it fails or times out.
#[cfg_attr(feature = "tracing", tracing::instrument(skip(client)))]
pub async fn wait_for_running(
    client: &NomadClient,
    job_id: &str,
    eval_id: &str,
) -> Result<Allocation> {
    let start = std::time::Instant::now();
    let mut backoff = INITIAL_BACKOFF;

    // First wait for the evaluation to complete.
    loop {
        if start.elapsed() > MAX_WAIT {
            return Err(NomadError::AllocationTimeout {
                job_id: job_id.into(),
                seconds: MAX_WAIT.as_secs(),
            });
        }

        let eval = client.get_evaluation(eval_id).await?;
        match eval.status.as_str() {
            "complete" => break,
            "blocked" => {
                let reason = eval
                    .blocked_eval
                    .unwrap_or_else(|| "evaluation blocked".into());
                return Err(NomadError::AllocationFailed { reason });
            },
            "failed" | "canceled" => {
                return Err(NomadError::AllocationFailed {
                    reason: format!("evaluation {}: {}", eval.status, eval.id),
                });
            },
            _ => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            },
        }
    }

    // Now wait for the allocation to be running.
    backoff = INITIAL_BACKOFF;
    loop {
        if start.elapsed() > MAX_WAIT {
            return Err(NomadError::AllocationTimeout {
                job_id: job_id.into(),
                seconds: MAX_WAIT.as_secs(),
            });
        }

        let allocs = client.job_allocations(job_id).await?;
        if let Some(alloc) = allocs.first() {
            match alloc.client_status.as_str() {
                "running" => return Ok(alloc.clone()),
                "failed" | "lost" | "complete" => {
                    let reason = get_failure_reason(alloc);
                    return Err(NomadError::AllocationFailed { reason });
                },
                _ => {
                    // pending — keep polling.
                },
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Extract a human-readable failure reason from an allocation's task events.
fn get_failure_reason(alloc: &Allocation) -> String {
    if let Some(ref tasks) = alloc.task_states {
        for (task_name, state) in tasks {
            if state.failed {
                if let Some(ref events) = state.events {
                    let messages: Vec<_> = events
                        .iter()
                        .filter_map(|e| {
                            e.display_message
                                .as_ref()
                                .map(|m| format!("{}: {m}", e.event_type))
                        })
                        .collect();
                    if !messages.is_empty() {
                        return format!("task {task_name}: {}", messages.join("; "));
                    }
                }
                return format!("task {task_name} failed (state: {})", state.state);
            }
        }
    }
    format!(
        "allocation {} status: {}",
        &alloc.id[..8.min(alloc.id.len())],
        alloc.client_status
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{TaskEvent, TaskState};

    #[test]
    fn failure_reason_from_task_events() {
        let alloc = Allocation {
            id: "abc12345-def0-1234-5678-abcdef012345".into(),
            eval_id: "eval-1".into(),
            job_id: "test-job".into(),
            client_status: "failed".into(),
            desired_status: "run".into(),
            task_states: Some(std::collections::HashMap::from([(
                "sandbox".into(),
                TaskState {
                    state: "dead".into(),
                    failed: true,
                    restarts: 0,
                    events: Some(vec![TaskEvent {
                        event_type: "Driver Failure".into(),
                        display_message: Some("image not found".into()),
                    }]),
                },
            )])),
        };

        let reason = get_failure_reason(&alloc);
        assert!(reason.contains("image not found"));
    }

    #[test]
    fn failure_reason_no_events() {
        let alloc = Allocation {
            id: "abc12345".into(),
            eval_id: "eval-1".into(),
            job_id: "test-job".into(),
            client_status: "failed".into(),
            desired_status: "run".into(),
            task_states: None,
        };

        let reason = get_failure_reason(&alloc);
        assert!(reason.contains("failed"));
    }
}
