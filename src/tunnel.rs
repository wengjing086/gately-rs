use crate::config::TunnelTask;
use crate::state::AppState;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

async fn start_task(state: &AppState, task: &TunnelTask) -> Result<u32, String> {
    let mut cmd = Command::new(&task.binary);
    cmd.args(&task.args).envs(&task.env);
    if let Some(dir) = &task.workdir { cmd.current_dir(dir); }
    cmd.stdout(Stdio::null()).stderr(Stdio::null()).stdin(Stdio::null());
    let child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", task.binary))?;
    let pid = child.id().unwrap_or(0);
    state.tunnel_children.write().await.insert(task.id.clone(), child);
    Ok(pid)
}

pub fn spawn_tunnel_supervisor(state: AppState) {
    tokio::spawn(async move {
        loop {
            let tasks: Vec<TunnelTask> = state.config.read().await.tunnels.clone();
            let ids: Vec<String> = tasks.iter().map(|t| t.id.clone()).collect();

            for task in &tasks {
                let running = {
                    let mut children = state.tunnel_children.write().await;
                    match children.get_mut(&task.id) {
                        Some(child) => matches!(child.try_wait(), Ok(None)),
                        None => false,
                    }
                };
                if running { continue; }

                {
                    let mut children = state.tunnel_children.write().await;
                    if let Some(mut child) = children.remove(&task.id) {
                        let _ = child.kill().await;
                    }
                }

                let mut statuses = state.tunnel_status.write().await;
                let entry = statuses.entry(task.id.clone()).or_default();
                entry.running = false;
                entry.pid = None;
                if !task.enabled { entry.last_error = None; continue; }
                if !task.auto_restart && entry.restarts > 0 {
                    entry.last_error = Some("auto_restart disabled".into());
                    continue;
                }
                match start_task(&state, task).await {
                    Ok(pid) => {
                        entry.running = true;
                        entry.pid = Some(pid);
                        entry.restarts += 1;
                        entry.last_error = None;
                    }
                    Err(err) => entry.last_error = Some(err),
                }
            }

            {
                let mut children = state.tunnel_children.write().await;
                let stale: Vec<String> = children.keys().filter(|k| !ids.contains(k)).cloned().collect();
                for id in stale {
                    if let Some(mut child) = children.remove(&id) { let _ = child.kill().await; }
                }
                let mut statuses = state.tunnel_status.write().await;
                statuses.retain(|k, _| ids.contains(k));
            }

            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

pub async fn stop_all(state: &AppState) {
    let mut children = state.tunnel_children.write().await;
    let ids: Vec<String> = children.keys().cloned().collect();
    for id in ids {
        if let Some(mut child) = children.remove(&id) { let _ = child.kill().await; }
    }
}
