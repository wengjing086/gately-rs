use crate::config::{DdnsTask, IpSource};
use crate::state::{AppState, DdnsStatus};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

#[derive(Deserialize)]
struct CfEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default)]
    result: serde_json::Value,
}

#[derive(Deserialize)]
struct CfError {
    #[serde(default)]
    message: String,
}

fn cf_errors(env: &CfEnvelope) -> String {
    env.errors
        .iter()
        .map(|e| e.message.clone())
        .collect::<Vec<_>>()
        .join("; ")
}

async fn resolve_ip(client: &reqwest::Client, source: &IpSource) -> Result<String, String> {
    match source {
        IpSource::Static { ip } => Ok(ip.trim().to_string()),
        IpSource::Url { url } => {
            let text = client
                .get(url)
                .send()
                .await
                .map_err(|e| format!("fetch ip: {e}"))?
                .text()
                .await
                .map_err(|e| format!("read ip: {e}"))?;
            Ok(text.trim().to_string())
        }
    }
}

async fn apply_cloudflare(client: &reqwest::Client, task: &DdnsTask, ip: &str) -> Result<(), String> {
    let base = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
        task.zone_id
    );

    let listed: CfEnvelope = client
        .get(&base)
        .bearer_auth(&task.api_token)
        .query(&[("name", &task.name), ("type", &task.record_type)])
        .send()
        .await
        .map_err(|e| format!("list records: {e}"))?
        .json()
        .await
        .map_err(|e| format!("parse list response: {e}"))?;
    if !listed.success {
        return Err(format!("cloudflare list failed: {}", cf_errors(&listed)));
    }

    let existing_id = listed
        .result
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let payload = json!({
        "type": task.record_type,
        "name": task.name,
        "content": ip,
        "ttl": 1,
        "proxied": false,
    });

    let request = match existing_id {
        Some(id) => client.put(format!("{base}/{id}")),
        None => client.post(&base),
    };

    let written: CfEnvelope = request
        .bearer_auth(&task.api_token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("write record: {e}"))?
        .json()
        .await
        .map_err(|e| format!("parse write response: {e}"))?;
    if !written.success {
        return Err(format!("cloudflare write failed: {}", cf_errors(&written)));
    }
    Ok(())
}

async fn run_task_inner(state: &AppState, id: &str) -> Result<String, String> {
    let task = {
        let cfg = state.config.read().await;
        cfg.ddns
            .iter()
            .find(|t| t.id == id)
            .cloned()
            .ok_or_else(|| format!("ddns task {id} not found"))?
    };
    if task.provider != "cloudflare" {
        return Err(format!("unsupported provider: {}", task.provider));
    }

    let ip = resolve_ip(&state.client, &task.ip_source).await?;
    if ip.is_empty() {
        return Err("resolved ip is empty".into());
    }
    apply_cloudflare(&state.client, &task, &ip).await?;

    {
        let mut cfg = state.config.write().await;
        if let Some(t) = cfg.ddns.iter_mut().find(|t| t.id == id) {
            t.last_ip = Some(ip.clone());
        }
        cfg.save(&state.config_path)?;
    }
    Ok(ip)
}

pub async fn run_and_record(state: &AppState, id: &str) -> Result<String, String> {
    let result = run_task_inner(state, id).await;
    let mut statuses = state.ddns_status.write().await;
    let entry: &mut DdnsStatus = statuses.entry(id.to_string()).or_default();
    match &result {
        Ok(ip) => {
            entry.last_ip = Some(ip.clone());
            entry.last_run = Some(Utc::now());
            entry.last_error = None;
        }
        Err(err) => {
            entry.last_run = Some(Utc::now());
            entry.last_error = Some(err.clone());
        }
    }
    result
}

pub fn spawn_ddns_loop(state: AppState) {
    tokio::spawn(async move {
        loop {
            let ids: Vec<String> = {
                let cfg = state.config.read().await;
                cfg.ddns
                    .iter()
                    .filter(|t| t.enabled)
                    .map(|t| t.id.clone())
                    .collect()
            };

            for id in ids {
                let interval = {
                    let cfg = state.config.read().await;
                    match cfg.ddns.iter().find(|t| t.id == id) {
                        Some(t) => t.interval_secs.max(30),
                        None => continue,
                    }
                };
                let due = {
                    let statuses = state.ddns_status.read().await;
                    match statuses.get(&id).and_then(|s| s.last_run) {
                        None => true,
                        Some(last) => (Utc::now() - last).num_seconds() as u64 >= interval,
                    }
                };
                if due {
                    if let Err(err) = run_and_record(&state, &id).await {
                        eprintln!("[ddns] {id}: {err}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}
