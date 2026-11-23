use crate::config::{DdnsTask, IpSource};
use crate::state::{AppState, DdnsStatus};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use tokio::process::Command;

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)] success: bool,
    #[serde(default)] errors: Vec<ErrItem>,
    #[serde(default)] result: serde_json::Value,
}
#[derive(Deserialize)]
struct ErrItem { #[serde(default)] message: String }

fn errors(env: &Envelope) -> String { env.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>().join("; ") }

pub async fn resolve_ip(state: &AppState, source: &IpSource) -> Result<String, String> {
    match source {
        IpSource::Static { ip } => Ok(ip.trim().to_string()),
        IpSource::Url { url } => {
            let mut url = url.clone();
            let statuses = state.stun_status.read().await;
            for (id, status) in statuses.iter() {
                if let Some(ip) = &status.public_ip { url = url.replace(&format!("{{STUN_{id}_ADDR}}"), ip); }
                if let Some(port) = status.public_port { url = url.replace(&format!("{{STUN_{id}_PORT}}"), &port.to_string()); }
            }
            drop(statuses);
            let text = state.client.get(&url).send().await.map_err(|e| format!("fetch ip: {e}"))?
                .text().await.map_err(|e| format!("read ip: {e}"))?;
            Ok(text.trim().to_string())
        }
        IpSource::Command { command } => {
            let mut parts = command.split_whitespace();
            let program = parts.next().ok_or("empty command")?;
            let out = Command::new(program).args(parts.collect::<Vec<_>>()).output().await.map_err(|e| e.to_string())?;
            if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).to_string()); }
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
    }
}

async fn apply_cloudflare(client: &reqwest::Client, task: &DdnsTask, ip: &str) -> Result<(), String> {
    let base = format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records", task.zone_id);
    let listed: Envelope = client.get(&base).bearer_auth(&task.api_token)
        .query(&[("name", &task.name), ("type", &task.record_type)]).send().await.map_err(|e| format!("list: {e}"))?
        .json().await.map_err(|e| format!("parse: {e}"))?;
    if !listed.success { return Err(format!("cloudflare: {}", errors(&listed))); }
    let existing = listed.result.as_array().and_then(|a| a.first())
        .and_then(|v| v.get("id")).and_then(|v| v.as_str()).map(str::to_string);
    let payload = json!({"type": task.record_type, "name": task.name, "content": ip, "ttl": 1,
        "proxied": task.options.get("proxied").and_then(|v| v.parse().ok()).unwrap_or(false),
        "comment": task.remark});
    let req = match existing { Some(id) => client.put(format!("{base}/{id}")), None => client.post(&base) };
    let written: Envelope = req.bearer_auth(&task.api_token).json(&payload).send().await.map_err(|e| format!("write: {e}"))?
        .json().await.map_err(|e| format!("parse: {e}"))?;
    if !written.success { return Err(format!("cloudflare: {}", errors(&written))); }
    Ok(())
}

fn provider_template(provider: &str) -> Option<(&'static str, &'static str)> {
    let p = provider.to_ascii_lowercase();
    let t = match p.as_str() {
        "duckdns" => ("https://www.duckdns.org/update?domains={name}&ip={ip}&token={token}", ""),
        "dynv6" => ("https://ipv4.dynv6.com/api/update?hostname={name}&ipv4={ip}&token={token}", ""),
        "godaddy" => ("https://api.godaddy.com/v1/domains/{zone}/records/{type}/{name}", "PUT"),
        "porkbun" => ("https://api.porkbun.com/api/json/v3/dns/create/{zone}", ""),
        "namecheap" => ("https://dynamicdns.park-your-domain.com/update?host={name}&domain={zone}&password={token}&ip={ip}", ""),
        "namesilo" => ("https://www.namesilo.com/api/dnsUpdate?version=1&type=json&key={token}&domain={zone}&rrhost={name}&rrvalue={ip}&rrtype={type}", ""),
        "noip" | "dynu" | "dynv2" => ("https://dynupdate.no-ip.com/nic/update?hostname={name}&myip={ip}", ""),
        "route53" | "aws" => ("https://route53.amazonaws.com/2013-04-01/hostedzone/{zone}/rrset/", "POST"),
        "alibaba" | "aliyun" => ("https://alidns.aliyuncs.com/?Action=UpdateDomainRecord&RecordId={zone}&RR={name}&Type={type}&Value={ip}", ""),
        "tencent" | "dnspod" => ("https://dnsapi.cn/Record.Modify", "POST"),
        "huawei" => ("https://dns.myhuaweicloud.com/v2.0/zones/{zone}/recordsets", "PUT"),
        "vercel" => ("https://api.vercel.com/v1/domains/records/{zone}", "PATCH"),
        "gcore" => ("https://api.gcore.com/dns/v1/zones/{zone}/rrsets", "PATCH"),
        "clouddns" => ("https://dns.api.gandi.net/api/v5/zones/{zone}/records/{name}/{type}", "PUT"),
        "desec" => ("https://api.desec.io/api/v1/domains/{zone}/rrsets/{name}/{type}/", "PATCH"),
        "bunny" => ("https://api.bunny.net/dnszone/{zone}/records", "POST"),
        "ns1" => ("https://api.nsone.net/v1/zones/{zone}/{name}/{type}", "PUT"),
        "gandi" => ("https://api.gandi.net/v5/livedns/domains/{zone}/records/{name}/{type}", "PUT"),
        "ovh" => ("https://api.ovh.com/1.0/domain/zone/{zone}/record", "POST"),
        "edgeone" | "baidu" | "volcano" | "dnsla" | "rainyun" | "nowcn" | "eranet" | "tnet" | "hipm" | "dynadot" | "spaceship" | "name" => ("", ""),
        _ => return None,
    };
    Some(t)
}

async fn apply_generic(state: &AppState, task: &DdnsTask, ip: &str) -> Result<(), String> {
    let (template, method) = provider_template(&task.provider).ok_or_else(|| format!("unsupported provider: {}", task.provider))?;
    let zone = if task.zone_id.is_empty() {
        task.name.split('.').skip(1).collect::<Vec<_>>().join(".")
    } else { task.zone_id.clone() };
    let name = if template.contains("host={name}") || template.contains("domains={name}") || template.contains("hostname={name}") {
        task.name.split('.').next().unwrap_or(&task.name).to_string()
    } else { task.name.clone() };
    let url = template.replace("{name}", &name).replace("{zone}", &zone).replace("{ip}", ip)
        .replace("{type}", &task.record_type).replace("{token}", &task.api_token);
    if url.is_empty() {
        let opts = &task.options;
        let endpoint = opts.get("endpoint").ok_or("provider requires options.endpoint")?
            .replace("{name}", &task.name).replace("{ip}", ip).replace("{type}", &task.record_type)
            .replace("{token}", &task.api_token).replace("{zone}", &zone);
        let method = opts.get("method").cloned().unwrap_or_else(|| "GET".into());
        let body = opts.get("body").cloned().unwrap_or_default();
        let mut req = state.client.request(method.parse().map_err(|_| "bad method")?, &endpoint);
        if !task.api_token.is_empty() { req = req.bearer_auth(&task.api_token); }
        if !body.is_empty() { req = req.header("content-type", "application/json").body(body.replace("{ip}", ip)); }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() { return Err(format!("http {}", resp.status())); }
        return Ok(());
    }
    let method = if method.is_empty() { "GET" } else { method };
    let mut req = state.client.request(method.parse().map_err(|_| "bad method")?, &url);
    if !task.api_token.is_empty() && !url.contains("token=") { req = req.bearer_auth(&task.api_token); }
    if method == "POST" || method == "PUT" || method == "PATCH" {
        req = req.json(&json!({"type": task.record_type, "name": task.name, "content": ip, "remark": task.remark}));
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() { return Err(format!("http {}", resp.status())); }
    Ok(())
}

async fn fire_webhooks(state: &AppState, task: &DdnsTask, ip: &str) {
    for url in &task.webhooks {
        let replaced = url.replace("{ip}", ip).replace("{name}", &task.name);
        let _ = state.client.get(&replaced).send().await;
    }
}

async fn run_inner(state: &AppState, id: &str) -> Result<String, String> {
    let task = state.config.read().await.ddns.iter().find(|t| t.id == id).cloned()
        .ok_or_else(|| format!("ddns task {id} not found"))?;
    let ip = resolve_ip(state, &task.ip_source).await?;
    if ip.is_empty() { return Err("resolved ip is empty".into()); }
    match task.provider.as_str() {
        "cloudflare" => apply_cloudflare(&state.client, &task, &ip).await?,
        "custom" => apply_generic(state, &task, &ip).await?,
        _ => apply_generic(state, &task, &ip).await?,
    }
    fire_webhooks(state, &task, &ip).await;
    {
        let mut cfg = state.config.write().await;
        if let Some(t) = cfg.ddns.iter_mut().find(|t| t.id == id) { t.last_ip = Some(ip.clone()); }
        let _ = cfg.save(&state.config_path);
    }
    Ok(ip)
}

pub async fn run_and_record(state: &AppState, id: &str) -> Result<String, String> {
    let result = run_inner(state, id).await;
    let mut statuses = state.ddns_status.write().await;
    let entry: &mut DdnsStatus = statuses.entry(id.to_string()).or_default();
    match &result {
        Ok(ip) => { entry.last_ip = Some(ip.clone()); entry.last_run = Some(Utc::now()); entry.last_error = None; }
        Err(err) => { entry.last_run = Some(Utc::now()); entry.last_error = Some(err.clone()); }
    }
    if let Ok(ip) = &result {
        crate::notify::emit(state, "address.changed", &format!("{} -> {ip}", id)).await;
    }
    result
}

pub fn spawn_ddns_loop(state: AppState) {
    tokio::spawn(async move {
        loop {
            let ids: Vec<(String, u64)> = state.config.read().await.ddns.iter()
                .filter(|t| t.enabled).map(|t| (t.id.clone(), t.interval_secs.max(30))).collect();
            for (id, interval) in ids {
                let due = state.ddns_status.read().await.get(&id).and_then(|s| s.last_run)
                    .map(|last| (Utc::now() - last).num_seconds() as u64 >= interval).unwrap_or(true);
                if due {
                    if let Err(err) = run_and_record(&state, &id).await { eprintln!("[ddns] {id}: {err}"); }
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}
