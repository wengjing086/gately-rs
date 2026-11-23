use crate::config::{AcmeTask, CertificateConfig, Config};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use chrono::Utc;
use instant_acme::{
    Account, ChallengeType, ExternalAccountKey, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path as FsPath, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

fn directory_url(config: &Config, task_id: &str) -> String {
    let task = config.acme.iter().find(|t| t.id == task_id);
    if let Some(url) = task.and_then(|t| if t.directory.is_empty() { None } else { Some(t.directory.clone()) }) { return url; }
    match task.map(|t| t.provider.as_str()) {
        Some("zerossl") => "https://acme.zerossl.com/v2/DV90".into(),
        _ => LetsEncrypt::Staging.url().to_owned(),
    }
}

fn write_pem(path: &FsPath, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent).map_err(|e| format!("create dir: {e}"))?; }
    let tmp = path.with_extension("pem.tmp");
    fs::write(&tmp, content).map_err(|e| format!("write pem: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename pem: {e}"))?;
    Ok(())
}

fn txt_value(key_auth: &str) -> String {
    let digest = Sha256::digest(key_auth.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

async fn cloudflare_txt(state: &AppState, task: &AcmeTask, name: &str, value: &str, remove: bool) -> Result<(), String> {
    let token = task.dns_credentials.get("api_token").cloned().unwrap_or_default();
    let zone = if task.dns_zone.is_empty() { task.dns_credentials.get("zone_id").cloned().unwrap_or_default() } else { task.dns_zone.clone() };
    if zone.is_empty() || token.is_empty() { return Err("cloudflare DNS-01 needs dns_zone and dns_credentials.api_token".into()); }
    let base = format!("https://api.cloudflare.com/client/v4/zones/{zone}/dns_records");
    if remove {
        let list: serde_json::Value = state.client.get(&base).bearer_auth(&token)
            .query(&[("name", name), ("type", "TXT")]).send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
        if let Some(id) = list.get("result").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(|v| v.get("id")).and_then(|v| v.as_str()) {
            let _ = state.client.delete(format!("{base}/{id}")).bearer_auth(&token).send().await;
        }
        return Ok(());
    }
    let resp = state.client.post(&base).bearer_auth(&token)
        .json(&json!({"type": "TXT", "name": name, "content": value, "ttl": 60}))
        .send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() { return Err(format!("cloudflare dns {}", resp.status())); }
    Ok(())
}

async fn hook_txt(task: &AcmeTask, name: &str, value: &str, remove: bool) -> Result<(), String> {
    if task.dns_hook.is_empty() { return Err("dns_hook not configured".into()); }
    let mut parts = task.dns_hook.split_whitespace();
    let program = parts.next().ok_or("empty dns_hook")?;
    let out = Command::new(program).args(parts.collect::<Vec<_>>())
        .env("GATELY_DNS_NAME", name).env("GATELY_DNS_VALUE", value)
        .env("GATELY_DNS_ACTION", if remove { "remove" } else { "add" })
        .stdout(Stdio::piped()).stderr(Stdio::piped()).output().await.map_err(|e| e.to_string())?;
    if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).to_string()); }
    Ok(())
}

async fn dns_txt(state: &AppState, task: &AcmeTask, name: &str, value: &str, remove: bool) -> Result<(), String> {
    match task.dns_provider.as_str() {
        "cloudflare" => cloudflare_txt(state, task, name, value, remove).await,
        "hook" | "command" | "manual" if !task.dns_hook.is_empty() => hook_txt(task, name, value, remove).await,
        "manual" => {
            let key = format!("{}:{}", name, value);
            let mut tokens = state.acme_dns_tokens.write().await;
            if remove { tokens.remove(&key); } else { tokens.insert(key, value.to_string()); }
            Ok(())
        }
        "" => Err("dns-01 requires dns_provider".into()),
        other => Err(format!("unsupported dns provider: {other}")),
    }
}

async fn deploy_cert(state: &AppState, cert: &CertificateConfig) {
    for target in &cert.deploy_ssh {
        let remote = format!("{}@{}:{}", target.user, target.host, target.cert_path);
        let _ = Command::new("scp").arg(&cert.cert_path).arg(&remote).status().await;
        let key_remote = format!("{}@{}:{}", target.user, target.host, target.key_path);
        let _ = Command::new("scp").arg(&cert.key_path).arg(&key_remote).status().await;
        if !target.command.is_empty() {
            let _ = Command::new("ssh").arg(format!("{}@{}", target.user, target.host)).arg(&target.command).status().await;
        }
    }
    for container in &cert.deploy_containers {
        let _ = Command::new("docker").args(["restart", container]).status().await;
    }
    if !cert.hook.is_empty() {
        let mut parts = cert.hook.split_whitespace();
        if let Some(program) = parts.next() {
            let _ = Command::new(program).args(parts.collect::<Vec<_>>())
                .env("GATELY_CERT", &cert.cert_path).env("GATELY_KEY", &cert.key_path).status().await;
        }
    }
    let _ = state;
}

pub async fn issue(state: &AppState, task_id: &str) -> Result<String, String> {
    let (task, dir_url, paths) = {
        let config = state.config.read().await;
        let task = config.acme.iter().find(|t| t.id == task_id).cloned()
            .ok_or_else(|| format!("acme task {task_id} not found"))?;
        if task.domains.is_empty() { return Err("no domains".into()); }
        let url = directory_url(&config, task_id);
        let cert = config.certificates.iter().find(|c| c.id == task.cert_id).cloned();
        let paths = match cert {
            Some(c) => (PathBuf::from(&c.cert_path), PathBuf::from(&c.key_path)),
            None => {
                let parent = state.config_path.parent().unwrap_or_else(|| FsPath::new("."));
                let dir = parent.join("certs");
                fs::create_dir_all(&dir).map_err(|e| format!("create cert dir: {e}"))?;
                (dir.join(format!("{}.pem", task.cert_id)), dir.join(format!("{}.key", task.cert_id)))
            }
        };
        (task, url, paths)
    };

    let contacts = vec![format!("mailto:{}", task.email)];
    let contact_refs: Vec<&str> = contacts.iter().map(|s| s.as_str()).collect();
    let builder = Account::builder().map_err(|e| format!("account builder: {e}"))?;
    let eab = if task.eab_kid.is_empty() || task.eab_hmac.is_empty() { None } else {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&task.eab_hmac)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&task.eab_hmac))
            .map_err(|e| format!("bad EAB hmac: {e}"))?;
        Some(ExternalAccountKey::new(task.eab_kid.clone(), &raw))
    };
    let (account, _credentials) = builder.create(
        &NewAccount { contact: &contact_refs, terms_of_service_agreed: true, only_return_existing: false },
        dir_url, eab.as_ref(),
    ).await.map_err(|e| format!("create account: {e}"))?;

    let identifiers: Vec<Identifier> = task.domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut new_order = NewOrder::new(&identifiers);
    if task.profile == "shortlived" { new_order = new_order.profile("shortlived"); }
    let mut order = account.new_order(&new_order).await.map_err(|e| format!("new order: {e}"))?;

    let mut dns_records: Vec<(String, String)> = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| format!("authorization: {e}"))?;
            if !matches!(authz.status, instant_acme::AuthorizationStatus::Pending) { continue; }
            if task.challenge == "dns-01" {
                let domain = authz.identifier().to_string();
                let mut challenge = authz.challenge(ChallengeType::Dns01).ok_or("no dns-01 challenge")?;
                let base_domain = domain.trim_start_matches("*.");
                let record = format!("_acme-challenge.{base_domain}");
                let value = txt_value(challenge.key_authorization().as_str());
                dns_txt(state, &task, &record, &value, false).await?;
                dns_records.push((record, value));
                challenge.set_ready().await.map_err(|e| format!("challenge ready: {e}"))?;
            } else {
                let mut challenge = authz.challenge(ChallengeType::Http01).ok_or("no http-01 challenge")?;
                let token = challenge.token.clone();
                let key_auth = challenge.key_authorization().as_str().to_string();
                state.acme_tokens.write().await.insert(token, key_auth);
                challenge.set_ready().await.map_err(|e| format!("challenge ready: {e}"))?;
            }
        }
    }

    let result = async {
        let status = order.poll_ready(&RetryPolicy::default()).await.map_err(|e| format!("poll ready: {e}"))?;
        if status != OrderStatus::Ready { return Err(format!("order status: {status:?}")); }
        let key_pem = order.finalize().await.map_err(|e| format!("finalize: {e}"))?;
        let cert_pem = order.poll_certificate(&RetryPolicy::default()).await.map_err(|e| format!("poll certificate: {e}"))?;
        write_pem(&paths.0, &cert_pem)?;
        write_pem(&paths.1, &key_pem)?;
        Ok::<(), String>(())
    }.await;

    for (record, value) in &dns_records { let _ = dns_txt(state, &task, record, value, true).await; }
    state.acme_tokens.write().await.clear();
    result?;

    let cert_config = {
        let mut config = state.config.write().await;
        if !config.certificates.iter().any(|c| c.id == task.cert_id) {
            config.certificates.push(CertificateConfig {
                id: task.cert_id.clone(),
                cert_path: paths.0.to_string_lossy().to_string(),
                key_path: paths.1.to_string_lossy().to_string(),
                acme_id: Some(task.id.clone()),
                domains: task.domains.clone(),
                deploy_ssh: Vec::new(), deploy_containers: Vec::new(), hook: String::new(),
            });
        }
        if let Some(t) = config.acme.iter_mut().find(|t| t.id == task_id) {
            t.last_issued = Some(Utc::now().to_rfc3339());
            t.last_error = None;
        }
        let _ = config.save(&state.config_path);
        config.certificates.iter().find(|c| c.id == task.cert_id).cloned()
    };
    if let Some(cert) = cert_config { deploy_cert(state, &cert).await; }
    crate::notify::emit(state, "cert.issued", &format!("{}: {}", task.cert_id, task.domains.join(", "))).await;
    Ok(format!("issued {}", task.cert_id))
}

pub async fn run_handler(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match issue(&state, &id).await {
        Ok(msg) => (StatusCode::OK, msg).into_response(),
        Err(err) => {
            let mut config = state.config.write().await;
            if let Some(t) = config.acme.iter_mut().find(|t| t.id == id) { t.last_error = Some(err.clone()); }
            let _ = config.save(&state.config_path);
            crate::notify::emit(&state, "cert.failed", &format!("{id}: {err}")).await;
            (StatusCode::BAD_GATEWAY, err).into_response()
        }
    }
}

pub fn spawn_acme_loop(state: AppState) {
    tokio::spawn(async move {
        loop {
            let due: Vec<String> = {
                let config = state.config.read().await;
                config.acme.iter().filter(|t| t.auto_renew).filter(|t| {
                    let stale = match &t.last_issued {
                        Some(s) => chrono::DateTime::parse_from_rfc3339(s)
                            .map(|dt| (Utc::now() - dt.with_timezone(&Utc)).num_days() >= (89 - t.renew_before_days.min(89)) as i64)
                            .unwrap_or(true),
                        None => true,
                    };
                    let cert = config.certificates.iter().find(|c| c.id == t.cert_id);
                    let missing = cert.map(|c| !std::path::Path::new(&c.cert_path).exists()).unwrap_or(true);
                    stale || missing
                }).map(|t| t.id.clone()).collect()
            };
            for id in due {
                if let Err(err) = issue(&state, &id).await { eprintln!("[acme] {id}: {err}"); }
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}

pub async fn challenge_handler(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let value = state.acme_tokens.read().await.get(&token).cloned();
    match value {
        Some(v) => (StatusCode::OK, v).into_response(),
        None => (StatusCode::NOT_FOUND, "no challenge").into_response(),
    }
}

pub async fn dns_tokens_handler(State(state): State<AppState>) -> Response {
    axum::Json(state.acme_dns_tokens.read().await.clone()).into_response()
}

pub fn challenge_router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/.well-known/acme-challenge/{token}", axum::routing::get(challenge_handler))
        .with_state(state)
}
