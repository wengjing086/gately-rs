use crate::config::{AcmeTask, CertificateConfig, Config};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use std::fs;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;

fn directory_url(config: &Config, task_id: &str) -> String {
    let task = config.acme.iter().find(|t| t.id == task_id);
    if let Some(url) = task.and_then(|t| if t.directory.is_empty() { None } else { Some(t.directory.clone()) }) {
        return url;
    }
    match task.map(|t| t.provider.as_str()) {
        Some("zerossl") => "https://acme.zerossl.com/v2/DV90".into(),
        _ => LetsEncrypt::Production.url().to_owned(),
    }
}

fn write_pem(path: &FsPath, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent).map_err(|e| format!("create dir: {e}"))?; }
    let tmp = path.with_extension("pem.tmp");
    fs::write(&tmp, content).map_err(|e| format!("write pem: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename pem: {e}"))?;
    Ok(())
}

pub async fn issue(state: &AppState, task_id: &str) -> Result<String, String> {
    let (task, dir_url, paths) = {
        let config = state.config.read().await;
        let task = config.acme.iter().find(|t| t.id == task_id).cloned()
            .ok_or_else(|| format!("acme task {task_id} not found"))?;
        if task.domains.is_empty() { return Err("no domains".into()); }
        if task.challenge != "http-01" { return Err(format!("unsupported challenge: {}", task.challenge)); }
        let url = directory_url(&config, task_id);
        let cert = config.certificates.iter().find(|c| c.id == task.cert_id);
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
    let (account, _credentials) = Account::builder()
        .map_err(|e| format!("account builder: {e}"))?
        .create(
            &NewAccount { contact: &contact_refs, terms_of_service_agreed: true, only_return_existing: false },
            dir_url,
            None,
        )
        .await
        .map_err(|e| format!("create account: {e}"))?;

    let identifiers: Vec<Identifier> = task.domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await.map_err(|e| format!("new order: {e}"))?;

    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| format!("authorization: {e}"))?;
            if !matches!(authz.status, instant_acme::AuthorizationStatus::Pending) { continue; }
            let mut challenge = authz.challenge(ChallengeType::Http01)
                .ok_or_else(|| "no http-01 challenge".to_string())?;
            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization().as_str().to_string();
            state.acme_tokens.write().await.insert(token, key_auth);
            challenge.set_ready().await.map_err(|e| format!("challenge ready: {e}"))?;
        }
    }

    let status = order.poll_ready(&RetryPolicy::default()).await.map_err(|e| format!("poll ready: {e}"))?;
    if status != OrderStatus::Ready { return Err(format!("order status: {status:?}")); }

    let key_pem = order.finalize().await.map_err(|e| format!("finalize: {e}"))?;
    let cert_pem = order.poll_certificate(&RetryPolicy::default()).await.map_err(|e| format!("poll certificate: {e}"))?;
    write_pem(&paths.0, &cert_pem)?;
    write_pem(&paths.1, &key_pem)?;

    {
        let mut config = state.config.write().await;
        if !config.certificates.iter().any(|c| c.id == task.cert_id) {
            config.certificates.push(CertificateConfig {
                id: task.cert_id.clone(),
                cert_path: paths.0.to_string_lossy().to_string(),
                key_path: paths.1.to_string_lossy().to_string(),
                acme_id: Some(task.id.clone()),
            });
        }
        if let Some(t) = config.acme.iter_mut().find(|t| t.id == task_id) {
            t.last_issued = Some(Utc::now().to_rfc3339());
            t.last_error = None;
        }
        config.save(&state.config_path).map_err(|e| format!("save config: {e}"))?;
    }

    state.acme_tokens.write().await.clear();
    Ok(format!("issued {}", task.cert_id))
}

pub async fn run_handler(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match issue(&state, &id).await {
        Ok(msg) => (StatusCode::OK, msg).into_response(),
        Err(err) => {
            let mut config = state.config.write().await;
            if let Some(t) = config.acme.iter_mut().find(|t| t.id == id) { t.last_error = Some(err.clone()); }
            let _ = config.save(&state.config_path);
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
                if let Err(err) = issue(&state, &id).await {
                    eprintln!("[acme] {id}: {err}");
                    let mut config = state.config.write().await;
                    if let Some(t) = config.acme.iter_mut().find(|t| t.id == id) { t.last_error = Some(err); }
                    let _ = config.save(&state.config_path);
                }
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

pub fn challenge_router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/.well-known/acme-challenge/{token}", axum::routing::get(challenge_handler))
        .with_state(state)
}
