use crate::config::{Config, DockerConfig};
use crate::state::{AppState, JobStatus};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use uuid::Uuid;

/// Max amount of captured output kept per background job (64 KiB).
const MAX_OUTPUT: usize = 64 * 1024;
/// Upper bound for `docker logs --tail`.
const MAX_TAIL: u32 = 10_000;
/// Timeout applied to synchronous compose invocations.
const COMPOSE_TIMEOUT_SECS: u64 = 600;

/// job id -> child process pid, so a running job can be interrupted.
static CHILDREN: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();

fn children() -> &'static Mutex<HashMap<String, u32>> {
    CHILDREN.get_or_init(|| Mutex::new(HashMap::new()))
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

fn bad_request(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, msg)
}

fn bad_gateway(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, msg)
}

/// Read the docker section of the configuration, rejecting the call when the feature is off.
async fn docker_config(state: &AppState) -> Result<DockerConfig, ApiError> {
    let cfg = state.config.read().await.docker.clone();
    if !cfg.enabled {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Docker 功能未启用：请在配置中设置 docker.enabled = true",
        ));
    }
    Ok(cfg)
}

/// Global docker flags (`--host` / `-H unix://...`) that must precede the sub command.
fn global_args(cfg: &DockerConfig) -> Vec<String> {
    let mut args = Vec::new();
    let host = cfg.host.trim();
    if !host.is_empty() {
        args.push("--host".to_string());
        args.push(host.to_string());
    }
    let socket = cfg.socket.trim();
    if !socket.is_empty() {
        args.push("-H".to_string());
        args.push(if socket.starts_with("unix://") { socket.to_string() } else { format!("unix://{socket}") });
    }
    args
}

/// Run a docker command and capture stdout / stderr / exit code.
async fn run_docker(
    cfg: &DockerConfig,
    args: &[String],
    cwd: Option<&PathBuf>,
) -> Result<(String, String, Option<i32>), ApiError> {
    let mut cmd = Command::new("docker");
    cmd.args(global_args(cfg));
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let out = cmd.output().await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            bad_gateway("docker 命令不可用：未找到 docker 可执行文件，请确认已安装 Docker 并已加入 PATH")
        } else {
            bad_gateway(format!("执行 docker 命令失败: {e}"))
        }
    })?;
    Ok((
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code(),
    ))
}

/// Run a docker command and fail with 502 when the command exits with a non zero status.
async fn run_docker_ok(
    cfg: &DockerConfig,
    args: &[String],
    cwd: Option<&PathBuf>,
) -> Result<String, ApiError> {
    let (stdout, stderr, code) = run_docker(cfg, args, cwd).await?;
    if code != Some(0) {
        let msg = if !stderr.trim().is_empty() { stderr.trim().to_string() } else { stdout.trim().to_string() };
        return Err(bad_gateway(if msg.is_empty() {
            format!("docker {} 执行失败", args.join(" "))
        } else {
            msg
        }));
    }
    Ok(stdout)
}

/// Parse `docker ... --format {{json .}}` output: one JSON object per line.
fn parse_json_lines(out: &str) -> Option<Vec<Value>> {
    let mut items = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => items.push(v),
            Err(_) => return None,
        }
    }
    Some(items)
}

/// Split a tab separated table row, tolerating a literal `\t` sequence as separator.
fn split_fields(line: &str) -> Vec<&str> {
    if line.contains('\t') { line.split('\t').collect() } else { line.split("\\t").collect() }
}

/// Fallback parser for the plain table output of docker.
fn parse_table(out: &str, keys: &[&str]) -> Vec<Value> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let cols = split_fields(line);
            let mut obj = serde_json::Map::new();
            for (i, key) in keys.iter().enumerate() {
                obj.insert((*key).to_string(), Value::String(cols.get(i).unwrap_or(&"").trim().to_string()));
            }
            Value::Object(obj)
        })
        .collect()
}

/// Prefix an image reference with the configured registry when it does not carry one.
fn apply_registry(registry: &str, image: &str) -> String {
    let reg = registry.trim().trim_end_matches('/');
    if reg.is_empty() || image.is_empty() {
        return image.to_string();
    }
    if let Some((first, _)) = image.split_once('/') {
        if first.contains('.') || first.contains(':') || first == "localhost" {
            return image.to_string();
        }
        return format!("{reg}/{image}");
    }
    format!("{reg}/library/{image}")
}

/// Persist the configuration, keeping a history snapshot of the previous version.
async fn persist_config(state: &AppState, config: &Config) -> Result<(), String> {
    if let Ok(text) = std::fs::read_to_string(&state.config_path) {
        let _ = crate::history::snapshot(&state.config_path, &text);
    }
    config.save(&state.config_path)
}

/// Append captured output to a job, keeping the most recent 64 KiB.
async fn append_output(state: &AppState, job_id: &str, chunk: &str) {
    let mut jobs = state.jobs.write().await;
    if let Some(job) = jobs.get_mut(job_id) {
        job.output.push_str(chunk);
        if job.output.len() > MAX_OUTPUT {
            let mut cut = job.output.len() - MAX_OUTPUT;
            while cut < job.output.len() && !job.output.is_char_boundary(cut) {
                cut += 1;
            }
            job.output = format!("…[输出已截断]\n{}", &job.output[cut..]);
        }
    }
}

/// Mark a job as finished.
async fn finish_job(state: &AppState, job_id: &str, code: Option<i32>, success: bool) {
    let mut jobs = state.jobs.write().await;
    if let Some(job) = jobs.get_mut(job_id) {
        job.exit_code = code;
        job.finished_at = Some(Utc::now());
        if job.cancelled {
            job.status = "cancelled".into();
        } else {
            job.status = if success { "success".into() } else { "failed".into() };
        }
    }
}

/// Copy a pipe line by line into the job output buffer.
async fn pump<R>(reader: Option<R>, state: AppState, job_id: String)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let Some(reader) = reader else { return };
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) => break,
            Ok(_) => {
                let chunk = String::from_utf8_lossy(&buf).to_string();
                append_output(&state, &job_id, &chunk).await;
            }
            Err(_) => break,
        }
    }
}

/// Run a docker command in the background and stream its output into the job record.
async fn run_job(
    state: AppState,
    job_id: String,
    cfg: DockerConfig,
    args: Vec<String>,
    cwd: Option<PathBuf>,
) {
    let mut cmd = Command::new("docker");
    cmd.args(global_args(&cfg));
    cmd.args(&args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            let msg = if e.kind() == std::io::ErrorKind::NotFound {
                "docker 命令不可用：未找到 docker 可执行文件".to_string()
            } else {
                format!("启动 docker 失败: {e}")
            };
            append_output(&state, &job_id, &format!("{msg}\n")).await;
            finish_job(&state, &job_id, None, false).await;
            return;
        }
    };
    if let Some(pid) = child.id() {
        if let Ok(mut map) = children().lock() {
            map.insert(job_id.clone(), pid);
        }
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let s1 = state.clone();
    let j1 = job_id.clone();
    let h1 = tokio::spawn(async move { pump(stdout, s1, j1).await });
    let s2 = state.clone();
    let j2 = job_id.clone();
    let h2 = tokio::spawn(async move { pump(stderr, s2, j2).await });
    let status = child.wait().await;
    let _ = h1.await;
    let _ = h2.await;
    if let Ok(mut map) = children().lock() {
        map.remove(&job_id);
    }
    let code = status.ok().and_then(|s| s.code());
    finish_job(&state, &job_id, code, code == Some(0)).await;
}

/// Register a new background job and start the docker process for it.
async fn spawn_job(
    state: &AppState,
    kind: &str,
    target: String,
    cfg: DockerConfig,
    args: Vec<String>,
    cwd: Option<PathBuf>,
) -> String {
    let id = format!("job_{}", Uuid::new_v4().simple());
    let job = JobStatus {
        id: id.clone(),
        kind: kind.to_string(),
        target,
        status: "running".to_string(),
        output: String::new(),
        exit_code: None,
        started_at: Utc::now(),
        finished_at: None,
        cancelled: false,
    };
    state.jobs.write().await.insert(id.clone(), job);
    let s = state.clone();
    let jid = id.clone();
    tokio::spawn(async move { run_job(s, jid, cfg, args, cwd).await });
    id
}

/// Kill the process tree of a running job.
async fn kill_pid(pid: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        let status = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|e| format!("taskkill 失败: {e}"))?;
        if !status.success() {
            return Err(format!("taskkill 退出码 {}", status.code().unwrap_or(-1)));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let status = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|e| format!("kill 失败: {e}"))?;
        if !status.success() {
            return Err(format!("kill 退出码 {}", status.code().unwrap_or(-1)));
        }
        Ok(())
    }
}

/// Interrupt a running background job.
pub async fn cancel_job(state: &AppState, id: &str) -> Result<(), String> {
    {
        let jobs = state.jobs.read().await;
        let job = jobs.get(id).ok_or_else(|| format!("任务不存在: {id}"))?;
        if job.cancelled {
            return Err(format!("任务已取消: {id}"));
        }
        if job.status != "running" {
            return Err(format!("任务已结束: {id}"));
        }
    }
    // Mark the job as cancelled first, so the worker that owns the child process
    // does not overwrite the status once the process dies.
    {
        let mut jobs = state.jobs.write().await;
        if let Some(job) = jobs.get_mut(id) {
            job.cancelled = true;
            job.status = "cancelled".into();
            job.finished_at = Some(Utc::now());
        }
    }
    let pid = children().lock().ok().and_then(|map| map.get(id).copied());
    let result = match pid {
        Some(pid) => kill_pid(pid).await,
        None => Err(format!("找不到任务进程: {id}")),
    };
    if let Ok(mut map) = children().lock() {
        map.remove(id);
    }
    result
}

#[derive(Debug, Deserialize)]
struct LogsQuery {
    #[serde(default)]
    tail: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct PullRequest {
    pub image: String,
}

#[derive(Debug, Deserialize)]
pub struct BuildRequest {
    pub tag: String,
    #[serde(default)]
    pub context: String,
}

#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    pub container: String,
    pub cmd: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DockerConfigUpdate {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub socket: Option<String>,
    #[serde(default)]
    pub compose_file: Option<String>,
    #[serde(default)]
    pub compose_dir: Option<String>,
    #[serde(default)]
    pub registry: Option<String>,
}

const CONTAINER_ACTIONS: &[&str] = &["start", "stop", "restart", "kill", "rm", "pause", "unpause"];
const COMPOSE_ACTIONS: &[&str] = &["up", "down", "pull", "restart"];

async fn list_containers(State(state): State<AppState>) -> Result<Json<Vec<Value>>, ApiError> {
    let cfg = docker_config(&state).await?;
    let args = vec!["ps".to_string(), "-a".to_string(), "--format".to_string(), "{{json .}}".to_string()];
    let stdout = run_docker_ok(&cfg, &args, None).await?;
    if let Some(items) = parse_json_lines(&stdout) {
        return Ok(Json(items));
    }
    let args = vec![
        "ps".to_string(),
        "-a".to_string(),
        "--format".to_string(),
        "{{.ID}}\\t{{.Image}}\\t{{.Names}}\\t{{.Status}}\\t{{.Ports}}".to_string(),
    ];
    let stdout = run_docker_ok(&cfg, &args, None).await?;
    Ok(Json(parse_table(&stdout, &["ID", "Image", "Names", "Status", "Ports"])))
}

async fn container_logs(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<LogsQuery>,
) -> Result<Json<Value>, ApiError> {
    let cfg = docker_config(&state).await?;
    let tail = query.tail.unwrap_or(200).clamp(1, MAX_TAIL);
    let args = vec!["logs".to_string(), "--tail".to_string(), tail.to_string(), id];
    let (stdout, stderr, code) = run_docker(&cfg, &args, None).await?;
    if code != Some(0) {
        let msg = if !stderr.trim().is_empty() { stderr.trim().to_string() } else { stdout.trim().to_string() };
        return Err(bad_gateway(if msg.is_empty() { "读取容器日志失败".to_string() } else { msg }));
    }
    let mut logs = stdout;
    if !stderr.trim().is_empty() {
        if !logs.is_empty() && !logs.ends_with('\n') {
            logs.push('\n');
        }
        logs.push_str(&stderr);
    }
    Ok(Json(json!({ "logs": logs })))
}

async fn container_action(
    State(state): State<AppState>,
    Path((id, action)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    if !CONTAINER_ACTIONS.contains(&action.as_str()) {
        return Err(bad_request(format!(
            "不支持的操作: {action}（支持 {}）",
            CONTAINER_ACTIONS.join(" / ")
        )));
    }
    let cfg = docker_config(&state).await?;
    let args = vec![action.clone(), id];
    let stdout = run_docker_ok(&cfg, &args, None).await?;
    Ok(Json(json!({ "ok": true, "action": action, "output": stdout })))
}

async fn list_images(State(state): State<AppState>) -> Result<Json<Vec<Value>>, ApiError> {
    let cfg = docker_config(&state).await?;
    let args = vec!["images".to_string(), "--format".to_string(), "{{json .}}".to_string()];
    let stdout = run_docker_ok(&cfg, &args, None).await?;
    if let Some(items) = parse_json_lines(&stdout) {
        return Ok(Json(items));
    }
    let args = vec![
        "images".to_string(),
        "--format".to_string(),
        "{{.Repository}}\\t{{.Tag}}\\t{{.ID}}\\t{{.CreatedSince}}\\t{{.Size}}".to_string(),
    ];
    let stdout = run_docker_ok(&cfg, &args, None).await?;
    Ok(Json(parse_table(&stdout, &["Repository", "Tag", "ID", "CreatedSince", "Size"])))
}

async fn pull_image(
    State(state): State<AppState>,
    Json(payload): Json<PullRequest>,
) -> Result<Json<Value>, ApiError> {
    let cfg = docker_config(&state).await?;
    let image = payload.image.trim().to_string();
    if image.is_empty() {
        return Err(bad_request("image 不能为空"));
    }
    let target = apply_registry(&cfg.registry, &image);
    let args = vec!["pull".to_string(), target.clone()];
    let id = spawn_job(&state, "pull", target, cfg, args, None).await;
    let job = state.jobs.read().await.get(&id).cloned();
    Ok(Json(json!({ "ok": true, "id": id, "job": job })))
}

async fn build_image(
    State(state): State<AppState>,
    Json(payload): Json<BuildRequest>,
) -> Result<Json<Value>, ApiError> {
    let cfg = docker_config(&state).await?;
    let tag = payload.tag.trim().to_string();
    if tag.is_empty() {
        return Err(bad_request("tag 不能为空"));
    }
    let context = payload.context.trim();
    let context = if context.is_empty() { ".".to_string() } else { context.to_string() };
    let args = vec!["build".to_string(), "-t".to_string(), tag.clone(), context.clone()];
    let id = spawn_job(&state, "build", tag, cfg, args, None).await;
    let job = state.jobs.read().await.get(&id).cloned();
    Ok(Json(json!({ "ok": true, "id": id, "job": job })))
}

async fn compose_action(
    State(state): State<AppState>,
    Path(action): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if !COMPOSE_ACTIONS.contains(&action.as_str()) {
        return Err(bad_request(format!(
            "不支持的操作: {action}（支持 {}）",
            COMPOSE_ACTIONS.join(" / ")
        )));
    }
    let cfg = docker_config(&state).await?;
    let file = cfg.compose_file.trim();
    if file.is_empty() {
        return Err(bad_request("未配置 compose 文件：请设置 docker.compose_file"));
    }
    let dir = cfg.compose_dir.trim();
    let cwd = if dir.is_empty() { None } else { Some(PathBuf::from(dir)) };
    let mut args = vec!["compose".to_string(), "-f".to_string(), file.to_string(), action.clone()];
    if action == "up" {
        args.push("-d".to_string());
    }
    let stdout = match tokio::time::timeout(
        Duration::from_secs(COMPOSE_TIMEOUT_SECS),
        run_docker_ok(&cfg, &args, cwd.as_ref()),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => return Err(bad_gateway(format!("docker compose {action} 超时"))),
    };
    Ok(Json(json!({ "ok": true, "action": action, "output": stdout })))
}

async fn exec_in_container(
    State(state): State<AppState>,
    Json(payload): Json<ExecRequest>,
) -> Result<Json<Value>, ApiError> {
    let cfg = docker_config(&state).await?;
    let container = payload.container.trim().to_string();
    if container.is_empty() {
        return Err(bad_request("container 不能为空"));
    }
    if payload.cmd.is_empty() {
        return Err(bad_request("cmd 不能为空"));
    }
    let mut args = vec!["exec".to_string(), container];
    args.extend(payload.cmd.iter().cloned());
    let (stdout, stderr, code) = run_docker(&cfg, &args, None).await?;
    if code != Some(0) {
        let msg = if !stderr.trim().is_empty() { stderr.trim().to_string() } else { stdout.trim().to_string() };
        return Err(bad_gateway(if msg.is_empty() { "docker exec 执行失败".to_string() } else { msg }));
    }
    Ok(Json(json!({ "ok": true, "output": stdout, "stderr": stderr, "exit_code": code })))
}

async fn list_jobs(State(state): State<AppState>) -> Result<Json<Vec<JobStatus>>, ApiError> {
    docker_config(&state).await?;
    let jobs = state.jobs.read().await;
    let mut list: Vec<JobStatus> = jobs.values().cloned().collect();
    list.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    Ok(Json(list))
}

async fn get_job(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<JobStatus>, ApiError> {
    docker_config(&state).await?;
    let job = state
        .jobs
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, format!("任务不存在: {id}")))?;
    Ok(Json(job))
}

async fn cancel_job_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    {
        let jobs = state.jobs.read().await;
        if !jobs.contains_key(&id) {
            return Err(ApiError::new(StatusCode::NOT_FOUND, format!("任务不存在: {id}")));
        }
    }
    cancel_job(&state, &id).await.map_err(|err| ApiError::new(StatusCode::CONFLICT, err))?;
    Ok(Json(json!({ "ok": true, "id": id })))
}

/// Update the docker section of the configuration.
///
/// The feature has to be enabled already; toggling it on is done through the
/// admin `PUT /api/config` endpoint, so every `/docker/*` route keeps returning
/// 403 while the feature is disabled.
async fn update_docker_config(
    State(state): State<AppState>,
    Json(payload): Json<DockerConfigUpdate>,
) -> Result<Json<Value>, ApiError> {
    docker_config(&state).await?;
    let mut config = state.config.write().await;
    let mut docker = config.docker.clone();
    if let Some(v) = payload.enabled {
        docker.enabled = v;
    }
    if let Some(v) = payload.host {
        docker.host = v;
    }
    if let Some(v) = payload.socket {
        docker.socket = v;
    }
    if let Some(v) = payload.compose_file {
        docker.compose_file = v;
    }
    if let Some(v) = payload.compose_dir {
        docker.compose_dir = v;
    }
    if let Some(v) = payload.registry {
        docker.registry = v;
    }
    config.docker = docker.clone();
    if let Err(err) = persist_config(&state, &config).await {
        return Err(ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, err));
    }
    Ok(Json(json!({ "ok": true, "docker": docker })))
}

/// Docker management routes. Merge them below the `/api` prefix.
pub fn router(state: AppState) -> axum::Router<AppState> {
    Router::new()
        .route("/docker/containers", get(list_containers))
        .route("/docker/containers/{id}/logs", get(container_logs))
        .route("/docker/containers/{id}/{action}", post(container_action))
        .route("/docker/images", get(list_images))
        .route("/docker/images/pull", post(pull_image))
        .route("/docker/build", post(build_image))
        .route("/docker/compose/{action}", post(compose_action))
        .route("/docker/exec", post(exec_in_container))
        .route("/docker/jobs", get(list_jobs))
        .route("/docker/jobs/{id}", get(get_job))
        .route("/docker/jobs/{id}/cancel", post(cancel_job_route))
        .route("/docker/config", axum::routing::put(update_docker_config))
}
