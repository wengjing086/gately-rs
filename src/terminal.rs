//! Web 终端：浏览器内使用本机 Shell / SSH / Telnet 会话，并提供文件浏览、上传与下载。
//!
//! 路由由 `router(state)` 返回，路径不带 `/api` 前缀，由调用方决定挂载位置。
//!
//! 安全说明：
//! * 本版本不支持交互式密码登录（SSH / Telnet 弹出密码提示的场景无法完成认证）。
//!   SSH 请配置好私钥或 ssh-agent 后使用。
//! * 文件相关接口统一走 `safe_path` 做路径穿越防护：拒绝包含 `..` 的路径，
//!   相对路径固定落在进程当前工作目录内。

use crate::config::TerminalConfig;
use crate::state::AppState;

use axum::body::Body;
use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::path::{Component, Path as FsPath, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc;
use uuid::Uuid;

/// 单个上传文件大小上限（32MB）。
const MAX_UPLOAD_BYTES: usize = 32 * 1024 * 1024;
/// 单个下载文件大小上限（64MB）。
const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// 后台回收任务的扫描间隔。
const REAP_INTERVAL: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// 会话存储
// ---------------------------------------------------------------------------

/// 会话持有的子进程管道。
struct SessionIo {
    stdin: ChildStdin,
    stdout: tokio::process::ChildStdout,
    stderr: tokio::process::ChildStderr,
}

/// 一个终端会话。
#[derive(Clone)]
struct Session {
    id: String,
    kind: String,
    target: String,
    created_at: DateTime<Utc>,
    pid: Option<u32>,
    /// 子进程管道，WebSocket 接入时取走。
    io: Arc<tokio::sync::Mutex<Option<SessionIo>>>,
    /// 子进程句柄，用于会话关闭时结束进程。
    child: Arc<Mutex<Option<Child>>>,
    /// 当前是否有 WebSocket 接入。
    connected: Arc<AtomicBool>,
    /// 子进程是否已经退出。
    dead: Arc<AtomicBool>,
}

impl Session {
    fn summary(&self) -> SessionSummary {
        SessionSummary {
            id: self.id.clone(),
            kind: self.kind.clone(),
            target: self.target.clone(),
            created_at: self.created_at.to_rfc3339(),
            active: self.connected.load(Ordering::Relaxed),
        }
    }
}

/// 会话列表条目。
#[derive(Debug, Serialize)]
struct SessionSummary {
    id: String,
    kind: String,
    target: String,
    created_at: String,
    active: bool,
}

/// 全局会话表：`id -> 会话`。
///
/// 使用 `std::sync::Mutex`，所有临界区都很短，绝不跨 `await` 持有。
static SESSIONS: OnceLock<Mutex<HashMap<String, Arc<Session>>>> = OnceLock::new();

fn sessions() -> &'static Mutex<HashMap<String, Arc<Session>>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 在会话表上执行一段同步操作（临界区内不得发生 `await`）。
fn with_sessions<R>(f: impl FnOnce(&mut HashMap<String, Arc<Session>>) -> R) -> R {
    let mut guard = sessions().lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

/// 结束会话对应的子进程。
async fn kill_session(session: &Session) {
    let child = {
        let mut guard = session.child.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    if let Some(mut child) = child {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    session.dead.store(true, Ordering::Relaxed);
}

/// 从会话表移除并结束进程。
async fn close_session(id: &str) -> bool {
    let session = with_sessions(|map| map.remove(id));
    match session {
        Some(session) => {
            kill_session(&session).await;
            true
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// 子进程输出转发
// ---------------------------------------------------------------------------

/// 后台读取子进程的一路输出并推送到通道。
///
/// 按块读取（而不是按行），这样没有换行结尾的提示符（例如 `$ `）也能立刻显示。
fn spawn_pump<R>(reader: R, tx: mpsc::UnboundedSender<String>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = reader;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let chunk = String::from_utf8_lossy(&buf[..n]).into_owned();
            if tx.send(normalize_newlines(&chunk)).is_err() {
                break;
            }
        }
    });
}

/// 将 `\n` 转换为 `\r\n`（已存在的 `\r\n` 不重复添加）。
fn normalize_newlines(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                out.push('\r');
                if chars.peek() == Some(&'\n') {
                    out.push('\n');
                    chars.next();
                }
            }
            '\n' => {
                out.push('\r');
                out.push('\n');
            }
            other => out.push(other),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 路径安全
// ---------------------------------------------------------------------------

/// 进程当前工作目录，作为相对路径的基准根目录。
fn base_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// 解析用户传入的路径，阻断路径穿越。
///
/// * 任何包含 `..` 的路径一律拒绝；
/// * 绝对路径按原样使用（去掉 `.` 片段）；
/// * 相对路径固定挂载在 `base` 之下。
fn safe_path(base: &FsPath, user_path: &str) -> Result<PathBuf, String> {
    let raw = user_path.trim();
    if raw.is_empty() {
        return Ok(base.to_path_buf());
    }
    let candidate = FsPath::new(raw);
    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("路径中不允许包含 `..`".to_string());
    }
    let mut cleaned = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::CurDir => {}
            other => cleaned.push(other.as_os_str()),
        }
    }
    if candidate.is_absolute() {
        return Ok(cleaned);
    }
    let joined = base.join(&cleaned);
    if !joined.starts_with(base) {
        return Err("路径超出允许的根目录".to_string());
    }
    Ok(joined)
}

// ---------------------------------------------------------------------------
// 命令构造
// ---------------------------------------------------------------------------

/// 构造会话对应的子进程命令，返回 `(展示用 target, 可执行程序名, 命令)`。
fn build_command(
    kind: &str,
    req: &CreateSessionRequest,
) -> Result<(String, String, Command), (StatusCode, String)> {
    match kind {
        "local" => {
            let program = if std::env::consts::OS == "windows" {
                "cmd.exe".to_string()
            } else {
                "sh".to_string()
            };
            let mut cmd = Command::new(&program);
            for arg in &req.args {
                cmd.arg(arg);
            }
            Ok(("local".to_string(), program, cmd))
        }
        "ssh" => {
            let host = req.host.trim();
            if host.is_empty() {
                return Err((StatusCode::BAD_REQUEST, "ssh 会话必须提供 host".to_string()));
            }
            let port = if req.port == 0 { 22 } else { req.port };
            let user = req.user.trim();
            let target = if user.is_empty() {
                host.to_string()
            } else {
                format!("{user}@{host}")
            };
            let mut cmd = Command::new("ssh");
            cmd.arg("-p")
                .arg(port.to_string())
                .arg("-o")
                .arg("StrictHostKeyChecking=accept-new");
            for arg in &req.args {
                cmd.arg(arg);
            }
            cmd.arg(&target);
            Ok((format!("{target}:{port}"), "ssh".to_string(), cmd))
        }
        "telnet" => {
            let host = req.host.trim();
            if host.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "telnet 会话必须提供 host".to_string(),
                ));
            }
            let port = if req.port == 0 { 23 } else { req.port };
            let mut cmd = Command::new("telnet");
            cmd.arg(host).arg(port.to_string());
            for arg in &req.args {
                cmd.arg(arg);
            }
            Ok((format!("{host}:{port}"), "telnet".to_string(), cmd))
        }
        other => Err((
            StatusCode::BAD_REQUEST,
            format!("不支持的会话类型: {other}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// 请求 / 响应模型
// ---------------------------------------------------------------------------

/// 创建会话的请求体。
#[derive(Debug, Deserialize)]
struct CreateSessionRequest {
    /// `local` / `ssh` / `telnet`
    #[serde(default)]
    kind: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    user: String,
    #[serde(default)]
    args: Vec<String>,
}

/// 文件接口的查询参数。
#[derive(Debug, Deserialize)]
struct PathQuery {
    #[serde(default)]
    path: String,
}

/// 目录条目。
#[derive(Debug, Serialize)]
struct DirEntry {
    name: String,
    is_dir: bool,
    size: u64,
    modified: Option<String>,
}

// ---------------------------------------------------------------------------
// 路由处理
// ---------------------------------------------------------------------------

/// 返回统一的 JSON 错误响应。
fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

/// 读取终端配置快照。
async fn terminal_config(state: &AppState) -> TerminalConfig {
    state.config.read().await.terminal.clone()
}

/// 判断会话类型是否被允许。
fn kind_allowed(cfg: &TerminalConfig, kind: &str) -> bool {
    match kind {
        "local" => cfg.allow_local_shell,
        "ssh" => cfg.allow_ssh,
        "telnet" => cfg.allow_telnet,
        _ => false,
    }
}

/// 列出当前所有终端会话。
async fn list_sessions(State(state): State<AppState>) -> Response {
    let cfg = terminal_config(&state).await;
    if !cfg.enabled {
        return err(StatusCode::FORBIDDEN, "终端功能未启用");
    }
    let mut items: Vec<SessionSummary> =
        with_sessions(|map| map.values().map(|s| s.summary()).collect());
    items.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Json(items).into_response()
}

/// 创建一个终端会话。
async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSessionRequest>,
) -> Response {
    let cfg = terminal_config(&state).await;
    if !cfg.enabled {
        return err(StatusCode::FORBIDDEN, "终端功能未启用");
    }
    let kind = req.kind.trim().to_lowercase();
    if !matches!(kind.as_str(), "local" | "ssh" | "telnet") {
        return err(StatusCode::BAD_REQUEST, "不支持的会话类型");
    }
    if !kind_allowed(&cfg, &kind) {
        return err(StatusCode::FORBIDDEN, "该类型的终端会话未被允许");
    }
    let (target, program, mut cmd) = match build_command(&kind, &req) {
        Ok(v) => v,
        Err((status, message)) => return err(status, message),
    };
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return err(
                StatusCode::BAD_GATEWAY,
                format!("系统中未找到 `{program}` 命令，无法建立会话"),
            )
        }
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("启动进程失败: {e}")),
    };
    let pid = child.id();
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (stdin, stdout, stderr) = match (stdin, stdout, stderr) {
        (Some(stdin), Some(stdout), Some(stderr)) => (stdin, stdout, stderr),
        _ => {
            let _ = child.start_kill();
            return err(StatusCode::INTERNAL_SERVER_ERROR, "无法获取进程管道");
        }
    };
    let id = Uuid::new_v4().to_string();
    let session = Arc::new(Session {
        id: id.clone(),
        kind,
        target,
        created_at: Utc::now(),
        pid,
        io: Arc::new(tokio::sync::Mutex::new(Some(SessionIo {
            stdin,
            stdout,
            stderr,
        }))),
        child: Arc::new(Mutex::new(Some(child))),
        connected: Arc::new(AtomicBool::new(false)),
        dead: Arc::new(AtomicBool::new(false)),
    });
    with_sessions(|map| {
        map.insert(id.clone(), session);
    });
    Json(json!({ "id": id })).into_response()
}

/// 关闭一个终端会话并结束其进程。
async fn delete_session(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let cfg = terminal_config(&state).await;
    if !cfg.enabled {
        return err(StatusCode::FORBIDDEN, "终端功能未启用");
    }
    if close_session(&id).await {
        Json(json!({ "ok": true, "id": id })).into_response()
    } else {
        err(StatusCode::NOT_FOUND, "会话不存在")
    }
}

/// 目录浏览。
async fn list_directory(State(state): State<AppState>, Query(query): Query<PathQuery>) -> Response {
    let cfg = terminal_config(&state).await;
    if !cfg.enabled {
        return err(StatusCode::FORBIDDEN, "终端功能未启用");
    }
    let base = base_dir();
    let path = match safe_path(&base, &query.path) {
        Ok(path) => path,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    let mut dir = match tokio::fs::read_dir(&path).await {
        Ok(dir) => dir,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("无法读取目录: {e}")),
    };
    let mut entries: Vec<DirEntry> = Vec::new();
    loop {
        let entry = match dir.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("读取目录失败: {e}")),
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let metadata = entry.metadata().await.ok();
        let is_dir = metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified = metadata
            .as_ref()
            .and_then(|m| m.modified().ok())
            .map(|t| DateTime::<Utc>::from(t).to_rfc3339());
        entries.push(DirEntry {
            name,
            is_dir,
            size,
            modified,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Json(json!({ "path": path.to_string_lossy(), "entries": entries })).into_response()
}

/// 下载文件。
async fn download_file(State(state): State<AppState>, Query(query): Query<PathQuery>) -> Response {
    let cfg = terminal_config(&state).await;
    if !cfg.enabled {
        return err(StatusCode::FORBIDDEN, "终端功能未启用");
    }
    if query.path.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "缺少 path 参数");
    }
    let base = base_dir();
    let path = match safe_path(&base, &query.path) {
        Ok(path) => path,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) => metadata,
        Err(e) => return err(StatusCode::NOT_FOUND, format!("文件不存在: {e}")),
    };
    if metadata.is_dir() {
        return err(StatusCode::BAD_REQUEST, "目标是一个目录");
    }
    if metadata.len() > MAX_DOWNLOAD_BYTES {
        return err(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("文件超过 {} MB 下载上限", MAX_DOWNLOAD_BYTES / 1024 / 1024),
        );
    }
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("读取文件失败: {e}")),
    }
}

/// 上传文件（请求体即文件原始内容）。
async fn upload_file(
    State(state): State<AppState>,
    Query(query): Query<PathQuery>,
    body: Body,
) -> Response {
    let cfg = terminal_config(&state).await;
    if !cfg.enabled {
        return err(StatusCode::FORBIDDEN, "终端功能未启用");
    }
    if query.path.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "缺少 path 参数");
    }
    let base = base_dir();
    let path = match safe_path(&base, &query.path) {
        Ok(path) => path,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    let bytes = match axum::body::to_bytes(body, MAX_UPLOAD_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return err(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("文件超过 {} MB 上传上限", MAX_UPLOAD_BYTES / 1024 / 1024),
            )
        }
    };
    if let Some(parent) = target_parent(&path) {
        if !parent.exists() {
            if let Err(e) = tokio::fs::create_dir_all(&parent).await {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("创建目录 {} 失败: {e}", parent.display()),
                );
            }
        }
    }
    match tokio::fs::write(&path, &bytes).await {
        Ok(_) => Json(json!({
            "ok": true,
            "path": path.to_string_lossy(),
            "size": bytes.len(),
        }))
        .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("写入文件失败: {e}")),
    }
}

/// 取目标路径的父目录（根目录返回 `None`）。
fn target_parent(path: &FsPath) -> Option<PathBuf> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Some(parent.to_path_buf()),
        _ => None,
    }
}

/// WebSocket 升级入口：把浏览器接到会话的子进程上。
async fn ws_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let cfg = terminal_config(&state).await;
    if !cfg.enabled {
        return err(StatusCode::FORBIDDEN, "终端功能未启用");
    }
    let session = with_sessions(|map| map.get(&id).cloned());
    let session = match session {
        Some(session) => session,
        None => return err(StatusCode::NOT_FOUND, "会话不存在"),
    };
    if !kind_allowed(&cfg, &session.kind) {
        return err(StatusCode::FORBIDDEN, "该类型的终端会话已被禁用");
    }
    if session.dead.load(Ordering::Relaxed) {
        return err(StatusCode::CONFLICT, "会话进程已退出");
    }
    // 管道只能被一个连接取走，避免多个浏览器同时写入同一个进程。
    let io = {
        let mut guard = session.io.lock().await;
        guard.take()
    };
    let io = match io {
        Some(io) => io,
        None => return err(StatusCode::CONFLICT, "会话已被其他连接占用"),
    };
    session.connected.store(true, Ordering::Relaxed);
    let motd = cfg.motd.clone();
    let idle = cfg.idle_timeout_secs;
    let child = session.child.clone();
    let connected = session.connected.clone();
    ws.on_upgrade(move |socket| async move {
        run_terminal(socket, io, motd, idle).await;
        connected.store(false, Ordering::Relaxed);
        // 连接断开后结束子进程，避免留下孤儿进程。
        let process = {
            let mut guard = child.lock().unwrap_or_else(|e| e.into_inner());
            guard.take()
        };
        if let Some(mut process) = process {
            let _ = process.start_kill();
            let _ = process.wait().await;
        }
    })
}

// ---------------------------------------------------------------------------
// WebSocket 会话循环
// ---------------------------------------------------------------------------

/// 终端循环中等待的事件。
enum Event {
    /// 客户端发来的消息。
    Client(Option<Message>),
    /// 子进程输出。
    Output(Option<String>),
}

/// 等待下一个终端事件：客户端输入或子进程输出。
///
/// 单独抽成函数是为了让 `socket` 的可变借用在返回后就结束，
/// 这样调用方可以安全地调用 `socket.send()`。
async fn next_event(
    socket: &mut WebSocket,
    rx: &mut mpsc::UnboundedReceiver<String>,
) -> Event {
    tokio::select! {
        message = socket.recv() => Event::Client(message.and_then(|m| m.ok())),
        output = rx.recv() => Event::Output(output),
    }
}

/// WebSocket 与子进程之间的双向桥接。
async fn run_terminal(mut socket: WebSocket, io: SessionIo, motd: String, idle_secs: u64) {
    let SessionIo {
        stdin,
        stdout,
        stderr,
    } = io;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    spawn_pump(stdout, tx.clone());
    spawn_pump(stderr, tx);
    let mut stdin = stdin;
    if !motd.is_empty() {
        let _ = socket
            .send(Message::Text(Utf8Bytes::from(motd)))
            .await;
    }
    // 空闲回收：idle_secs 为 0 表示不启用。
    let idle = if idle_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(idle_secs))
    };
    loop {
        let event = match idle {
            Some(idle) => match tokio::time::timeout(idle, next_event(&mut socket, &mut rx)).await {
                Ok(event) => event,
                Err(_) => {
                    let _ = socket
                        .send(Message::Text(Utf8Bytes::from(
                            "\r\n[会话空闲超时，已关闭]\r\n".to_string(),
                        )))
                        .await;
                    break;
                }
            },
            None => next_event(&mut socket, &mut rx).await,
        };
        match event {
            Event::Client(Some(Message::Text(text))) => {
                let data = normalize_input(text.as_str());
                if write_stdin(&mut stdin, data.as_bytes()).await.is_err() {
                    break;
                }
            }
            Event::Client(Some(Message::Binary(data))) => {
                // 二进制帧按 UTF-8 尝试解码为文本。
                let data = normalize_input(&String::from_utf8_lossy(&data));
                if write_stdin(&mut stdin, data.as_bytes()).await.is_err() {
                    break;
                }
            }
            // Ping 由底层协议自动应答，无需额外处理。
            Event::Client(Some(Message::Ping(_))) | Event::Client(Some(Message::Pong(_))) => {}
            Event::Client(Some(Message::Close(_))) | Event::Client(None) => break,
            Event::Output(Some(text)) => {
                if socket.send(Message::Text(Utf8Bytes::from(text))).await.is_err() {
                    break;
                }
            }
            // 所有输出管道关闭 => 子进程已退出。
            Event::Output(None) => break,
        }
    }
    // 关闭标准输入，让子进程感知到输入结束。
    drop(stdin);
    let _ = socket.send(Message::Close(None)).await;
}

/// 把浏览器输入写进子进程 stdin。
async fn write_stdin(stdin: &mut ChildStdin, data: &[u8]) -> std::io::Result<()> {
    stdin.write_all(data).await?;
    stdin.flush().await
}

/// 归一化浏览器发来的按键：回车统一成当前平台需要的行尾。
fn normalize_input(data: &str) -> String {
    let unified = data.replace("\r\n", "\n");
    if std::env::consts::OS == "windows" {
        unified.replace('\n', "\r\n")
    } else {
        unified.replace('\r', "\n")
    }
}

// ---------------------------------------------------------------------------
// 空闲回收
// ---------------------------------------------------------------------------

/// 定期回收已经退出或长时间无人连接的会话。
fn spawn_reaper(state: AppState) {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle,
            Err(_) => return,
        };
        handle.spawn(async move {
            loop {
                tokio::time::sleep(REAP_INTERVAL).await;
                let idle = state.config.read().await.terminal.idle_timeout_secs;
                let stale: Vec<String> = with_sessions(|map| {
                    map.iter()
                        .filter(|(_, session)| session_is_stale(session, idle))
                        .map(|(id, _)| id.clone())
                        .collect()
                });
                for id in stale {
                    close_session(&id).await;
                }
            }
        });
    });
}

/// 判断会话是否应该被回收。
fn session_is_stale(session: &Session, idle_secs: u64) -> bool {
    if session.dead.load(Ordering::Relaxed) {
        return true;
    }
    if idle_secs == 0 || session.connected.load(Ordering::Relaxed) {
        return false;
    }
    // 未连接的会话按创建时间计算空闲时长。
    let age = Utc::now() - session.created_at;
    age.num_seconds() as u64 >= idle_secs
}

// ---------------------------------------------------------------------------
// 路由
// ---------------------------------------------------------------------------

/// 构造终端模块路由。
///
/// 返回类型是 `Router<()>`（状态已注入），可以与其它 `Router<()>` 直接 `merge`；
/// 若需要放进 `/api` 分组，请先对该分组调用 `.with_state(state.clone())`。
pub fn router(state: AppState) -> axum::Router<AppState> {
    spawn_reaper(state.clone());
    Router::new()
        .route("/terminal/sessions", get(list_sessions).post(create_session))
        .route("/terminal/sessions/{id}", delete(delete_session))
        .route("/terminal/ws/{id}", get(ws_handler))
        .route("/terminal/list", get(list_directory))
        .route("/terminal/download", get(download_file))
        .route("/terminal/upload", post(upload_file))
}
