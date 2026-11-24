//! File services: a minimal WebDAV server (HTTP) and a minimal FTP server (raw TCP).
//!
//! Both services share the same model:
//!
//! * `FileServiceConfig::roots` declares the directories that may be published.
//! * `FileUser::roots` restricts the roots a user may reach (empty = every root).
//! * `FileRoot::users` restricts a root to the listed users (empty = every user).
//! * `FileServiceConfig::readonly`, `FileRoot::readonly` and `FileUser::readonly`
//!   make the affected roots read-only.
//!
//! Requests are mapped into a root by the first path segment (the root `id`, or its
//! `name`); when a user may only reach a single root the prefix may be omitted.
//! `..` segments are resolved and are rejected when they would leave the root.

use crate::config::{FileServiceConfig, FileUser};
use crate::state::AppState;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use base64::Engine;
use chrono::{DateTime, Utc};
use hyper::body::Frame;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Realm advertised on `WWW-Authenticate` when a WebDAV request is not authorized.
const DAV_REALM: &str = "gately";
/// Methods announced by `OPTIONS`.
const DAV_ALLOW: &str = "OPTIONS,GET,HEAD,PUT,DELETE,MKCOL,PROPFIND,MOVE,COPY";
/// Interval at which the file service configuration is re-read.
const RELOAD_INTERVAL: Duration = Duration::from_secs(10);
/// Timeout for accepting an FTP data connection.
const FTP_DATA_TIMEOUT: Duration = Duration::from_secs(30);
/// Chunk size used while streaming a file back to a WebDAV client.
const FILE_CHUNK: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

fn html_escape(input: &str) -> String {
    xml_escape(input)
}

/// Percent-decode a single path segment. Returns `None` for malformed escapes.
fn percent_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            if idx + 2 >= bytes.len() {
                return None;
            }
            let hi = (bytes[idx + 1] as char).to_digit(16)?;
            let lo = (bytes[idx + 2] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            idx += 3;
        } else {
            out.push(bytes[idx]);
            idx += 1;
        }
    }
    Some(out)
}

/// Percent-encode a path, keeping `/` intact so the result stays a path.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

/// Split a URL path into decoded segments.
fn decode_path_segments(path: &str) -> Option<Vec<String>> {
    let mut segments = Vec::new();
    for raw in path.split('/') {
        if raw.is_empty() {
            continue;
        }
        let decoded = percent_decode(raw)?;
        segments.push(String::from_utf8(decoded).ok()?);
    }
    Some(segments)
}

/// Resolve `.` and `..` inside a root relative path.
///
/// Returns `Err(())` when a `..` would escape the root.
fn resolve_relative(segments: &[String]) -> Result<Vec<String>, ()> {
    let mut stack: Vec<String> = Vec::with_capacity(segments.len());
    for segment in segments {
        match segment.as_str() {
            "." => continue,
            ".." => {
                if stack.pop().is_none() {
                    return Err(());
                }
            }
            other => stack.push(other.to_string()),
        }
    }
    Ok(stack)
}

fn http_date(secs: i64) -> String {
    match DateTime::from_timestamp(secs, 0) {
        Some(stamp) => stamp.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        None => "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
    }
}

fn content_type_for(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "txt" | "log" | "conf" | "ini" => "text/plain; charset=utf-8",
        "md" | "markdown" => "text/markdown; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "xml" => "application/xml",
        "csv" => "text/csv; charset=utf-8",
        "yaml" | "yml" => "application/yaml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn build_response(status: StatusCode, headers: &[(&str, &str)], body: Body) -> Response {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(body).unwrap_or_else(|_| {
        let mut fallback = Response::new(Body::empty());
        *fallback.status_mut() = status;
        fallback
    })
}

fn text_response(status: StatusCode, message: &str) -> Response {
    build_response(
        status,
        &[(header::CONTENT_TYPE.as_str(), "text/plain; charset=utf-8")],
        Body::from(message.to_string()),
    )
}

fn unauthorized_response() -> Response {
    build_response(
        StatusCode::UNAUTHORIZED,
        &[
            (header::WWW_AUTHENTICATE.as_str(), "Basic realm=\"gately\""),
            (header::CONTENT_TYPE.as_str(), "text/plain; charset=utf-8"),
        ],
        Body::from("authentication required".to_string()),
    )
}

/// Accept both plain text passwords and sha256 hex digests.
fn password_matches(stored: &str, given: &str) -> bool {
    if stored == given {
        return true;
    }
    if stored.len() == 64 && stored.chars().all(|ch| ch.is_ascii_hexdigit()) {
        let mut hasher = Sha256::new();
        hasher.update(given.as_bytes());
        let digest = hasher.finalize();
        let hex: String = digest.iter().map(|byte| format!("{:02x}", byte)).collect();
        return hex.eq_ignore_ascii_case(stored);
    }
    false
}

/// A root the current session may reach.
#[derive(Clone, Debug)]
struct RootEntry {
    id: String,
    name: String,
    path: PathBuf,
    readonly: bool,
}

impl RootEntry {
    /// The segment that selects this root inside a request path.
    fn key(&self) -> &str {
        if self.id.is_empty() {
            &self.name
        } else {
            &self.id
        }
    }
}

/// The effective view of the file service for one user.
#[derive(Clone, Debug)]
struct Session {
    username: Option<String>,
    roots: Vec<RootEntry>,
}

impl Session {
    fn is_readonly(&self, root: usize) -> bool {
        self.roots.get(root).map(|entry| entry.readonly).unwrap_or(true)
    }
}

/// Resolve the set of roots a user may reach.
fn build_session(cfg: &FileServiceConfig, creds: Option<&(String, String)>) -> Result<Session, ()> {
    // Public servers (require_login=false, no users configured) must accept the
    // `USER anonymous` / `PASS anonymous@` pair that every FTP client sends by
    // default. Treat any credentials as anonymous in that mode.
    let creds = if !cfg.require_login && cfg.users.is_empty() { None } else { creds };
    let matched: Option<FileUser> = match creds {
        Some((username, password)) => cfg
            .users
            .iter()
            .find(|user| user.username == *username && password_matches(&user.password, password))
            .cloned(),
        None => None,
    };

    // Invalid credentials are always rejected, even when login is not required.
    if creds.is_some() && matched.is_none() {
        return Err(());
    }
    if cfg.require_login && matched.is_none() {
        return Err(());
    }

    let mut roots = Vec::new();
    for root in &cfg.roots {
        if !root.users.is_empty() {
            match &matched {
                Some(user) => {
                    if !root.users.iter().any(|name| name == &user.username) {
                        continue;
                    }
                }
                None => continue,
            }
        }
        if let Some(user) = &matched {
            if !user.roots.is_empty() && !user.roots.iter().any(|id| id == &root.id) {
                continue;
            }
        }
        let path = PathBuf::from(&root.path);
        if !path.is_dir() {
            continue;
        }
        let readonly = cfg.readonly || root.readonly || matched.as_ref().map(|u| u.readonly).unwrap_or(false);
        roots.push(RootEntry {
            id: root.id.clone(),
            name: root.name.clone(),
            path,
            readonly,
        });
    }

    // At least one reachable root is required.
    if roots.is_empty() {
        return Err(());
    }

    Ok(Session {
        username: matched.map(|user| user.username),
        roots,
    })
}

/// A resolved location inside a root.
#[derive(Clone, Debug)]
struct Target {
    root: usize,
    rel: Vec<String>,
}

impl Target {
    fn physical(&self, session: &Session) -> PathBuf {
        let mut path = session.roots[self.root].path.clone();
        for segment in &self.rel {
            path.push(segment);
        }
        path
    }
}

/// Map a request path onto a root.
///
/// `Ok(None)` means "the collection of roots" (only reachable when several roots
/// are configured and the request path is empty).
fn resolve_target(session: &Session, segments: &[String]) -> Result<Option<Target>, ()> {
    if segments.is_empty() {
        if session.roots.len() == 1 {
            return Ok(Some(Target {
                root: 0,
                rel: Vec::new(),
            }));
        }
        return Ok(None);
    }

    let head = &segments[0];
    let root_idx = session
        .roots
        .iter()
        .position(|entry| entry.key() == head || (!entry.name.is_empty() && entry.name == *head));
    let (root_idx, tail) = match root_idx {
        Some(idx) => (idx, &segments[1..]),
        None => {
            if session.roots.len() == 1 {
                (0, &segments[..])
            } else {
                return Err(());
            }
        }
    };
    let rel = resolve_relative(tail)?;
    Ok(Some(Target { root: root_idx, rel }))
}

/// Make sure `target` really lives inside `root` (symlinks included).
async fn ensure_within(root: &Path, target: &Path) -> bool {
    let Ok(root_real) = tokio::fs::canonicalize(root).await else {
        return false;
    };
    let mut probe = target.to_path_buf();
    loop {
        match tokio::fs::canonicalize(&probe).await {
            Ok(real) => return real.starts_with(&root_real),
            Err(_) => match probe.parent() {
                Some(parent) => probe = parent.to_path_buf(),
                None => return false,
            },
        }
    }
}

/// Metadata of a directory entry.
struct EntryInfo {
    name: String,
    is_dir: bool,
    size: u64,
    modified: Option<i64>,
}

async fn list_directory(path: &Path) -> Vec<EntryInfo> {
    let mut entries = Vec::new();
    let Ok(mut reader) = tokio::fs::read_dir(path).await else {
        return entries;
    };
    while let Ok(Some(entry)) = reader.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        let metadata = entry.metadata().await.ok();
        entries.push(EntryInfo {
            name,
            is_dir: metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false),
            size: metadata.as_ref().map(|m| m.len()).unwrap_or(0),
            modified: metadata
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs() as i64),
        });
    }
    entries.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    entries
}

// ---------------------------------------------------------------------------
// WebDAV
// ---------------------------------------------------------------------------

/// Build the WebDAV router.
///
/// The router serves the whole path space, so it must be mounted without a prefix.
pub fn dav_router(state: AppState) -> Router {
    Router::new().fallback(dav_handler).with_state(state)
}

async fn dav_handler(State(state): State<AppState>, req: Request) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let body = req.into_body();

    let cfg = { state.config.read().await.files.webdav.clone() };
    if !cfg.enabled {
        return text_response(StatusCode::NOT_FOUND, "webdav service is disabled");
    }

    let creds = parse_basic_auth(&headers);
    let session = match build_session(&cfg, creds.as_ref()) {
        Ok(session) => session,
        Err(()) => return unauthorized_response(),
    };

    let Some(segments) = decode_path_segments(uri.path()) else {
        return text_response(StatusCode::BAD_REQUEST, "malformed path");
    };

    match method.as_str() {
        "OPTIONS" => dav_options(),
        "PROPFIND" => dav_propfind(&session, &segments, &headers, body).await,
        "GET" => dav_get(&session, &segments, false).await,
        "HEAD" => dav_get(&session, &segments, true).await,
        "PUT" => dav_put(&session, &segments, body).await,
        "DELETE" => dav_delete(&session, &segments).await,
        "MKCOL" => dav_mkcol(&session, &segments, body).await,
        "MOVE" => dav_move_or_copy(&session, &segments, &headers, true).await,
        "COPY" => dav_move_or_copy(&session, &segments, &headers, false).await,
        _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    }
}

fn parse_basic_auth(headers: &axum::http::HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (username, password) = text.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

fn dav_options() -> Response {
    build_response(
        StatusCode::OK,
        &[
            ("dav", "1,2"),
            (header::ALLOW.as_str(), DAV_ALLOW),
            (header::CONTENT_LENGTH.as_str(), "0"),
        ],
        Body::empty(),
    )
}

/// Build the `207 Multi-Status` payload for a PROPFIND request.
fn propfind_entry(href: &str, is_dir: bool, size: u64, modified: Option<i64>) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("<D:response><D:href>");
    out.push_str(&xml_escape(href));
    out.push_str("</D:href><D:propstat><D:prop>");
    out.push_str(&format!("<D:getcontentlength>{}</D:getcontentlength>", size));
    if let Some(stamp) = modified {
        out.push_str(&format!(
            "<D:getlastmodified>{}</D:getlastmodified>",
            http_date(stamp)
        ));
    }
    if is_dir {
        out.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
    } else {
        out.push_str("<D:resourcetype></D:resourcetype>");
    }
    out.push_str("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>");
    out
}

fn href_for(session: &Session, target: &Target, is_dir: bool) -> String {
    let mut href = String::from("/");
    if session.roots.len() > 1 {
        href.push_str(&percent_encode(session.roots[target.root].key()));
        href.push('/');
    }
    for segment in &target.rel {
        href.push_str(&percent_encode(segment));
        href.push('/');
    }
    if !is_dir && href.ends_with('/') {
        href.pop();
    }
    href
}

async fn dav_propfind(
    session: &Session,
    segments: &[String],
    headers: &axum::http::HeaderMap,
    body: Body,
) -> Response {
    // The request body may carry a propfind document; it is not needed here.
    let _ = axum::body::to_bytes(body, 1024 * 1024).await;

    let depth = headers
        .get("depth")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("1")
        .trim()
        .to_ascii_lowercase();
    let depth = match depth.as_str() {
        "0" => 0u8,
        "1" => 1,
        _ => 1,
    };

    let target = match resolve_target(session, segments) {
        Ok(Some(target)) => target,
        Ok(None) => {
            // The collection of roots.
            let mut payload = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">");
            for entry in &session.roots {
                let href = format!("/{}/", percent_encode(entry.key()));
                payload.push_str(&propfind_entry(&href, true, 0, None));
            }
            payload.push_str("</D:multistatus>");
            return build_response(
                StatusCode::MULTI_STATUS,
                &[(header::CONTENT_TYPE.as_str(), "application/xml; charset=utf-8")],
                Body::from(payload),
            );
        }
        Err(()) => return text_response(StatusCode::FORBIDDEN, "path escapes the root"),
    };

    let path = target.physical(session);
    if !ensure_within(&session.roots[target.root].path, &path).await {
        return text_response(StatusCode::FORBIDDEN, "path escapes the root");
    }

    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        return text_response(StatusCode::NOT_FOUND, "not found");
    };

    let mut payload = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">");

    if metadata.is_dir() {
        let href = href_for(session, &target, true);
        payload.push_str(&propfind_entry(&href, true, 0, None));
        if depth >= 1 {
            for entry in list_directory(&path).await {
                let mut child = target.clone();
                child.rel.push(entry.name.clone());
                let child_href = href_for(session, &child, entry.is_dir);
                payload.push_str(&propfind_entry(
                    &child_href,
                    entry.is_dir,
                    entry.size,
                    entry.modified,
                ));
            }
        }
    } else {
        let href = href_for(session, &target, false);
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs() as i64);
        payload.push_str(&propfind_entry(&href, false, metadata.len(), modified));
    }

    payload.push_str("</D:multistatus>");
    build_response(
        StatusCode::MULTI_STATUS,
        &[(header::CONTENT_TYPE.as_str(), "application/xml; charset=utf-8")],
        Body::from(payload),
    )
}

/// A simple HTML index for directories.
fn html_index(target: &Session, entries: &[EntryInfo]) -> String {
    let mut out = String::from("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Index</title></head><body><h1>Index</h1><ul>");
    for entry in entries {
        let suffix = if entry.is_dir { "/" } else { "" };
        out.push_str(&format!(
            "<li><a href=\"{}{}\">{}{}</a></li>",
            percent_encode(&entry.name),
            suffix,
            html_escape(&entry.name),
            suffix
        ));
    }
    out.push_str("</ul></body></html>");
    let _ = target;
    out
}

async fn dav_get(session: &Session, segments: &[String], head_only: bool) -> Response {
    let target = match resolve_target(session, segments) {
        Ok(Some(target)) => target,
        Ok(None) => {
            let entries: Vec<EntryInfo> = session
                .roots
                .iter()
                .map(|entry| EntryInfo {
                    name: entry.key().to_string(),
                    is_dir: true,
                    size: 0,
                    modified: None,
                })
                .collect();
            let html = html_index(session, &entries);
            return build_response(
                StatusCode::OK,
                &[(header::CONTENT_TYPE.as_str(), "text/html; charset=utf-8")],
                Body::from(html),
            );
        }
        Err(()) => return text_response(StatusCode::FORBIDDEN, "path escapes the root"),
    };

    let path = target.physical(session);
    if !ensure_within(&session.roots[target.root].path, &path).await {
        return text_response(StatusCode::FORBIDDEN, "path escapes the root");
    }

    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        return text_response(StatusCode::NOT_FOUND, "not found");
    };

    if metadata.is_dir() {
        let entries = list_directory(&path).await;
        let html = html_index(session, &entries);
        return build_response(
            StatusCode::OK,
            &[(header::CONTENT_TYPE.as_str(), "text/html; charset=utf-8")],
            Body::from(html),
        );
    }

    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64);
    let last_modified = modified.map(|stamp| http_date(stamp)).unwrap_or_default();

    let content_length = metadata.len().to_string();
    let mut headers: Vec<(&str, &str)> = vec![
        (header::CONTENT_TYPE.as_str(), content_type_for(&path)),
        (header::CONTENT_LENGTH.as_str(), &content_length),
    ];
    if !last_modified.is_empty() {
        headers.push((header::LAST_MODIFIED.as_str(), &last_modified));
    }

    if head_only {
        return build_response(StatusCode::OK, &headers, Body::empty());
    }

    let Ok(file) = tokio::fs::File::open(&path).await else {
        return text_response(StatusCode::INTERNAL_SERVER_ERROR, "cannot open file");
    };

    build_response(
        StatusCode::OK,
        &headers,
        Body::new(FileBody {
            file,
            buf: vec![0u8; FILE_CHUNK],
        }),
    )
}

/// Streams a file back to the client without buffering it entirely in memory.
struct FileBody {
    file: tokio::fs::File,
    buf: Vec<u8>,
}

impl axum::body::HttpBody for FileBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let mut buf = std::mem::take(&mut this.buf);
        let mut read_buf = ReadBuf::new(buf.as_mut_slice());
        let polled = Pin::new(&mut this.file).poll_read(cx, &mut read_buf);
        match polled {
            Poll::Pending => {
                this.buf = buf;
                Poll::Pending
            }
            Poll::Ready(Err(err)) => {
                this.buf = buf;
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled().len();
                let data = if filled == 0 {
                    None
                } else {
                    Some(Bytes::copy_from_slice(read_buf.filled()))
                };
                drop(read_buf);
                this.buf = buf;
                match data {
                    None => Poll::Ready(None),
                    Some(data) => Poll::Ready(Some(Ok(Frame::data(data)))),
                }
            }
        }
    }
}

/// Copy a request body into a file.
async fn write_body_to_file(body: Body, file: &mut tokio::fs::File) -> std::io::Result<()> {
    let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024).await
        .map_err(|err| std::io::Error::other(format!("failed to read request body: {err}")))?;
    file.write_all(&bytes).await?;
    file.flush().await
}

async fn dav_put(session: &Session, segments: &[String], body: Body) -> Response {
    let target = match resolve_target(session, segments) {
        Ok(Some(target)) => target,
        Ok(None) => return text_response(StatusCode::METHOD_NOT_ALLOWED, "cannot write to the root list"),
        Err(()) => return text_response(StatusCode::FORBIDDEN, "path escapes the root"),
    };

    if session.is_readonly(target.root) {
        return text_response(StatusCode::FORBIDDEN, "root is read-only");
    }

    let path = target.physical(session);
    if !ensure_within(&session.roots[target.root].path, &path).await {
        return text_response(StatusCode::FORBIDDEN, "path escapes the root");
    }

    if let Ok(metadata) = tokio::fs::metadata(&path).await {
        if metadata.is_dir() {
            return text_response(StatusCode::METHOD_NOT_ALLOWED, "target is a collection");
        }
    } else if let Some(parent) = path.parent() {
        if !parent.is_dir() {
            return text_response(StatusCode::CONFLICT, "parent collection does not exist");
        }
    }

    let existed = path.exists();
    let Ok(mut file) = tokio::fs::File::create(&path).await else {
        return text_response(StatusCode::INTERNAL_SERVER_ERROR, "cannot create file");
    };
    if let Err(err) = write_body_to_file(body, &mut file).await {
        let _ = tokio::fs::remove_file(&path).await;
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("cannot write file: {err}"),
        );
    }

    if existed {
        text_response(StatusCode::NO_CONTENT, "")
    } else {
        text_response(StatusCode::CREATED, "created")
    }
}

async fn dav_delete(session: &Session, segments: &[String]) -> Response {
    let target = match resolve_target(session, segments) {
        Ok(Some(target)) => target,
        Ok(None) => return text_response(StatusCode::METHOD_NOT_ALLOWED, "cannot delete the root list"),
        Err(()) => return text_response(StatusCode::FORBIDDEN, "path escapes the root"),
    };

    if session.is_readonly(target.root) {
        return text_response(StatusCode::FORBIDDEN, "root is read-only");
    }

    let path = target.physical(session);
    if !ensure_within(&session.roots[target.root].path, &path).await {
        return text_response(StatusCode::FORBIDDEN, "path escapes the root");
    }

    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        return text_response(StatusCode::NOT_FOUND, "not found");
    };

    let result = if metadata.is_dir() {
        tokio::fs::remove_dir_all(&path).await
    } else {
        tokio::fs::remove_file(&path).await
    };

    match result {
        Ok(()) => text_response(StatusCode::NO_CONTENT, ""),
        Err(err) => text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("cannot delete: {err}"),
        ),
    }
}

async fn dav_mkcol(session: &Session, segments: &[String], body: Body) -> Response {
    // A request body is not allowed for MKCOL.
    if !axum::body::to_bytes(body, 1024 * 1024)
        .await
        .map(|bytes| bytes.is_empty())
        .unwrap_or(true)
    {
        return text_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "MKCOL does not accept a body");
    }

    let target = match resolve_target(session, segments) {
        Ok(Some(target)) => target,
        Ok(None) => return text_response(StatusCode::METHOD_NOT_ALLOWED, "cannot create here"),
        Err(()) => return text_response(StatusCode::FORBIDDEN, "path escapes the root"),
    };

    if session.is_readonly(target.root) {
        return text_response(StatusCode::FORBIDDEN, "root is read-only");
    }

    let path = target.physical(session);
    if !ensure_within(&session.roots[target.root].path, &path).await {
        return text_response(StatusCode::FORBIDDEN, "path escapes the root");
    }
    if path.exists() {
        return text_response(StatusCode::METHOD_NOT_ALLOWED, "resource already exists");
    }
    if let Some(parent) = path.parent() {
        if !parent.is_dir() {
            return text_response(StatusCode::CONFLICT, "parent collection does not exist");
        }
    }

    match tokio::fs::create_dir(&path).await {
        Ok(()) => text_response(StatusCode::CREATED, "created"),
        Err(err) => text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("cannot create collection: {err}"),
        ),
    }
}

/// Extract the path part of a `Destination` header.
fn destination_path(value: &str) -> Option<String> {
    let value = value.trim();
    let path = if let Some((_, rest)) = value.split_once("://") {
        match rest.find('/') {
            Some(idx) => &rest[idx..],
            None => "/",
        }
    } else {
        value
    };
    Some(path.split(['?', '#']).next().unwrap_or("/").to_string())
}

async fn dav_move_or_copy(
    session: &Session,
    segments: &[String],
    headers: &axum::http::HeaderMap,
    is_move: bool,
) -> Response {
    let Some(raw_destination) = headers.get("destination").and_then(|value| value.to_str().ok()) else {
        return text_response(StatusCode::BAD_REQUEST, "missing destination header");
    };
    let Some(destination) = destination_path(raw_destination) else {
        return text_response(StatusCode::BAD_REQUEST, "malformed destination header");
    };
    let Some(destination_segments) = decode_path_segments(&destination) else {
        return text_response(StatusCode::BAD_REQUEST, "malformed destination path");
    };

    let source = match resolve_target(session, segments) {
        Ok(Some(target)) => target,
        Ok(None) => return text_response(StatusCode::METHOD_NOT_ALLOWED, "cannot move the root list"),
        Err(()) => return text_response(StatusCode::FORBIDDEN, "path escapes the root"),
    };
    let destination = match resolve_target(session, &destination_segments) {
        Ok(Some(target)) => target,
        Ok(None) => return text_response(StatusCode::BAD_REQUEST, "invalid destination"),
        Err(()) => return text_response(StatusCode::FORBIDDEN, "destination escapes the root"),
    };

    if session.is_readonly(source.root) || session.is_readonly(destination.root) {
        return text_response(StatusCode::FORBIDDEN, "root is read-only");
    }

    let source_path = source.physical(session);
    let destination_path = destination.physical(session);
    if !ensure_within(&session.roots[source.root].path, &source_path).await
        || !ensure_within(&session.roots[destination.root].path, &destination_path).await
    {
        return text_response(StatusCode::FORBIDDEN, "path escapes the root");
    }

    let Ok(metadata) = tokio::fs::metadata(&source_path).await else {
        return text_response(StatusCode::NOT_FOUND, "not found");
    };

    let overwrite = headers
        .get("overwrite")
        .and_then(|value| value.to_str().ok())
        .map(|value| !value.eq_ignore_ascii_case("F"))
        .unwrap_or(true);
    let destination_exists = destination_path.exists();
    if destination_exists && !overwrite {
        return text_response(StatusCode::PRECONDITION_FAILED, "destination already exists");
    }

    if let Some(parent) = destination_path.parent() {
        if !parent.is_dir() {
            return text_response(StatusCode::CONFLICT, "parent collection does not exist");
        }
    }

    // Moving a collection into itself is not allowed.
    if metadata.is_dir() && destination_path.starts_with(&source_path) {
        return text_response(
            StatusCode::FORBIDDEN,
            "cannot move a collection into itself",
        );
    }

    if destination_exists {
        let removal = if tokio::fs::metadata(&destination_path)
            .await
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
        {
            tokio::fs::remove_dir_all(&destination_path).await
        } else {
            tokio::fs::remove_file(&destination_path).await
        };
        if let Err(err) = removal {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("cannot replace destination: {err}"),
            );
        }
    }

    if is_move {
        if tokio::fs::rename(&source_path, &destination_path).await.is_ok() {
            return if destination_exists {
                text_response(StatusCode::NO_CONTENT, "")
            } else {
                text_response(StatusCode::CREATED, "created")
            };
        }
        // Fall back to copy + delete when the rename crosses a filesystem.
        if let Err(err) = copy_recursive(&source_path, &destination_path).await {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("cannot move: {err}"),
            );
        }
        let removal = if metadata.is_dir() {
            tokio::fs::remove_dir_all(&source_path).await
        } else {
            tokio::fs::remove_file(&source_path).await
        };
        if let Err(err) = removal {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("cannot remove source: {err}"),
            );
        }
    } else if let Err(err) = copy_recursive(&source_path, &destination_path).await {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("cannot copy: {err}"),
        );
    }

    if destination_exists {
        text_response(StatusCode::NO_CONTENT, "")
    } else {
        text_response(StatusCode::CREATED, "created")
    }
}

async fn copy_recursive(source: &Path, destination: &Path) -> std::io::Result<()> {
    let metadata = tokio::fs::metadata(source).await?;
    if metadata.is_dir() {
        tokio::fs::create_dir_all(destination).await?;
        let mut reader = tokio::fs::read_dir(source).await?;
        while let Some(entry) = reader.next_entry().await? {
            let child_source = entry.path();
            let child_destination = destination.join(entry.file_name());
            Box::pin(copy_recursive(&child_source, &child_destination)).await?;
        }
        Ok(())
    } else {
        tokio::fs::copy(source, destination).await.map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// FTP
// ---------------------------------------------------------------------------

/// State of one FTP control connection.
struct FtpSession {
    session: Option<Session>,
    pending_user: Option<String>,
    /// Directory the user is currently in, relative to the current root.
    cwd_root: usize,
    cwd_rel: Vec<String>,
    passive: Option<TcpListener>,
    passive_addr: Option<SocketAddr>,
}

impl FtpSession {
    fn new() -> Self {
        FtpSession {
            session: None,
            pending_user: None,
            cwd_root: 0,
            cwd_rel: Vec::new(),
            passive: None,
            passive_addr: None,
        }
    }
}

/// Split a FTP path into its raw segments.
fn split_ftp_path(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.to_string())
        .collect()
}

/// Resolve a FTP path argument against the current working directory.
fn ftp_resolve(session: &Session, cwd_root: usize, cwd_rel: &[String], argument: &str) -> Result<Target, ()> {
    let argument = argument.trim();
    let (root_idx, segments): (usize, Vec<String>) = if argument.starts_with('/') {
        let segments = split_ftp_path(argument);
        let head = match segments.first() {
            Some(head) => head.clone(),
            None => return Ok(Target {
                root: cwd_root,
                rel: cwd_rel.to_vec(),
            }),
        };
        match session
            .roots
            .iter()
            .position(|entry| entry.key() == head || (!entry.name.is_empty() && entry.name == head))
        {
            Some(idx) => (idx, segments[1..].to_vec()),
            None => {
                if session.roots.len() == 1 {
                    (0, segments)
                } else {
                    return Err(());
                }
            }
        }
    } else {
        let mut segments = cwd_rel.to_vec();
        segments.extend(split_ftp_path(argument));
        (cwd_root, segments)
    };

    let rel = resolve_relative(&segments)?;
    Ok(Target {
        root: root_idx,
        rel,
    })
}

fn ftp_path_display(session: &Session, target: &Target) -> String {
    let mut out = String::from("/");
    out.push_str(session.roots[target.root].key());
    for segment in &target.rel {
        out.push('/');
        out.push_str(segment);
    }
    out.push('/');
    out
}

async fn write_line(writer: &mut tokio::net::tcp::OwnedWriteHalf, line: &str) -> bool {
    let mut buffer = String::with_capacity(line.len() + 2);
    buffer.push_str(line);
    buffer.push_str("\r\n");
    writer.write_all(buffer.as_bytes()).await.is_ok() && writer.flush().await.is_ok()
}

/// Bind a passive data listener inside the configured port range.
async fn open_passive(cfg: &FileServiceConfig, advertised: &str) -> Option<(TcpListener, SocketAddr)> {
    let start = cfg.passive_port_start;
    let end = cfg.passive_port_end;
    if start == 0 || end < start {
        return None;
    }
    let host = if advertised.is_empty() {
        "127.0.0.1"
    } else {
        advertised
    };
    for port in start..=end {
        if let Ok(listener) = TcpListener::bind((host, port)).await {
            let addr = listener.local_addr().ok()?;
            return Some((listener, addr));
        }
    }
    None
}

/// Handle one FTP control connection.
async fn handle_ftp_connection(state: AppState, socket: TcpStream, cfg: FileServiceConfig) {
    let local_ip = socket
        .local_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string());
    let advertised = if local_ip.starts_with("0.") || local_ip == "::" {
        "127.0.0.1".to_string()
    } else {
        local_ip
    };

    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut state = FtpSession::new();
    let mut line = String::new();

    if !write_line(&mut writer, "220 gately-rs FTP service ready").await {
        return;
    }

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let trimmed = line.trim_end_matches(['\r', '\n']).trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        let (command, argument) = match trimmed.split_once(' ') {
            Some((cmd, arg)) => (cmd.to_ascii_uppercase(), arg.trim().to_string()),
            None => (trimmed.to_ascii_uppercase(), String::new()),
        };

        match command.as_str() {
            "USER" => {
                if argument.is_empty() {
                    let _ = write_line(&mut writer, "501 Syntax error in USER parameter.").await;
                    continue;
                }
                state.pending_user = Some(argument.clone());
                let _ = write_line(
                    &mut writer,
                    &format!("331 Password required for {argument}."),
                )
                .await;
            }
            "PASS" => {
                let Some(username) = state.pending_user.take() else {
                    let _ = write_line(&mut writer, "503 Login with USER first.").await;
                    continue;
                };
                let creds = Some((username, argument));
                match build_session(&cfg, creds.as_ref().map(|(u, p)| (u.clone(), p.clone())).as_ref()) {
                    Ok(session) => {
                        state.session = Some(session);
                        state.cwd_root = 0;
                        state.cwd_rel.clear();
                        let _ = write_line(&mut writer, "230 Login successful.").await;
                    }
                    Err(()) => {
                        let _ = write_line(&mut writer, "530 Login incorrect.").await;
                    }
                }
            }
            "QUIT" => {
                let _ = write_line(&mut writer, "221 Goodbye.").await;
                break;
            }
            "NOOP" => {
                let _ = write_line(&mut writer, "200 NOOP ok.").await;
            }
            "FEAT" => {
                let _ = write_line(&mut writer, "211-Features:").await;
                let _ = write_line(&mut writer, " PASV").await;
                let _ = write_line(&mut writer, " SIZE").await;
                let _ = write_line(&mut writer, "211 End").await;
            }
            "TYPE" => {
                let _ = write_line(&mut writer, "200 Type set to I.").await;
            }
            "PASV" => {
                match open_passive(&cfg, &advertised).await {
                    Some((listener, addr)) => {
                        state.passive = Some(listener);
                        state.passive_addr = Some(addr);
                        let ip = addr.ip();
                        let octets = match ip {
                            std::net::IpAddr::V4(v4) => v4.octets(),
                            std::net::IpAddr::V6(_) => [127, 0, 0, 1],
                        };
                        let port = addr.port();
                        let _ = write_line(
                            &mut writer,
                            &format!(
                                "227 Entering Passive Mode ({},{},{},{},{},{})",
                                octets[0],
                                octets[1],
                                octets[2],
                                octets[3],
                                port / 256,
                                port % 256
                            ),
                        )
                        .await;
                    }
                    None => {
                        let _ = write_line(&mut writer, "425 Cannot open passive connection.").await;
                    }
                }
            }
            _ => {
                let Some(session) = state.session.clone() else {
                    let _ = write_line(&mut writer, "530 Please login with USER and PASS.").await;
                    continue;
                };
                let cfg_snapshot = cfg.clone();
                let handled = handle_ftp_authenticated(
                    &mut state,
                    &session,
                    &cfg_snapshot,
                    &command,
                    &argument,
                    &mut writer,
                )
                .await;
                if !handled {
                    let _ = write_line(&mut writer, "500 Unknown command.").await;
                }
            }
        }

        let _ = state.config_snapshot_refresh(&cfg).await;
    }
}

impl FtpSession {
    async fn config_snapshot_refresh(&mut self, _cfg: &FileServiceConfig) -> std::io::Result<()> {
        Ok(())
    }
}

/// Execute an authenticated FTP command.
async fn handle_ftp_authenticated(
    state: &mut FtpSession,
    session: &Session,
    cfg: &FileServiceConfig,
    command: &str,
    argument: &str,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
) -> bool {
    match command {
        "PWD" | "XPWD" => {
            let target = Target {
                root: state.cwd_root,
                rel: state.cwd_rel.clone(),
            };
            let display = ftp_path_display(session, &target);
            write_line(writer, &format!("257 \"{display}\" is the current directory.")).await;
        }
        "CWD" | "XCWD" => {
            match ftp_resolve(session, state.cwd_root, &state.cwd_rel, argument) {
                Ok(target) => {
                    let path = target.physical(session);
                    if path.is_dir() {
                        state.cwd_root = target.root;
                        state.cwd_rel = target.rel;
                        write_line(writer, "250 Directory successfully changed.").await;
                    } else {
                        write_line(writer, "550 Failed to change directory.").await;
                    }
                }
                Err(()) => {
                    write_line(writer, "550 Failed to change directory.").await;
                }
            }
        }
        "CDUP" | "XCUP" => {
            if state.cwd_rel.is_empty() {
                write_line(writer, "550 Failed to change directory.").await;
            } else {
                state.cwd_rel.pop();
                write_line(writer, "250 Directory successfully changed.").await;
            }
        }
        "LIST" | "NLST" => {
            let names_only = command == "NLST";
            let argument = argument
                .strip_prefix('-')
                .map(|rest| rest.trim_start().to_string())
                .unwrap_or_else(|| argument.to_string());
            match ftp_resolve(session, state.cwd_root, &state.cwd_rel, &argument) {
                Ok(target) => {
                    let path = target.physical(session);
                    if !path.is_dir() {
                        write_line(writer, "550 Not a directory.").await;
                        return true;
                    }
                    let entries = list_directory(&path).await;
                    let mut payload = String::new();
                    for entry in entries {
                        if names_only {
                            payload.push_str(&entry.name);
                            payload.push_str("\r\n");
                        } else {
                            let mode = if entry.is_dir { "drwxr-xr-x" } else { "-rw-r--r--" };
                            let stamp = entry.modified.map(http_date).unwrap_or_default();
                            payload.push_str(&format!(
                                "{} {:>10} {} {}\r\n",
                                mode,
                                entry.size,
                                stamp,
                                entry.name
                            ));
                        }
                    }
                    // FTP clients wait for a 1xx reply before connecting to the
                    // passive port; send it first to avoid a deadlock.
                    let _ = write_line(writer, "150 Here comes the directory listing.").await;
                    if ftp_transfer_data(state, writer, payload.as_bytes()).await {
                        let _ = write_line(writer, "226 Transfer complete.").await;
                    } else {
                        let _ = write_line(writer, "426 Transfer aborted.").await;
                    }
                }
                Err(()) => {
                    write_line(writer, "550 Failed to open directory.").await;
                }
            }
        }
        "RETR" => {
            match ftp_resolve(session, state.cwd_root, &state.cwd_rel, argument) {
                Ok(target) => {
                    let path = target.physical(session);
                    if !path.is_file() {
                        write_line(writer, "550 Failed to open file.").await;
                        return true;
                    }
                    let Ok(mut file) = tokio::fs::File::open(&path).await else {
                        write_line(writer, "550 Failed to open file.").await;
                        return true;
                    };
                    write_line(writer, "150 Opening data connection for file.").await;
                    match ftp_accept_data(state).await {
                        Some(mut stream) => {
                            let copied = tokio::io::copy(&mut file, &mut stream).await;
                            let _ = stream.flush().await;
                            let _ = stream.shutdown().await;
                            match copied {
                                Ok(_) => { let _ = write_line(writer, "226 Transfer complete.").await; }
                                Err(_) => { let _ = write_line(writer, "426 Transfer aborted.").await; }
                            }
                        }
                        None => {
                            write_line(writer, "425 Cannot open data connection.").await;
                        }
                    }
                }
                Err(()) => {
                    write_line(writer, "550 Failed to open file.").await;
                }
            }
        }
        "STOR" => {
            match ftp_resolve(session, state.cwd_root, &state.cwd_rel, argument) {
                Ok(target) => {
                    if session.is_readonly(target.root) {
                        write_line(writer, "550 Permission denied.").await;
                        return true;
                    }
                    let path = target.physical(session);
                    let Ok(mut file) = tokio::fs::File::create(&path).await else {
                        write_line(writer, "550 Failed to create file.").await;
                        return true;
                    };
                    write_line(writer, "150 Ok to send data.").await;
                    match ftp_accept_data(state).await {
                        Some(mut stream) => {
                            let copied = tokio::io::copy(&mut stream, &mut file).await;
                            let _ = file.flush().await;
                            match copied {
                                Ok(_) => { let _ = write_line(writer, "226 Transfer complete.").await; }
                                Err(_) => { let _ = write_line(writer, "426 Transfer aborted.").await; }
                            }
                        }
                        None => {
                            write_line(writer, "425 Cannot open data connection.").await;
                        }
                    }
                }
                Err(()) => {
                    write_line(writer, "550 Failed to create file.").await;
                }
            }
        }
        "DELE" => {
            match ftp_resolve(session, state.cwd_root, &state.cwd_rel, argument) {
                Ok(target) => {
                    if session.is_readonly(target.root) {
                        write_line(writer, "550 Permission denied.").await;
                        return true;
                    }
                    let path = target.physical(session);
                    match tokio::fs::remove_file(&path).await {
                        Ok(()) => { let _ = write_line(writer, "250 File deleted.").await; }
                        Err(_) => { let _ = write_line(writer, "550 Failed to delete file.").await; }
                    }
                }
                Err(()) => {
                    write_line(writer, "550 Failed to delete file.").await;
                }
            }
        }
        "MKD" | "XMKD" => {
            match ftp_resolve(session, state.cwd_root, &state.cwd_rel, argument) {
                Ok(target) => {
                    if session.is_readonly(target.root) {
                        write_line(writer, "550 Permission denied.").await;
                        return true;
                    }
                    let path = target.physical(session);
                    match tokio::fs::create_dir(&path).await {
                        Ok(()) => {
                            let _ = write_line(
                                writer,
                                &format!("257 \"{}\" created.", ftp_path_display(session, &target)),
                            ).await;
                        }
                        Err(_) => {
                            let _ = write_line(writer, "550 Failed to create directory.").await;
                        }
                    }
                }
                Err(()) => {
                    write_line(writer, "550 Failed to create directory.").await;
                }
            }
        }
        "RMD" | "XRMD" => {
            match ftp_resolve(session, state.cwd_root, &state.cwd_rel, argument) {
                Ok(target) => {
                    if session.is_readonly(target.root) {
                        write_line(writer, "550 Permission denied.").await;
                        return true;
                    }
                    let path = target.physical(session);
                    match tokio::fs::remove_dir(&path).await {
                        Ok(()) => { let _ = write_line(writer, "250 Directory removed.").await; }
                        Err(_) => { let _ = write_line(writer, "550 Failed to remove directory.").await; }
                    }
                }
                Err(()) => {
                    write_line(writer, "550 Failed to remove directory.").await;
                }
            }
        }
        "SIZE" => {
            match ftp_resolve(session, state.cwd_root, &state.cwd_rel, argument) {
                Ok(target) => {
                    let path = target.physical(session);
                    match tokio::fs::metadata(&path).await {
                        Ok(metadata) if metadata.is_file() => {
                            let _ = write_line(writer, &format!("213 {}", metadata.len())).await;
                        }
                        _ => {
                            let _ = write_line(writer, "550 Could not get file size.").await;
                        }
                    }
                }
                Err(()) => {
                    write_line(writer, "550 Could not get file size.").await;
                }
            }
        }
        "PASV" => {
            // Already handled by the caller.
        }
        _ => return false,
    }
    let _ = cfg;
    true
}

/// Accept a connection on the passive data listener.
async fn ftp_accept_data(state: &mut FtpSession) -> Option<TcpStream> {
    let listener = state.passive.as_ref()?;
    match tokio::time::timeout(FTP_DATA_TIMEOUT, listener.accept()).await {
        Ok(Ok((stream, _))) => Some(stream),
        _ => None,
    }
}

/// Send a payload over the passive data connection.
async fn ftp_transfer_data(state: &mut FtpSession, writer: &mut tokio::net::tcp::OwnedWriteHalf, payload: &[u8]) -> bool {
    let Some(mut stream) = ftp_accept_data(state).await else {
        let _ = write_line(writer, "425 Cannot open data connection.").await;
        return false;
    };
    if stream.write_all(payload).await.is_err() {
        return false;
    }
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
    true
}

// ---------------------------------------------------------------------------
// Supervision
// ---------------------------------------------------------------------------

/// Start the WebDAV and FTP services and keep them in sync with the configuration.
///
/// The configuration is re-read every ten seconds; whenever the file service
/// section changes the affected listener is restarted.
pub fn spawn_file_services(state: AppState) {
    tokio::spawn(async move {
        let mut webdav: Option<(String, JoinHandle<()>)> = None;
        let mut ftp: Option<(String, JoinHandle<()>)> = None;

        loop {
            let files = { state.config.read().await.files.clone() };

            let webdav_signature = serde_json::to_string(&files.webdav).unwrap_or_default();
            let webdav_wanted = files.webdav.enabled && !files.webdav.listen.trim().is_empty();
            let webdav_changed = webdav
                .as_ref()
                .map(|(signature, _)| signature != &webdav_signature)
                .unwrap_or(true);
            if webdav_wanted {
                if webdav_changed {
                    if let Some((_, handle)) = webdav.take() {
                        handle.abort();
                    }
                    let cfg = files.webdav.clone();
                    let state = state.clone();
                    webdav = Some((
                        webdav_signature,
                        tokio::spawn(async move { run_webdav(state, cfg).await }),
                    ));
                }
            } else if let Some((_, handle)) = webdav.take() {
                handle.abort();
            }

            let ftp_signature = serde_json::to_string(&files.ftp).unwrap_or_default();
            let ftp_wanted = files.ftp.enabled && !files.ftp.listen.trim().is_empty();
            let ftp_changed = ftp
                .as_ref()
                .map(|(signature, _)| signature != &ftp_signature)
                .unwrap_or(true);
            if ftp_wanted {
                if ftp_changed {
                    if let Some((_, handle)) = ftp.take() {
                        handle.abort();
                    }
                    let cfg = files.ftp.clone();
                    let state = state.clone();
                    ftp = Some((
                        ftp_signature,
                        tokio::spawn(async move { run_ftp(state, cfg).await }),
                    ));
                }
            } else if let Some((_, handle)) = ftp.take() {
                handle.abort();
            }

            tokio::time::sleep(RELOAD_INTERVAL).await;
        }
    });
}

/// Run the WebDAV listener until the task is aborted.
async fn run_webdav(state: AppState, cfg: FileServiceConfig) {
    let listener = match TcpListener::bind(&cfg.listen).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("[files] webdav bind {} failed: {err}", cfg.listen);
            return;
        }
    };
    eprintln!("[files] webdav listening on {}", cfg.listen);
    let router = dav_router(state);
    if let Err(err) = axum::serve(listener, router.into_make_service()).await {
        eprintln!("[files] webdav stopped: {err}");
    }
}

/// Run the FTP listener until the task is aborted.
async fn run_ftp(state: AppState, cfg: FileServiceConfig) {
    let listener = match TcpListener::bind(&cfg.listen).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("[files] ftp bind {} failed: {err}", cfg.listen);
            return;
        }
    };
    eprintln!("[files] ftp listening on {}", cfg.listen);
    loop {
        let Ok((socket, _peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let state = state.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            handle_ftp_connection(state, socket, cfg).await;
        });
    }
}
