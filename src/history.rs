use chrono::Utc;
use similar::TextDiff;
use std::fs;
use std::path::{Path, PathBuf};

fn history_dir(config_path: &Path) -> PathBuf {
    let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = config_path.file_stem().and_then(|s| s.to_str()).unwrap_or("gately");
    parent.join(format!("{stem}.history"))
}

fn safe_id(id: &str) -> Result<&str, String> {
    if id.is_empty() || id.contains(['/', '\\']) || id.contains("..") || Path::new(id).file_name().and_then(|s| s.to_str()) != Some(id) {
        return Err("invalid history id".into());
    }
    Ok(id)
}

pub fn snapshot(config_path: &Path, text: &str) -> Result<String, String> {
    let dir = history_dir(config_path);
    fs::create_dir_all(&dir).map_err(|e| format!("create history dir: {e}"))?;
    let id = format!("{}-{}.json", Utc::now().format("%Y%m%d-%H%M%S"), Utc::now().timestamp_millis() % 1000);
    fs::write(dir.join(&id), text).map_err(|e| format!("write snapshot: {e}"))?;
    prune(&dir)?;
    Ok(id)
}

fn prune(dir: &Path) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("read history: {e}"))?
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    entries.sort_by_key(|e| e.file_name());
    while entries.len() > 50 {
        let oldest = entries.remove(0);
        let _ = fs::remove_file(oldest.path());
    }
    Ok(())
}

pub fn list(config_path: &Path) -> Result<Vec<String>, String> {
    let dir = history_dir(config_path);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut ids: Vec<String> = fs::read_dir(dir)
        .map_err(|e| format!("read history: {e}"))?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".json"))
        .collect();
    ids.sort();
    ids.reverse();
    Ok(ids)
}

pub fn read(config_path: &Path, id: &str) -> Result<String, String> {
    let id = safe_id(id)?;
    fs::read_to_string(history_dir(config_path).join(id)).map_err(|e| format!("read snapshot: {e}"))
}

pub fn diff(config_path: &Path, old_id: &str, new_id: &str) -> Result<String, String> {
    let old = read(config_path, old_id)?;
    let new = read(config_path, new_id)?;
    let diff = TextDiff::from_lines(&old, &new);
    Ok(diff.unified_diff().header("old", "new").to_string())
}

pub fn diff_with_current(config_path: &Path, old_id: &str) -> Result<String, String> {
    let old = read(config_path, old_id)?;
    let current = fs::read_to_string(config_path).map_err(|e| format!("read config: {e}"))?;
    let diff = TextDiff::from_lines(&old, &current);
    Ok(diff.unified_diff().header("snapshot", "current").to_string())
}
