use crate::config::Config;
use std::io::{BufRead, Write};
use std::path::Path;

const COMMANDS: [&str; 6] = ["reset-password", "reset-totp", "rollback", "backup", "ctl", "mcp"];

pub fn parse_args(args: Vec<String>) -> Option<(String, Vec<String>)> {
    let mut iter = args.into_iter();
    let first = iter.next()?;
    if !COMMANDS.contains(&first.as_str()) { return None; }
    Some((first, iter.collect()))
}

fn load(path: &Path) -> Result<Config, String> { Config::load(path) }

pub fn run(path: &Path, cmd: &str, args: &[String]) -> Result<String, String> {
    match cmd {
        "reset-password" => {
            let mut cfg = load(path)?;
            let password = args.first().cloned().ok_or("usage: reset-password <new-password>")?;
            cfg.admin.password = password;
            cfg.save(path)?;
            Ok("password reset".into())
        }
        "reset-totp" => {
            let mut cfg = load(path)?;
            cfg.auth.totp_secret = None;
            cfg.auth.require_totp = false;
            cfg.save(path)?;
            Ok("totp reset".into())
        }
        "rollback" => {
            let id = args.first().ok_or("usage: rollback <snapshot-id>")?;
            let text = crate::history::read(path, id)?;
            let cfg: Config = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            cfg.save(path)?;
            Ok(format!("rolled back to {id}"))
        }
        "backup" => {
            let cfg = load(path)?;
            let text = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
            let out = args.first().cloned().unwrap_or_else(|| "gately-backup.json".into());
            std::fs::write(&out, text).map_err(|e| e.to_string())?;
            Ok(format!("backup written to {out}"))
        }
        "ctl" => {
            let endpoint = args.first().map(|s| s.as_str()).ok_or("usage: ctl <path> [json-body]")?;
            let token = args.get(2).cloned().or_else(|| std::env::var("GATELY_TOKEN").ok())
                .ok_or("set GATELY_TOKEN or pass token as third argument")?;
            let base = std::env::var("GATELY_URL").unwrap_or_else(|_| "http://127.0.0.1:16680".into());
            let client = reqwest::blocking::Client::new();
            let mut req = client.request(if args.get(1).is_some() { "POST".parse().unwrap() } else { "GET".parse().unwrap() }, format!("{base}/api{endpoint}"));
            req = req.bearer_auth(&token);
            if let Some(body) = args.get(1) { req = req.header("content-type", "application/json").body(body.clone()); }
            let resp = req.send().map_err(|e| e.to_string())?;
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            if !status.is_success() { return Err(format!("http {status}: {text}")); }
            Ok(text)
        }
        "mcp" => {
            println!("gately-rs MCP bridge (read-only). Send JSON-RPC lines on stdin.");
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let line = match line { Ok(l) => l, Err(_) => break };
                let req: serde_json::Value = match serde_json::from_str(&line) { Ok(v) => v, Err(_) => continue };
                let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
                let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let result = match method {
                    "tools/list" => serde_json::json!({"tools": [
                        {"name": "gately_config", "description": "Read the current gately-rs config"},
                        {"name": "gately_status", "description": "Read runtime status"}
                    ]}),
                    "tools/call" => {
                        let name = req.get("params").and_then(|v| v.get("name")).and_then(|v| v.as_str()).unwrap_or("");
                        let cfg = load(path).unwrap_or_default();
                        match name {
                            "gately_config" => serde_json::to_value(cfg).unwrap_or_default(),
                            "gately_status" => serde_json::json!({"version": env!("CARGO_PKG_VERSION")}),
                            _ => serde_json::json!({"error": "unknown tool"}),
                        }
                    }
                    _ => serde_json::json!({"error": "unknown method"}),
                };
                let response = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result});
                println!("{response}");
                std::io::stdout().flush().ok();
            }
            Ok("mcp stopped".into())
        }
        _ => Err(format!("unknown command: {cmd}")),
    }
}
