use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn collect(dir: &Path, base: &Path, out: &mut Vec<String>) {
    if !dir.is_dir() { return; }
    let mut entries: Vec<_> = fs::read_dir(dir).into_iter().flatten().flatten().collect();
    entries.sort_by_key(|e| e.path());
    for e in entries {
        let p = e.path();
        if p.is_dir() { collect(&p, base, out); continue; }
        if let Ok(rel) = p.strip_prefix(base) {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let source = manifest.join("web-dist");
    println!("cargo:rerun-if-changed=web-dist");

    let mut files = Vec::new();
    collect(&source, &source, &mut files);
    let asset_dir = out.join("assets");
    let _ = fs::remove_dir_all(&asset_dir);
    fs::create_dir_all(&asset_dir).unwrap();

    let mut assets = Vec::new();
    for rel in files {
        let bytes = fs::read(source.join(&rel)).unwrap_or_default();
        let dest = asset_dir.join(&rel);
        if let Some(parent) = dest.parent() { fs::create_dir_all(parent).unwrap(); }
        fs::write(&dest, &bytes).unwrap();
        let escaped = dest.to_string_lossy().replace('\\', "/");
        assets.push(format!("    ({:?}, include_bytes!({:?}).as_slice(), {:?}),", rel, escaped, mime_for(&rel)));
    }

    let index = fs::read_to_string(source.join("index.html")).unwrap_or_else(|_| {
        "<!doctype html><meta charset=utf-8><title>Gately</title><p>web-dist missing</p>".into()
    });
    let index = if index.contains("gately-base") { index } else {
        index.replacen("</head>", "  <meta name=\"gately-base\" content=\"/gately\" />\n  </head>", 1)
    };
    let index_path = out.join("upstream_index.html");
    fs::write(&index_path, index).unwrap();

    let modules = fs::read_to_string(source.join("modules.json")).ok().and_then(|s| {
        let v: serde_json::Value = serde_json::from_str(&s).ok()?;
        let ids = v.get("modules")?.as_array()?;
        Some(ids.iter().filter_map(|m| m.get("id").and_then(|id| id.as_str()).map(str::to_string)).collect::<Vec<_>>())
    }).unwrap_or_else(|| {
        ["webservice", "ssl", "ddns", "cron", "notify", "waf", "guard", "knock", "portforward",
         "protoroute", "stun", "frp", "cloudflared", "tailscale", "netbird", "easytier", "webdav",
         "ftp", "smb", "storage", "filebrowser", "wol", "webterminal", "nettools", "docker",
         "perf", "acme", "ipset", "backup"].iter().map(|s| s.to_string()).collect()
    });
    let modules = modules.iter().map(|m| format!("    {:?},", m)).collect::<Vec<_>>().join("\n");

    let generated = format!(
        "pub static MODULES: &[&str] = &[\n{modules}\n];\n\
         pub static INDEX_HTML: &[u8] = include_bytes!({:?});\n\
         pub static ASSETS: &[(&str, &[u8], &str)] = &[\n{}\n];\n",
        index_path.to_string_lossy().replace('\\', "/"),
        assets.join("\n")
    );
    fs::write(out.join("upstream_assets.rs"), generated).unwrap();
}

fn mime_for(name: &str) -> &'static str {
    if name.ends_with(".html") { "text/html; charset=utf-8" }
    else if name.ends_with(".js") { "text/javascript; charset=utf-8" }
    else if name.ends_with(".css") { "text/css; charset=utf-8" }
    else if name.ends_with(".svg") { "image/svg+xml" }
    else if name.ends_with(".json") || name.ends_with(".webmanifest") { "application/json" }
    else if name.ends_with(".png") { "image/png" }
    else if name.ends_with(".ico") { "image/x-icon" }
    else if name.ends_with(".woff2") { "font/woff2" }
    else { "application/octet-stream" }
}
