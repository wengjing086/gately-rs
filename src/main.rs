mod acme;
mod admin;
mod auth_ext;
mod cli;
mod config;
mod ddns;
mod history;
mod metrics;
mod migrate;
mod notify;
mod portforward;
mod protoroute;
mod proxy;
mod scheduler;
mod site_ext;
mod state;
mod stun;
mod tunnel;
mod waf;

use axum::Extension;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use config::Config;
use proxy::{ListenerCtx, proxy_handler};
use state::AppState;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("gately.json"));

    if let Some((cmd, args)) = cli::parse_args(env::args().skip(1).collect()) {
        match cli::run(&config_path, &cmd, &args) {
            Ok(msg) => { println!("{msg}"); return; }
            Err(err) => { eprintln!("{err}"); std::process::exit(1); }
        }
    }

    let config = match Config::load(&config_path) {
        Ok(config) => config,
        Err(err) => { eprintln!("load config failed: {err}"); return; }
    };

    let admin_listen = config.admin.listen.clone();
    let admin_token = config.admin.token.clone();
    let listeners = config.listeners.clone();
    let certificates = config.certificates.clone();

    let state = AppState::new(config_path.clone(), config);
    ddns::spawn_ddns_loop(state.clone());
    acme::spawn_acme_loop(state.clone());
    stun::spawn_stun_loop(state.clone());
    tunnel::spawn_tunnel_supervisor(state.clone());
    waf::spawn_jail_loop(state.clone());
    waf::spawn_trap_ports(state.clone());
    notify::spawn_notify_loop(state.clone());
    scheduler::spawn_task_loop(state.clone());
    scheduler::spawn_ip_list_loop(state.clone());
    portforward::spawn_port_forward_supervisor(state.clone());
    protoroute::spawn_proto_route_supervisor(state.clone());

    let challenge_state = state.clone();
    tokio::spawn(async move {
        match axum_server::bind("0.0.0.0:80".parse::<SocketAddr>().unwrap())
            .serve(acme::challenge_router(challenge_state).into_make_service()).await
        {
            Ok(_) => {}
            Err(err) => eprintln!("[acme] challenge listener stopped: {err}"),
        }
    });

    for listener in listeners {
        let addr: SocketAddr = match listener.listen.parse() {
            Ok(addr) => addr,
            Err(err) => { eprintln!("[listener {}] invalid address {}: {}", listener.name, listener.listen, err); continue; }
        };
        let router = Router::new()
            .fallback(proxy_handler)
            .layer(Extension(ListenerCtx { name: listener.name.clone() }))
            .with_state(state.clone());
        match &listener.tls_cert {
            Some(cert_id) => {
                let cert = certificates.iter().find(|c| &c.id == cert_id);
                match cert {
                    Some(c) => match RustlsConfig::from_pem_file(&c.cert_path, &c.key_path).await {
                        Ok(tls) => {
                            let name = listener.name.clone();
                            tokio::spawn(async move {
                                if let Err(err) = axum_server::bind_rustls(addr, tls).serve(router.into_make_service()).await {
                                    eprintln!("[listener {name}] stopped: {err}");
                                }
                            });
                        }
                        Err(err) => eprintln!("[listener {}] tls load failed: {}", listener.name, err),
                    },
                    None => eprintln!("[listener {}] certificate {} not found", listener.name, cert_id),
                }
            }
            None => {
                let name = listener.name.clone();
                tokio::spawn(async move {
                    if let Err(err) = axum_server::bind(addr).serve(router.into_make_service()).await {
                        eprintln!("[listener {name}] stopped: {err}");
                    }
                });
            }
        }
        if let Some(port) = listener.http_port {
            let addr: SocketAddr = match format!("0.0.0.0:{port}").parse() { Ok(a) => a, Err(_) => continue };
            let router = Router::new()
                .fallback(proxy_handler)
                .layer(Extension(ListenerCtx { name: listener.name.clone() }))
                .with_state(state.clone());
            let name = listener.name.clone();
            tokio::spawn(async move {
                if let Err(err) = axum_server::bind(addr).serve(router.into_make_service()).await {
                    eprintln!("[listener http {name}] stopped: {err}");
                }
            });
        }
    }

    let admin_addr: SocketAddr = match admin_listen.parse() {
        Ok(addr) => addr,
        Err(err) => { eprintln!("invalid admin address {admin_listen}: {err}"); return; }
    };

    println!("gately-rs {} started", env!("CARGO_PKG_VERSION"));
    println!("config: {}", config_path.display());
    println!("admin:  http://{admin_addr}/  (token: {admin_token})");

    if let Err(err) = axum_server::bind(admin_addr)
        .serve(admin::admin_router(state.clone()).into_make_service()).await
    {
        eprintln!("admin server stopped: {err}");
    }
    tunnel::stop_all(&state).await;
}
