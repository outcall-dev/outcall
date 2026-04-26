#[cfg(target_os = "linux")]
mod agent_api;
#[cfg(target_os = "linux")]
mod bridge;
#[cfg(target_os = "linux")]
mod api;
#[cfg(target_os = "linux")]
mod dns;
#[cfg(target_os = "linux")]
mod docker;
#[cfg(target_os = "linux")]
mod dynamic;
#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
mod proxy;
mod rules;

use anyhow::Result;
use clap::Parser;
use tracing::info;

#[derive(Parser)]
#[command(name = "outcalld", about = "Outcall security daemon")]
struct Args {
    /// Path for the host API unix socket
    #[arg(long, default_value = outcall_api::DEFAULT_HOST_SOCKET)]
    socket: String,

    /// Bridge interface name
    #[arg(long, default_value = outcall_api::DEFAULT_BRIDGE_NAME)]
    bridge: String,

    /// Directory containing rule YAML files
    #[arg(long, default_value = "/etc/outcall/rules.d")]
    rules_dir: String,

    /// DNS filter listen address (IP only; port set by --dns-port)
    #[arg(long, default_value = "0.0.0.0")]
    dns_listen: String,

    /// DNS filter listen port
    #[arg(long, default_value_t = 53)]
    dns_port: u16,

    /// Upstream DNS resolvers, comma-separated IP[:port] (default: /etc/resolv.conf)
    #[arg(long, default_value = "")]
    dns_upstream: String,

    /// HTTP proxy listen address (host:port)
    #[arg(long, default_value = "0.0.0.0:8080")]
    proxy_addr: String,

    /// Disable the HTTP proxy entirely
    #[arg(long)]
    no_proxy: bool,

    /// Host path of the agent unix socket to bind-mount into containers
    #[arg(long, default_value = outcall_api::DEFAULT_AGENT_SOCKET)]
    agent_socket_host_path: String,

    /// Host path of the outcall-agent shim binary to bind-mount into containers
    #[arg(long, default_value = "/usr/local/bin/outcall-agent")]
    shim_host_path: String,

    /// Server-side timeout (seconds) for permission-check rule evaluation (S004-FR-015).
    #[arg(long, default_value_t = 5)]
    agent_timeout_secs: u64,

    /// Sliding-window rate limit for agent permission checks, as `<count>/<seconds>`.
    /// Example: `100/10` means 100 checks per 10-second window per container.
    #[arg(long, default_value = "100/10")]
    agent_perm_rate: String,

    /// Sliding-window rate limit for agent rule submissions, as `<count>/<seconds>`.
    /// Example: `10/60` means 10 submissions per 60-second window per container.
    #[arg(long, default_value = "10/60")]
    agent_rule_rate: String,

    /// CIDR block for outcall network /24 auto-allocation (S002-FR-029).
    /// Must be within RFC 1918 private space.
    #[arg(long, default_value = outcall_api::SUBNET_BLOCK)]
    subnet_block: String,
}

/// Parse a rate limit string of the form `<count>/<seconds>`.
fn parse_rate(s: &str) -> (usize, std::time::Duration) {
    let (count_s, window_s) = s
        .split_once('/')
        .unwrap_or((s, "1"));
    let count = count_s.parse().unwrap_or(1);
    let window = std::time::Duration::from_secs(window_s.parse().unwrap_or(1));
    (count, window)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("outcalld=info")
        .init();

    let args = Args::parse();
    info!("outcalld starting");

    #[cfg(target_os = "linux")]
    linux_main(args).await?;

    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        tracing::warn!("outcalld requires Linux for bridge and nftables management");
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn linux_main(args: Args) -> Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Initialize rule engine
    let rule_engine = Arc::new(rules::RuleEngine::load(&args.rules_dir)?);
    info!(rules_dir = %args.rules_dir, "rule engine loaded");

    // Initialize bridge
    let mut mgr = bridge::BridgeManager::new(Some(&args.bridge)).await?;
    mgr.init().await?;

    let bridge = Arc::new(Mutex::new(mgr));

    // Initialize Docker Manager (S008).
    // EC-008 graceful degradation: unavailable Docker does NOT stop the daemon.
    let docker_manager = match docker::DockerManager::new(
        &args.agent_socket_host_path,
        &args.shim_host_path,
    )? {
        Some(mgr) => {
            info!("Docker Manager initialized");
            mgr
        }
        None => {
            info!("Docker Manager unavailable — continuing in degraded mode");
            Arc::new(docker::DockerManager::new_unavailable())
        }
    };

    // Initialize Dynamic Rule Manager (S009) — subscribes to Docker death events.
    let dynamic_mgr = dynamic::DynamicRuleManager::new(docker_manager.clone());
    info!("Dynamic Rule Manager initialized");

    // Initialize DNS filter (FR-003: Tokio task inside outcalld)
    let dns_listen: SocketAddr = format!("{}:{}", args.dns_listen, args.dns_port).parse()?;
    let upstreams = dns::parse_upstream_arg(&args.dns_upstream);
    let dns_server = dns::DnsServer::new(dns_listen, upstreams);
    match dns_server
        .start(rule_engine.clone(), dynamic_mgr.clone())
        .await
    {
        Ok(()) => info!("DNS filter started on {dns_listen}"),
        Err(e) => {
            // EC-008: bind failure doesn't stop the daemon
            tracing::error!("DNS filter failed to start: {e} — continuing without DNS filtering");
        }
    }

    // Initialize HTTP proxy (S006)
    let proxy_server = proxy::ProxyServer::new(
        args.proxy_addr.parse().map_err(|e| anyhow::anyhow!("invalid --proxy-addr: {e}"))?,
    );
    if !args.no_proxy {
        if let Err(e) = proxy_server.start(rule_engine.clone()).await {
            return Err(anyhow::anyhow!(
                "HTTP proxy failed to bind {}: {e}. Set --no-proxy to run without the proxy.",
                args.proxy_addr
            ));
        }
        info!(addr = %args.proxy_addr, "HTTP proxy started");
    } else {
        info!("HTTP proxy disabled (--no-proxy)");
    }

    // Initialize Network Manager (S002).
    let network_mgr = network::NetworkManager::new(
        bridge.clone(),
        &args.bridge,
        &args.subnet_block,
    )?;
    info!(subnet_block = %args.subnet_block, "Network Manager initialized");

    let app = api::router(bridge.clone(), rule_engine.clone(), dns_server.clone(), proxy_server.clone(), docker_manager.clone(), dynamic_mgr, network_mgr);

    // Prepare host socket
    if let Some(parent) = std::path::Path::new(&args.socket).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&args.socket);

    let listener = tokio::net::UnixListener::bind(&args.socket)?;
    info!(socket = %args.socket, "host API listening");

    // Initialize Agent API (S004) — separate listener on agent.sock.
    if let Some(parent) = std::path::Path::new(&args.agent_socket_host_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&args.agent_socket_host_path);
    let agent_listener = tokio::net::UnixListener::bind(&args.agent_socket_host_path)?;
    info!(socket = %args.agent_socket_host_path, "agent API listening");

    let (perm_count, perm_window) = parse_rate(&args.agent_perm_rate);
    let (rule_count, rule_window) = parse_rate(&args.agent_rule_rate);
    // FR-010: path for rule-request queue persistence.
    let rule_state_path = format!("{}/{}", outcall_api::DEFAULT_STATE_DIR, outcall_api::RULE_REQUESTS_FILE);
    // Ensure the state directory exists before loading.
    std::fs::create_dir_all(outcall_api::DEFAULT_STATE_DIR)?;
    let agent_app = agent_api::router(
        docker_manager.clone(),
        rule_engine.clone(),
        std::time::Duration::from_secs(args.agent_timeout_secs),
        perm_count,
        perm_window,
        rule_count,
        rule_window,
        rule_state_path,
    );

    let agent_server = tokio::spawn(async move {
        let make_svc = agent_app
            .into_make_service_with_connect_info::<agent_api::UnixPeerCred>();
        if let Err(e) = axum::serve(agent_listener, make_svc).await {
            tracing::error!("agent API server error: {e}");
        }
    });

    // Run until interrupted (SIGINT or SIGTERM)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");

    tokio::select! {
        result = axum::serve(listener, app) => {
            if let Err(e) = result {
                tracing::error!("API server error: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
        }
        _ = sigterm.recv() => {
            info!("received SIGTERM, shutting down");
        }
    }

    // Cleanup
    proxy_server.shutdown().await;
    dns_server.shutdown().await;
    bridge.lock().await.teardown().await.ok();
    agent_server.abort();
    let _ = std::fs::remove_file(&args.socket);
    let _ = std::fs::remove_file(&args.agent_socket_host_path);
    info!("outcalld stopped");

    Ok(())
}
