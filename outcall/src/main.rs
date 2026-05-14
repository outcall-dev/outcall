#![forbid(unsafe_code)]

use outcall::{parse_memory_arg, urlencoded};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};
use clap::Parser;
use outcall_api::{
    BridgeStatus, ContainerCreateResult, ContainerInfo, ContainerInspectResult,
    ContainerRemoveResult, ContainerStopResult, DnsCacheDetail, DnsFilterStatus, EvalContext,
    EvaluateRequest, ImagePullResult, NetworkCreateRequest, NetworkCreateResult,
    NetworkDestroyRequest, NetworkDestroyResult, NetworkStatus, ProxyStatus,
};
use serde::Deserialize;

#[derive(Parser)]
#[command(name = "outcall", about = "Outcall host CLI", version)]
struct Cli {
    /// Path to the outcalld host socket
    #[arg(long, default_value = outcall_api::DEFAULT_HOST_SOCKET, global = true)]
    socket: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Manage the network bridge
    Bridge {
        #[command(subcommand)]
        action: BridgeAction,
    },
    /// Manage the DNS filter
    Dns {
        #[command(subcommand)]
        action: DnsAction,
    },
    /// Manage the HTTP proxy
    Proxy {
        #[command(subcommand)]
        action: ProxyAction,
    },
    /// Manage agent containers
    Container {
        #[command(subcommand)]
        action: ContainerAction,
    },
    /// Boot an AI agent for the current project
    Agent {
        /// Custom agent name (default: <folder>-agent)
        #[arg(short, long)]
        name: Option<String>,
        /// Custom Docker image
        #[arg(short, long)]
        image: Option<String>,
        /// Network to connect to
        #[arg(short, long)]
        network: Option<String>,
        /// Workspace mount path inside container
        #[arg(short, long)]
        workspace: Option<String>,
        /// Run in detached mode
        #[arg(short, long)]
        detach: bool,
        /// Stop a running agent
        #[arg(long)]
        stop: bool,
        /// List running agents
        #[arg(long)]
        list: bool,
        /// Show agent logs
        #[arg(long)]
        logs: bool,
        /// Follow log output (with --logs)
        #[arg(short, long)]
        follow: bool,
        /// Initialize .outcall directory with template config
        #[arg(long)]
        init: bool,
        /// Agent name for --stop or --logs
        #[arg(long)]
        agent_name: Option<String>,
        /// Command to pass to agent entrypoint
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Manage outcall networks
    Network {
        #[command(subcommand)]
        action: NetworkAction,
    },
    /// Manage the TLS interception CA (S011)
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
    /// Start, stop, or inspect the outcalld daemon container
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Manage the rule engine (reload from disk, etc.)
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Open the operator dashboard in a browser via a local TCP→unix-socket bridge
    Ui {
        /// TCP port to bind on 127.0.0.1 (default: 8080)
        #[arg(long, default_value_t = 8080)]
        port: u16,
        /// Don't try to launch a browser; just print the URL
        #[arg(long)]
        no_open: bool,
    },
}

#[derive(clap::Subcommand)]
enum RulesAction {
    /// Atomically reload all rule files from the rules.d directory
    Reload,
}

#[derive(clap::Subcommand)]
enum DaemonAction {
    /// Start the outcalld daemon as a Docker container
    Start {
        /// Daemon container image (default: ghcr.io/outcall-dev/outcalld:latest)
        #[arg(long)]
        image: Option<String>,
        /// Bridge interface name (default: outcall0)
        #[arg(long)]
        bridge: Option<String>,
        /// Host directory holding rule YAML files (default: /etc/outcall/rules.d)
        #[arg(long)]
        rules_dir: Option<String>,
        /// Container name (default: outcall-daemon)
        #[arg(long)]
        name: Option<String>,
        /// Disable the in-daemon HTTP proxy (passes --no-proxy to outcalld)
        #[arg(long)]
        no_proxy: bool,
        /// Build the image locally from the given Dockerfile before starting
        #[arg(long)]
        build_from: Option<String>,
    },
    /// Stop and remove the daemon container
    Stop {
        /// Container name (default: outcall-daemon)
        #[arg(long)]
        name: Option<String>,
    },
    /// Show whether the daemon container is running
    Status {
        /// Container name (default: outcall-daemon)
        #[arg(long)]
        name: Option<String>,
    },
    /// Tail the daemon container's stderr/stdout (`docker logs`)
    Logs {
        /// Container name (default: outcall-daemon)
        #[arg(long)]
        name: Option<String>,
        /// Follow log output (Ctrl-C to stop)
        #[arg(short, long)]
        follow: bool,
        /// Show only the last N lines
        #[arg(long, default_value_t = 200)]
        tail: usize,
    },
}

#[derive(clap::Subcommand)]
enum NetworkAction {
    /// Create or reuse an outcall network
    Create {
        /// Name suffix (prepended with `outcall-`). Omit for the default network.
        #[arg(long)]
        name: Option<String>,
        /// Explicit subnet override (CIDR), e.g. 10.200.50.0/24
        #[arg(long)]
        subnet: Option<String>,
        /// Explicit gateway override
        #[arg(long)]
        gateway: Option<String>,
    },
    /// Show a network's status (containers, subnet, gateway)
    Status {
        /// Network name suffix (default: outcall-default)
        #[arg(long)]
        name: Option<String>,
    },
    /// List all outcall-managed networks
    List,
    /// Destroy a network (refuses if any containers connected)
    Destroy {
        /// Name suffix (default: outcall-default)
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(clap::Subcommand)]
enum ProxyAction {
    /// Show HTTP proxy status
    Status,
}

#[derive(clap::Subcommand)]
enum BridgeAction {
    /// Show bridge status
    Status,
    /// Initialize bridge and apply nftables rules
    Up,
    /// Tear down bridge and remove nftables rules
    Down,
}

#[derive(clap::Subcommand)]
enum DnsAction {
    /// Show DNS filter status
    Status,
    /// Test a hostname against the rule engine
    Test {
        hostname: String,
        /// Record type to test (default: A)
        #[arg(long, default_value = "A")]
        r#type: String,
    },
    /// Show DNS cache statistics
    Cache {
        /// Also list cached entries
        #[arg(long)]
        entries: bool,
    },
    /// Flush the DNS cache
    Flush,
}

#[derive(clap::Subcommand)]
enum ContainerAction {
    /// Create and start an agent container
    Create {
        /// Docker image to run
        #[arg(long)]
        image: String,
        /// Outcall-managed network (default: outcall-default)
        #[arg(long)]
        network: Option<String>,
        /// Container name suffix (prepended with outcall-agent-)
        #[arg(long)]
        name: Option<String>,
        /// Memory limit (e.g. 256m, 1g)
        #[arg(long)]
        memory: Option<String>,
        /// CPU shares (default: 1024)
        #[arg(long)]
        cpu_shares: Option<i64>,
    },
    /// List all agent containers
    List,
    /// Inspect a single container
    Inspect {
        /// Container name
        #[arg(long)]
        name: String,
    },
    /// Stop a running container
    Stop {
        /// Container name
        #[arg(long)]
        name: String,
        /// Seconds to wait after SIGTERM before SIGKILL (default: 10)
        #[arg(long)]
        timeout: Option<i64>,
    },
    /// Remove a stopped container
    Remove {
        /// Container name
        #[arg(long)]
        name: String,
        /// Force stop a running container before removal
        #[arg(long)]
        force: bool,
    },
    /// Pull an image from a registry
    Pull {
        /// Docker image (e.g. my-agent:latest)
        #[arg(long)]
        image: String,
    },
}

#[derive(clap::Subcommand)]
enum CaAction {
    /// Initialise a new CA for TLS interception (S011-FR-002)
    Init {
        /// Output directory for ca.crt and ca.key (default: /etc/outcall/ca/)
        #[arg(long)]
        out: Option<String>,
    },
    /// Export the CA certificate bundle for container distribution (S011-FR-018)
    Bundle,
    /// Show loaded CA status (S011-FR-001)
    Status,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Bridge { action } => match action {
            BridgeAction::Status => cmd_bridge_status(&cli.socket),
            BridgeAction::Up => cmd_bridge_up(&cli.socket),
            BridgeAction::Down => cmd_bridge_down(&cli.socket),
        },
        Commands::Dns { action } => match action {
            DnsAction::Status => cmd_dns_status(&cli.socket),
            DnsAction::Test { hostname, r#type } => cmd_dns_test(&cli.socket, &hostname, &r#type),
            DnsAction::Cache { entries } => cmd_dns_cache(&cli.socket, entries),
            DnsAction::Flush => cmd_dns_flush(&cli.socket),
        },
        Commands::Proxy { action } => match action {
            ProxyAction::Status => cmd_proxy_status(&cli.socket),
        },
        Commands::Container { action } => match action {
            ContainerAction::Create {
                image,
                network,
                name,
                memory,
                cpu_shares,
            } => cmd_container_create(&cli.socket, image, network, name, memory, cpu_shares),
            ContainerAction::List => cmd_container_list(&cli.socket),
            ContainerAction::Inspect { name } => cmd_container_inspect(&cli.socket, &name),
            ContainerAction::Stop { name, timeout } => {
                cmd_container_stop(&cli.socket, &name, timeout)
            }
            ContainerAction::Remove { name, force } => {
                cmd_container_remove(&cli.socket, &name, force)
            }
            ContainerAction::Pull { image } => cmd_container_pull(&cli.socket, &image),
        },
        Commands::Agent {
            name,
            image,
            network,
            workspace,
            detach,
            stop,
            list,
            logs,
            follow,
            init,
            agent_name,
            args,
        } => {
            if init {
                let project_dir = std::env::current_dir()?;
                let _ = outcall::agent_boot::init_outcall(&project_dir)?;
                return Ok(());
            }
            
            if list {
                return outcall::agent_boot::list_agents();
            }
            
            if stop {
                let default_name = outcall::agent_boot::auto_detect_name();
                let name = agent_name.as_deref().unwrap_or(&default_name);
                return outcall::agent_boot::stop_agent(name);
            }
            
            if logs {
                let default_name = outcall::agent_boot::auto_detect_name();
                let name = agent_name.as_deref().unwrap_or(&default_name);
                return outcall::agent_boot::agent_logs(name, follow);
            }
            
            // Boot agent
            let project_dir = std::env::current_dir()?;
            let flags = outcall::agent_config::AgentCliFlags {
                image,
                name,
                network,
                workspace,
                detach,
            };
            outcall::agent_boot::boot_agent(&project_dir, flags, args)
        }
        Commands::Network { action } => match action {
            NetworkAction::Create {
                name,
                subnet,
                gateway,
            } => cmd_network_create(&cli.socket, name, subnet, gateway),
            NetworkAction::Status { name } => cmd_network_status(&cli.socket, name.as_deref()),
            NetworkAction::List => cmd_network_list(&cli.socket),
            NetworkAction::Destroy { name } => cmd_network_destroy(&cli.socket, name),
        },
        Commands::Ca { action } => match action {
            CaAction::Init { out } => cmd_ca_init(out),
            CaAction::Bundle => cmd_ca_bundle(&cli.socket),
            CaAction::Status => cmd_ca_status(&cli.socket),
        },
        Commands::Daemon { action } => match action {
            DaemonAction::Start {
                image,
                bridge,
                rules_dir,
                name,
                no_proxy,
                build_from,
            } => cmd_daemon_start(image, bridge, rules_dir, name, no_proxy, build_from),
            DaemonAction::Stop { name } => cmd_daemon_stop(name),
            DaemonAction::Status { name } => cmd_daemon_status(name),
            DaemonAction::Logs { name, follow, tail } => cmd_daemon_logs(name, follow, tail),
        },
        Commands::Rules { action } => match action {
            RulesAction::Reload => cmd_rules_reload(&cli.socket),
        },
        Commands::Ui { port, no_open } => cmd_ui(&cli.socket, port, !no_open),
    }
}

// ── UI command — local TCP → unix-socket bridge for the dashboard ──────────
//
// The host API is served on a Unix domain socket; browsers can't open Unix
// sockets directly. `outcall ui` listens on 127.0.0.1:<port> and forwards each
// connection into the daemon's host socket, byte-for-byte. Equivalent to:
//   socat TCP-LISTEN:8080,reuseaddr,fork UNIX-CONNECT:/run/outcall/host.sock
//
// One OS thread per connection. Fine for a single-operator dashboard;
// blocking I/O keeps the CLI free of an async runtime dependency.

fn cmd_ui(socket: &str, port: u16, auto_open: bool) -> Result<()> {
    use std::net::TcpListener;

    let socket_path = std::path::PathBuf::from(socket);
    if !socket_path.exists() {
        anyhow::bail!(
            "host socket not found at {socket}. Is the daemon running? Try `outcall daemon status`."
        );
    }

    let bind = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&bind)
        .with_context(|| format!("failed to bind {bind}; pick another port with --port"))?;

    let url = format!("http://127.0.0.1:{port}/ui/");
    println!("Dashboard available at: {url}");
    println!("Bridging 127.0.0.1:{port} → {socket}");
    println!("Press Ctrl-C to stop.");

    if auto_open {
        let _ = open_in_browser(&url);
    }

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let target = socket_path.clone();
        std::thread::spawn(move || {
            if let Err(e) = bridge_connection(stream, &target) {
                eprintln!("bridge error: {e}");
            }
        });
    }
    Ok(())
}

fn bridge_connection(tcp: std::net::TcpStream, socket_path: &std::path::Path) -> Result<()> {
    use std::io;
    use std::net::Shutdown;

    let unix = std::os::unix::net::UnixStream::connect(socket_path)
        .context("failed to connect to host socket")?;

    let tcp_clone = tcp.try_clone()?;
    let unix_clone = unix.try_clone()?;

    let upstream = std::thread::spawn(move || {
        let mut r = tcp_clone;
        let mut w = unix_clone;
        let _ = io::copy(&mut r, &mut w);
        let _ = w.shutdown(Shutdown::Write);
    });

    let mut r = unix;
    let mut w = tcp;
    let _ = io::copy(&mut r, &mut w);
    let _ = w.shutdown(Shutdown::Write);
    let _ = upstream.join();
    Ok(())
}

fn open_in_browser(url: &str) -> Result<()> {
    use std::process::Command;
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "explorer"
    } else {
        "xdg-open"
    };
    Command::new(opener).arg(url).spawn()?;
    Ok(())
}

fn cmd_rules_reload(socket: &str) -> Result<()> {
    let body = http_post(socket, "/api/v1/rules/reload")?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;
    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }
    let result: outcall_api::ReloadResult =
        serde_json::from_value(resp.data.context("no data")?)?;
    println!(
        "Reloaded {} rule(s) from {} file(s).",
        result.rules_loaded, result.files_loaded
    );
    for w in &result.warnings {
        println!("  warning: {w}");
    }
    Ok(())
}

// ── Bridge commands ────────────────────────────────────────────────────────

fn cmd_bridge_status(socket: &str) -> Result<()> {
    let body = http_get(socket, "/api/v1/bridge")?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        let msg = resp.error.unwrap_or_else(|| "unknown error".into());
        anyhow::bail!("{msg}");
    }

    let status: BridgeStatus = serde_json::from_value(resp.data.context("no data in response")?)?;

    println!("Bridge:    {}", status.name);
    println!("Status:    {}", if status.up { "up" } else { "down" });
    if let Some(idx) = status.index {
        println!("Index:     {idx}");
    }
    println!(
        "nftables:  {}",
        if status.nftables_active {
            "active"
        } else {
            "inactive"
        }
    );

    Ok(())
}

fn cmd_bridge_up(socket: &str) -> Result<()> {
    let body = http_post(socket, "/api/v1/bridge/up")?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;
    if resp.success {
        println!("Bridge is up.");
    } else {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }
    Ok(())
}

fn cmd_bridge_down(socket: &str) -> Result<()> {
    let body = http_post(socket, "/api/v1/bridge/down")?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;
    if resp.success {
        println!("Bridge is down.");
    } else {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }
    Ok(())
}

// ── DNS commands ───────────────────────────────────────────────────────────

fn cmd_dns_status(socket: &str) -> Result<()> {
    let body = http_get(socket, "/api/v1/dns")?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let status: DnsFilterStatus = serde_json::from_value(resp.data.context("no data")?)?;

    if status.running {
        println!("DNS Filter:     active");
        println!(
            "Listen:         {}:{}",
            status.listen_address, status.listen_port
        );
        println!("Upstreams:      {}", status.upstreams.join(", "));
        println!("Cache:          {} entries", status.cache_entries);
        println!(
            "Queries:        {} total ({} allowed, {} blocked)",
            status.queries_total, status.queries_allowed, status.queries_blocked
        );
    } else {
        println!("DNS Filter:     inactive (bridge not up)");
    }

    Ok(())
}

fn cmd_dns_test(socket: &str, hostname: &str, record_type: &str) -> Result<()> {
    use outcall_api::DnsContext;

    let req = EvaluateRequest {
        context: EvalContext {
            dns: Some(DnsContext {
                query: hostname.to_lowercase(),
                record_type: record_type.to_ascii_uppercase(),
            }),
            ..Default::default()
        },
    };
    let body = http_post_json(socket, "/api/v1/rule/evaluate", &req)?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let result: outcall_api::EvaluateResult =
        serde_json::from_value(resp.data.context("no data")?)?;

    println!("Hostname:       {hostname}");
    println!("Record type:    {record_type}");
    println!(
        "Decision:       {}",
        if matches!(result.decision, outcall_api::Decision::Allow) {
            "ALLOW"
        } else {
            "BLOCK"
        }
    );
    match &result.matched_rule {
        Some(rule) => {
            let file = result.file.as_deref().unwrap_or("?");
            println!("Matched rule:   {rule} ({file})");
        }
        None => println!("Matched rule:   (default policy)"),
    }

    Ok(())
}

fn cmd_dns_cache(socket: &str, show_entries: bool) -> Result<()> {
    let path = if show_entries {
        "/api/v1/dns/cache?entries=true"
    } else {
        "/api/v1/dns/cache"
    };
    let body = http_get(socket, path)?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let detail: DnsCacheDetail = serde_json::from_value(resp.data.context("no data")?)?;
    let s = &detail.stats;

    let hit_rate = if s.hits + s.misses > 0 {
        format!("{:.1}%", s.hits as f64 / (s.hits + s.misses) as f64 * 100.0)
    } else {
        "N/A".to_string()
    };

    println!("Entries:        {} / {}", s.entries, s.max_entries);
    println!("Hits:           {}", s.hits);
    println!("Misses:         {}", s.misses);
    println!("Evictions:      {}", s.evictions);
    println!("Hit rate:       {hit_rate}");

    if show_entries && !detail.entries.is_empty() {
        println!("\n{:<32} {:<6} TTL", "HOSTNAME", "TYPE");
        for e in &detail.entries {
            println!(
                "{:<32} {:<6} {}s",
                e.hostname, e.record_type, e.ttl_remaining_secs
            );
        }
    }

    Ok(())
}

fn cmd_dns_flush(socket: &str) -> Result<()> {
    let body = http_post(socket, "/api/v1/dns/cache/flush")?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let result: outcall_api::DnsCacheFlushResult =
        serde_json::from_value(resp.data.context("no data")?)?;

    println!(
        "DNS cache flushed ({} entries cleared).",
        result.entries_flushed
    );
    Ok(())
}

// ── Proxy commands ─────────────────────────────────────────────────────────

fn cmd_proxy_status(socket: &str) -> Result<()> {
    let body = http_get(socket, "/api/v1/proxy")?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let status: ProxyStatus = serde_json::from_value(resp.data.context("no data")?)?;

    if status.running {
        println!("HTTP Proxy:     active");
        println!("Listen:         {}", status.listen_address);
        println!("Proxy URL:      {}", status.proxy_url);
        println!("Active conns:   {}", status.active_connections);
        println!(
            "Requests:       {} total ({} blocked)",
            status.total_requests, status.total_blocked
        );
    } else {
        println!("HTTP Proxy:     inactive");
    }

    Ok(())
}

// ── Container commands (S008) ──────────────────────────────────────────────

fn cmd_container_create(
    socket: &str,
    image: String,
    network: Option<String>,
    name: Option<String>,
    memory: Option<String>,
    cpu_shares: Option<i64>,
) -> Result<()> {
    let memory_limit = memory.as_deref().map(parse_memory_arg).transpose()?;

    let req = outcall_api::ContainerCreateRequest {
        image,
        network,
        name,
        memory_limit,
        cpu_shares,
        env: None,
        cmd: None,
        volumes: None,
    };

    let body = http_post_json(socket, "/api/v1/container/create", &req)?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let result: ContainerCreateResult = serde_json::from_value(resp.data.context("no data")?)?;
    println!("Container \"{}\" created and started.", result.name);
    Ok(())
}

fn cmd_container_list(socket: &str) -> Result<()> {
    let body = http_get(socket, "/api/v1/containers")?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let containers: Vec<ContainerInfo> = serde_json::from_value(resp.data.context("no data")?)?;

    if containers.is_empty() {
        println!("No agent containers found.");
        return Ok(());
    }

    println!(
        "{:<30} {:<20} {:<10} {:<20} CREATED",
        "NAME", "IMAGE", "STATE", "NETWORK"
    );
    for c in &containers {
        println!(
            "{:<30} {:<20} {:<10} {:<20} {}",
            c.name, c.image, c.state, c.network, c.created_at
        );
    }
    Ok(())
}

fn cmd_container_inspect(socket: &str, name: &str) -> Result<()> {
    let path = format!("/api/v1/container?name={}", urlencoded(name));
    let body = http_get(socket, &path)?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let c: ContainerInspectResult = serde_json::from_value(resp.data.context("no data")?)?;

    println!("Container:    {}", c.name);
    println!("ID:           {}", c.container_id);
    println!("Image:        {}", c.image);
    println!("State:        {}", c.state);
    println!("Network:      {}", c.network);
    println!("IP Address:   {}", c.ip_address);
    if !c.mounts.is_empty() {
        println!("Mounts:");
        for m in &c.mounts {
            println!("  {m}");
        }
    }
    if !c.env.is_empty() {
        println!("Environment:");
        for e in &c.env {
            println!("  {e}");
        }
    }
    println!("Created:      {}", c.created_at);
    Ok(())
}

fn cmd_container_stop(socket: &str, name: &str, timeout: Option<i64>) -> Result<()> {
    let req = outcall_api::ContainerStopRequest {
        name: name.to_string(),
        timeout,
    };
    let body = http_post_json(socket, "/api/v1/container/stop", &req)?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let result: ContainerStopResult = serde_json::from_value(resp.data.context("no data")?)?;
    println!("Container \"{}\" stopped.", result.name);
    Ok(())
}

fn cmd_container_remove(socket: &str, name: &str, force: bool) -> Result<()> {
    let req = outcall_api::ContainerRemoveRequest {
        name: name.to_string(),
        force: Some(force),
    };
    let body = http_post_json(socket, "/api/v1/container/remove", &req)?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let result: ContainerRemoveResult = serde_json::from_value(resp.data.context("no data")?)?;
    println!("Container \"{}\" removed.", result.name);
    Ok(())
}

fn cmd_container_pull(socket: &str, image: &str) -> Result<()> {
    let req = outcall_api::ImagePullRequest {
        image: image.to_string(),
    };
    let body = http_post_json(socket, "/api/v1/container/pull", &req)?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let result: ImagePullResult = serde_json::from_value(resp.data.context("no data")?)?;
    println!("Image \"{}\" pulled.", result.image);
    Ok(())
}

// ── Raw HTTP over unix socket (HTTP/1.0, no extra deps) ────────────────────

/// Minimal response struct — avoids generic deserialization issues.
#[derive(Deserialize)]
struct Response {
    success: bool,
    data: Option<serde_json::Value>,
    error: Option<String>,
}

fn http_get(socket: &str, path: &str) -> Result<String> {
    let mut stream = connect(socket)?;
    write!(stream, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
    read_body(&mut stream)
}

fn http_post(socket: &str, path: &str) -> Result<String> {
    let mut stream = connect(socket)?;
    write!(
        stream,
        "POST {path} HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
    )?;
    read_body(&mut stream)
}

fn http_post_json<T: serde::Serialize>(socket: &str, path: &str, body: &T) -> Result<String> {
    let json = serde_json::to_string(body)?;
    let mut stream = connect(socket)?;
    write!(
        stream,
        "POST {path} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
        json.len()
    )?;
    read_body(&mut stream)
}

fn connect(socket: &str) -> Result<UnixStream> {
    UnixStream::connect(socket)
        .with_context(|| format!("cannot connect to outcalld at {socket} — is it running?"))
}

fn read_body(stream: &mut UnixStream) -> Result<String> {
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;

    buf.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .context("malformed HTTP response from outcalld")
}

// ── Network commands (S002) ────────────────────────────────────────────────

fn cmd_network_create(
    socket: &str,
    name: Option<String>,
    subnet: Option<String>,
    gateway: Option<String>,
) -> Result<()> {
    let req = NetworkCreateRequest {
        name,
        subnet,
        gateway,
    };
    let body = http_post_json(socket, "/api/v1/network/create", &req)?;
    let resp: Response = serde_json::from_str(&body)?;
    if !resp.success {
        eprintln!(
            "Error: {}",
            resp.error.unwrap_or_else(|| "unknown".to_string())
        );
        std::process::exit(1);
    }
    let r: NetworkCreateResult = serde_json::from_value(resp.data.context("no data")?)?;
    if r.created {
        if let Some(s) = r.subnet {
            println!("Network \"{}\" created ({}).", r.name, s);
        } else {
            println!("Network \"{}\" created.", r.name);
        }
    } else {
        println!(
            "Network \"{}\" already exists (id: {}).",
            r.name,
            &r.network_id[..12.min(r.network_id.len())]
        );
    }
    Ok(())
}

fn cmd_network_status(socket: &str, name: Option<&str>) -> Result<()> {
    let path = match name {
        Some(n) => format!("/api/v1/network?name={}", urlencoded(n)),
        None => "/api/v1/network".to_string(),
    };
    let body = http_get(socket, &path)?;
    let resp: Response = serde_json::from_str(&body)?;
    if !resp.success {
        eprintln!(
            "Error: {}",
            resp.error.unwrap_or_else(|| "unknown".to_string())
        );
        std::process::exit(1);
    }
    let s: NetworkStatus = serde_json::from_value(resp.data.context("no data")?)?;
    if !s.exists {
        println!("Network \"{}\" does not exist.", s.name);
        return Ok(());
    }
    println!("Network:      {}", s.name);
    println!("Status:       active");
    if let Some(sub) = &s.subnet {
        println!("Subnet:       {sub}");
    }
    if let Some(gw) = &s.gateway {
        println!("Gateway:      {gw}");
    }
    println!("Containers:   {}", s.containers.len());
    for c in &s.containers {
        println!("  {:<16} {}", c.name, c.ipv4_address);
    }
    Ok(())
}

fn cmd_network_list(socket: &str) -> Result<()> {
    let body = http_get(socket, "/api/v1/networks")?;
    let resp: Response = serde_json::from_str(&body)?;
    if !resp.success {
        eprintln!(
            "Error: {}",
            resp.error.unwrap_or_else(|| "unknown".to_string())
        );
        std::process::exit(1);
    }
    let nets: Vec<NetworkStatus> = serde_json::from_value(resp.data.context("no data")?)?;
    println!("{:<18} {:<16} CONTAINERS", "NAME", "SUBNET");
    for n in nets {
        println!(
            "{:<18} {:<16} {}",
            n.name,
            n.subnet.unwrap_or_else(|| "-".to_string()),
            n.containers.len()
        );
    }
    Ok(())
}

fn cmd_network_destroy(socket: &str, name: Option<String>) -> Result<()> {
    let req = NetworkDestroyRequest { name };
    let body = http_post_json(socket, "/api/v1/network/destroy", &req)?;
    let resp: Response = serde_json::from_str(&body)?;
    if !resp.success {
        eprintln!(
            "Error: {}",
            resp.error.unwrap_or_else(|| "unknown".to_string())
        );
        std::process::exit(1);
    }
    let r: NetworkDestroyResult = serde_json::from_value(resp.data.context("no data")?)?;
    if r.destroyed {
        println!("Network \"{}\" destroyed.", r.name);
    } else {
        println!("Network \"{}\" did not exist.", r.name);
    }
    Ok(())
}

// ── CA commands (S011) ────────────────────────────────────────────────────

fn cmd_ca_init(out_dir: Option<String>) -> Result<()> {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose, SanType, date_time_ymd,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use time::OffsetDateTime;

    let dir = PathBuf::from(out_dir.unwrap_or_else(|| "/etc/outcall/ca".to_string()));

    // Generate 4096-bit RSA CA cert valid 10 years (S011-AS-009).
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Outcall CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // Validity: 10 years from now.
    let now = OffsetDateTime::now_utc();
    let y = now.year();
    let m = now.month() as i32;
    let d = now.day() as i32;
    ca_params.not_before = date_time_ymd(y, m.try_into().unwrap(), d.try_into().unwrap());
    ca_params.not_after = date_time_ymd(y + 10, m.try_into().unwrap(), d.try_into().unwrap());
    ca_params.subject_alt_names = vec![SanType::DnsName("outcall-ca".try_into()?)];

    let ca_key_pair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .map_err(|e| anyhow::anyhow!("failed to generate RSA key pair: {e}"))?;
    let ca_cert = ca_params
        .self_signed(&ca_key_pair)
        .map_err(|e| anyhow::anyhow!("failed to sign CA certificate: {e}"))?;

    let ca_cert_pem = ca_cert.pem();
    let ca_key_pem = ca_key_pair.serialize_pem();

    fs::create_dir_all(&dir).context("failed to create CA directory")?;
    let cert_path = dir.join("ca.crt");
    let key_path = dir.join("ca.key");
    fs::write(&cert_path, &ca_cert_pem).context("failed to write ca.crt")?;
    fs::write(&key_path, &ca_key_pem).context("failed to write ca.key")?;

    // Restrict key file permissions to owner-only.
    let key_perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(&key_path, key_perms).context("failed to set ca.key permissions")?;

    println!(
        "CA initialised in {}\n  cert: {}\n  key:  {}",
        dir.display(),
        cert_path.display(),
        key_path.display()
    );
    println!("Use --ca-cert and --ca-key with outcalld to enable interception.");
    println!("Distribute ca.crt to agent containers as a trusted CA.");
    Ok(())
}

fn cmd_ca_bundle(socket: &str) -> Result<()> {
    let body = http_get(socket, "/api/v1/ca/bundle")?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let bundle: outcall_api::CaBundleResult =
        serde_json::from_value(resp.data.context("no data")?)?;
    print!("{}", bundle.pem_bundle);
    Ok(())
}

fn cmd_ca_status(socket: &str) -> Result<()> {
    let body = http_get(socket, "/api/v1/ca/status")?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let status: outcall_api::CaStatus = serde_json::from_value(resp.data.context("no data")?)?;

    println!("CA loaded:    {}", if status.loaded { "yes" } else { "no" });
    if let Some(cert_path) = status.cert_path {
        println!("Cert:         {cert_path}");
    }
    if let Some(key_path) = status.key_path {
        println!("Key:          {key_path}");
    }
    if let Some(serial) = status.subject_serial {
        println!("Serial:       {serial}");
    }
    println!(
        "Interception: {}",
        if status.interception_enabled {
            "enabled"
        } else {
            "disabled (no CA)"
        }
    );
    Ok(())
}

// ── Daemon commands ────────────────────────────────────────────────────────
//
// These shell out to `docker` to manage the outcalld daemon container.
// Required because outcalld needs Linux netfilter (NET_ADMIN) to function;
// running it in Docker is the supported install path on macOS hosts and the
// recommended isolation boundary on Linux hosts.

const DEFAULT_DAEMON_NAME: &str = "outcall-daemon";
const DEFAULT_DAEMON_IMAGE: &str = "ghcr.io/outcall-dev/outcalld:latest";

fn cmd_daemon_start(
    image: Option<String>,
    bridge: Option<String>,
    rules_dir: Option<String>,
    name: Option<String>,
    no_proxy: bool,
    build_from: Option<String>,
) -> Result<()> {
    use std::process::Command;

    let name = name.unwrap_or_else(|| DEFAULT_DAEMON_NAME.to_string());
    let image = image.unwrap_or_else(|| DEFAULT_DAEMON_IMAGE.to_string());
    let bridge = bridge.unwrap_or_else(|| outcall_api::DEFAULT_BRIDGE_NAME.to_string());
    let rules_dir = rules_dir.unwrap_or_else(|| "/etc/outcall/rules.d".to_string());

    if let Some(dockerfile) = build_from {
        println!("Building image {image} from {dockerfile}…");
        let status = Command::new("docker")
            .args(["build", "-f", &dockerfile, "-t", &image, "."])
            .status()
            .context("failed to invoke docker build")?;
        if !status.success() {
            anyhow::bail!("docker build failed (exit {:?})", status.code());
        }
    }

    // Idempotent: remove any prior container of the same name.
    let _ = Command::new("docker")
        .args(["rm", "-f", &name])
        .output();

    // The daemon binds its Unix sockets inside the container at /run/outcall/.
    // Bind-mounting the host's /run/outcall makes those sockets reachable
    // from host-installed tools (e.g. brew-installed `outcall`, `outcall ui`,
    // anything calling DEFAULT_HOST_SOCKET). The directory must exist on
    // the host before docker run, so we create it idempotently.
    let socket_dir = "/run/outcall";
    if let Err(e) = std::fs::create_dir_all(socket_dir) {
        // Non-fatal warning: on macOS the dir is created inside the Docker
        // VM, not on macOS itself, and the host CLI talks via docker exec.
        eprintln!("note: could not create {socket_dir} on host ({e}); host CLI may need `docker exec {name}` to reach the socket");
    }

    let mut args: Vec<String> = vec![
        "run".into(), "-d".into(), "--name".into(), name.clone(),
        "--network".into(), "host".into(),
        "--cap-add".into(), "NET_ADMIN".into(),
        "--cap-add".into(), "SYS_ADMIN".into(),
        "-v".into(), "/var/run/docker.sock:/var/run/docker.sock".into(),
        "-v".into(), format!("{socket_dir}:{socket_dir}"),
        "-v".into(), format!("{rules_dir}:/etc/outcall/rules.d:ro"),
        "--entrypoint".into(), "outcalld".into(),
        image.clone(),
        "--bridge".into(), bridge.clone(),
    ];
    if no_proxy {
        args.push("--no-proxy".into());
    }

    let output = Command::new("docker")
        .args(&args)
        .output()
        .context("failed to invoke docker run; is Docker installed and running?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("docker run failed: {}", stderr.trim());
    }

    let cid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("Daemon \"{name}\" started ({}, image={image}, bridge={bridge}).",
        cid.chars().take(12).collect::<String>());
    Ok(())
}

fn cmd_daemon_stop(name: Option<String>) -> Result<()> {
    use std::process::Command;
    let name = name.unwrap_or_else(|| DEFAULT_DAEMON_NAME.to_string());
    let output = Command::new("docker")
        .args(["rm", "-f", &name])
        .output()
        .context("failed to invoke docker rm")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such container") {
            println!("Daemon \"{name}\" was not running.");
            return Ok(());
        }
        anyhow::bail!("docker rm failed: {}", stderr.trim());
    }
    println!("Daemon \"{name}\" stopped.");
    Ok(())
}

fn cmd_daemon_logs(name: Option<String>, follow: bool, tail: usize) -> Result<()> {
    use std::process::Command;
    let name = name.unwrap_or_else(|| DEFAULT_DAEMON_NAME.to_string());
    let mut args: Vec<String> = vec!["logs".into(), "--tail".into(), tail.to_string()];
    if follow {
        args.push("-f".into());
    }
    args.push(name.clone());
    let status = Command::new("docker")
        .args(&args)
        .status()
        .context("failed to invoke docker logs")?;
    if !status.success() {
        anyhow::bail!(
            "docker logs failed (exit {:?}); is the container \"{name}\" running?",
            status.code()
        );
    }
    Ok(())
}

fn cmd_daemon_status(name: Option<String>) -> Result<()> {
    use std::process::Command;
    let name = name.unwrap_or_else(|| DEFAULT_DAEMON_NAME.to_string());
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Running}}\t{{.Config.Image}}", &name])
        .output()
        .context("failed to invoke docker inspect")?;
    if !output.status.success() {
        println!("Daemon \"{name}\" is not running (no such container).");
        return Ok(());
    }
    let line = String::from_utf8_lossy(&output.stdout);
    let mut parts = line.trim().splitn(2, '\t');
    let running = parts.next().unwrap_or("false");
    let image = parts.next().unwrap_or("?");
    println!(
        "Daemon \"{name}\": {} (image={image})",
        if running == "true" { "running" } else { "stopped" }
    );
    Ok(())
}
