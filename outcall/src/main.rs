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
#[command(name = "outcall", about = "Outcall host CLI")]
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
    /// Manage outcall networks
    Network {
        #[command(subcommand)]
        action: NetworkAction,
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
            ContainerAction::Create { image, network, name, memory, cpu_shares } => {
                cmd_container_create(&cli.socket, image, network, name, memory, cpu_shares)
            }
            ContainerAction::List => cmd_container_list(&cli.socket),
            ContainerAction::Inspect { name } => cmd_container_inspect(&cli.socket, &name),
            ContainerAction::Stop { name, timeout } => cmd_container_stop(&cli.socket, &name, timeout),
            ContainerAction::Remove { name, force } => cmd_container_remove(&cli.socket, &name, force),
            ContainerAction::Pull { image } => cmd_container_pull(&cli.socket, &image),
        },
        Commands::Network { action } => match action {
            NetworkAction::Create { name, subnet, gateway } => {
                cmd_network_create(&cli.socket, name, subnet, gateway)
            }
            NetworkAction::Status { name } => cmd_network_status(&cli.socket, name.as_deref()),
            NetworkAction::List => cmd_network_list(&cli.socket),
            NetworkAction::Destroy { name } => cmd_network_destroy(&cli.socket, name),
        },
    }
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
        if status.nftables_active { "active" } else { "inactive" }
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

    let status: DnsFilterStatus =
        serde_json::from_value(resp.data.context("no data")?)?;

    if status.running {
        println!("DNS Filter:     active");
        println!("Listen:         {}:{}", status.listen_address, status.listen_port);
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
        format!(
            "{:.1}%",
            s.hits as f64 / (s.hits + s.misses) as f64 * 100.0
        )
    } else {
        "N/A".to_string()
    };

    println!("Entries:        {} / {}", s.entries, s.max_entries);
    println!("Hits:           {}", s.hits);
    println!("Misses:         {}", s.misses);
    println!("Evictions:      {}", s.evictions);
    println!("Hit rate:       {hit_rate}");

    if show_entries && !detail.entries.is_empty() {
        println!("\n{:<32} {:<6} {}", "HOSTNAME", "TYPE", "TTL");
        for e in &detail.entries {
            println!("{:<32} {:<6} {}s", e.hostname, e.record_type, e.ttl_remaining_secs);
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

    let containers: Vec<ContainerInfo> =
        serde_json::from_value(resp.data.context("no data")?)?;

    if containers.is_empty() {
        println!("No agent containers found.");
        return Ok(());
    }

    println!(
        "{:<30} {:<20} {:<10} {:<20} {}",
        "NAME", "IMAGE", "STATE", "NETWORK", "CREATED"
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
    UnixStream::connect(socket).with_context(|| {
        format!("cannot connect to outcalld at {socket} — is it running?")
    })
}

fn read_body(stream: &mut UnixStream) -> Result<String> {
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;

    buf.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .context("malformed HTTP response from outcalld")
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Parse a human-friendly memory string (e.g. "256m", "1g") to bytes.
fn parse_memory_arg(s: &str) -> Result<i64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('g').or_else(|| s.strip_suffix('G')) {
        (n, 1024 * 1024 * 1024i64)
    } else if let Some(n) = s.strip_suffix('m').or_else(|| s.strip_suffix('M')) {
        (n, 1024 * 1024i64)
    } else if let Some(n) = s.strip_suffix('k').or_else(|| s.strip_suffix('K')) {
        (n, 1024i64)
    } else {
        (s, 1i64)
    };
    let bytes: i64 = num
        .parse()
        .with_context(|| format!("invalid memory value: {s}"))?;
    Ok(bytes * mult)
}

/// Percent-encode a string for use in query parameters (minimal — only encodes spaces).
fn urlencoded(s: &str) -> String {
    s.replace(' ', "%20")
}

// ── Network commands (S002) ────────────────────────────────────────────────

fn cmd_network_create(
    socket: &str,
    name: Option<String>,
    subnet: Option<String>,
    gateway: Option<String>,
) -> Result<()> {
    let req = NetworkCreateRequest { name, subnet, gateway };
    let body = http_post_json(socket, "/api/v1/network/create", &req)?;
    let resp: Response = serde_json::from_str(&body)?;
    if !resp.success {
        eprintln!("Error: {}", resp.error.unwrap_or_else(|| "unknown".to_string()));
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
        println!("Network \"{}\" already exists (id: {}).", r.name, &r.network_id[..12.min(r.network_id.len())]);
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
        eprintln!("Error: {}", resp.error.unwrap_or_else(|| "unknown".to_string()));
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
        eprintln!("Error: {}", resp.error.unwrap_or_else(|| "unknown".to_string()));
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
        eprintln!("Error: {}", resp.error.unwrap_or_else(|| "unknown".to_string()));
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
