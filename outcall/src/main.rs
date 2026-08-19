#![forbid(unsafe_code)]

use outcall::{parse_memory_arg, request_target};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use outcall_api::{
    ApproveRuleResult, BridgeStatus, ContainerCreateResult, ContainerInfo, ContainerInspectResult,
    ContainerRemoveResult, ContainerStopResult, DnsCacheDetail, DnsFilterStatus, EvalContext,
    EvaluateRequest, ImagePullResult, NetworkCreateRequest, NetworkCreateResult,
    NetworkDestroyRequest, NetworkDestroyResult, NetworkStatus, PendingRuleRequest, ProxyStatus,
    RejectRuleRequest, RejectRuleResult,
};
use serde::Deserialize;
use std::io::IsTerminal;

#[derive(Parser)]
#[command(
    name = "outcall",
    about = "Outcall host CLI",
    version,
    arg_required_else_help = false
)]
struct Cli {
    /// Path to the outcalld host socket
    #[arg(long, default_value = outcall_api::DEFAULT_HOST_SOCKET, global = true)]
    socket: String,

    #[command(subcommand)]
    command: Option<Commands>,
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
    /// Initialize project-local Outcall scaffolding
    Init {
        /// Optional recipe ID to scaffold immediately, e.g. claude or codex
        recipe: Option<String>,
        /// Overwrite existing generated files
        #[arg(long)]
        force: bool,
    },
    /// Check local prerequisites for first-time setup or a specific recipe
    Doctor {
        /// Optional recipe ID to check in detail, e.g. claude or codex
        recipe: Option<String>,
        /// Repair Docker readiness, the project scaffold, daemon image, and managed network
        #[arg(long)]
        fix: bool,
    },
    /// Stage only the selected provider authentication for this project
    Auth {
        /// Recipe ID, e.g. claude or codex
        recipe: String,
        /// How to transfer provider auth/config into the container
        #[arg(long, value_enum, default_value_t = RecipeAuthMode::Auto)]
        auth: RecipeAuthMode,
        /// Re-copy staged auth files even if they already exist
        #[arg(long)]
        force: bool,
    },
    /// Allow a recipe grant, exact HTTPS host, or declared host resource
    Allow {
        /// Recipe ID, e.g. claude or codex
        recipe: String,
        /// Named grant, exact hostname/HTTPS URL, tool:<id>, or file:<id>
        target: String,
    },
    /// Explain the effective project-local rule file for a recipe
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// List Outcall-managed agent containers
    Ps,
    /// Show logs for a managed agent container
    Logs {
        /// Container name
        name: String,
        /// Follow log output
        #[arg(short, long)]
        follow: bool,
    },
    /// Stop a managed agent container
    Stop {
        /// Container name
        name: String,
    },
    /// Initialize, verify, and smoke-test a first-time recipe setup
    Setup {
        /// Optional recipe ID, e.g. claude or codex
        recipe: Option<String>,
        /// Overwrite existing generated files
        #[arg(long)]
        force: bool,
        /// Skip docker build and use the local recipe image as-is
        #[arg(long)]
        no_build: bool,
        /// How to transfer provider auth/config into the container
        #[arg(long, value_enum, default_value_t = RecipeAuthMode::Auto)]
        auth: RecipeAuthMode,
        /// Re-copy staged auth files even if they already exist
        #[arg(long)]
        force_auth_copy: bool,
    },
    /// Initialize and launch a first-time Claude/Codex container in one command
    Run {
        /// Recipe ID, e.g. claude or codex
        recipe: String,
        /// Overwrite existing generated files
        #[arg(long)]
        force: bool,
        /// Skip docker build and use the local recipe image as-is
        #[arg(long)]
        no_build: bool,
        /// How to transfer provider auth/config into the container
        #[arg(long, value_enum, default_value_t = RecipeAuthMode::Auto)]
        auth: RecipeAuthMode,
        /// Re-copy staged auth files even if they already exist
        #[arg(long)]
        force_auth_copy: bool,
        /// Run in detached mode
        #[arg(short, long)]
        detach: bool,
        /// Custom container name (default: <folder>-1, <folder>-2, ...)
        #[arg(long)]
        name: Option<String>,
        /// Arguments passed to the recipe agent entrypoint
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
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
    /// Manage agent rule requests (list, approve, reject)
    Requests {
        #[command(subcommand)]
        action: RequestsAction,
    },
    /// Inspect and initialize agent runtime recipes
    Recipe {
        #[command(subcommand)]
        action: RecipeAction,
    },
    /// Run the host-native broker for explicit host tools/files
    HostBroker {
        #[command(subcommand)]
        action: HostBrokerAction,
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
enum PolicyAction {
    /// List active project rules and the named grants this recipe understands
    Explain {
        /// Recipe ID. Uses the project's selected recipe when omitted.
        recipe: Option<String>,
    },
}

#[derive(clap::Subcommand)]
enum RecipeAction {
    /// List built-in recipes
    List,
    /// Show recipe metadata and generated files
    Show {
        /// Recipe ID, e.g. claude or codex
        id: String,
    },
    /// Initialize .outcall recipe files in the current project
    Init {
        /// Recipe ID, e.g. claude or codex
        id: String,
        /// Overwrite existing generated recipe files
        #[arg(long)]
        force: bool,
    },
    /// Check local prerequisites and context/auth candidates
    Doctor {
        /// Recipe ID, e.g. claude or codex
        id: String,
    },
    /// Smoke-test the recipe image and first-run prerequisites
    Test {
        /// Recipe ID, e.g. claude or codex
        id: String,
        /// Skip docker build and use the local recipe image as-is
        #[arg(long)]
        no_build: bool,
        /// How to transfer provider auth/config into the container
        #[arg(long, value_enum, default_value_t = RecipeAuthMode::Auto)]
        auth: RecipeAuthMode,
        /// Re-copy staged auth files even if they already exist
        #[arg(long)]
        force_auth_copy: bool,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum RecipeAuthMode {
    /// Prefer detected environment credentials, then supported host auth files
    Auto,
    /// Copy selected provider files into .outcall/auth/<recipe>/home
    Copy,
    /// Mount selected provider files directly from the host home directory
    Mount,
    /// Pass only matching environment variables
    EnvOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecipeAuthHint {
    None,
    EnvOnly,
    Copy,
}

#[derive(Clone, Copy, Debug)]
struct AuthStageResult {
    found_auth: bool,
    effective_mode: RecipeAuthMode,
}

#[derive(clap::Subcommand)]
enum RequestsAction {
    /// List all pending rule requests
    List,
    /// Approve a rule request (writes the rule file and reloads the engine)
    Approve {
        /// Rule request ID (e.g. rr-aabbcc112233)
        id: String,
    },
    /// Reject a rule request
    Reject {
        /// Rule request ID (e.g. rr-aabbcc112233)
        id: String,
        /// Optional human-readable rejection reason (stored for audit)
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(clap::Subcommand)]
enum HostBrokerAction {
    /// Serve declared host tools/files over a Unix socket, gated by daemon rules
    Serve {
        /// Unix socket exposed by the host broker
        #[arg(
            long = "broker-socket",
            default_value = "/tmp/outcall-broker/host-broker.sock"
        )]
        broker_socket: String,
        /// Optional path to host-resources.yaml
        #[arg(long)]
        config: Option<String>,
        /// Shared bearer token required by broker clients
        #[arg(long)]
        auth_token: Option<String>,
    },
    /// Serve declared host tools/files over loopback TCP for Docker Desktop
    ServeTcp {
        /// Loopback TCP address exposed through Docker Desktop host forwarding
        #[arg(long)]
        listen: String,
        /// Optional path to host-resources.yaml
        #[arg(long)]
        config: Option<String>,
        /// Shared bearer token required by broker clients
        #[arg(long)]
        auth_token: Option<String>,
    },
}

#[derive(clap::Subcommand)]
enum DaemonAction {
    /// Start the outcalld daemon as a Docker container
    Start {
        /// Daemon container image (default: ghcr.io/outcall-dev/outcalld:v<CURRENT_VERSION>)
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
        /// Host path for the daemon API unix socket
        #[arg(long)]
        socket: Option<String>,
        /// Host path for the agent API unix socket
        #[arg(long)]
        agent_socket_host_path: Option<String>,
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
        None => cmd_onboarding(),
        Some(Commands::Bridge { action }) => match action {
            BridgeAction::Status => cmd_bridge_status(&cli.socket),
            BridgeAction::Up => cmd_bridge_up(&cli.socket),
            BridgeAction::Down => cmd_bridge_down(&cli.socket),
        },
        Some(Commands::Dns { action }) => match action {
            DnsAction::Status => cmd_dns_status(&cli.socket),
            DnsAction::Test { hostname, r#type } => cmd_dns_test(&cli.socket, &hostname, &r#type),
            DnsAction::Cache { entries } => cmd_dns_cache(&cli.socket, entries),
            DnsAction::Flush => cmd_dns_flush(&cli.socket),
        },
        Some(Commands::Proxy { action }) => match action {
            ProxyAction::Status => cmd_proxy_status(&cli.socket),
        },
        Some(Commands::Container { action }) => match action {
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
        Some(Commands::Network { action }) => match action {
            NetworkAction::Create {
                name,
                subnet,
                gateway,
            } => cmd_network_create(&cli.socket, name, subnet, gateway),
            NetworkAction::Status { name } => cmd_network_status(&cli.socket, name.as_deref()),
            NetworkAction::List => cmd_network_list(&cli.socket),
            NetworkAction::Destroy { name } => cmd_network_destroy(&cli.socket, name),
        },
        Some(Commands::Init { recipe, force }) => cmd_init(recipe.as_deref(), force),
        Some(Commands::Doctor { recipe, fix }) => cmd_doctor(&cli.socket, recipe.as_deref(), fix),
        Some(Commands::Auth {
            recipe,
            auth,
            force,
        }) => cmd_auth(&recipe, auth, force),
        Some(Commands::Allow { recipe, target }) => cmd_allow(&cli.socket, &recipe, &target),
        Some(Commands::Policy { action }) => match action {
            PolicyAction::Explain { recipe } => cmd_policy_explain(recipe.as_deref()),
        },
        Some(Commands::Ps) => cmd_container_list(&cli.socket),
        Some(Commands::Logs { name, follow }) => cmd_agent_logs(&name, follow),
        Some(Commands::Stop { name }) => cmd_container_stop(&cli.socket, &name, None),
        Some(Commands::Setup {
            recipe,
            force,
            no_build,
            auth,
            force_auth_copy,
        }) => cmd_setup(
            &cli.socket,
            recipe.as_deref(),
            force,
            no_build,
            auth,
            force_auth_copy,
        ),
        Some(Commands::Run {
            recipe,
            force,
            no_build,
            auth,
            force_auth_copy,
            detach,
            name,
            args,
        }) => cmd_run(
            &cli.socket,
            &recipe,
            force,
            no_build,
            auth,
            force_auth_copy,
            detach,
            name,
            args,
        ),
        Some(Commands::Ca { action }) => match action {
            CaAction::Init { out } => cmd_ca_init(out),
            CaAction::Bundle => cmd_ca_bundle(&cli.socket),
            CaAction::Status => cmd_ca_status(&cli.socket),
        },
        Some(Commands::Daemon { action }) => match action {
            DaemonAction::Start {
                image,
                bridge,
                rules_dir,
                name,
                socket,
                agent_socket_host_path,
                no_proxy,
                build_from,
            } => cmd_daemon_start(
                image,
                bridge,
                rules_dir,
                name,
                socket,
                agent_socket_host_path,
                no_proxy,
                build_from,
            ),
            DaemonAction::Stop { name } => cmd_daemon_stop(name),
            DaemonAction::Status { name } => cmd_daemon_status(name),
            DaemonAction::Logs { name, follow, tail } => cmd_daemon_logs(name, follow, tail),
        },
        Some(Commands::Rules { action }) => match action {
            RulesAction::Reload => cmd_rules_reload(&cli.socket),
        },
        Some(Commands::Requests { action }) => match action {
            RequestsAction::List => cmd_requests_list(&cli.socket),
            RequestsAction::Approve { id } => cmd_requests_approve(&cli.socket, &id),
            RequestsAction::Reject { id, reason } => cmd_requests_reject(&cli.socket, &id, reason),
        },
        Some(Commands::Recipe { action }) => match action {
            RecipeAction::List => cmd_recipe_list(),
            RecipeAction::Show { id } => cmd_recipe_show(&id),
            RecipeAction::Init { id, force } => cmd_recipe_init(&id, force),
            RecipeAction::Doctor { id } => cmd_recipe_doctor(&id),
            RecipeAction::Test {
                id,
                no_build,
                auth,
                force_auth_copy,
            } => cmd_recipe_test(&cli.socket, &id, no_build, auth, force_auth_copy),
        },
        Some(Commands::HostBroker { action }) => match action {
            HostBrokerAction::Serve {
                broker_socket,
                config,
                auth_token,
            } => cmd_host_broker_serve(&cli.socket, &broker_socket, config.as_deref(), auth_token),
            HostBrokerAction::ServeTcp {
                listen,
                config,
                auth_token,
            } => cmd_host_broker_serve_tcp(&cli.socket, &listen, config.as_deref(), auth_token),
        },
        Some(Commands::Ui { port, no_open }) => cmd_ui(&cli.socket, port, !no_open),
    }
}

fn cmd_onboarding() -> Result<()> {
    println!("Outcall");
    println!();
    print_first_run_recommendation();
    println!();
    println!("Common commands:");
    println!("  outcall run claude    # initialize and launch Claude Code");
    println!("  outcall run codex     # initialize and launch Codex CLI");
    println!("  outcall setup         # initialize, verify, and smoke-test without launching");
    println!("  outcall doctor        # inspect Docker, scaffold, and auth detection");
    println!("  outcall recipe list   # show built-in recipes");
    Ok(())
}

#[derive(serde::Deserialize)]
struct BrokerToolExecRequest {
    id: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(serde::Serialize)]
struct BrokerToolExecResult {
    status: i32,
    stdout: String,
    stderr: String,
}

#[derive(serde::Deserialize)]
struct BrokerFileReadRequest {
    id: String,
    #[serde(default)]
    relative_path: Option<String>,
}

#[derive(serde::Serialize)]
struct BrokerFileReadResult {
    path: String,
    contents: String,
}

#[derive(Debug, Clone)]
struct HostBrokerRuntime {
    transport: HostBrokerTransport,
    auth_token: String,
}

#[derive(Debug, Clone)]
enum HostBrokerTransport {
    Unix {
        host_socket: std::path::PathBuf,
        container_socket: String,
    },
    Http {
        listen_addr: std::net::SocketAddr,
        container_url: String,
    },
}

#[derive(Deserialize)]
struct GeneratedHostBrokerRuleFile {
    version: String,
    rules: Vec<GeneratedHostBrokerRule>,
}

#[derive(Deserialize)]
struct GeneratedHostBrokerRule {
    id: String,
    description: String,
    condition: String,
    action: String,
    priority: i32,
    egress: GeneratedHostBrokerEgress,
}

#[derive(Deserialize)]
struct GeneratedHostBrokerEgress {
    mode: String,
    ports: Vec<u16>,
}

fn cmd_host_broker_serve(
    daemon_socket: &str,
    socket: &str,
    config: Option<&str>,
    auth_token: Option<String>,
) -> Result<()> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let config_path = config
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| outcall::host_resources::default_config_path(&project_dir));
    let token = resolve_broker_auth_token(auth_token);
    let token_hint = token.clone();
    let listener = bind_broker_socket(socket)?;

    println!("Host broker listening on {}", socket);
    println!("Config: {}", config_path.display());
    println!("Auth token: {}", token_hint);
    println!(
        "Use this from a trusted client as `Authorization: Bearer {}`.",
        token_hint
    );

    loop {
        let (mut stream, _) = listener.accept().context("host broker accept failed")?;
        configure_unix_broker_stream(&stream)?;
        if let Err(err) = handle_broker_connection(&mut stream, daemon_socket, &config_path, &token)
        {
            let _ = write_http_json(
                &mut stream,
                500,
                &Response {
                    success: false,
                    data: None,
                    error: Some(err.to_string()),
                },
            );
        }
    }
}

fn cmd_host_broker_serve_tcp(
    daemon_socket: &str,
    listen: &str,
    config: Option<&str>,
    auth_token: Option<String>,
) -> Result<()> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let config_path = config
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| outcall::host_resources::default_config_path(&project_dir));
    let token = resolve_broker_auth_token(auth_token);
    let listener = std::net::TcpListener::bind(listen)
        .with_context(|| format!("failed to bind loopback broker at {listen}"))?;
    let local_addr = listener
        .local_addr()
        .context("failed to inspect loopback broker address")?;
    if !local_addr.ip().is_loopback() {
        anyhow::bail!("host broker TCP listener must bind to a loopback address");
    }

    println!("Host broker listening on http://{local_addr}");
    println!("Config: {}", config_path.display());
    println!("Auth token: {token}");

    loop {
        let (mut stream, _) = listener.accept().context("host broker accept failed")?;
        configure_tcp_broker_stream(&stream)?;
        if let Err(err) = handle_broker_connection(&mut stream, daemon_socket, &config_path, &token)
        {
            let _ = write_http_json(
                &mut stream,
                500,
                &Response {
                    success: false,
                    data: None,
                    error: Some(err.to_string()),
                },
            );
        }
    }
}

fn configure_unix_broker_stream(stream: &UnixStream) -> Result<()> {
    let timeout = Some(std::time::Duration::from_secs(10));
    stream
        .set_read_timeout(timeout)
        .context("failed to set host broker read timeout")?;
    stream
        .set_write_timeout(timeout)
        .context("failed to set host broker write timeout")
}

fn configure_tcp_broker_stream(stream: &std::net::TcpStream) -> Result<()> {
    let timeout = Some(std::time::Duration::from_secs(10));
    stream
        .set_read_timeout(timeout)
        .context("failed to set host broker read timeout")?;
    stream
        .set_write_timeout(timeout)
        .context("failed to set host broker write timeout")
}

fn bind_broker_socket(socket: &str) -> Result<std::os::unix::net::UnixListener> {
    let path = std::path::Path::new(socket);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path)
        .with_context(|| format!("failed to bind {}", path.display()))?;
    Ok(listener)
}

fn handle_broker_connection<S: Read + Write>(
    stream: &mut S,
    daemon_socket: &str,
    config_path: &std::path::Path,
    auth_token: &str,
) -> Result<()> {
    let request = read_http_request(stream)?;
    let auth = request
        .headers
        .get("authorization")
        .map(String::as_str)
        .unwrap_or_default();
    let expected = format!("Bearer {auth_token}");
    if auth != expected {
        return write_http_json(
            stream,
            403,
            &Response {
                success: false,
                data: None,
                error: Some("forbidden: invalid broker token".to_string()),
            },
        );
    }

    if request.path == "/v1/health" {
        return write_http_json(
            stream,
            200,
            &Response {
                success: true,
                data: Some(serde_json::json!({"ok": true})),
                error: None,
            },
        );
    }

    let config = outcall::host_resources::load_from_path(config_path)?;
    match request.path.as_str() {
        "/v1/tool/exec" => {
            let req: BrokerToolExecRequest =
                serde_json::from_slice(&request.body).context("invalid tool exec request")?;
            write_broker_result(stream, broker_exec_tool(daemon_socket, &config, req))
        }
        "/v1/file/read" => {
            let req: BrokerFileReadRequest =
                serde_json::from_slice(&request.body).context("invalid file read request")?;
            write_broker_result(stream, broker_read_file(daemon_socket, &config, req))
        }
        _ => write_http_json(
            stream,
            404,
            &Response {
                success: false,
                data: None,
                error: Some(format!("unknown broker path {}", request.path)),
            },
        ),
    }
}

fn write_broker_result<S: Write, T: serde::Serialize>(
    stream: &mut S,
    result: Result<T>,
) -> Result<()> {
    match result {
        Ok(data) => write_http_json(stream, 200, &Response::ok(data)),
        Err(error) => {
            let status = broker_error_status(&error);
            write_http_json(
                stream,
                status,
                &Response {
                    success: false,
                    data: None,
                    error: Some(error.to_string()),
                },
            )
        }
    }
}

fn broker_error_status(error: &anyhow::Error) -> u16 {
    let message = error.to_string();
    if message.starts_with("blocked by rules")
        || message.starts_with("host tool not declared")
        || message.starts_with("host file root not declared")
        || message.contains("escapes declared host file root")
    {
        403
    } else if message.starts_with("relative_path is ") {
        400
    } else {
        500
    }
}

fn broker_exec_tool(
    daemon_socket: &str,
    config: &outcall::host_resources::HostResourcesConfig,
    req: BrokerToolExecRequest,
) -> Result<BrokerToolExecResult> {
    let tool = outcall::host_resources::find_tool(config, &req.id)
        .with_context(|| format!("host tool not declared: {}", req.id))?;
    evaluate_broker_rule(
        daemon_socket,
        EvalContext {
            run: Some(outcall_api::RunContext {
                tool: format!("host.tool.{}", req.id),
                args: req.args.clone(),
                cwd: req.cwd.clone().unwrap_or_default(),
                ..Default::default()
            }),
            ..Default::default()
        },
    )?;

    let project_dir = std::env::current_dir().context("failed to get current project directory")?;
    let path = outcall::host_resources::resolve_tool_path(&project_dir, tool)?;
    let mut command = std::process::Command::new(&path);
    command.args(&tool.default_args).args(&req.args);
    if let Some(cwd) = req.cwd {
        command.current_dir(cwd);
    }
    for (key, value) in &tool.env {
        command.env(key, value);
    }
    let output = command
        .output()
        .with_context(|| format!("failed to execute host tool {}", path.display()))?;
    Ok(BrokerToolExecResult {
        status: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn broker_read_file(
    daemon_socket: &str,
    config: &outcall::host_resources::HostResourcesConfig,
    req: BrokerFileReadRequest,
) -> Result<BrokerFileReadResult> {
    let file = outcall::host_resources::find_file(config, &req.id)
        .with_context(|| format!("host file root not declared: {}", req.id))?;
    let root = outcall::host_resources::expand_home(&file.path);
    let resolved = resolve_host_file_path(&root, req.relative_path.as_deref())?;
    evaluate_broker_rule(
        daemon_socket,
        EvalContext {
            run: Some(outcall_api::RunContext {
                tool: format!("host.file.{}", req.id),
                args: vec![resolved.display().to_string()],
                cwd: resolved.display().to_string(),
                ..Default::default()
            }),
            ..Default::default()
        },
    )?;

    let bytes = std::fs::read(&resolved)
        .with_context(|| format!("failed to read host file {}", resolved.display()))?;
    Ok(BrokerFileReadResult {
        path: resolved.display().to_string(),
        contents: String::from_utf8_lossy(&bytes).to_string(),
    })
}

fn resolve_host_file_path(
    root: &std::path::Path,
    relative: Option<&str>,
) -> Result<std::path::PathBuf> {
    let root = std::fs::canonicalize(root)
        .with_context(|| format!("failed to canonicalize {}", root.display()))?;
    let candidate = if root.is_dir() {
        let relative = relative.context("relative_path is required for directory resources")?;
        root.join(relative)
    } else if relative.is_some() {
        anyhow::bail!("relative_path is not allowed for file resources");
    } else {
        root.clone()
    };
    let resolved = std::fs::canonicalize(&candidate)
        .with_context(|| format!("failed to canonicalize {}", candidate.display()))?;
    if root.is_dir() && !resolved.starts_with(&root) {
        anyhow::bail!("resolved path escapes declared host file root");
    }
    Ok(resolved)
}

fn evaluate_broker_rule(daemon_socket: &str, context: EvalContext) -> Result<()> {
    let req = EvaluateRequest { context };
    let body = http_post_json(daemon_socket, "/api/v1/rule/evaluate", &req)?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;
    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }
    let result: outcall_api::EvaluateResult =
        serde_json::from_value(resp.data.context("no data")?)?;
    if result.decision == outcall_api::Decision::Block {
        anyhow::bail!(
            "blocked by rules{}",
            result
                .matched_rule
                .as_deref()
                .map(|id| format!(" ({id})"))
                .unwrap_or_default()
        );
    }
    Ok(())
}

fn random_broker_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn resolve_broker_auth_token(explicit: Option<String>) -> String {
    explicit
        .or_else(|| std::env::var("OUTCALL_HOST_BROKER_TOKEN").ok())
        .filter(|token| !token.is_empty())
        .unwrap_or_else(random_broker_token)
}

struct RawHttpRequest {
    path: String,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut impl Read) -> Result<RawHttpRequest> {
    const MAX_HEADER_BYTES: usize = 64 * 1024;
    const MAX_BODY_BYTES: usize = 1024 * 1024;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
        if raw.len() >= MAX_HEADER_BYTES {
            anyhow::bail!("broker request headers exceed {MAX_HEADER_BYTES} bytes");
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            anyhow::bail!("unexpected EOF while reading broker request headers");
        }
        raw.extend_from_slice(&chunk[..read]);
    };

    let head = String::from_utf8(raw[..header_end].to_vec()).context("invalid HTTP header")?;
    let mut lines = head.lines();
    let request_line = lines.next().context("missing request line")?;
    let mut parts = request_line.split_whitespace();
    let _method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or("/").to_string();
    let mut headers = std::collections::HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    if headers.contains_key("transfer-encoding") {
        anyhow::bail!("broker requests do not support Transfer-Encoding");
    }
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .context("invalid Content-Length")?
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        anyhow::bail!("broker request body exceeds {MAX_BODY_BYTES} bytes");
    }

    let body_start = header_end + 4;
    let message_end = body_start + content_length;
    while raw.len() < message_end {
        let remaining = message_end - raw.len();
        let read_len = remaining.min(chunk.len());
        let read = stream.read(&mut chunk[..read_len])?;
        if read == 0 {
            anyhow::bail!("unexpected EOF while reading broker request body");
        }
        raw.extend_from_slice(&chunk[..read]);
    }
    let body = raw[body_start..message_end].to_vec();

    Ok(RawHttpRequest {
        path,
        headers,
        body,
    })
}

fn write_http_json<T: serde::Serialize>(
    stream: &mut impl Write,
    status: u16,
    body: &T,
) -> Result<()> {
    let json = serde_json::to_vec(body).context("failed to serialize broker response")?;
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        json.len()
    )?;
    stream.write_all(&json)?;
    Ok(())
}

// ── Recipe commands ───────────────────────────────────────────────────────

fn cmd_init(recipe: Option<&str>, force: bool) -> Result<()> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let outcall_dir = project_dir.join(".outcall");
    let rules_dir = outcall_dir.join("rules");
    std::fs::create_dir_all(&rules_dir)
        .with_context(|| format!("failed to create {}", rules_dir.display()))?;

    println!("Initialized Outcall in {}.", project_dir.display());

    if let Some(id) = recipe {
        let recipe = recipe_or_bail(id)?;
        let written = outcall::recipes::init_recipe(&project_dir, recipe, force)?;
        for path in written {
            println!("  wrote {}", path.display());
        }
        let selected = save_default_recipe(&project_dir, recipe.id)?;
        println!("  wrote {}", selected.display());
        println!("  ensured {}", rules_dir.display());
        println!();
        println!("Next:");
        println!("  outcall run {}", recipe.id);
        println!("  outcall setup         # repeat first-run checks without launching");
        println!("  outcall run {} --detach", recipe.id);
        return Ok(());
    }

    let config_path =
        outcall::agent_config::AgentConfig::save_template_with_force(&project_dir, force)?;
    println!("  wrote {}", config_path.display());
    if let Some(path) = outcall::recipes::ensure_outcall_gitignore(&project_dir)? {
        println!("  wrote {}", path.display());
    }
    println!("  ensured {}", rules_dir.display());

    if load_default_recipe(&project_dir)?.is_none()
        && let Ok(selection) = detect_default_recipe()
        && !matches!(selection.source, RecipeSource::SavedDefault)
    {
        let selected = save_default_recipe(&project_dir, selection.recipe.id)?;
        println!("  wrote {}", selected.display());
        println!(
            "  selected default recipe: {} ({})",
            selection.recipe.id,
            selection.source.label()
        );
    }

    println!();
    println!("Suggested next steps:");
    println!("  outcall doctor");
    println!("  outcall setup");
    println!("  outcall run claude");
    println!("  outcall run codex");
    Ok(())
}

fn cmd_doctor(socket: &str, recipe: Option<&str>, fix: bool) -> Result<()> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;

    println!("Outcall doctor");
    println!("Project: {}", project_dir.display());
    println!();

    doctor_platform();
    doctor_command("docker", &["--version"]);
    doctor_command("git", &["--version"]);
    doctor_docker_engine();
    doctor_socket_dir(std::path::Path::new("/tmp/outcall"));
    doctor_br_netfilter();

    println!();
    println!("Project scaffold:");
    doctor_path("outcall dir", &project_dir.join(".outcall"));
    doctor_path(
        "agent config",
        &project_dir.join(".outcall").join("agent.yaml"),
    );
    doctor_path("rules dir", &project_dir.join(".outcall").join("rules"));
    doctor_path(
        "gitignore",
        &project_dir.join(".outcall").join(".gitignore"),
    );
    if let Some(default_recipe) = load_default_recipe(&project_dir)? {
        doctor_path("default recipe", &default_recipe_path(&project_dir));
        println!("  selected recipe: {}", default_recipe.id);
    } else {
        println!("  default recipe: not set");
    }

    println!();
    println!("Recipes:");
    for recipe in outcall::recipes::RECIPES {
        let manifest = project_dir
            .join(".outcall")
            .join("recipes")
            .join(recipe.id)
            .join("recipe.yaml");
        let status = if manifest.exists() {
            "initialized"
        } else {
            "not initialized"
        };
        let auth_status = if recipe_has_auth_candidate(recipe) {
            "auth candidate found"
        } else {
            "no auth candidate"
        };
        println!("  {:<12} {:<16} {}", recipe.id, status, auth_status);
    }

    println!();
    println!("Managed runtime:");
    println!("  `outcall run <recipe>` starts or reuses the daemon and network automatically.");
    println!("  Manual daemon/network commands are available for troubleshooting.");

    if let Some(id) = recipe {
        println!();
        cmd_recipe_doctor(id)?;
    }

    if recipe.is_none() {
        println!();
        print_first_run_recommendation();
    }

    if fix {
        println!();
        cmd_doctor_fix(socket, recipe)?;
    }

    Ok(())
}

fn cmd_doctor_fix(socket: &str, requested_recipe: Option<&str>) -> Result<()> {
    println!("Applying explicit first-run repairs...");
    ensure_docker_access_with_fix()?;

    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let recipe = match requested_recipe {
        Some(id) => recipe_or_bail(id)?,
        None => detect_default_recipe()?.recipe,
    };
    ensure_recipe_initialized(&project_dir, recipe)?;
    let selected = save_default_recipe(&project_dir, recipe.id)?;
    println!(
        "  PASS project recipe: {} ({})",
        recipe.id,
        selected.display()
    );

    ensure_daemon_image_available()?;
    ensure_recipe_runtime_ready(socket, &project_dir)?;
    ensure_runtime_bridge_netfilter_enforceable()?;
    println!("  PASS managed runtime: daemon and network are ready");
    println!("Repair complete. Start the agent with:");
    println!("  {}", recommended_recipe_command(recipe));
    Ok(())
}

fn cmd_auth(recipe_id: &str, auth_mode: RecipeAuthMode, force: bool) -> Result<()> {
    let recipe = recipe_or_bail(recipe_id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    ensure_recipe_initialized(&project_dir, recipe)?;
    let selected = save_default_recipe(&project_dir, recipe.id)?;
    let image = outcall::recipes::recipe_image_name(recipe);
    let mut config = recipe_agent_config(recipe, &image, true);
    let staged = stage_recipe_auth(&project_dir, recipe, auth_mode, force, &mut config)?;
    if !staged.found_auth {
        anyhow::bail!(
            "no authentication material found for {}. Set one of: {} or sign in with the provider CLI, then rerun `outcall auth {}`",
            recipe.name,
            recipe.auth_env.join(", "),
            recipe.id
        );
    }
    save_auth_preference(&project_dir, recipe, staged.effective_mode)?;

    println!("Authentication ready for {}.", recipe.name);
    println!("  Project recipe: {}", selected.display());
    println!("  Mode: {:?}", staged.effective_mode);
    println!("  Next: {}", recommended_recipe_command(recipe));
    Ok(())
}

fn cmd_allow(socket: &str, recipe_id: &str, target: &str) -> Result<()> {
    let recipe = recipe_or_bail(recipe_id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    ensure_recipe_initialized(&project_dir, recipe)?;
    let change = outcall::policy::allow(&project_dir, recipe, target)?;
    if change.changed {
        println!("Allowed {} for {}.", target, recipe.name);
    } else {
        println!("{} is already allowed for {}.", target, recipe.name);
    }
    println!("  Rules: {}", change.path.display());
    println!("  Default deny remains active for every other destination.");

    if ensure_docker_access().is_ok() && ensure_recipe_runtime_ready(socket, &project_dir).is_ok() {
        println!("  Active: reloaded into the managed daemon.");
    } else {
        println!("  Pending: the grant will load when you next run this recipe.");
    }
    Ok(())
}

fn cmd_policy_explain(requested_recipe: Option<&str>) -> Result<()> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let recipe = match requested_recipe {
        Some(id) => recipe_or_bail(id)?,
        None => detect_default_recipe()?.recipe,
    };
    let rules = outcall::policy::explain(&project_dir, recipe)?;
    println!(
        "Policy: {} ({})",
        recipe.id,
        outcall::policy::rule_path(&project_dir, recipe).display()
    );
    println!("Default: block every destination not listed below.");
    if rules.is_empty() {
        println!("  No allow rules are configured.");
    } else {
        for rule in rules {
            match rule.description {
                Some(description) => println!("  {} - {}", rule.id, description),
                None => println!("  {}", rule.id),
            }
        }
    }
    let templates = outcall::policy::template_names(recipe).collect::<Vec<_>>();
    if !templates.is_empty() {
        println!("Named grants: {}", templates.join(", "));
    }
    Ok(())
}

fn cmd_agent_logs(name: &str, follow: bool) -> Result<()> {
    let mut args = vec!["logs"];
    if follow {
        args.push("--follow");
    }
    args.push(name);
    let status = std::process::Command::new("docker")
        .args(args)
        .status()
        .context("failed to invoke docker logs")?;
    if !status.success() {
        anyhow::bail!("docker logs failed for {name}");
    }
    Ok(())
}

fn cmd_setup(
    socket: &str,
    id: Option<&str>,
    force: bool,
    no_build: bool,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
) -> Result<()> {
    let selection = match id {
        Some(id) => RecipeSelection {
            recipe: recipe_or_bail(id)?,
            source: RecipeSource::Explicit,
        },
        None => detect_default_recipe()?,
    };
    println!(
        "Setting up recipe: {} ({})",
        selection.recipe.id,
        selection.source.label()
    );
    println!();
    cmd_setup_inner(
        socket,
        selection.recipe.id,
        force,
        no_build,
        auth_mode,
        force_auth_copy,
        true,
    )
}

fn cmd_setup_inner(
    socket: &str,
    id: &str,
    force: bool,
    no_build: bool,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
    print_next: bool,
) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;

    println!("Outcall setup: {} ({})", recipe.id, recipe.name);
    println!("Project:       {}", project_dir.display());
    println!();

    ensure_recipe_setup_state(&project_dir, recipe, force)?;
    println!();
    cmd_recipe_doctor(recipe.id)?;

    if let Some(message) = containerized_runtime_note() {
        println!();
        println!("{message}");
    }

    println!();
    cmd_recipe_test(socket, recipe.id, no_build, auth_mode, force_auth_copy)?;
    if print_next {
        println!();
        println!("Setup complete.");
        println!("Next:");
        println!("  {}", recommended_recipe_command(recipe));
        println!("  {} --detach", recommended_recipe_command(recipe));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_run(
    socket: &str,
    id: &str,
    force: bool,
    no_build: bool,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
    detach: bool,
    name: Option<String>,
    args: Vec<String>,
) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let needs_setup = force || !recipe_setup_is_complete(&project_dir, recipe);
    if needs_setup {
        cmd_setup_inner(
            socket,
            id,
            force,
            no_build,
            auth_mode,
            force_auth_copy,
            false,
        )?;
    } else {
        println!("Project recipe is ready; starting {}.", recipe.name);
    }
    save_default_recipe(&project_dir, recipe.id)?;
    println!();
    cmd_recipe_run(
        socket,
        id,
        no_build || needs_setup,
        auth_mode,
        force_auth_copy,
        detach,
        name,
        args,
    )
}

fn recipe_or_bail(id: &str) -> Result<&'static outcall::recipes::Recipe> {
    outcall::recipes::get_recipe(id).with_context(|| {
        let ids = outcall::recipes::recipe_ids()
            .collect::<Vec<_>>()
            .join(", ");
        format!("unknown recipe \"{id}\"; available recipes: {ids}")
    })
}

fn auth_hint(env_auth: bool, file_auth: bool) -> RecipeAuthHint {
    match (env_auth, file_auth) {
        (true, false) => RecipeAuthHint::EnvOnly,
        (_, true) => RecipeAuthHint::Copy,
        (false, false) => RecipeAuthHint::None,
    }
}

fn recommended_recipe_command(recipe: &outcall::recipes::Recipe) -> String {
    recommended_recipe_command_with_hint(recipe, default_auth_hint_for_recipe(recipe))
}

fn recommended_recipe_command_with_hint(
    recipe: &outcall::recipes::Recipe,
    hint: RecipeAuthHint,
) -> String {
    match hint {
        RecipeAuthHint::EnvOnly => format!("outcall run {} --auth env-only", recipe.id),
        RecipeAuthHint::Copy | RecipeAuthHint::None => format!("outcall run {}", recipe.id),
    }
}

fn default_auth_hint_for_recipe(recipe: &outcall::recipes::Recipe) -> RecipeAuthHint {
    if should_prefer_env_only_auth(recipe) {
        RecipeAuthHint::EnvOnly
    } else {
        RecipeAuthHint::Copy
    }
}

fn recipe_has_user_auth_paths(recipe: &outcall::recipes::Recipe) -> bool {
    recipe
        .user_paths
        .iter()
        .map(|path| outcall::recipes::expanded_path(path))
        .any(|path| path.exists())
}

fn recipe_has_auth_candidate(recipe: &outcall::recipes::Recipe) -> bool {
    recipe_has_env_auth(recipe) || recipe_has_user_auth_paths(recipe)
}

fn recipe_has_project_context(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
) -> bool {
    recipe
        .project_paths
        .iter()
        .map(|path| project_dir.join(path))
        .any(|path| path.exists())
}

fn recipe_has_env_auth(recipe: &outcall::recipes::Recipe) -> bool {
    recipe
        .auth_env
        .iter()
        .any(|key| std::env::var_os(key).is_some())
}

fn detect_recipe_candidates() -> Vec<&'static outcall::recipes::Recipe> {
    outcall::recipes::RECIPES
        .iter()
        .filter(|recipe| recipe_has_auth_candidate(recipe))
        .collect::<Vec<_>>()
}

struct RecipeSelection {
    recipe: &'static outcall::recipes::Recipe,
    source: RecipeSource,
}

enum RecipeSource {
    Explicit,
    SavedDefault,
    ProjectContext,
    HostAuth,
}

impl RecipeSource {
    fn label(&self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::SavedDefault => "saved project default",
            Self::ProjectContext => "project context",
            Self::HostAuth => "host auth",
        }
    }
}

fn default_recipe_path(project_dir: &std::path::Path) -> std::path::PathBuf {
    project_dir.join(".outcall").join("default-recipe")
}

fn save_default_recipe(project_dir: &std::path::Path, recipe: &str) -> Result<std::path::PathBuf> {
    let path = default_recipe_path(project_dir);
    std::fs::write(&path, format!("{recipe}\n"))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn load_default_recipe(
    project_dir: &std::path::Path,
) -> Result<Option<&'static outcall::recipes::Recipe>> {
    let path = default_recipe_path(project_dir);
    if !path.exists() {
        return Ok(None);
    }
    let recipe_id = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let recipe_id = recipe_id.trim();
    if recipe_id.is_empty() {
        return Ok(None);
    }
    let recipe = outcall::recipes::get_recipe(recipe_id)
        .with_context(|| format!("invalid recipe id {:?} in {}", recipe_id, path.display()))?;
    Ok(Some(recipe))
}

fn detect_default_recipe() -> Result<RecipeSelection> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    if let Some(recipe) = load_default_recipe(&project_dir)? {
        return Ok(RecipeSelection {
            recipe,
            source: RecipeSource::SavedDefault,
        });
    }

    let context_candidates = outcall::recipes::RECIPES
        .iter()
        .filter(|recipe| recipe_has_project_context(&project_dir, recipe))
        .collect::<Vec<_>>();
    match context_candidates.as_slice() {
        [recipe] => {
            return Ok(RecipeSelection {
                recipe,
                source: RecipeSource::ProjectContext,
            });
        }
        [] => {}
        many => {
            let ids = many
                .iter()
                .map(|recipe| recipe.id)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "found project context for multiple agents ({ids}); choose one explicitly:\n  outcall run claude\n  outcall run codex"
            )
        }
    }

    let candidates = detect_recipe_candidates();

    match candidates.as_slice() {
        [recipe] => Ok(RecipeSelection {
            recipe,
            source: RecipeSource::HostAuth,
        }),
        [] => anyhow::bail!(
            "could not infer which agent to start; no Claude or Codex auth candidates were found.\n\
             Run `outcall doctor`, then choose one explicitly:\n  outcall run claude\n  outcall run codex"
        ),
        many => {
            let ids = many
                .iter()
                .map(|recipe| recipe.id)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "found auth candidates for multiple agents ({ids}); choose one explicitly:\n  outcall run claude\n  outcall run codex"
            )
        }
    }
}

fn print_first_run_recommendation() {
    let project_dir = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(_) => {
            println!("Recommended first command:");
            println!("  outcall run codex");
            return;
        }
    };

    if let Ok(Some(recipe)) = load_default_recipe(&project_dir) {
        println!("Recommended first command:");
        println!("  outcall run {}", recipe.id);
        println!("  # project default recipe: {}", recipe.id);
        return;
    }

    let context_candidates = outcall::recipes::RECIPES
        .iter()
        .filter(|recipe| recipe_has_project_context(&project_dir, recipe))
        .collect::<Vec<_>>();
    match context_candidates.as_slice() {
        [recipe] => {
            println!("Recommended first command:");
            println!("  outcall run {}", recipe.id);
            println!("  # detected {} project context in this repo", recipe.name);
            return;
        }
        [] => {}
        many => {
            let ids = many
                .iter()
                .map(|recipe| recipe.id)
                .collect::<Vec<_>>()
                .join(", ");
            println!("Recommended first command:");
            println!("  outcall run claude");
            println!("  outcall run codex");
            println!("  # multiple project context candidates detected: {ids}");
            return;
        }
    }

    match detect_recipe_candidates().as_slice() {
        [recipe] => {
            println!("Recommended first command:");
            println!("  outcall run {}", recipe.id);
            println!("  # detected {} auth/config on this host", recipe.name);
        }
        [] => {
            println!("Recommended first command:");
            println!("  outcall run claude     # choose Claude explicitly");
            println!("  outcall run codex      # choose Codex explicitly");
        }
        many => {
            let ids = many
                .iter()
                .map(|recipe| recipe.id)
                .collect::<Vec<_>>()
                .join(", ");
            println!("Recommended first command:");
            println!("  outcall run claude");
            println!("  outcall run codex");
            println!("  # multiple auth candidates detected: {ids}");
        }
    }
}

fn cmd_recipe_list() -> Result<()> {
    println!("{:<12} {:<18} SUMMARY", "ID", "NAME");
    for recipe in outcall::recipes::RECIPES {
        println!("{:<12} {:<18} {}", recipe.id, recipe.name, recipe.summary);
    }
    Ok(())
}

fn cmd_recipe_show(id: &str) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    println!("Recipe:       {}", recipe.id);
    println!("Name:         {}", recipe.name);
    println!("Summary:      {}", recipe.summary);
    println!("Auth env:     {}", recipe.auth_env.join(", "));
    println!("User paths:   {}", recipe.user_paths.join(", "));
    println!("Project paths: {}", recipe.project_paths.join(", "));
    println!();
    println!("Generated files:");
    println!("  .outcall/recipes/{}/recipe.yaml", recipe.id);
    println!("  .outcall/recipes/{}/Dockerfile", recipe.id);
    println!("  .outcall/recipes/{}/README.md", recipe.id);
    println!("  .outcall/recipes/{}/context.md", recipe.id);
    println!("  .outcall/rules/{}.yaml", recipe.id);
    println!("  .outcall/agent.yaml");
    println!();
    println!("Manifest:");
    print!("{}", recipe.manifest);
    Ok(())
}

fn cmd_recipe_init(id: &str, force: bool) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let written = outcall::recipes::init_recipe(&project_dir, recipe, force)?;

    println!(
        "Initialized recipe \"{}\" in {}.",
        recipe.id,
        project_dir.display()
    );
    for path in written {
        println!("  wrote {}", path.display());
    }
    println!();
    println!("Next:");
    println!("  {}", recommended_recipe_command(recipe));
    Ok(())
}

fn cmd_recipe_doctor(id: &str) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;

    println!("Recipe doctor: {} ({})", recipe.id, recipe.name);
    println!("Project:       {}", project_dir.display());
    println!();

    doctor_platform();
    doctor_command("docker", &["--version"]);
    doctor_command("git", &["--version"]);
    doctor_docker_engine();
    doctor_socket_dir(std::path::Path::new("/tmp/outcall"));
    doctor_br_netfilter();

    let generated = [
        project_dir
            .join(".outcall")
            .join("recipes")
            .join(recipe.id)
            .join("recipe.yaml"),
        project_dir
            .join(".outcall")
            .join("recipes")
            .join(recipe.id)
            .join("Dockerfile"),
        project_dir
            .join(".outcall")
            .join("rules")
            .join(format!("{}.yaml", recipe.id)),
        project_dir.join(".outcall").join("agent.yaml"),
        project_dir.join(".outcall").join("host-resources.yaml"),
    ];
    for path in generated {
        doctor_path("generated file", &path);
    }

    println!();
    println!("Auth candidates:");
    let mut env_auth = false;
    let mut file_auth = false;
    for key in recipe.auth_env {
        let present = std::env::var_os(key).is_some();
        env_auth |= present;
        doctor_bool("env", key, present);
    }
    for path in recipe.user_paths {
        let expanded = outcall::recipes::expanded_path(path);
        let present = expanded.exists();
        file_auth |= present;
        doctor_bool("user path", path, present);
    }
    if !env_auth && !file_auth {
        println!("  WARN no auth candidates found; choose env, copy, or mount before running");
    } else if should_prefer_env_only_auth(recipe) && !env_auth {
        println!(
            "  WARN macOS Claude login state may still require interactive /login inside Linux. For unattended subscription auth, run `claude setup-token` on the host and export CLAUDE_CODE_OAUTH_TOKEN; API users can set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN"
        );
    }

    println!();
    println!("Project context:");
    let mut any_context = false;
    for path in recipe.project_paths {
        let full = project_dir.join(path);
        let present = full.exists();
        any_context |= present;
        doctor_bool("project path", path, present);
    }
    if !any_context {
        println!(
            "  WARN no project context files found; the agent will only see raw workspace files"
        );
    }

    println!();
    println!("Network reminder:");
    println!(
        "  `{}` handles init, daemon, network, smoke test, and launch.",
        recommended_recipe_command(recipe)
    );
    println!(
        "  Run `outcall recipe test {}` for a full smoke check.",
        recipe.id
    );
    println!(
        "  Copy or mount only selected auth/config paths; do not mount the whole home directory."
    );
    let host_resources = project_dir.join(".outcall").join("host-resources.yaml");
    if host_resources.exists() {
        println!("  Host resource registry: {}", host_resources.display());
    }
    println!();
    println!("Recommended first command:");
    println!(
        "  {}",
        recommended_recipe_command_with_hint(recipe, auth_hint(env_auth, file_auth))
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_recipe_run(
    socket: &str,
    id: &str,
    no_build: bool,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
    detach: bool,
    name: Option<String>,
    args: Vec<String>,
) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    ensure_recipe_initialized(&project_dir, recipe)?;
    ensure_docker_access()?;

    let image = outcall::recipes::recipe_image_name(recipe);
    if !no_build {
        build_recipe_image(&project_dir, recipe, &image)?;
    }

    let mut config = recipe_agent_config(recipe, &image, detach);
    config.name = name;
    let auth_result = stage_recipe_auth(
        &project_dir,
        recipe,
        auth_mode,
        force_auth_copy,
        &mut config,
    )?;

    ensure_recipe_runtime_ready(socket, &project_dir)?;
    ensure_runtime_bridge_netfilter_enforceable()?;
    maybe_prepare_host_broker(socket, &project_dir, &mut config)?;

    println!(
        "Starting recipe \"{}\" with auth mode {:?}.",
        recipe.id, auth_result.effective_mode
    );
    let entrypoint_args = rewrite_recipe_entrypoint_args(&project_dir, &config.workspace, args)?;
    launch_managed_recipe_container(socket, &project_dir, config, entrypoint_args).map(|_| ())
}

fn cmd_recipe_test(
    socket: &str,
    id: &str,
    no_build: bool,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    ensure_recipe_initialized(&project_dir, recipe)?;
    ensure_docker_access()?;

    let image = outcall::recipes::recipe_image_name(recipe);
    if !no_build {
        build_recipe_image(&project_dir, recipe, &image)?;
    }

    let mut config = recipe_agent_config(recipe, &image, true);
    let auth_result = stage_recipe_auth(
        &project_dir,
        recipe,
        auth_mode,
        force_auth_copy,
        &mut config,
    )?;
    ensure_recipe_runtime_ready(socket, &project_dir)?;
    ensure_runtime_bridge_netfilter_enforceable()?;

    if !auth_result.found_auth {
        anyhow::bail!(
            "no auth material found for recipe \"{}\"; run `outcall doctor {}` and add one of the listed env vars or user paths",
            recipe.id,
            recipe.id
        );
    }

    recipe_smoke_test(socket, &project_dir, &config)?;
    println!("Recipe test passed: {}", recipe.id);
    Ok(())
}

fn recipe_agent_config(
    recipe: &outcall::recipes::Recipe,
    image: &str,
    detach: bool,
) -> outcall::agent_config::AgentConfig {
    let mut env = std::collections::HashMap::new();
    // Recipe containers use a read-only root filesystem. stage_recipe_auth
    // supplies a writable project-local home mount for each auth mode.
    env.insert("HOME".to_string(), "/home/node".to_string());

    outcall::agent_config::AgentConfig {
        image: Some(image.to_string()),
        workspace: "/workspace".to_string(),
        network: outcall_api::DEFAULT_NETWORK_NAME.to_string(),
        detach,
        auto_pull: false,
        entrypoint: Some(vec![recipe.id.to_string()]),
        env,
        ..Default::default()
    }
}

fn stage_recipe_auth(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
    config: &mut outcall::agent_config::AgentConfig,
) -> Result<AuthStageResult> {
    let mut found_auth = false;
    let mut env_auth = false;
    for key in recipe.auth_env {
        if let Ok(value) = std::env::var(key) {
            found_auth = true;
            env_auth = true;
            config.env.insert((*key).to_string(), value);
        }
    }

    let saved_mode = if auth_mode == RecipeAuthMode::Auto {
        load_auth_preference(project_dir, recipe)?
    } else {
        None
    };
    let effective_mode = resolve_recipe_auth_mode(
        auth_mode,
        saved_mode,
        env_auth,
        should_prefer_auth_mount(recipe),
        recipe_has_user_auth_paths(recipe),
    );

    if auth_mode == RecipeAuthMode::Auto {
        println!(
            "Auto auth mode selected: {}{}.",
            match effective_mode {
                RecipeAuthMode::Copy => "copy",
                RecipeAuthMode::Mount => "mount",
                RecipeAuthMode::EnvOnly => "env-only",
                RecipeAuthMode::Auto => "auto",
            },
            if saved_mode.is_some() {
                " (saved project choice)"
            } else {
                ""
            }
        );
    }

    match effective_mode {
        RecipeAuthMode::Auto => unreachable!("auto mode should resolve before staging"),
        RecipeAuthMode::Copy => {
            let staged = outcall::recipes::stage_auth_copy(project_dir, recipe, force_auth_copy)?;
            if staged.copied.is_empty() {
                println!("No user auth files copied for recipe \"{}\".", recipe.id);
            } else {
                found_auth = true;
                println!("Staged auth files:");
                for (src, dest) in &staged.copied {
                    println!("  {} -> {}", src.display(), dest.display());
                }
                config
                    .volumes
                    .push(format!("{}:/home/node", staged.home_dir.display()));
                config
                    .env
                    .insert("HOME".to_string(), "/home/node".to_string());
            }
        }
        RecipeAuthMode::Mount => {
            let preserve_home_layout = should_preserve_host_home_layout(recipe);
            // The auth paths are mounted read-only-ish from the host, while
            // CLIs still need an ordinary writable home for state and helpers.
            if !preserve_home_layout {
                ensure_recipe_home_mount(project_dir, recipe, config)?;
            }
            let mount_plan = outcall::recipes::auth_mount_plan(recipe, preserve_home_layout);
            if mount_plan.mounts.is_empty() {
                println!(
                    "No existing user auth paths found to mount for recipe \"{}\".",
                    recipe.id
                );
            } else {
                found_auth = true;
                if let Some(home) = mount_plan.home_override {
                    config.env.insert("HOME".to_string(), home.clone());
                    if let Some(user) = std::path::Path::new(&home)
                        .file_name()
                        .and_then(|name| name.to_str())
                    {
                        config.env.insert("USER".to_string(), user.to_string());
                        config.env.insert("LOGNAME".to_string(), user.to_string());
                    }
                } else if !mount_plan.mounts.is_empty() {
                    config
                        .env
                        .insert("HOME".to_string(), "/home/node".to_string());
                }
            }
            config.volumes.extend(mount_plan.mounts);
        }
        RecipeAuthMode::EnvOnly => ensure_recipe_home_mount(project_dir, recipe, config)?,
    }

    Ok(AuthStageResult {
        found_auth,
        effective_mode,
    })
}

fn resolve_recipe_auth_mode(
    requested_mode: RecipeAuthMode,
    saved_mode: Option<RecipeAuthMode>,
    env_auth: bool,
    prefer_mount: bool,
    user_auth_paths: bool,
) -> RecipeAuthMode {
    match requested_mode {
        RecipeAuthMode::Auto if saved_mode.is_some() => {
            saved_mode.expect("saved auth mode checked")
        }
        RecipeAuthMode::Auto if env_auth => RecipeAuthMode::EnvOnly,
        RecipeAuthMode::Auto if prefer_mount => RecipeAuthMode::Mount,
        RecipeAuthMode::Auto if user_auth_paths => RecipeAuthMode::Copy,
        RecipeAuthMode::Auto => RecipeAuthMode::EnvOnly,
        mode => mode,
    }
}

fn ensure_recipe_home_mount(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
    config: &mut outcall::agent_config::AgentConfig,
) -> Result<()> {
    let home_dir = project_dir.join(".outcall").join("home").join(recipe.id);
    std::fs::create_dir_all(&home_dir)
        .with_context(|| format!("failed to create {}", home_dir.display()))?;
    secure_runtime_dir(&project_dir.join(".outcall").join("home"))?;
    secure_runtime_dir(&home_dir)?;
    let mount = format!("{}:/home/node", home_dir.display());
    if !config.volumes.iter().any(|existing| existing == &mount) {
        config.volumes.push(mount);
    }
    config
        .env
        .insert("HOME".to_string(), "/home/node".to_string());
    Ok(())
}

fn recipe_setup_is_complete(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
) -> bool {
    outcall::recipes::recipe_dockerfile(project_dir, recipe).exists()
        && outcall::policy::rule_path(project_dir, recipe).exists()
        && project_dir.join(".outcall").join("agent.yaml").exists()
        && project_dir
            .join(".outcall")
            .join("host-resources.yaml")
            .exists()
}

fn auth_preference_path(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
) -> std::path::PathBuf {
    project_dir
        .join(".outcall")
        .join("auth")
        .join(recipe.id)
        .join("mode")
}

fn save_auth_preference(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
    mode: RecipeAuthMode,
) -> Result<()> {
    let value = match mode {
        RecipeAuthMode::Auto => "auto",
        RecipeAuthMode::Copy => "copy",
        RecipeAuthMode::Mount => "mount",
        RecipeAuthMode::EnvOnly => "env-only",
    };
    let path = auth_preference_path(project_dir, recipe);
    let parent = path
        .parent()
        .context("auth preference path must have a parent")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    std::fs::write(&path, value).with_context(|| format!("failed to write {}", path.display()))?;
    secure_runtime_file(&path)
}

fn load_auth_preference(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
) -> Result<Option<RecipeAuthMode>> {
    let path = auth_preference_path(project_dir, recipe);
    if !path.exists() {
        return Ok(None);
    }
    let value = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let mode = match value.trim() {
        "copy" => RecipeAuthMode::Copy,
        "mount" => RecipeAuthMode::Mount,
        "env-only" => RecipeAuthMode::EnvOnly,
        "auto" => RecipeAuthMode::Auto,
        other => anyhow::bail!("invalid saved auth mode {other:?} in {}", path.display()),
    };
    Ok(Some(mode))
}

fn maybe_prepare_host_broker(
    daemon_socket: &str,
    project_dir: &std::path::Path,
    config: &mut outcall::agent_config::AgentConfig,
) -> Result<()> {
    let registry_path = outcall::host_resources::default_config_path(project_dir);
    if !registry_path.exists() {
        return Ok(());
    }

    let registry = outcall::host_resources::load_from_path(&registry_path)?;
    if registry.tools.is_empty() && registry.files.is_empty() {
        if remove_host_broker_transport_rule(project_dir)? {
            cmd_rules_reload(daemon_socket)?;
        }
        return Ok(());
    }

    let runtime = ensure_host_broker_running(daemon_socket, project_dir, &registry_path)?;
    match runtime.transport {
        HostBrokerTransport::Unix {
            host_socket,
            container_socket,
        } => {
            println!(
                "Host broker ready: {} -> {}",
                host_socket.display(),
                container_socket
            );
            config
                .env
                .insert("OUTCALL_HOST_BROKER_SOCKET".to_string(), container_socket);
        }
        HostBrokerTransport::Http {
            listen_addr,
            container_url,
        } => {
            println!("Host broker ready: http://{listen_addr} -> {container_url}");
            config
                .env
                .insert("OUTCALL_HOST_BROKER_URL".to_string(), container_url);
        }
    }
    config.env.insert(
        "OUTCALL_HOST_BROKER_TOKEN".to_string(),
        runtime.auth_token.clone(),
    );
    config
        .env
        .insert("OUTCALL_HOST_BROKER_ENABLED".to_string(), "1".to_string());
    Ok(())
}

fn ensure_host_broker_running(
    daemon_socket: &str,
    project_dir: &std::path::Path,
    registry_path: &std::path::Path,
) -> Result<HostBrokerRuntime> {
    let run_dir = project_dir.join(".outcall").join("run");
    std::fs::create_dir_all(&run_dir)
        .with_context(|| format!("failed to create {}", run_dir.display()))?;
    secure_runtime_dir(&run_dir)?;

    let token_path = run_dir.join("host-broker.token");
    let existing_token = std::fs::read_to_string(&token_path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| value.len() == 32 && value.chars().all(|ch| ch.is_ascii_hexdigit()));
    let auth_token = if let Some(token) = existing_token {
        token
    } else {
        let token = random_broker_token();
        std::fs::write(&token_path, &token)
            .with_context(|| format!("failed to write {}", token_path.display()))?;
        secure_runtime_file(&token_path)?;
        token
    };
    secure_runtime_file(&token_path)?;

    if std::env::consts::OS == "macos" {
        return ensure_tcp_host_broker_running(
            daemon_socket,
            project_dir,
            registry_path,
            &run_dir,
            auth_token,
        );
    }

    if remove_host_broker_transport_rule(project_dir)? {
        cmd_rules_reload(daemon_socket)?;
    }
    ensure_unix_host_broker_running(daemon_socket, registry_path, &run_dir, auth_token)
}

fn ensure_unix_host_broker_running(
    daemon_socket: &str,
    registry_path: &std::path::Path,
    run_dir: &std::path::Path,
    auth_token: String,
) -> Result<HostBrokerRuntime> {
    use std::os::unix::process::CommandExt;

    let host_socket = run_dir.join("host-broker.sock");
    let runtime = HostBrokerRuntime {
        transport: HostBrokerTransport::Unix {
            host_socket: host_socket.clone(),
            container_socket: "/workspace/.outcall/run/host-broker.sock".to_string(),
        },
        auth_token,
    };

    if unix_host_broker_healthy(&host_socket, &runtime.auth_token) {
        return Ok(runtime);
    }

    let current_exe =
        std::env::current_exe().context("failed to resolve current outcall binary")?;
    let mut command = std::process::Command::new(current_exe);
    command
        .arg("--socket")
        .arg(daemon_socket)
        .arg("host-broker")
        .arg("serve")
        .arg("--broker-socket")
        .arg(&host_socket)
        .arg("--config")
        .arg(registry_path)
        .env("OUTCALL_HOST_BROKER_TOKEN", &runtime.auth_token)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command.process_group(0);

    let mut child = command.spawn().with_context(|| {
        format!(
            "failed to start host broker for {}",
            registry_path.display()
        )
    })?;

    if let Err(error) = wait_for_unix_host_broker(&host_socket, &runtime.auth_token) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    write_host_broker_pid(run_dir, child.id())?;
    Ok(runtime)
}

fn ensure_tcp_host_broker_running(
    daemon_socket: &str,
    project_dir: &std::path::Path,
    registry_path: &std::path::Path,
    run_dir: &std::path::Path,
    auth_token: String,
) -> Result<HostBrokerRuntime> {
    use std::os::unix::process::CommandExt;

    let port_path = run_dir.join("host-broker.port");
    if let Ok(value) = std::fs::read_to_string(&port_path)
        && let Ok(port) = value.trim().parse::<u16>()
    {
        secure_runtime_file(&port_path)?;
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        if tcp_host_broker_healthy(addr, &auth_token) {
            write_host_broker_transport_rule(project_dir, port)?;
            cmd_rules_reload(daemon_socket)?;
            return Ok(tcp_host_broker_runtime(addr, auth_token));
        }
    }

    let current_exe =
        std::env::current_exe().context("failed to resolve current outcall binary")?;
    for _ in 0..3 {
        let reservation = std::net::TcpListener::bind(("127.0.0.1", 0))
            .context("failed to reserve a loopback broker port")?;
        let addr = reservation
            .local_addr()
            .context("failed to inspect reserved broker port")?;
        drop(reservation);

        let mut command = std::process::Command::new(&current_exe);
        command
            .arg("--socket")
            .arg(daemon_socket)
            .arg("host-broker")
            .arg("serve-tcp")
            .arg("--listen")
            .arg(addr.to_string())
            .arg("--config")
            .arg(registry_path)
            .env("OUTCALL_HOST_BROKER_TOKEN", &auth_token)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        command.process_group(0);
        let mut child = command.spawn().with_context(|| {
            format!(
                "failed to start loopback host broker for {}",
                registry_path.display()
            )
        })?;

        if wait_for_tcp_host_broker(addr, &auth_token) {
            std::fs::write(&port_path, format!("{}\n", addr.port()))
                .with_context(|| format!("failed to write {}", port_path.display()))?;
            secure_runtime_file(&port_path)?;
            write_host_broker_pid(run_dir, child.id())?;
            write_host_broker_transport_rule(project_dir, addr.port())?;
            cmd_rules_reload(daemon_socket)?;
            return Ok(tcp_host_broker_runtime(addr, auth_token));
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    anyhow::bail!("host broker did not become ready on a loopback TCP port")
}

fn write_host_broker_pid(run_dir: &std::path::Path, pid: u32) -> Result<()> {
    let path = run_dir.join("host-broker.pid");
    std::fs::write(&path, format!("{pid}\n"))
        .with_context(|| format!("failed to write {}", path.display()))?;
    secure_runtime_file(&path)
}

fn tcp_host_broker_runtime(
    listen_addr: std::net::SocketAddr,
    auth_token: String,
) -> HostBrokerRuntime {
    HostBrokerRuntime {
        transport: HostBrokerTransport::Http {
            listen_addr,
            container_url: format!("http://host.docker.internal:{}", listen_addr.port()),
        },
        auth_token,
    }
}

fn host_broker_transport_rule_path(project_dir: &std::path::Path) -> std::path::PathBuf {
    project_dir
        .join(".outcall")
        .join("rules")
        .join(".outcall-host-broker.yaml")
}

fn write_host_broker_transport_rule(project_dir: &std::path::Path, port: u16) -> Result<()> {
    let path = host_broker_transport_rule_path(project_dir);
    let contents = format!(
        r#"version: "1"
rules:
  - id: outcall-host-broker-transport
    description: Internal Docker Desktop transport to the tokenized host broker.
    condition: 'http.host == "host.docker.internal" && network.port == {port}'
    action: allow
    priority: 0
    egress:
      mode: proxy
      ports: [{port}]
"#
    );
    std::fs::write(&path, contents).with_context(|| format!("failed to write {}", path.display()))
}

fn remove_host_broker_transport_rule(project_dir: &std::path::Path) -> Result<bool> {
    let path = host_broker_transport_rule_path(project_dir);
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    Ok(true)
}

fn remove_invalid_host_broker_transport_rule(project_dir: &std::path::Path) -> Result<bool> {
    let path = host_broker_transport_rule_path(project_dir);
    if !path.exists() {
        return Ok(false);
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if valid_host_broker_transport_rule(&raw) {
        return Ok(false);
    }
    std::fs::remove_file(&path)
        .with_context(|| format!("failed to remove invalid {}", path.display()))?;
    Ok(true)
}

fn valid_host_broker_transport_rule(raw: &str) -> bool {
    let Ok(file) = serde_yaml::from_str::<GeneratedHostBrokerRuleFile>(raw) else {
        return false;
    };
    let [rule] = file.rules.as_slice() else {
        return false;
    };
    let [port] = rule.egress.ports.as_slice() else {
        return false;
    };
    file.version == "1"
        && rule.id == "outcall-host-broker-transport"
        && rule.description == "Internal Docker Desktop transport to the tokenized host broker."
        && rule.condition
            == format!(
                "http.host == \"host.docker.internal\" && network.port == {}",
                port
            )
        && rule.action == "allow"
        && rule.priority == 0
        && rule.egress.mode == "proxy"
}

fn unix_host_broker_healthy(socket: &std::path::Path, auth_token: &str) -> bool {
    if !socket.exists() {
        return false;
    }
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return false;
    };
    probe_host_broker(&mut stream, auth_token)
}

fn tcp_host_broker_healthy(addr: std::net::SocketAddr, auth_token: &str) -> bool {
    let Ok(mut stream) =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200))
    else {
        return false;
    };
    probe_host_broker(&mut stream, auth_token)
}

fn probe_host_broker(stream: &mut (impl Read + Write), auth_token: &str) -> bool {
    if write!(
        stream,
        "GET /v1/health HTTP/1.0\r\nHost: localhost\r\nAuthorization: Bearer {auth_token}\r\n\r\n"
    )
    .is_err()
    {
        return false;
    }
    let Ok(body) = read_body(stream) else {
        return false;
    };
    let Ok(resp) = serde_json::from_str::<Response>(&body) else {
        return false;
    };
    resp.success
}

fn wait_for_unix_host_broker(socket: &std::path::Path, auth_token: &str) -> Result<()> {
    for _ in 0..50 {
        if unix_host_broker_healthy(socket, auth_token) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    anyhow::bail!("host broker did not become ready at {}", socket.display());
}

fn wait_for_tcp_host_broker(addr: std::net::SocketAddr, auth_token: &str) -> bool {
    for _ in 0..50 {
        if tcp_host_broker_healthy(addr, auth_token) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

#[cfg(unix)]
fn secure_runtime_dir(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to chmod {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_runtime_dir(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_runtime_file(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?
        .permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to chmod {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_runtime_file(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

fn ensure_recipe_runtime_ready(socket: &str, project_dir: &std::path::Path) -> Result<()> {
    if remove_invalid_host_broker_transport_rule(project_dir)? {
        println!("Removed invalid generated host broker transport rule.");
    }
    let rules_dir = project_dir.join(".outcall").join("rules");
    ensure_daemon_ready(socket, Some(&rules_dir))?;
    cmd_rules_reload(socket)?;
    ensure_default_network(socket)?;
    Ok(())
}

fn launch_managed_recipe_container(
    socket: &str,
    project_dir: &std::path::Path,
    config: outcall::agent_config::AgentConfig,
    entrypoint_args: Vec<String>,
) -> Result<String> {
    let image = config.effective_image();
    let name = config.effective_name(project_dir);
    let workspace = config.workspace.clone();
    let abs_project_dir = std::fs::canonicalize(project_dir)
        .with_context(|| format!("failed to canonicalize {}", project_dir.display()))?;
    let memory_limit = config
        .resources
        .as_ref()
        .and_then(|resources| resources.memory.as_deref())
        .map(parse_memory_arg)
        .transpose()?;
    let cpu_shares = config
        .resources
        .as_ref()
        .and_then(|resources| resources.cpus.as_deref())
        .map(parse_cpu_shares)
        .transpose()?;

    let mut volumes = vec![format!("{}:{}", abs_project_dir.display(), workspace)];
    volumes.extend(config.volumes.clone());
    volumes.push(protected_outcall_mount(&abs_project_dir, &workspace)?);

    let env = if config.env.is_empty() {
        None
    } else {
        Some(
            config
                .env
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect(),
        )
    };

    let batch_command = !entrypoint_args.is_empty() || config.command.is_some();
    let interactive = !config.detach && !batch_command;
    let tty = interactive && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let cmd = if !entrypoint_args.is_empty() {
        Some(entrypoint_args)
    } else {
        config.command.clone()
    };

    let automatic_name = config.name.is_none();
    let mut req = outcall_api::ContainerCreateRequest {
        image,
        network: Some(config.network.clone()),
        name: Some(name.clone()),
        memory_limit,
        cpu_shares,
        env,
        cmd,
        entrypoint: config.entrypoint.clone(),
        working_dir: Some(config.workspace.clone()),
        volumes: Some(volumes),
        include_outcall_helper_mounts: Some(false),
        interactive: Some(interactive),
        tty: Some(tty),
    };

    println!(
        "Booting managed agent '{}' for project '{}'...",
        name,
        project_dir.display()
    );
    println!("  Image: {}", req.image);
    println!(
        "  Workspace: {} -> {}",
        abs_project_dir.display(),
        workspace
    );
    println!("  Network: {}", config.network);
    println!("  Starting container via outcalld...");

    let mut name_retry_count = 0usize;
    let result: ContainerCreateResult = loop {
        let resp = post_managed_container_create(socket, &req)?;
        if resp.success {
            break serde_json::from_value(resp.data.context("no data")?)?;
        }

        let error = resp.error.unwrap_or_else(|| "unknown error".into());
        let current_name = req.name.as_deref().unwrap_or_default();
        if is_container_name_conflict(&error) {
            let candidate = config.effective_name(project_dir);
            if let Some(next_name) = automatic_name_retry_candidate(
                automatic_name,
                name_retry_count,
                current_name,
                candidate,
            ) {
                name_retry_count += 1;
                println!(
                    "  Container name '{}' was claimed concurrently; retrying as '{}'...",
                    current_name, next_name
                );
                req.name = Some(next_name);
                continue;
            }
        }
        anyhow::bail!("{error}");
    };

    if config.detach {
        println!(
            "Agent '{}' started ({}) in detached mode.",
            result.name,
            &result.container_id[..12.min(result.container_id.len())]
        );
        println!("  Attach: docker attach {}", result.name);
        println!("  Logs:   docker logs -f {}", result.name);
        println!("  Stop:   outcall stop {}", result.name);
        return Ok(result.name);
    }

    // Commands passed after `--` are one-shot recipe invocations, not an
    // interactive agent session. Waiting avoids the race where a quick command
    // exits successfully before `docker attach` has connected.
    if batch_command {
        wait_for_recipe_container(&result.name)?;
        println!("\nAgent '{}' stopped.", result.name);
        return Ok(result.name);
    }

    println!("  Container running. Press Ctrl+C to detach.");
    println!();

    let status = std::process::Command::new("docker")
        .args(["attach", &result.name])
        .status()
        .context("failed to invoke docker attach")?;
    if !status.success() {
        anyhow::bail!("agent exited with code {:?}", status.code());
    }

    println!("\nAgent '{}' stopped.", result.name);
    Ok(result.name)
}

fn post_managed_container_create(
    socket: &str,
    req: &outcall_api::ContainerCreateRequest,
) -> Result<Response> {
    let body = match http_post_json(socket, "/api/v1/container/create", req) {
        Ok(body) => body,
        Err(err) if should_retry_legacy_container_create(&err) => {
            println!(
                "  Daemon is using the legacy container API; retrying with compatible fields..."
            );
            let legacy_req = outcall_api::ContainerCreateRequest {
                entrypoint: None,
                working_dir: None,
                include_outcall_helper_mounts: None,
                interactive: None,
                tty: None,
                ..req.clone()
            };
            http_post_json(socket, "/api/v1/container/create", &legacy_req)?
        }
        Err(err) => return Err(err),
    };
    serde_json::from_str(&body).context("failed to parse response")
}

fn automatic_name_retry_candidate(
    automatic_name: bool,
    retry_count: usize,
    current_name: &str,
    candidate: String,
) -> Option<String> {
    const MAX_NAME_RETRIES: usize = 20;
    if !automatic_name || retry_count >= MAX_NAME_RETRIES {
        return None;
    }
    if candidate != current_name {
        return Some(candidate);
    }

    let (base, suffix) = current_name.rsplit_once('-')?;
    let next_suffix = suffix.parse::<u32>().ok()?.checked_add(1)?;
    Some(format!("{base}-{next_suffix}"))
}

fn is_container_name_conflict(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("status code 409")
        && error.contains("container name")
        && error.contains("already in use")
}

fn protected_outcall_mount(project_dir: &std::path::Path, workspace: &str) -> Result<String> {
    let outcall_dir = project_dir.join(".outcall");
    let source = std::fs::canonicalize(&outcall_dir)
        .with_context(|| format!("failed to canonicalize {}", outcall_dir.display()))?;
    let destination = format!("{}/.outcall", workspace.trim_end_matches('/'));
    Ok(format!("{}:{destination}:ro", source.display()))
}

fn wait_for_recipe_container(name: &str) -> Result<()> {
    let wait = std::process::Command::new("docker")
        .args(["wait", name])
        .output()
        .context("failed to invoke docker wait")?;
    if !wait.status.success() {
        anyhow::bail!(
            "failed while waiting for agent container {name}: {}",
            String::from_utf8_lossy(&wait.stderr).trim()
        );
    }

    let logs = std::process::Command::new("docker")
        .args(["logs", name])
        .output()
        .context("failed to invoke docker logs")?;
    print!("{}", String::from_utf8_lossy(&logs.stdout));
    eprint!("{}", String::from_utf8_lossy(&logs.stderr));
    if !logs.status.success() {
        anyhow::bail!(
            "failed to read agent container logs for {name}: {}",
            String::from_utf8_lossy(&logs.stderr).trim()
        );
    }

    let exit_code = String::from_utf8_lossy(&wait.stdout)
        .trim()
        .parse::<i32>()
        .context("docker wait returned an invalid exit code")?;
    if exit_code != 0 {
        anyhow::bail!("agent exited with code {exit_code}");
    }
    Ok(())
}

fn parse_cpu_shares(value: &str) -> Result<i64> {
    value
        .parse::<i64>()
        .with_context(|| format!("invalid cpu shares value: {value}"))
}

fn should_prefer_auth_mount(recipe: &outcall::recipes::Recipe) -> bool {
    cfg!(target_os = "macos") && recipe.id == "claude" && recipe_has_user_auth_paths(recipe)
}

fn should_preserve_host_home_layout(recipe: &outcall::recipes::Recipe) -> bool {
    cfg!(target_os = "macos") && recipe.id == "claude"
}

fn should_prefer_env_only_auth(recipe: &outcall::recipes::Recipe) -> bool {
    cfg!(target_os = "macos") && recipe.id == "claude"
}

fn should_retry_legacy_container_create(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    msg.contains("unknown field `entrypoint`")
        || msg.contains("unknown field `working_dir`")
        || msg.contains("unknown field `interactive`")
        || msg.contains("unknown field `tty`")
}

fn ensure_daemon_ready(socket: &str, rules_dir: Option<&std::path::Path>) -> Result<()> {
    let desired_rules_dir = rules_dir
        .map(std::fs::canonicalize)
        .transpose()
        .with_context(|| {
            rules_dir
                .map(|path| format!("failed to canonicalize rules dir {}", path.display()))
                .unwrap_or_else(|| "failed to canonicalize rules dir".to_string())
        })?;
    let output = std::process::Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{.State.Running}}",
            DEFAULT_DAEMON_NAME,
        ])
        .output();

    match output {
        Ok(output)
            if output.status.success()
                && String::from_utf8_lossy(&output.stdout).trim() == "true" =>
        {
            if let Some(ref desired) = desired_rules_dir
                && daemon_rules_mount_mismatch(DEFAULT_DAEMON_NAME, desired)?
            {
                println!(
                    "Restarting outcall-daemon to mount project rules from {}...",
                    desired.display()
                );
                cmd_daemon_stop(None)?;
                start_daemon_with_rules(socket, desired)?;
            }
            wait_for_daemon_socket(socket)
        }
        _ => {
            println!("Starting outcall-daemon...");
            if let Some(ref desired) = desired_rules_dir {
                start_daemon_with_rules(socket, desired)?;
            } else {
                start_daemon_with_rules(socket, std::path::Path::new("/etc/outcall/rules.d"))?;
            }
            wait_for_daemon_socket(socket)
        }
    }
}

fn start_daemon_with_rules(socket: &str, rules_dir: &std::path::Path) -> Result<()> {
    let agent_socket = std::path::Path::new(socket)
        .parent()
        .map(|parent| parent.join("agent.sock"))
        .and_then(|path| path.into_os_string().into_string().ok());
    cmd_daemon_start(
        None,
        None,
        Some(rules_dir.display().to_string()),
        None,
        Some(socket.to_string()),
        agent_socket,
        false,
        None,
    )
}

fn daemon_rules_mount_mismatch(name: &str, desired_rules_dir: &std::path::Path) -> Result<bool> {
    let output = std::process::Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{range .Mounts}}{{if eq .Destination \"/etc/outcall/rules.d\"}}{{.Source}}{{end}}{{end}}",
            name,
        ])
        .output()
        .context("failed to inspect daemon rules mount")?;
    if !output.status.success() {
        return Ok(true);
    }

    let actual = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if actual.is_empty() {
        return Ok(true);
    }

    let actual = std::path::PathBuf::from(actual);
    let actual = std::fs::canonicalize(&actual).unwrap_or(actual);
    Ok(actual != desired_rules_dir)
}

fn wait_for_daemon_socket(socket: &str) -> Result<()> {
    use std::time::Duration;

    if daemon_requests_via_exec() {
        let mut last_error = None;
        for _ in 0..300 {
            match daemon_exec_socket_ready(socket) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    if let Some(state) = daemon_container_state(DEFAULT_DAEMON_NAME)?
                        && state != "running"
                    {
                        let logs = daemon_container_logs(DEFAULT_DAEMON_NAME)?;
                        anyhow::bail!(
                            "outcalld container is not running (state: {state}) while waiting for {socket}\n{logs}"
                        );
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(err) => {
                    last_error = Some(err.to_string());
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        let last_error = last_error.unwrap_or_else(|| "unknown error".to_string());
        let logs = daemon_container_logs(DEFAULT_DAEMON_NAME).unwrap_or_default();
        anyhow::bail!(
            "cannot reach outcalld inside daemon container after startup wait: {last_error}\n{logs}"
        );
    }

    use std::os::unix::net::UnixStream;
    let mut last_error = None;
    for _ in 0..300 {
        match UnixStream::connect(socket) {
            Ok(_) => return Ok(()),
            Err(err) => {
                if let Some(state) = daemon_container_state(DEFAULT_DAEMON_NAME)?
                    && state != "running"
                {
                    let logs = daemon_container_logs(DEFAULT_DAEMON_NAME)?;
                    anyhow::bail!(
                        "outcalld container is not running (state: {state}) while waiting for {socket}\n{logs}"
                    );
                }
                last_error = Some(err);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    let last_error = last_error
        .map(|err| err.to_string())
        .unwrap_or_else(|| "unknown error".to_string());
    let logs = daemon_container_logs(DEFAULT_DAEMON_NAME).unwrap_or_default();
    anyhow::bail!(
        "cannot connect to outcalld at {socket} after startup wait: {last_error}\n{logs}"
    );
}

fn daemon_container_state(name: &str) -> Result<Option<String>> {
    use std::process::Command;

    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Status}}", name])
        .output()
        .context("failed to inspect daemon container state")?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

fn daemon_container_logs(name: &str) -> Result<String> {
    use std::process::Command;

    let output = Command::new("docker")
        .args(["logs", "--tail", "200", name])
        .output()
        .context("failed to fetch daemon container logs")?;
    if !output.status.success() {
        return Ok(String::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let combined = match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout,
        (true, false) => stderr,
        (false, false) => format!("{stdout}\n{stderr}"),
    };
    Ok(combined)
}

fn ensure_default_network(socket: &str) -> Result<()> {
    println!("Ensuring default Outcall network exists...");
    cmd_network_create(socket, None, None, None)
}

fn recipe_smoke_test(
    socket: &str,
    project_dir: &std::path::Path,
    config: &outcall::agent_config::AgentConfig,
) -> Result<()> {
    let mut smoke_config = config.clone();
    // Smoke runs must wait for the recipe command and inspect its exit status;
    // a detached container could otherwise be removed before it reports a
    // startup failure.
    smoke_config.detach = false;
    smoke_config.name = Some(format!(
        "{}-smoke-{}",
        config.effective_name(project_dir),
        std::process::id()
    ));

    println!("Running managed recipe smoke test...");
    let container_name = launch_managed_recipe_container(
        socket,
        project_dir,
        smoke_config,
        vec!["--version".to_string()],
    )?;

    if let Err(err) = container_remove_request(socket, &container_name, true) {
        eprintln!("warning: failed to remove smoke container {container_name}: {err}");
    }
    Ok(())
}

fn ensure_recipe_initialized(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
) -> Result<()> {
    let dockerfile = outcall::recipes::recipe_dockerfile(project_dir, recipe);
    if dockerfile.exists() {
        return Ok(());
    }

    println!(
        "Recipe files for \"{}\" are missing; initializing defaults.",
        recipe.id
    );
    let written = outcall::recipes::init_recipe(project_dir, recipe, false)?;
    for path in written {
        println!("  wrote {}", path.display());
    }
    Ok(())
}

fn ensure_recipe_setup_state(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
    force: bool,
) -> Result<()> {
    let outcall_dir = project_dir.join(".outcall");
    let rules_dir = outcall_dir.join("rules");
    std::fs::create_dir_all(&rules_dir)
        .with_context(|| format!("failed to create {}", rules_dir.display()))?;

    if force {
        cmd_init(Some(recipe.id), true)?;
        return Ok(());
    }

    println!("Initialized Outcall in {}.", project_dir.display());

    let mut wrote_any = false;
    if outcall_dir
        .join("recipes")
        .join(recipe.id)
        .join("recipe.yaml")
        .exists()
    {
        println!("  recipe files already exist for {}", recipe.id);
    } else {
        let written = outcall::recipes::init_recipe(project_dir, recipe, false)?;
        for path in written {
            println!("  wrote {}", path.display());
        }
        wrote_any = true;
    }

    let selected = save_default_recipe(project_dir, recipe.id)?;
    println!("  wrote {}", selected.display());
    println!("  ensured {}", rules_dir.display());
    if !wrote_any {
        println!("  kept existing generated recipe files");
    }
    println!();
    println!("Next:");
    println!("  outcall run {}", recipe.id);
    println!("  outcall setup         # repeat first-run checks without launching");
    println!("  outcall run {} --detach", recipe.id);
    Ok(())
}

fn rewrite_recipe_entrypoint_args(
    project_dir: &std::path::Path,
    workspace: &str,
    args: Vec<String>,
) -> Result<Vec<String>> {
    let abs_project_dir = std::fs::canonicalize(project_dir)
        .with_context(|| format!("failed to canonicalize {}", project_dir.display()))?;
    let mut rewritten = Vec::with_capacity(args.len());
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "-o" || arg == "--output-last-message" {
            let path = iter
                .next()
                .with_context(|| format!("missing value for {}", arg))?;
            rewritten.push(arg);
            rewritten.push(rewrite_container_output_path(
                &abs_project_dir,
                workspace,
                &path,
            )?);
            continue;
        }
        if let Some((flag, value)) = arg.split_once('=')
            && flag == "--output-last-message"
        {
            let rewritten_value =
                rewrite_container_output_path(&abs_project_dir, workspace, value)?;
            rewritten.push(format!("{flag}={rewritten_value}"));
            continue;
        }
        rewritten.push(arg);
    }
    Ok(rewritten)
}

fn rewrite_container_output_path(
    project_dir: &std::path::Path,
    workspace: &str,
    path: &str,
) -> Result<String> {
    let candidate = std::path::Path::new(path);
    if !candidate.is_absolute() {
        return Ok(path.to_string());
    }
    if let Ok(relative) = candidate.strip_prefix(project_dir) {
        return workspace_output_path(workspace, candidate, relative);
    }

    if let Some(resolved) = resolve_output_path_for_workspace(candidate)?
        && let Ok(relative) = resolved.strip_prefix(project_dir)
    {
        return workspace_output_path(workspace, candidate, relative);
    }
    anyhow::bail!(
        "output path {} is outside the mounted workspace; use a relative path or a file inside {}",
        candidate.display(),
        project_dir.display()
    );
}

fn resolve_output_path_for_workspace(
    candidate: &std::path::Path,
) -> Result<Option<std::path::PathBuf>> {
    let Some(parent) = candidate.parent() else {
        return Ok(None);
    };
    if !parent.exists() {
        return Ok(None);
    }
    let resolved_parent = std::fs::canonicalize(parent)
        .with_context(|| format!("failed to canonicalize {}", parent.display()))?;
    Ok(candidate.file_name().map(|name| resolved_parent.join(name)))
}

fn workspace_output_path(
    workspace: &str,
    original: &std::path::Path,
    relative: &std::path::Path,
) -> Result<String> {
    let relative = relative
        .to_str()
        .with_context(|| format!("non-utf8 output path: {}", original.display()))?;
    let relative = relative.trim_start_matches('/');
    if relative.is_empty() {
        anyhow::bail!(
            "output path {} resolves to the project root; choose a file path inside the workspace",
            original.display()
        );
    }
    Ok(format!("{}/{}", workspace.trim_end_matches('/'), relative))
}

fn ensure_docker_access() -> Result<()> {
    let failure = match retry_with_delay(
        docker_probe_attempts(),
        docker_probe_retry_delay(),
        docker_info_probe,
    ) {
        Ok(()) => return Ok(()),
        Err(failure) => failure,
    };

    if let DockerProbeFailure::Io(error) = failure {
        return Err(error).context(
            "failed to invoke `docker info`; install Docker and ensure the CLI is available",
        );
    }

    let context_name = docker_context_name().unwrap_or_else(|_| "unknown".to_string());
    match failure {
        DockerProbeFailure::TimedOut { timeout } => {
            anyhow::bail!(
                "Docker is not ready for Outcall.\n\
                 Detail: `docker info` did not respond within {} seconds after {} attempts.\n\
                 Active Docker context: {context_name}\n\
                 Start or restart Docker Desktop, wait for the daemon to finish booting, then rerun `outcall`.\n\
                 Run `outcall doctor` if you want the full prerequisite report first.",
                timeout.as_secs(),
                docker_probe_attempts()
            );
        }
        DockerProbeFailure::Unavailable { detail } if detail.contains("permission denied") => {
            anyhow::bail!(
                "Docker is installed but the current user cannot access the Docker socket.\n\
                 Detail: {detail}\n\
                 Start Docker Desktop or fix Docker socket permissions, then rerun `outcall`.\n\
                 Run `outcall doctor` if you want the full prerequisite report first."
            );
        }
        DockerProbeFailure::Unavailable { detail } => {
            anyhow::bail!(
                "Docker is not ready for Outcall after {} attempts.\n\
                 Detail: {detail}\n\
                 Active Docker context: {context_name}\n\
                 Start Docker and rerun `outcall`.\n\
                 Run `outcall doctor` if you want the full prerequisite report first.",
                docker_probe_attempts()
            );
        }
        DockerProbeFailure::Io(_) => unreachable!("I/O failures return before context lookup"),
    }
}

#[derive(Debug)]
enum DockerProbeFailure {
    TimedOut { timeout: std::time::Duration },
    Io(anyhow::Error),
    Unavailable { detail: String },
}

fn docker_info_probe() -> std::result::Result<(), DockerProbeFailure> {
    let output = command_output_with_timeout("docker", &["info"], docker_probe_timeout()).map_err(
        |error| match error {
            CommandTimeoutError::TimedOut { timeout } => DockerProbeFailure::TimedOut { timeout },
            CommandTimeoutError::Io(error) => DockerProbeFailure::Io(error),
        },
    )?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "docker info failed".to_string()
    };
    Err(DockerProbeFailure::Unavailable { detail })
}

fn retry_with_delay<T, E>(
    attempts: usize,
    delay: std::time::Duration,
    mut operation: impl FnMut() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    assert!(attempts > 0, "retry attempts must be greater than zero");
    for attempt in 1..=attempts {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if attempt == attempts => return Err(error),
            Err(_) => std::thread::sleep(delay),
        }
    }
    unreachable!("positive retry count always returns")
}

fn ensure_docker_access_with_fix() -> Result<()> {
    match ensure_docker_access() {
        Ok(()) => Ok(()),
        Err(initial_error) if std::env::consts::OS != "macos" => Err(initial_error),
        Err(initial_error) => {
            println!("  Starting Docker Desktop and waiting for it to become ready...");
            let launched = std::process::Command::new("open")
                .args(["-gja", "Docker"])
                .status()
                .context("failed to ask macOS to open Docker Desktop")?;
            if !launched.success() {
                return Err(initial_error).context("Docker Desktop did not start");
            }
            let timeout = std::time::Duration::from_secs(90);
            let deadline = std::time::Instant::now() + timeout;
            loop {
                if docker_info_probe().is_ok() {
                    println!("  PASS docker: Docker Desktop is ready");
                    return Ok(());
                }
                let now = std::time::Instant::now();
                if now >= deadline {
                    break;
                }
                std::thread::sleep(
                    std::time::Duration::from_secs(1).min(deadline.saturating_duration_since(now)),
                );
            }
            Err(initial_error).context("Docker Desktop did not become ready within 90 seconds")
        }
    }
}

fn ensure_daemon_image_available() -> Result<()> {
    let inspected = std::process::Command::new("docker")
        .args(["image", "inspect", DEFAULT_DAEMON_IMAGE])
        .output()
        .context("failed to inspect the Outcall daemon image")?;
    if inspected.status.success() {
        println!("  PASS daemon image: {DEFAULT_DAEMON_IMAGE}");
        return Ok(());
    }

    println!("  Pulling daemon image: {DEFAULT_DAEMON_IMAGE}");
    let status = std::process::Command::new("docker")
        .args(["pull", DEFAULT_DAEMON_IMAGE])
        .status()
        .context("failed to invoke docker pull for the Outcall daemon image")?;
    if !status.success() {
        anyhow::bail!("failed to pull daemon image {DEFAULT_DAEMON_IMAGE}");
    }
    Ok(())
}

fn containerized_runtime_note() -> Option<String> {
    if std::env::consts::OS == "linux" {
        return None;
    }

    Some(format!(
        "Detected {}. Outcall will use Docker's Linux runtime for the daemon and agent containers.",
        std::env::consts::OS
    ))
}

fn ensure_bridge_netfilter_enforceable() -> Result<()> {
    if std::env::consts::OS != "linux" {
        return Ok(());
    }

    let (iptables, ip6tables) = bridge_netfilter_values()?;

    if iptables != "1" || ip6tables != "1" {
        anyhow::bail!(
            "Secure unattended mode requires bridge netfilter enforcement.\n\
             Current values are:\n\
             - /proc/sys/net/bridge/bridge-nf-call-iptables = {iptables}\n\
             - /proc/sys/net/bridge/bridge-nf-call-ip6tables = {ip6tables}\n\
             Set both to `1` (for example via `modprobe br_netfilter` and `sysctl -w`)"
        )
    }

    Ok(())
}

fn ensure_runtime_bridge_netfilter_enforceable() -> Result<()> {
    if std::env::consts::OS == "linux" {
        return ensure_bridge_netfilter_enforceable();
    }

    let iptables = daemon_exec_output(["cat", "/proc/sys/net/bridge/bridge-nf-call-iptables"])?;
    let ip6tables = daemon_exec_output(["cat", "/proc/sys/net/bridge/bridge-nf-call-ip6tables"])?;
    let iptables = iptables.trim();
    let ip6tables = ip6tables.trim();
    if iptables != "1" || ip6tables != "1" {
        anyhow::bail!(
            "Secure unattended mode requires bridge netfilter enforcement inside the Linux runtime.\n\
             Current values are:\n\
             - /proc/sys/net/bridge/bridge-nf-call-iptables = {iptables}\n\
             - /proc/sys/net/bridge/bridge-nf-call-ip6tables = {ip6tables}\n\
             Enable `br_netfilter` and set both sysctls to `1` in the Docker Linux runtime."
        );
    }
    Ok(())
}

fn bridge_netfilter_values() -> Result<(String, String)> {
    fn read_bridge_sysctl(path: &str) -> Result<String> {
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {path}"))
            .map(|value| value.trim().to_string())
    }

    Ok((
        read_bridge_sysctl("/proc/sys/net/bridge/bridge-nf-call-iptables")?,
        read_bridge_sysctl("/proc/sys/net/bridge/bridge-nf-call-ip6tables")?,
    ))
}

fn bridge_netfilter_enforceable() -> bool {
    if std::env::consts::OS != "linux" {
        return false;
    }

    match bridge_netfilter_values() {
        Ok((iptables, ip6tables)) => iptables == "1" && ip6tables == "1",
        Err(_) => false,
    }
}

fn build_recipe_image(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
    image: &str,
) -> Result<()> {
    let recipe_dir = outcall::recipes::recipe_dockerfile(project_dir, recipe)
        .parent()
        .context("recipe dockerfile has no parent path")?
        .to_path_buf();
    let fingerprint = recipe_directory_fingerprint(&recipe_dir)
        .context("failed to compute recipe build fingerprint")?;
    let fingerprint_path = recipe_dir.join(".outcall-image-fingerprint");

    if docker_image_exists(image)? && is_recipe_image_cached(&fingerprint_path, &fingerprint)? {
        println!("Recipe image {image} already up-to-date; skipping build.");
        return Ok(());
    }

    if docker_image_exists(image)? {
        println!("Rebuilding recipe image {image} (recipe context changed).");
    }

    let dockerfile = recipe_dir.join("Dockerfile");
    println!("Building recipe image {image}...");
    let status = std::process::Command::new("docker")
        .arg("build")
        .arg("-t")
        .arg(image)
        .arg("-f")
        .arg(&dockerfile)
        .arg(".")
        .status()
        .context("failed to invoke docker build")?;
    if !status.success() {
        anyhow::bail!("docker build failed (exit {:?})", status.code());
    }

    std::fs::write(&fingerprint_path, format!("{fingerprint}\n"))
        .with_context(|| format!("failed to write {}", fingerprint_path.display()))?;
    Ok(())
}

fn docker_image_exists(image: &str) -> Result<bool> {
    let output = std::process::Command::new("docker")
        .args(["image", "inspect", "--format", "{{.Id}}", image])
        .output()
        .context("failed to invoke docker image inspect")?;

    Ok(output.status.success())
}

fn is_recipe_image_cached(fingerprint_path: &std::path::Path, fingerprint: &str) -> Result<bool> {
    if !fingerprint_path.exists() {
        return Ok(false);
    }

    let existing = std::fs::read_to_string(fingerprint_path)
        .with_context(|| format!("failed to read {}", fingerprint_path.display()))?;

    Ok(existing.trim() == fingerprint)
}

fn recipe_directory_fingerprint(recipe_dir: &std::path::Path) -> Result<String> {
    let mut files = Vec::new();
    collect_files(recipe_dir, &mut files, recipe_dir)
        .with_context(|| format!("failed to collect files from {}", recipe_dir.display()))?;
    files.sort();

    let mut hasher = DefaultHasher::new();
    for file in files {
        let relative = file
            .strip_prefix(recipe_dir)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        relative.hash(&mut hasher);

        let bytes =
            std::fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?;
        hasher.write(&bytes);
    }

    Ok(format!("{:016x}", hasher.finish()))
}

fn collect_files(
    dir: &std::path::Path,
    files: &mut Vec<std::path::PathBuf>,
    root: &std::path::Path,
) -> Result<()> {
    for entry in std::fs::read_dir(dir).context("failed to read recipe directory")? {
        let entry = entry.context("failed to read recipe directory entry")?;
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(&path);
        if rel == std::path::Path::new(".outcall-image-fingerprint") {
            continue;
        }

        let metadata = entry
            .metadata()
            .with_context(|| format!("failed to stat {}", path.display()))?;

        if metadata.is_dir() {
            collect_files(&path, files, root)?;
            continue;
        }

        if metadata.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn doctor_command(command: &str, args: &[&str]) {
    match command_output_with_timeout(command, args, doctor_command_timeout()) {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            let first = version.lines().next().unwrap_or("available");
            println!("  PASS {command}: {first}");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let msg = stderr.lines().next().unwrap_or("command failed");
            println!("  WARN {command}: {msg}");
        }
        Err(CommandTimeoutError::TimedOut { timeout }) => {
            println!(
                "  WARN {command}: timed out after {} seconds",
                timeout.as_secs()
            );
        }
        Err(CommandTimeoutError::Io(e)) => println!("  WARN {command}: {e}"),
    }
}

fn doctor_docker_engine() {
    doctor_command(
        "docker",
        &[
            "version",
            "--format",
            "Docker Engine {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})",
        ],
    );
}

fn doctor_command_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(3)
}

fn docker_probe_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(5)
}

fn docker_probe_attempts() -> usize {
    3
}

fn docker_probe_retry_delay() -> std::time::Duration {
    std::time::Duration::from_millis(250)
}

#[derive(Debug)]
enum CommandTimeoutError {
    TimedOut { timeout: std::time::Duration },
    Io(anyhow::Error),
}

fn command_output_with_timeout(
    command: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> std::result::Result<std::process::Output, CommandTimeoutError> {
    use std::process::Command;
    use std::thread;
    use std::time::Instant;

    let mut child = Command::new(command)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| CommandTimeoutError::Io(e.into()))?;
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| CommandTimeoutError::Io(e.into()));
            }
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CommandTimeoutError::TimedOut { timeout });
            }
            Ok(None) => thread::sleep(std::time::Duration::from_millis(100)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CommandTimeoutError::Io(e.into()));
            }
        }
    }
}

fn docker_context_name() -> Result<String> {
    let output =
        command_output_with_timeout("docker", &["context", "show"], doctor_command_timeout())
            .map_err(|err| match err {
                CommandTimeoutError::TimedOut { timeout } => anyhow::anyhow!(
                    "`docker context show` timed out after {} seconds",
                    timeout.as_secs()
                ),
                CommandTimeoutError::Io(e) => e,
            })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        anyhow::bail!("docker context show failed: {detail}");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn doctor_platform() {
    println!("{}", doctor_platform_line_for(std::env::consts::OS));
}

fn doctor_platform_line_for(os: &str) -> String {
    if os == "linux" {
        "  PASS platform: Linux host (native daemon runtime available)".to_string()
    } else if os == "macos" {
        "  INFO platform: macOS host detected; CLI runs locally and Outcall uses Docker Desktop's Linux runtime for the daemon and agent containers".to_string()
    } else {
        format!(
            "  WARN platform: {os} host detected; the isolated daemon runtime still requires Linux"
        )
    }
}

fn doctor_socket_dir(path: &std::path::Path) {
    if path.exists() {
        println!("  PASS socket dir: {}", path.display());
        return;
    }

    match std::fs::create_dir_all(path) {
        Ok(()) => {
            println!("  PASS socket dir: {} (created)", path.display());
        }
        Err(e) => {
            println!("  WARN socket dir: {} ({e})", path.display());
        }
    }
}

fn doctor_br_netfilter() {
    if std::env::consts::OS != "linux" {
        match daemon_container_state(DEFAULT_DAEMON_NAME) {
            Ok(Some(state)) if state == "running" => {
                let ipv4 =
                    daemon_exec_output(["cat", "/proc/sys/net/bridge/bridge-nf-call-iptables"]);
                let ipv6 =
                    daemon_exec_output(["cat", "/proc/sys/net/bridge/bridge-nf-call-ip6tables"]);
                match (ipv4, ipv6) {
                    (Ok(ipv4), Ok(ipv6)) => println!(
                        "{}",
                        runtime_bridge_netfilter_line(ipv4.trim(), ipv6.trim())
                    ),
                    (Err(error), _) | (_, Err(error)) => println!(
                        "  WARN secure unattended mode: could not inspect Docker's Linux runtime ({error})"
                    ),
                }
            }
            Ok(_) => println!(
                "  INFO secure unattended mode: bridge netfilter will be checked inside Docker's Linux runtime when `outcall run` starts"
            ),
            Err(error) => println!(
                "  WARN secure unattended mode: could not inspect Docker's Linux runtime ({error})"
            ),
        }
        return;
    }

    if bridge_netfilter_enforceable() {
        println!("  PASS secure unattended mode: bridge netfilter enforcement enabled");
    } else {
        println!(
            "  WARN secure unattended mode: bridge netfilter enforcement not fully enabled (run set up check via `outcall doctor` output below)"
        );
    }

    doctor_proc_value(
        "br_netfilter ipv4",
        std::path::Path::new("/proc/sys/net/bridge/bridge-nf-call-iptables"),
        "1",
        "load br_netfilter and set net.bridge.bridge-nf-call-iptables=1",
    );
    doctor_proc_value(
        "br_netfilter ipv6",
        std::path::Path::new("/proc/sys/net/bridge/bridge-nf-call-ip6tables"),
        "1",
        "set net.bridge.bridge-nf-call-ip6tables=1",
    );
}

fn runtime_bridge_netfilter_line(ipv4: &str, ipv6: &str) -> String {
    if ipv4 == "1" && ipv6 == "1" {
        "  PASS secure unattended mode: Docker Linux runtime bridge netfilter enforcement enabled"
            .to_string()
    } else {
        format!(
            "  WARN secure unattended mode: Docker Linux runtime bridge netfilter is not enforceable (ipv4={ipv4}, ipv6={ipv6}; expected both to be 1)"
        )
    }
}

fn doctor_proc_value(label: &str, path: &std::path::Path, expected: &str, hint: &str) {
    match std::fs::read_to_string(path) {
        Ok(value) => {
            let actual = value.trim();
            if actual == expected {
                println!("  PASS {label}: {actual}");
            } else {
                println!("  WARN {label}: {actual} (expected {expected}; {hint})");
            }
        }
        Err(e) => {
            println!("  WARN {label}: {} ({e}; {hint})", path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BrokerToolExecRequest, Cli, CommandTimeoutError, Commands, HostBrokerAction,
        RecipeAuthMode, automatic_name_retry_candidate, broker_error_status, broker_exec_tool,
        command_output_with_timeout, daemon_build_inputs, doctor_platform_line_for,
        ensure_recipe_setup_state, handle_broker_connection, host_broker_transport_rule_path,
        is_container_name_conflict, protected_outcall_mount, read_http_request,
        remove_invalid_host_broker_transport_rule, resolve_broker_auth_token,
        resolve_host_file_path, resolve_recipe_auth_mode, retry_with_delay,
        rewrite_container_output_path, rewrite_recipe_entrypoint_args,
        runtime_bridge_netfilter_line, valid_host_broker_transport_rule,
        write_host_broker_transport_rule,
    };
    use clap::Parser;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn doctor_platform_message_covers_linux_macos_and_other_hosts() {
        assert_eq!(
            doctor_platform_line_for("linux"),
            "  PASS platform: Linux host (native daemon runtime available)"
        );
        assert_eq!(
            doctor_platform_line_for("macos"),
            "  INFO platform: macOS host detected; CLI runs locally and Outcall uses Docker Desktop's Linux runtime for the daemon and agent containers"
        );
        assert_eq!(
            doctor_platform_line_for("windows"),
            "  WARN platform: windows host detected; the isolated daemon runtime still requires Linux"
        );
    }

    #[test]
    fn runtime_bridge_netfilter_message_reports_enforceability() {
        assert!(runtime_bridge_netfilter_line("1", "1").contains("PASS secure unattended mode"));
        assert!(runtime_bridge_netfilter_line("0", "1").contains("WARN secure unattended mode"));
    }

    #[test]
    fn automatic_name_retries_with_discovered_or_incremented_candidate() {
        assert_eq!(
            automatic_name_retry_candidate(true, 0, "foobar-4", "foobar-5".to_string()),
            Some("foobar-5".to_string())
        );
        assert_eq!(
            automatic_name_retry_candidate(true, 0, "foobar-4", "foobar-4".to_string()),
            Some("foobar-5".to_string())
        );
        assert_eq!(
            automatic_name_retry_candidate(false, 0, "fixed", "foobar-5".to_string()),
            None
        );
        assert_eq!(
            automatic_name_retry_candidate(true, 20, "foobar-4", "foobar-5".to_string()),
            None
        );
    }

    #[test]
    fn automatic_name_retry_requires_numeric_suffix_for_fallback() {
        assert_eq!(
            automatic_name_retry_candidate(true, 0, "foobar", "foobar".to_string()),
            None
        );
        assert_eq!(
            automatic_name_retry_candidate(true, 0, "foobar-final", "foobar-final".to_string()),
            None
        );
        assert_eq!(
            automatic_name_retry_candidate(
                true,
                0,
                "foobar-4294967295",
                "foobar-4294967295".into()
            ),
            None
        );
    }

    #[test]
    fn container_name_conflict_detection_is_specific() {
        assert!(is_container_name_conflict(
            "daemon request failed with status code 409: Conflict. The container name \"/foobar-4\" is already in use"
        ));
        assert!(is_container_name_conflict(
            "STATUS CODE 409: CONTAINER NAME /FOOBAR-4 IS ALREADY IN USE"
        ));
        assert!(!is_container_name_conflict(
            "daemon request failed with status code 500: container name lookup failed"
        ));
        assert!(!is_container_name_conflict(
            "daemon request failed with status code 409: image is already in use"
        ));
    }

    #[test]
    fn automatic_auth_prefers_environment_credentials() {
        assert_eq!(
            resolve_recipe_auth_mode(RecipeAuthMode::Auto, None, true, true, true),
            RecipeAuthMode::EnvOnly
        );
        assert_eq!(
            resolve_recipe_auth_mode(
                RecipeAuthMode::Auto,
                Some(RecipeAuthMode::Mount),
                true,
                false,
                false,
            ),
            RecipeAuthMode::Mount
        );
    }

    #[test]
    fn automatic_auth_falls_back_from_mount_to_copy_then_env_only() {
        assert_eq!(
            resolve_recipe_auth_mode(RecipeAuthMode::Auto, None, false, true, true),
            RecipeAuthMode::Mount
        );
        assert_eq!(
            resolve_recipe_auth_mode(RecipeAuthMode::Auto, None, false, false, true),
            RecipeAuthMode::Copy
        );
        assert_eq!(
            resolve_recipe_auth_mode(RecipeAuthMode::Auto, None, false, false, false),
            RecipeAuthMode::EnvOnly
        );
        assert_eq!(
            resolve_recipe_auth_mode(RecipeAuthMode::Copy, None, true, true, true),
            RecipeAuthMode::Copy
        );
    }

    #[test]
    fn command_output_with_timeout_returns_output_for_fast_command() {
        let output =
            command_output_with_timeout("sh", &["-c", "printf ok"], Duration::from_secs(1))
                .expect("fast command should succeed");
        assert!(
            output.status.success(),
            "fast command should exit successfully"
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout), "ok");
    }

    #[test]
    fn command_output_with_timeout_times_out_slow_command() {
        let err = command_output_with_timeout("sh", &["-c", "sleep 2"], Duration::from_millis(100))
            .expect_err("slow command should time out");
        assert!(
            matches!(err, CommandTimeoutError::TimedOut { .. }),
            "expected timeout error, got: {err:?}"
        );
    }

    #[test]
    fn retry_with_delay_recovers_from_transient_failures() {
        let mut attempts = 0;
        let result = retry_with_delay(3, Duration::ZERO, || {
            attempts += 1;
            if attempts < 3 {
                Err("not ready")
            } else {
                Ok("ready")
            }
        });

        assert_eq!(result, Ok("ready"));
        assert_eq!(attempts, 3);
    }

    #[test]
    fn rewrite_container_output_path_maps_absolute_workspace_paths() {
        let rewritten = rewrite_container_output_path(
            Path::new("/tmp/project"),
            "/workspace",
            "/tmp/project/out/last.txt",
        )
        .expect("workspace path should rewrite");
        assert_eq!(rewritten, "/workspace/out/last.txt");
    }

    #[test]
    fn rewrite_container_output_path_rejects_paths_outside_workspace() {
        let err = rewrite_container_output_path(
            Path::new("/tmp/project"),
            "/workspace",
            "/tmp/elsewhere/last.txt",
        )
        .expect_err("external path should be rejected");
        assert!(
            err.to_string().contains("outside the mounted workspace"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rewrite_recipe_entrypoint_args_updates_output_flag_values() {
        let temp = tempdir().expect("tempdir");
        let rewritten = rewrite_recipe_entrypoint_args(
            temp.path(),
            "/workspace",
            vec![
                "exec".into(),
                "--output-last-message".into(),
                temp.path().join("out.txt").display().to_string(),
                format!(
                    "--output-last-message={}",
                    temp.path().join("out2.txt").display()
                ),
            ],
        )
        .expect("args should rewrite");
        assert_eq!(
            rewritten,
            vec![
                "exec",
                "--output-last-message",
                "/workspace/out.txt",
                "--output-last-message=/workspace/out2.txt",
            ]
        );
    }

    #[test]
    fn ensure_recipe_setup_state_is_idempotent_without_force() {
        let temp = tempdir().expect("tempdir");
        let recipe = outcall::recipes::get_recipe("codex").expect("codex recipe");
        ensure_recipe_setup_state(temp.path(), recipe, false).expect("first setup should succeed");
        ensure_recipe_setup_state(temp.path(), recipe, false)
            .expect("second setup should keep existing files");
        let default_recipe = std::fs::read_to_string(temp.path().join(".outcall/default-recipe"))
            .expect("default recipe should exist");
        assert_eq!(default_recipe.trim(), "codex");
    }

    #[test]
    fn broker_http_parser_finishes_without_client_eof() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        server
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("read timeout");
        client
            .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write request");

        let request = read_http_request(&mut server).expect("parse request");
        assert_eq!(request.path, "/v1/health");
        assert!(request.body.is_empty());
    }

    #[test]
    fn broker_http_parser_reads_content_length_body() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let body = br#"{"id":"demo"}"#;
        let request = format!(
            "POST /v1/tool/exec HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        client
            .write_all(request.as_bytes())
            .expect("write request headers");
        client.write_all(body).expect("write request body");

        let parsed = read_http_request(&mut server).expect("parse request");
        assert_eq!(parsed.path, "/v1/tool/exec");
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn broker_rejects_invalid_token_before_loading_config() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let body = br#"{"id":"demo"}"#;
        let request = format!(
            "POST /v1/tool/exec HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        client
            .write_all(request.as_bytes())
            .expect("write request headers");
        client.write_all(body).expect("write request body");
        client.shutdown(Shutdown::Write).expect("finish request");

        handle_broker_connection(
            &mut server,
            "/tmp/missing-outcall.sock",
            Path::new("/tmp/missing-host-resources.yaml"),
            "expected",
        )
        .expect("write forbidden response");
        drop(server);

        let mut response = String::new();
        client.read_to_string(&mut response).expect("read response");
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("invalid broker token"));
    }

    #[test]
    fn broker_health_requires_the_shared_token() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        client
            .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write request");
        client.shutdown(Shutdown::Write).expect("finish request");

        handle_broker_connection(
            &mut server,
            "/tmp/missing-outcall.sock",
            Path::new("/tmp/missing-host-resources.yaml"),
            "expected",
        )
        .expect("write forbidden response");
        drop(server);

        let mut response = String::new();
        client.read_to_string(&mut response).expect("read response");
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("invalid broker token"));
    }

    #[test]
    fn explicit_broker_token_takes_precedence() {
        assert_eq!(
            resolve_broker_auth_token(Some("explicit-token".to_string())),
            "explicit-token"
        );
    }

    #[test]
    fn broker_rejects_undeclared_tool_before_execution() {
        let config = outcall::host_resources::HostResourcesConfig::default();
        let error = broker_exec_tool(
            "/tmp/missing-outcall.sock",
            &config,
            BrokerToolExecRequest {
                id: "missing".to_string(),
                args: Vec::new(),
                cwd: None,
            },
        )
        .err()
        .expect("undeclared tool should fail");
        assert!(error.to_string().contains("host tool not declared"));
    }

    #[test]
    fn broker_file_resolution_rejects_parent_traversal() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("root");
        std::fs::create_dir(&root).expect("create root");
        std::fs::write(temp.path().join("outside.txt"), "secret").expect("write fixture");

        let error = resolve_host_file_path(&root, Some("../outside.txt"))
            .expect_err("parent traversal should fail");
        assert!(
            error
                .to_string()
                .contains("escapes declared host file root")
        );
    }

    #[test]
    fn broker_cli_keeps_daemon_and_listener_sockets_distinct() {
        let cli = Cli::try_parse_from([
            "outcall",
            "--socket",
            "/tmp/daemon.sock",
            "host-broker",
            "serve",
            "--broker-socket",
            "/tmp/broker.sock",
        ])
        .expect("parse broker command");
        assert_eq!(cli.socket, "/tmp/daemon.sock");
        let Some(Commands::HostBroker {
            action: HostBrokerAction::Serve { broker_socket, .. },
        }) = cli.command
        else {
            panic!("expected host broker serve command");
        };
        assert_eq!(broker_socket, "/tmp/broker.sock");
    }

    #[test]
    fn broker_cli_parses_loopback_tcp_listener() {
        let cli = Cli::try_parse_from([
            "outcall",
            "--socket",
            "/tmp/daemon.sock",
            "host-broker",
            "serve-tcp",
            "--listen",
            "127.0.0.1:19001",
        ])
        .expect("parse TCP broker command");
        assert_eq!(cli.socket, "/tmp/daemon.sock");
        let Some(Commands::HostBroker {
            action: HostBrokerAction::ServeTcp { listen, .. },
        }) = cli.command
        else {
            panic!("expected host broker serve-tcp command");
        };
        assert_eq!(listen, "127.0.0.1:19001");
    }

    #[test]
    fn broker_transport_rule_allows_only_the_selected_proxy_port() {
        let temp = tempdir().expect("tempdir");
        std::fs::create_dir_all(temp.path().join(".outcall/rules")).expect("create rules dir");

        write_host_broker_transport_rule(temp.path(), 17890).expect("write transport rule");

        let path = host_broker_transport_rule_path(temp.path());
        let rule = std::fs::read_to_string(path).expect("read transport rule");
        let document: serde_yaml::Value =
            serde_yaml::from_str(&rule).expect("transport rule should be valid YAML");
        assert_eq!(
            document["rules"]
                .as_sequence()
                .expect("rules should be a sequence")
                .len(),
            1
        );
        assert!(valid_host_broker_transport_rule(&rule));
        assert!(rule.contains("http.host == \"host.docker.internal\""));
        assert!(rule.contains("network.port == 17890"));
        assert!(rule.contains("mode: proxy"));
        assert!(rule.contains("ports: [17890]"));
        assert!(!rule.contains("direct"));
    }

    #[test]
    fn invalid_generated_broker_rule_is_removed_before_reload() {
        let temp = tempdir().expect("tempdir");
        std::fs::create_dir_all(temp.path().join(".outcall/rules")).expect("create rules dir");
        let path = host_broker_transport_rule_path(temp.path());
        std::fs::write(
            &path,
            "version: \"1\"\nrules:\n- id: bad\ndescription: invalid\n",
        )
        .expect("write invalid rule");

        assert!(
            remove_invalid_host_broker_transport_rule(temp.path())
                .expect("remove invalid generated rule")
        );
        assert!(!path.exists());
    }

    #[test]
    fn project_policy_is_overlay_mounted_read_only() {
        let temp = tempdir().expect("tempdir");
        std::fs::create_dir_all(temp.path().join(".outcall")).expect("create policy dir");
        let source =
            std::fs::canonicalize(temp.path().join(".outcall")).expect("canonicalize policy dir");

        let mount =
            protected_outcall_mount(temp.path(), "/workspace/").expect("build protected mount");

        assert_eq!(
            mount,
            format!("{}:/workspace/.outcall:ro", source.display())
        );
    }

    #[test]
    fn broker_errors_use_security_appropriate_http_statuses() {
        assert_eq!(
            broker_error_status(&anyhow::anyhow!("blocked by rules")),
            403
        );
        assert_eq!(
            broker_error_status(&anyhow::anyhow!("host tool not declared: demo")),
            403
        );
        assert_eq!(
            broker_error_status(&anyhow::anyhow!(
                "resolved path escapes declared host file root"
            )),
            403
        );
        assert_eq!(
            broker_error_status(&anyhow::anyhow!(
                "relative_path is required for directory resources"
            )),
            400
        );
        assert_eq!(
            broker_error_status(&anyhow::anyhow!("failed to execute host tool")),
            500
        );
    }

    #[test]
    fn daemon_build_uses_dockerfile_parent_as_context() {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join("source");
        std::fs::create_dir(&source).expect("create source");
        let dockerfile = source.join("Dockerfile");
        std::fs::write(&dockerfile, "FROM scratch\n").expect("write Dockerfile");

        let (resolved_dockerfile, context) =
            daemon_build_inputs(&dockerfile).expect("resolve build inputs");
        let expected_source = std::fs::canonicalize(&source).expect("canonicalize source");

        assert_eq!(resolved_dockerfile, expected_source.join("Dockerfile"));
        assert_eq!(context, expected_source);
    }
}

fn doctor_path(label: &str, path: &std::path::Path) {
    if path.exists() {
        println!("  PASS {label}: {}", path.display());
    } else {
        println!("  WARN {label}: {} missing", path.display());
    }
}

fn doctor_bool(label: &str, name: &str, present: bool) {
    if present {
        println!("  PASS {label}: {name}");
    } else {
        println!("  INFO {label}: {name} not found");
    }
}

// ── Rule Request commands (S010-FR-007) ───────────────────────────────────

fn cmd_requests_list(socket: &str) -> Result<()> {
    let body = http_get(socket, "/api/v1/requests/rules")?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let requests: Vec<PendingRuleRequest> = serde_json::from_value(resp.data.context("no data")?)?;

    if requests.is_empty() {
        println!("No pending rule requests.");
        return Ok(());
    }

    println!("{:<18} {:<32} STATUS", "ID", "CONTAINER");
    for r in &requests {
        println!("{:<18} {:<32} {:?}", r.id, r.container_id, r.status);
    }
    Ok(())
}

fn cmd_requests_approve(socket: &str, id: &str) -> Result<()> {
    let path = format!(
        "/api/v1/requests/rules/{}/approve",
        request_target::path_segment(id)
    );
    let body = http_post(socket, &path)?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let result: ApproveRuleResult = serde_json::from_value(resp.data.context("no data")?)?;
    println!(
        "Rule request \"{}\" approved (rules_loaded={}).",
        result.id, result.nft_handle
    );
    Ok(())
}

fn cmd_requests_reject(socket: &str, id: &str, reason: Option<String>) -> Result<()> {
    let path = format!(
        "/api/v1/requests/rules/{}/reject",
        request_target::path_segment(id)
    );
    let req = RejectRuleRequest { reason };
    let body = http_post_json(socket, &path, &req)?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let result: RejectRuleResult = serde_json::from_value(resp.data.context("no data")?)?;
    println!("Rule request \"{}\" rejected.", result.id);
    Ok(())
}

// ── UI command — local TCP → unix-socket bridge for the dashboard ──────────
//
// The host API is served on a Unix domain socket; browsers can't open Unix
// sockets directly. `outcall ui` listens on 127.0.0.1:<port> and forwards each
// connection into the daemon's host socket, byte-for-byte. Equivalent to:
//   socat TCP-LISTEN:8080,reuseaddr,fork UNIX-CONNECT:/tmp/outcall/host.sock
//
// One OS thread per connection. Fine for a single-operator dashboard;
// blocking I/O keeps the CLI free of an async runtime dependency.
//
// Security hardening (DNS-rebinding / cross-origin protection):
//
//   1. Bind explicitly to 127.0.0.1 (never 0.0.0.0).
//
//   2. For every request the bridge reads the HTTP request-line + headers,
//      then enforces:
//        a. Host header must be 127.0.0.1:<port> or localhost:<port>.
//           Any other value (e.g. "evil.com") → 403.
//        b. Origin header, if present, must start with
//           "http://127.0.0.1:<port>" or "http://localhost:<port>".
//           Any other origin → 403.
//      This stops DNS-rebinding: the attacker's page runs under a different
//      origin and/or sets Host to the rebound domain — both are rejected.
//
//   3. For /api/* and /v1/* paths the request must also carry:
//        X-Outcall-Token: <TOKEN>   (header on API calls)
//      OR the URL query string contains  ?token=<TOKEN>  (initial page load).
//      TOKEN is a cryptographically random 256-bit value printed to stdout on
//      startup.  An attacker page can never read the token because it lives in
//      a different browsing context and CORS blocks cross-origin reads.
//
//   Static assets (HTML/JS/CSS) served without token so the browser can fetch
//   index.html, which must then attach the token to its API calls.

/// Generate a 32-byte (256-bit) random token from the OS RNG and hex-encode it.
fn generate_token() -> String {
    use rand::RngCore;
    use rand::rngs::OsRng;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn cmd_ui(socket: &str, port: u16, auto_open: bool) -> Result<()> {
    use std::net::TcpListener;
    use std::sync::Arc;

    let socket_path = std::path::PathBuf::from(socket);
    if !socket_path.exists() {
        anyhow::bail!(
            "host socket not found at {socket}. Is the daemon running? Try `outcall daemon status`."
        );
    }

    // Always bind to loopback — never 0.0.0.0.
    let bind = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&bind)
        .with_context(|| format!("failed to bind {bind}; pick another port with --port"))?;

    let token = generate_token();
    let url = format!("http://127.0.0.1:{port}/ui/?token={token}");
    println!("Outcall UI listening on {url}");
    println!("Open this URL in your browser. The token expires when the bridge exits.");
    println!("Bridging 127.0.0.1:{port} → {socket}");
    println!("Press Ctrl-C to stop.");

    if auto_open {
        let _ = open_in_browser(&url);
    }

    let token = Arc::new(token);

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let target = socket_path.clone();
        let tok = Arc::clone(&token);
        std::thread::spawn(move || {
            if let Err(e) = bridge_connection(stream, &target, port, &tok) {
                eprintln!("bridge error: {e}");
            }
        });
    }
    Ok(())
}

/// Read raw HTTP request headers from `tcp` (stops at the blank line),
/// validate Host/Origin/token, then either:
///   - write a 403/401 response and return, or
///   - forward the full request (headers + body) to the Unix socket and
///     pipe both directions until EOF.
fn bridge_connection(
    tcp: std::net::TcpStream,
    socket_path: &std::path::Path,
    port: u16,
    token: &str,
) -> Result<()> {
    use std::io::{self, BufRead, BufReader, Write};
    use std::net::Shutdown;

    // --- 1. Read request headers -------------------------------------------
    // We need to inspect headers before deciding whether to forward the
    // connection.  We read until the blank line that ends the header section,
    // then re-splice the headers back with the body before forwarding.

    let mut reader = BufReader::new(tcp.try_clone()?);
    let mut header_lines: Vec<String> = Vec::new();

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            // Connection closed before headers finished — nothing to forward.
            return Ok(());
        }
        let done = line == "\r\n" || line == "\n";
        header_lines.push(line);
        if done {
            break;
        }
    }

    // Re-join for forwarding later.
    let raw_headers: String = header_lines.concat();

    // --- 2. Parse the request line + relevant headers ----------------------
    // Format: METHOD SP request-target SP HTTP/version CRLF
    let request_line = header_lines.first().map(|s| s.trim()).unwrap_or("");

    // Extract the path component from the request line (second token).
    let path: String = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();

    let mut host_hdr: Option<String> = None;
    let mut origin_hdr: Option<String> = None;
    let mut token_hdr: Option<String> = None;

    for line in &header_lines[1..] {
        let trimmed = line.trim_end();
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("host:") {
            host_hdr = Some(rest.trim().to_string());
        } else if let Some(rest) = lower.strip_prefix("origin:") {
            // Preserve original case for origin value.
            let colon_pos = trimmed.find(':').unwrap_or(0);
            origin_hdr = Some(trimmed[colon_pos + 1..].trim().to_string());
            let _ = rest; // suppress unused warning
        } else if let Some(rest) = lower.strip_prefix("x-outcall-token:") {
            let colon_pos = trimmed.find(':').unwrap_or(0);
            token_hdr = Some(trimmed[colon_pos + 1..].trim().to_string());
            let _ = rest;
        }
    }

    let path = path.as_str();

    // --- 3. Host header validation ------------------------------------------
    // Allowed: 127.0.0.1:<port>  or  localhost:<port>
    let allowed_host_ip = format!("127.0.0.1:{port}");
    let allowed_host_name = format!("localhost:{port}");
    let host_ok = match &host_hdr {
        None => false, // HTTP/1.1 requires Host; reject absent too.
        Some(h) => h == &allowed_host_ip || h == &allowed_host_name,
    };

    if !host_ok {
        let mut w = tcp;
        write!(
            w,
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 40\r\nConnection: close\r\n\r\nForbidden: Host header failed validation."
        )?;
        return Ok(());
    }

    // --- 4. Origin header validation ----------------------------------------
    // Origin must be absent (curl/CLI) or exactly our loopback origin.
    let allowed_origin_ip = format!("http://127.0.0.1:{port}");
    let allowed_origin_name = format!("http://localhost:{port}");
    let origin_ok = match &origin_hdr {
        None => true, // absent is fine (non-browser clients)
        Some(o) => o == &allowed_origin_ip || o == &allowed_origin_name,
    };

    if !origin_ok {
        let mut w = tcp;
        write!(
            w,
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 41\r\nConnection: close\r\n\r\nForbidden: Origin header failed validation."
        )?;
        return Ok(());
    }

    // --- 5. Token validation for API paths ----------------------------------
    // Paths under /api/* or /v1/* require the token, either via:
    //   X-Outcall-Token header, or
    //   ?token=<TOKEN> query string in the URL.
    let is_api_path =
        path.starts_with("/api/") || path.starts_with("/v1/") || path == "/api" || path == "/v1";

    if is_api_path {
        // Check header first.
        let header_ok = token_hdr.as_deref().map(|t| t == token).unwrap_or(false);

        // Check query string: look for ?token=<TOKEN> or &token=<TOKEN>.
        let query_ok = path
            .split_once('?')
            .map(|(_, qs)| qs)
            .map(|qs| {
                qs.split('&').any(|pair| {
                    let mut kv = pair.splitn(2, '=');
                    let k = kv.next().unwrap_or("");
                    let v = kv.next().unwrap_or("");
                    k == "token" && v == token
                })
            })
            .unwrap_or(false);

        if !header_ok && !query_ok {
            let mut w = tcp;
            write!(
                w,
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nContent-Length: 48\r\nWWW-Authenticate: OutcallToken\r\nConnection: close\r\n\r\nUnauthorized: missing or invalid X-Outcall-Token."
            )?;
            return Ok(());
        }
    }

    // --- 6. Forward the validated request -----------------------------------
    // Reconnect from the buffered reader's underlying stream.
    let unix = std::os::unix::net::UnixStream::connect(socket_path)
        .context("failed to connect to host socket")?;

    let mut unix_w = unix.try_clone()?;

    // Write the headers we already consumed, then pipe the remainder of the
    // TCP stream (the body) into the Unix socket.
    unix_w.write_all(raw_headers.as_bytes())?;

    // body → unix (upstream direction, in a separate thread)
    let mut body_src = reader.into_inner(); // the original TcpStream
    let mut unix_w2 = unix_w;
    let upstream = std::thread::spawn(move || {
        let _ = io::copy(&mut body_src, &mut unix_w2);
        let _ = unix_w2.shutdown(Shutdown::Write);
    });

    // unix response → tcp (downstream direction)
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
    let result: outcall_api::ReloadResult = serde_json::from_value(resp.data.context("no data")?)?;
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
        entrypoint: None,
        working_dir: None,
        volumes: None,
        include_outcall_helper_mounts: None,
        interactive: None,
        tty: None,
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
    let path = format!(
        "/api/v1/container?name={}",
        request_target::query_value(name)
    );
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
    let result = container_remove_request(socket, name, force)?;
    println!("Container \"{}\" removed.", result.name);
    Ok(())
}

fn container_remove_request(
    socket: &str,
    name: &str,
    force: bool,
) -> Result<ContainerRemoveResult> {
    let req = outcall_api::ContainerRemoveRequest {
        name: name.to_string(),
        force: Some(force),
    };
    let body = http_post_json(socket, "/api/v1/container/remove", &req)?;
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;

    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    serde_json::from_value(resp.data.context("no data")?)
        .context("failed to parse container remove response")
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
#[derive(Deserialize, serde::Serialize)]
struct Response {
    success: bool,
    data: Option<serde_json::Value>,
    error: Option<String>,
}

impl Response {
    fn ok<T: serde::Serialize>(data: T) -> Self {
        Self {
            success: true,
            data: Some(serde_json::to_value(data).unwrap_or(serde_json::Value::Null)),
            error: None,
        }
    }
}

fn http_get(socket: &str, path: &str) -> Result<String> {
    if daemon_requests_via_exec() {
        return daemon_http_request_via_exec("GET", socket, path, None);
    }
    let mut stream = connect(socket)?;
    write!(stream, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
    read_body(&mut stream)
}

fn http_post(socket: &str, path: &str) -> Result<String> {
    if daemon_requests_via_exec() {
        return daemon_http_request_via_exec("POST", socket, path, Some(String::new()));
    }
    let mut stream = connect(socket)?;
    write!(
        stream,
        "POST {path} HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
    )?;
    read_body(&mut stream)
}

fn http_post_json<T: serde::Serialize>(socket: &str, path: &str, body: &T) -> Result<String> {
    let json = serde_json::to_string(body)?;
    if daemon_requests_via_exec() {
        return daemon_http_request_via_exec("POST", socket, path, Some(json));
    }
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

fn daemon_requests_via_exec() -> bool {
    std::env::consts::OS == "macos"
}

fn daemon_exec_output<const N: usize>(args: [&str; N]) -> Result<String> {
    let output = std::process::Command::new("docker")
        .arg("exec")
        .arg(DEFAULT_DAEMON_NAME)
        .args(args)
        .output()
        .context("failed to invoke docker exec against outcall-daemon")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        anyhow::bail!(
            "docker exec {} failed: {}",
            DEFAULT_DAEMON_NAME,
            if detail.is_empty() {
                "unknown error"
            } else {
                detail.as_str()
            }
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn daemon_exec_socket_ready(socket: &str) -> Result<bool> {
    let output = std::process::Command::new("docker")
        .args(["exec", DEFAULT_DAEMON_NAME, "test", "-S", socket])
        .output()
        .context("failed to probe daemon socket via docker exec")?;
    Ok(output.status.success())
}

fn daemon_http_request_via_exec(
    method: &str,
    socket: &str,
    path: &str,
    body: Option<String>,
) -> Result<String> {
    let mut args = vec![
        "exec".to_string(),
        DEFAULT_DAEMON_NAME.to_string(),
        "curl".to_string(),
        "--silent".to_string(),
        "--show-error".to_string(),
        "--fail-with-body".to_string(),
        "--unix-socket".to_string(),
        socket.to_string(),
        "-H".to_string(),
        "Host: localhost".to_string(),
        "-X".to_string(),
        method.to_string(),
    ];
    if let Some(body) = body {
        if !body.is_empty() {
            args.push("-H".to_string());
            args.push("Content-Type: application/json".to_string());
            args.push("--data".to_string());
            args.push(body);
        } else {
            args.push("-H".to_string());
            args.push("Content-Length: 0".to_string());
        }
    }
    args.push(format!("http://localhost{path}"));

    let output = std::process::Command::new("docker")
        .args(&args)
        .output()
        .context("failed to invoke docker exec curl against outcall-daemon")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = match (stdout.is_empty(), stderr.is_empty()) {
            (true, true) => String::new(),
            (false, true) => stdout,
            (true, false) => stderr,
            (false, false) => format!("{stdout}\n{stderr}"),
        };
        anyhow::bail!(
            "daemon API request via docker exec failed: {}",
            if detail.is_empty() {
                "unknown error"
            } else {
                detail.as_str()
            }
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn read_body(stream: &mut impl Read) -> Result<String> {
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
        Some(n) => format!("/api/v1/network?name={}", request_target::query_value(n)),
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
    let m = now.month() as u8;
    let d = now.day();
    ca_params.not_before = date_time_ymd(y, m, d);
    ca_params.not_after = date_time_ymd(y + 10, m, d);
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
const DEFAULT_DAEMON_IMAGE: &str =
    concat!("ghcr.io/outcall-dev/outcalld:v", env!("CARGO_PKG_VERSION"));

fn daemon_build_inputs(
    dockerfile: impl AsRef<std::path::Path>,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let dockerfile = std::fs::canonicalize(dockerfile.as_ref()).with_context(|| {
        format!(
            "failed to resolve daemon Dockerfile {}",
            dockerfile.as_ref().display()
        )
    })?;
    let context = dockerfile
        .parent()
        .context("daemon Dockerfile has no parent directory")?
        .to_path_buf();
    Ok((dockerfile, context))
}

#[allow(clippy::too_many_arguments)]
fn cmd_daemon_start(
    image: Option<String>,
    bridge: Option<String>,
    rules_dir: Option<String>,
    name: Option<String>,
    socket: Option<String>,
    agent_socket_host_path: Option<String>,
    no_proxy: bool,
    build_from: Option<String>,
) -> Result<()> {
    use std::process::Command;

    let name = name.unwrap_or_else(|| DEFAULT_DAEMON_NAME.to_string());
    let image = image.unwrap_or_else(|| DEFAULT_DAEMON_IMAGE.to_string());
    let bridge = bridge.unwrap_or_else(|| outcall_api::DEFAULT_BRIDGE_NAME.to_string());
    let rules_dir = rules_dir.unwrap_or_else(|| "/etc/outcall/rules.d".to_string());
    let socket = socket.unwrap_or_else(|| outcall_api::DEFAULT_HOST_SOCKET.to_string());
    let agent_socket_host_path =
        agent_socket_host_path.unwrap_or_else(|| outcall_api::DEFAULT_AGENT_SOCKET.to_string());
    let (operator_uid, operator_gid) = host_operator_identity()?;

    if let Some(dockerfile) = build_from {
        let (dockerfile, context) = daemon_build_inputs(dockerfile)?;
        println!("Building image {image} from {}…", dockerfile.display());
        let status = Command::new("docker")
            .arg("build")
            .arg("-f")
            .arg(&dockerfile)
            .arg("-t")
            .arg(&image)
            .arg(&context)
            .status()
            .context("failed to invoke docker build")?;
        if !status.success() {
            anyhow::bail!("docker build failed (exit {:?})", status.code());
        }
    }

    // Idempotent: remove any prior container of the same name.
    let _ = Command::new("docker").args(["rm", "-f", &name]).output();

    let use_container_local_sockets = daemon_requests_via_exec();
    let socket_dir = std::path::Path::new(&socket)
        .parent()
        .context("daemon socket path must have a parent directory")?;
    if !use_container_local_sockets {
        // Bind-mount the host socket directory so the daemon's unix sockets are
        // reachable from the installed CLI and agent containers.
        std::fs::create_dir_all(socket_dir).with_context(|| {
            format!(
                "failed to create daemon socket directory {}",
                socket_dir.display()
            )
        })?;
    }

    let mut args: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        name.clone(),
        "--network".into(),
        "host".into(),
        "--cap-add".into(),
        "NET_ADMIN".into(),
        "--cap-add".into(),
        "SYS_ADMIN".into(),
        "-v".into(),
        "/var/run/docker.sock:/var/run/docker.sock".into(),
        "-v".into(),
        format!("{rules_dir}:/etc/outcall/rules.d:ro"),
    ];
    if !use_container_local_sockets {
        args.push("-v".into());
        args.push(format!("{}:{}", socket_dir.display(), socket_dir.display()));
    }
    let mut daemon_args = vec![
        "--entrypoint".into(),
        "outcalld".into(),
        image.clone(),
        "--socket".into(),
        socket.clone(),
        "--operator-uid".into(),
        operator_uid.to_string(),
        "--operator-gid".into(),
        operator_gid.to_string(),
        "--agent-socket-host-path".into(),
        agent_socket_host_path.clone(),
        "--bridge".into(),
        bridge.clone(),
    ];
    if no_proxy {
        daemon_args.push("--no-proxy".into());
    }
    args.extend(daemon_args);

    let output = Command::new("docker")
        .args(&args)
        .output()
        .context("failed to invoke docker run; is Docker installed and running?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.contains("unauthorized")
            || stderr.contains("pull access denied")
            || stderr.contains("manifest unknown")
        {
            anyhow::bail!(
                "docker run failed: {stderr}\nHint: preload the matching daemon image via the install script, or pass `outcall daemon start --image <image>`."
            );
        }
        anyhow::bail!("docker run failed: {stderr}");
    }

    let cid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!(
        "Daemon \"{name}\" started ({}, image={image}, bridge={bridge}).",
        cid.chars().take(12).collect::<String>()
    );
    Ok(())
}

fn host_operator_identity() -> Result<(u32, u32)> {
    if let (Ok(uid), Ok(gid)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
        let uid = uid
            .parse::<u32>()
            .context("failed to parse SUDO_UID as a numeric uid")?;
        let gid = gid
            .parse::<u32>()
            .context("failed to parse SUDO_GID as a numeric gid")?;
        return Ok((uid, gid));
    }

    fn read_id_flag(flag: &str) -> Result<u32> {
        let output = std::process::Command::new("id")
            .arg(flag)
            .output()
            .with_context(|| {
                format!("failed to invoke `id {flag}` while determining host operator identity")
            })?;
        if !output.status.success() {
            anyhow::bail!(
                "`id {flag}` failed with exit {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        String::from_utf8(output.stdout)
            .context("`id` returned non-utf8 output")?
            .trim()
            .parse::<u32>()
            .with_context(|| format!("failed to parse `id {flag}` output as uid/gid"))
    }

    Ok((read_id_flag("-u")?, read_id_flag("-g")?))
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
        .args([
            "inspect",
            "--format",
            "{{.State.Running}}\t{{.Config.Image}}",
            &name,
        ])
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
        if running == "true" {
            "running"
        } else {
            "stopped"
        }
    );
    Ok(())
}
