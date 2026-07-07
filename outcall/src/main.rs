#![forbid(unsafe_code)]

use outcall::{parse_memory_arg, urlencoded};
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

#[derive(clap::Args, Clone)]
struct RecipeLaunchArgs {
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
    /// Arguments passed to the recipe agent entrypoint
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
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
        /// Custom agent name (default: <folder>-1, <folder>-2, ...)
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
        /// Arguments passed to the recipe agent entrypoint
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Start an isolated Claude/Codex container, auto-detecting the provider when possible
    Start {
        /// Optional recipe ID, e.g. claude or codex
        recipe: Option<String>,
        #[command(flatten)]
        launch: RecipeLaunchArgs,
    },
    /// Initialize and launch an isolated Claude Code container
    Claude(RecipeLaunchArgs),
    /// Initialize and launch an isolated Codex container
    Codex(RecipeLaunchArgs),
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
    /// Build the recipe image, stage auth, and start the agent
    Run {
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
        /// Run in detached mode
        #[arg(short, long)]
        detach: bool,
        /// Arguments passed to the recipe agent entrypoint
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
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
    /// Automatically choose copy when recipe files exist, otherwise env-only
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
        #[arg(long, default_value = "/tmp/outcall-broker/host-broker.sock")]
        socket: String,
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
        None => cmd_onboarding(&cli.socket),
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
        Some(Commands::Agent {
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
        }) => {
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
        Some(Commands::Doctor { recipe }) => cmd_doctor(recipe.as_deref()),
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
            args,
        }) => cmd_run(
            &cli.socket,
            &recipe,
            force,
            no_build,
            auth,
            force_auth_copy,
            detach,
            args,
        ),
        Some(Commands::Start { recipe, launch }) => {
            cmd_start(&cli.socket, recipe.as_deref(), launch)
        }
        Some(Commands::Claude(args)) => cmd_recipe_alias(&cli.socket, "claude", args),
        Some(Commands::Codex(args)) => cmd_recipe_alias(&cli.socket, "codex", args),
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
            RecipeAction::Run {
                id,
                no_build,
                auth,
                force_auth_copy,
                detach,
                args,
            } => cmd_recipe_run(
                &cli.socket,
                &id,
                no_build,
                auth,
                force_auth_copy,
                detach,
                args,
            ),
            RecipeAction::Test {
                id,
                no_build,
                auth,
                force_auth_copy,
            } => cmd_recipe_test(&cli.socket, &id, no_build, auth, force_auth_copy),
        },
        Some(Commands::HostBroker { action }) => match action {
            HostBrokerAction::Serve {
                socket,
                config,
                auth_token,
            } => cmd_host_broker_serve(&cli.socket, &socket, config.as_deref(), auth_token),
        },
        Some(Commands::Ui { port, no_open }) => cmd_ui(&cli.socket, port, !no_open),
    }
}

fn cmd_onboarding(socket: &str) -> Result<()> {
    if let Ok(selection) = detect_default_recipe() {
        println!("Outcall");
        println!();
        return cmd_start_with_selection(socket, selection, default_launch_args());
    }

    println!("Outcall");
    println!();
    print_first_run_recommendation();
    println!();
    println!("Common commands:");
    println!("  outcall start         # initialize and launch the isolated agent");
    println!("  outcall setup         # initialize, verify, and smoke-test without launching");
    println!("  outcall doctor        # inspect Docker, scaffold, and auth detection");
    println!("  outcall recipe list   # show built-in recipes");
    Ok(())
}

fn cmd_recipe_alias(socket: &str, recipe: &str, args: RecipeLaunchArgs) -> Result<()> {
    cmd_run(
        socket,
        recipe,
        args.force,
        args.no_build,
        args.auth,
        args.force_auth_copy,
        args.detach,
        args.args,
    )
}

fn default_launch_args() -> RecipeLaunchArgs {
    RecipeLaunchArgs {
        force: false,
        no_build: false,
        auth: RecipeAuthMode::Auto,
        force_auth_copy: false,
        detach: false,
        args: Vec::new(),
    }
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
    host_socket: std::path::PathBuf,
    container_socket: String,
    auth_token: String,
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
    let token = auth_token.unwrap_or_else(random_broker_token);
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

fn handle_broker_connection(
    stream: &mut std::os::unix::net::UnixStream,
    daemon_socket: &str,
    config_path: &std::path::Path,
    auth_token: &str,
) -> Result<()> {
    let request = read_http_request(stream)?;
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

    let config = outcall::host_resources::load_from_path(config_path)?;
    match request.path.as_str() {
        "/v1/tool/exec" => {
            let req: BrokerToolExecRequest =
                serde_json::from_slice(&request.body).context("invalid tool exec request")?;
            let result = broker_exec_tool(daemon_socket, &config, req)?;
            write_http_json(stream, 200, &Response::ok(result))
        }
        "/v1/file/read" => {
            let req: BrokerFileReadRequest =
                serde_json::from_slice(&request.body).context("invalid file read request")?;
            let result = broker_read_file(daemon_socket, &config, req)?;
            write_http_json(stream, 200, &Response::ok(result))
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

    let path = outcall::host_resources::expand_home(&tool.path);
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

struct RawHttpRequest {
    path: String,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut std::os::unix::net::UnixStream) -> Result<RawHttpRequest> {
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP request")?;
    let head = String::from_utf8(raw[..header_end].to_vec()).context("invalid HTTP header")?;
    let body = raw[header_end + 4..].to_vec();
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
    Ok(RawHttpRequest {
        path,
        headers,
        body,
    })
}

fn write_http_json<T: serde::Serialize>(
    stream: &mut std::os::unix::net::UnixStream,
    status: u16,
    body: &T,
) -> Result<()> {
    let json = serde_json::to_vec(body).context("failed to serialize broker response")?;
    let status_text = match status {
        200 => "OK",
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

fn cmd_start(socket: &str, recipe: Option<&str>, mut args: RecipeLaunchArgs) -> Result<()> {
    let selection = match recipe {
        Some(id) if outcall::recipes::get_recipe(id).is_some() => RecipeSelection {
            recipe: recipe_or_bail(id)?,
            source: RecipeSource::Explicit,
        },
        Some(id) if id.starts_with('-') => {
            args.args.insert(0, id.to_string());
            detect_default_recipe()?
        }
        Some(id) => RecipeSelection {
            recipe: recipe_or_bail(id)?,
            source: RecipeSource::Explicit,
        },
        None => detect_default_recipe()?,
    };
    cmd_start_with_selection(socket, selection, args)
}

fn cmd_start_with_selection(
    socket: &str,
    selection: RecipeSelection,
    args: RecipeLaunchArgs,
) -> Result<()> {
    println!(
        "Starting with recipe: {} ({})",
        selection.recipe.id,
        selection.source.label()
    );
    cmd_recipe_alias(socket, selection.recipe.id, args)
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
        println!("  outcall start");
        println!("  outcall setup         # repeat first-run checks without launching");
        println!("  outcall start --detach");
        return Ok(());
    }

    let config_path =
        outcall::agent_config::AgentConfig::save_template_with_force(&project_dir, force)?;
    println!("  wrote {}", config_path.display());
    if let Some(path) = outcall::recipes::ensure_outcall_gitignore(&project_dir)? {
        println!("  wrote {}", path.display());
    }
    println!("  ensured {}", rules_dir.display());

    if load_default_recipe(&project_dir)?.is_none() {
        if let Ok(selection) = detect_default_recipe() {
            if !matches!(selection.source, RecipeSource::SavedDefault) {
                let selected = save_default_recipe(&project_dir, selection.recipe.id)?;
                println!("  wrote {}", selected.display());
                println!(
                    "  selected default recipe: {} ({})",
                    selection.recipe.id,
                    selection.source.label()
                );
            }
        }
    }

    println!();
    println!("Suggested next steps:");
    println!("  outcall doctor");
    println!("  outcall start");
    println!("  outcall setup");
    println!("  outcall claude         # fallback if auto-detect is ambiguous");
    println!("  outcall codex");
    Ok(())
}

fn cmd_doctor(recipe: Option<&str>) -> Result<()> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;

    println!("Outcall doctor");
    println!("Project: {}", project_dir.display());
    println!();

    doctor_platform();
    doctor_command("docker", &["--version"]);
    doctor_command("git", &["--version"]);
    doctor_command("docker", &["info"]);
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
    println!("Network reminder:");
    println!("  `outcall network create` creates the default managed network.");
    println!("  `outcall daemon start` starts the local daemon container when needed.");

    if let Some(id) = recipe {
        println!();
        return cmd_recipe_doctor(id);
    }

    println!();
    print_first_run_recommendation();

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

    cmd_init(Some(recipe.id), force)?;
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
        println!("  outcall start");
        println!("  outcall start --detach");
        println!("  {}", recommended_recipe_command(recipe));
    }
    Ok(())
}

fn cmd_run(
    socket: &str,
    id: &str,
    force: bool,
    no_build: bool,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
    detach: bool,
    args: Vec<String>,
) -> Result<()> {
    cmd_setup_inner(
        socket,
        id,
        force,
        no_build,
        auth_mode,
        force_auth_copy,
        false,
    )?;
    println!();
    cmd_recipe_run(socket, id, true, auth_mode, force_auth_copy, detach, args)
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
        RecipeAuthHint::EnvOnly => format!("outcall {} --auth env-only", recipe.id),
        RecipeAuthHint::Copy | RecipeAuthHint::None => format!("outcall {}", recipe.id),
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
                "found project context for multiple agents ({ids}); choose one explicitly once for this project:\n  outcall claude\n  outcall codex\n\
                 Future `outcall start` runs will reuse the saved project default."
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
             Run `outcall doctor`, then choose one explicitly:\n  outcall claude\n  outcall codex"
        ),
        many => {
            let ids = many
                .iter()
                .map(|recipe| recipe.id)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "found auth candidates for multiple agents ({ids}); choose one explicitly once for this project:\n  outcall claude\n  outcall codex\n\
                 Future `outcall start` runs will reuse the saved project default."
            )
        }
    }
}

fn print_first_run_recommendation() {
    let project_dir = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(_) => {
            println!("Recommended first command:");
            println!("  outcall start");
            return;
        }
    };

    if let Ok(Some(recipe)) = load_default_recipe(&project_dir) {
        println!("Recommended first command:");
        println!("  outcall start");
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
            println!("  outcall start");
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
            println!("  outcall claude");
            println!("  outcall codex");
            println!("  # multiple project context candidates detected: {ids}");
            return;
        }
    }

    match detect_recipe_candidates().as_slice() {
        [recipe] => {
            println!("Recommended first command:");
            println!("  outcall start");
            println!("  # detected {} auth/config on this host", recipe.name);
        }
        [] => {
            println!("Recommended first command:");
            println!("  outcall start          # after you export provider auth");
            println!("  outcall claude         # choose Claude explicitly");
            println!("  outcall codex          # choose Codex explicitly");
        }
        many => {
            let ids = many
                .iter()
                .map(|recipe| recipe.id)
                .collect::<Vec<_>>()
                .join(", ");
            println!("Recommended first command:");
            println!("  outcall claude");
            println!("  outcall codex");
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
    println!(
        "  outcall recipe run {}   # lower-level equivalent",
        recipe.id
    );
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
    doctor_command("docker", &["info"]);
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
            "  WARN macOS Claude unattended mode is most reliable with ANTHROPIC_API_KEY; mounted login state may still require interactive /login"
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

fn cmd_recipe_run(
    socket: &str,
    id: &str,
    no_build: bool,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
    detach: bool,
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
    launch_managed_recipe_container(socket, &project_dir, config, args)
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

    recipe_smoke_test(&project_dir, &config, recipe)?;
    println!("Recipe test passed: {}", recipe.id);
    Ok(())
}

fn recipe_agent_config(
    recipe: &outcall::recipes::Recipe,
    image: &str,
    detach: bool,
) -> outcall::agent_config::AgentConfig {
    let mut env = std::collections::HashMap::new();
    let proxy = format!("http://{}:8080", outcall_api::DEFAULT_GATEWAY);
    env.insert("HOME".to_string(), "/home/node".to_string());
    env.insert("HTTP_PROXY".to_string(), proxy.clone());
    env.insert("HTTPS_PROXY".to_string(), proxy);
    env.insert("NO_PROXY".to_string(), "localhost,127.0.0.1".to_string());

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
    for key in recipe.auth_env {
        if let Ok(value) = std::env::var(key) {
            found_auth = true;
            config.env.insert((*key).to_string(), value);
        }
    }

    let effective_mode = match auth_mode {
        RecipeAuthMode::Auto if should_prefer_auth_mount(recipe) => RecipeAuthMode::Mount,
        RecipeAuthMode::Auto if recipe_has_user_auth_paths(recipe) => RecipeAuthMode::Copy,
        RecipeAuthMode::Auto => RecipeAuthMode::EnvOnly,
        mode => mode,
    };

    if auth_mode == RecipeAuthMode::Auto {
        println!(
            "Auto auth mode selected: {}.",
            match effective_mode {
                RecipeAuthMode::Copy => "copy",
                RecipeAuthMode::Mount => "mount",
                RecipeAuthMode::EnvOnly => "env-only",
                RecipeAuthMode::Auto => "auto",
            }
        );
    }

    match effective_mode {
        RecipeAuthMode::Auto => unreachable!("auto mode should resolve before staging"),
        RecipeAuthMode::Copy => {
            let staged = outcall::recipes::stage_auth_copy(&project_dir, recipe, force_auth_copy)?;
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
            }
        }
        RecipeAuthMode::Mount => {
            let preserve_home_layout = should_preserve_host_home_layout(recipe);
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
                }
            }
            config.volumes.extend(mount_plan.mounts);
        }
        RecipeAuthMode::EnvOnly => {}
    }

    Ok(AuthStageResult {
        found_auth,
        effective_mode,
    })
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
        return Ok(());
    }

    let runtime = ensure_host_broker_running(daemon_socket, project_dir, &registry_path)?;
    println!(
        "Host broker ready: {} -> {}",
        runtime.host_socket.display(),
        runtime.container_socket
    );
    config.env.insert(
        "OUTCALL_HOST_BROKER_SOCKET".to_string(),
        runtime.container_socket,
    );
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

    let host_socket = run_dir.join("host-broker.sock");
    let token_path = run_dir.join("host-broker.token");
    let auth_token = if token_path.exists() {
        std::fs::read_to_string(&token_path)
            .with_context(|| format!("failed to read {}", token_path.display()))?
            .trim()
            .to_string()
    } else {
        let token = random_broker_token();
        std::fs::write(&token_path, &token)
            .with_context(|| format!("failed to write {}", token_path.display()))?;
        secure_runtime_file(&token_path)?;
        token
    };

    let runtime = HostBrokerRuntime {
        host_socket: host_socket.clone(),
        container_socket: "/workspace/.outcall/run/host-broker.sock".to_string(),
        auth_token,
    };

    if host_broker_healthy(&host_socket) {
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
        .arg("--socket")
        .arg(&host_socket)
        .arg("--config")
        .arg(registry_path)
        .arg("--auth-token")
        .arg(&runtime.auth_token)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    let _child = command.spawn().with_context(|| {
        format!(
            "failed to start host broker for {}",
            registry_path.display()
        )
    })?;

    wait_for_host_broker(&host_socket)?;
    Ok(runtime)
}

fn host_broker_healthy(socket: &std::path::Path) -> bool {
    if !socket.exists() {
        return false;
    }
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return false;
    };
    if write!(stream, "GET /v1/health HTTP/1.0\r\nHost: localhost\r\n\r\n").is_err() {
        return false;
    }
    let Ok(body) = read_body(&mut stream) else {
        return false;
    };
    let Ok(resp) = serde_json::from_str::<Response>(&body) else {
        return false;
    };
    resp.success
}

fn wait_for_host_broker(socket: &std::path::Path) -> Result<()> {
    for _ in 0..50 {
        if host_broker_healthy(socket) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    anyhow::bail!("host broker did not become ready at {}", socket.display());
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
) -> Result<()> {
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

    let interactive = !config.detach && entrypoint_args.is_empty() && config.command.is_none();
    let tty = interactive && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let cmd = if !entrypoint_args.is_empty() {
        Some(entrypoint_args)
    } else {
        config.command.clone()
    };

    let req = outcall_api::ContainerCreateRequest {
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

    let body = match http_post_json(socket, "/api/v1/container/create", &req) {
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
    let resp: Response = serde_json::from_str(&body).context("failed to parse response")?;
    if !resp.success {
        anyhow::bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
    }

    let result: ContainerCreateResult = serde_json::from_value(resp.data.context("no data")?)?;

    if config.detach {
        println!(
            "Agent '{}' started ({}) in detached mode.",
            result.name,
            &result.container_id[..12.min(result.container_id.len())]
        );
        println!("  Attach: docker attach {}", result.name);
        println!("  Logs:   docker logs -f {}", result.name);
        println!("  Stop:   outcall agent --stop {}", result.name);
        return Ok(());
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
            if let Some(ref desired) = desired_rules_dir {
                if daemon_rules_mount_mismatch(DEFAULT_DAEMON_NAME, desired)? {
                    println!(
                        "Restarting outcall-daemon to mount project rules from {}...",
                        desired.display()
                    );
                    cmd_daemon_stop(None)?;
                    start_daemon_with_rules(socket, desired)?;
                }
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
                    if let Some(state) = daemon_container_state(DEFAULT_DAEMON_NAME)? {
                        if state != "running" {
                            let logs = daemon_container_logs(DEFAULT_DAEMON_NAME)?;
                            anyhow::bail!(
                                "outcalld container is not running (state: {state}) while waiting for {socket}\n{logs}"
                            );
                        }
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
                if let Some(state) = daemon_container_state(DEFAULT_DAEMON_NAME)? {
                    if state != "running" {
                        let logs = daemon_container_logs(DEFAULT_DAEMON_NAME)?;
                        anyhow::bail!(
                            "outcalld container is not running (state: {state}) while waiting for {socket}\n{logs}"
                        );
                    }
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
    project_dir: &std::path::Path,
    config: &outcall::agent_config::AgentConfig,
    recipe: &outcall::recipes::Recipe,
) -> Result<()> {
    let image = config.effective_image();
    let workspace = &config.workspace;
    let abs_project_dir = std::fs::canonicalize(project_dir)
        .with_context(|| format!("failed to canonicalize {}", project_dir.display()))?;

    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--network".to_string(),
        config.network.clone(),
        "-v".to_string(),
        format!("{}:{}", abs_project_dir.display(), workspace),
        "-w".to_string(),
        workspace.clone(),
    ];

    for vol in &config.volumes {
        args.extend_from_slice(&["-v".to_string(), vol.clone()]);
    }
    for (key, value) in &config.env {
        args.extend_from_slice(&["-e".to_string(), format!("{}={}", key, value)]);
    }
    args.extend_from_slice(&["--entrypoint".to_string(), recipe.id.to_string()]);
    args.push(image);
    args.push("--version".to_string());

    println!("Running recipe smoke test...");
    let output = std::process::Command::new("docker")
        .args(&args)
        .output()
        .context("failed to invoke docker run for recipe smoke test")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("recipe smoke test failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let first_line = stdout.lines().next().unwrap_or("ok");
    println!("  PASS entrypoint: {first_line}");
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

fn ensure_docker_access() -> Result<()> {
    let output = std::process::Command::new("docker")
        .args(["info"])
        .output()
        .context(
            "failed to invoke `docker info`; install Docker and ensure the CLI is available",
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

    if detail.contains("permission denied") {
        anyhow::bail!(
            "Docker is installed but the current user cannot access the Docker socket.\n\
             Detail: {detail}\n\
             Start Docker Desktop or fix Docker socket permissions, then rerun `outcall`.\n\
             Run `outcall doctor` if you want the full prerequisite report first."
        );
    }

    anyhow::bail!(
        "Docker is not ready for Outcall.\n\
         Detail: {detail}\n\
         Start Docker and rerun `outcall`.\n\
         Run `outcall doctor` if you want the full prerequisite report first."
    );
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
    let dockerfile = outcall::recipes::recipe_dockerfile(project_dir, recipe);
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
    Ok(())
}

fn doctor_command(command: &str, args: &[&str]) {
    match std::process::Command::new(command).args(args).output() {
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
        Err(e) => println!("  WARN {command}: {e}"),
    }
}

fn doctor_platform() {
    let os = std::env::consts::OS;
    if os == "linux" {
        println!("  PASS platform: Linux host");
    } else {
        println!("  WARN platform: {os} host detected; outcalld only runs on Linux");
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
        println!("  INFO br_netfilter: Linux-only prerequisite");
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
    let path = format!("/api/v1/requests/rules/{}/approve", urlencoded(id));
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
    let path = format!("/api/v1/requests/rules/{}/reject", urlencoded(id));
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
