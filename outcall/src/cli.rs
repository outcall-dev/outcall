use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(
    name = "outcall",
    about = "Outcall host CLI",
    version,
    arg_required_else_help = false
)]
pub(crate) struct Cli {
    /// Path to the outcalld host socket
    #[arg(long, default_value = outcall_api::DEFAULT_HOST_SOCKET, global = true)]
    pub(crate) socket: String,

    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(clap::Subcommand)]
pub(crate) enum Commands {
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
        /// Also copy selected global config; host-only integrations may not work in Linux
        #[arg(long)]
        include_global_config: bool,
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
    /// Inspect a managed agent container with environment values redacted
    Inspect {
        /// Container name
        name: String,
    },
    /// Show logs for a managed agent container
    Logs {
        /// Container name
        name: String,
        /// Follow log output
        #[arg(short, long)]
        follow: bool,
    },
    /// Attach to a running managed agent container
    Attach {
        /// Container name
        name: String,
    },
    /// Stop a managed agent container
    Stop {
        /// Container name
        name: String,
        /// Retain the stopped container for logs or inspection
        #[arg(long)]
        keep: bool,
    },
    /// Initialize, verify, and smoke-test a first-time recipe setup
    Setup {
        /// Optional recipe ID, e.g. claude or codex
        recipe: Option<String>,
        /// Overwrite existing generated files
        #[arg(long)]
        force: bool,
        /// Do not pull or build; require the selected image to exist locally
        #[arg(long)]
        no_build: bool,
        /// How to transfer provider auth/config into the container
        #[arg(long, value_enum, default_value_t = RecipeAuthMode::Auto)]
        auth: RecipeAuthMode,
        /// Re-copy staged auth files even if they already exist
        #[arg(long)]
        force_auth_copy: bool,
        /// Also copy selected global config; host-only integrations may not work in Linux
        #[arg(long)]
        include_global_config: bool,
    },
    /// Initialize and launch a first-time Claude/Codex container in one command
    Run {
        /// Recipe ID, e.g. claude or codex
        recipe: String,
        /// Overwrite existing generated files
        #[arg(long)]
        force: bool,
        /// Do not pull or build; require the selected image to exist locally
        #[arg(long)]
        no_build: bool,
        /// How to transfer provider auth/config into the container
        #[arg(long, value_enum, default_value_t = RecipeAuthMode::Auto)]
        auth: RecipeAuthMode,
        /// Re-copy staged auth files even if they already exist
        #[arg(long)]
        force_auth_copy: bool,
        /// Also copy selected global config; host-only integrations may not work in Linux
        #[arg(long)]
        include_global_config: bool,
        /// Run in detached mode
        #[arg(short, long)]
        detach: bool,
        /// Retain the stopped container after a successful attached run
        #[arg(long)]
        keep: bool,
        /// Custom container name (default: <folder>-1, <folder>-2, ...)
        #[arg(long)]
        name: Option<String>,
        /// Arguments passed to the recipe agent entrypoint
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Prepare or inspect CA state for the future TLS-interception feature
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
pub(crate) enum RulesAction {
    /// Atomically reload all rule files from the rules.d directory
    Reload,
}

#[derive(clap::Subcommand)]
pub(crate) enum PolicyAction {
    /// List active project rules and the named grants this recipe understands
    Explain {
        /// Recipe ID. Uses the project's selected recipe when omitted.
        recipe: Option<String>,
    },
}

#[derive(clap::Subcommand)]
pub(crate) enum RecipeAction {
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
        /// Do not pull or build; require the selected image to exist locally
        #[arg(long)]
        no_build: bool,
        /// How to transfer provider auth/config into the container
        #[arg(long, value_enum, default_value_t = RecipeAuthMode::Auto)]
        auth: RecipeAuthMode,
        /// Re-copy staged auth files even if they already exist
        #[arg(long)]
        force_auth_copy: bool,
        /// Also copy selected global config; host-only integrations may not work in Linux
        #[arg(long)]
        include_global_config: bool,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub(crate) enum RecipeAuthMode {
    /// Reuse a saved choice, otherwise use env credentials or selected copy paths
    Auto,
    /// Copy bounded selected provider files into .outcall/home/<recipe>
    Copy,
    /// Mount the complete provider directory read-write from the host
    Mount,
    /// Pass matching environment variables without copying host configuration
    EnvOnly,
}

#[derive(clap::Subcommand)]
pub(crate) enum RequestsAction {
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
pub(crate) enum HostBrokerAction {
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
pub(crate) enum DaemonAction {
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
pub(crate) enum NetworkAction {
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
pub(crate) enum ProxyAction {
    /// Show HTTP proxy status
    Status,
}

#[derive(clap::Subcommand)]
pub(crate) enum BridgeAction {
    /// Show bridge status
    Status,
    /// Initialize bridge and apply nftables rules
    Up,
    /// Tear down bridge and remove nftables rules
    Down,
}

#[derive(clap::Subcommand)]
pub(crate) enum DnsAction {
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
pub(crate) enum ContainerAction {
    /// Create and start an agent container
    Create {
        /// Docker image to run
        #[arg(long)]
        image: String,
        /// Outcall-managed network (default: outcall-default)
        #[arg(long)]
        network: Option<String>,
        /// Exact container name (generated when omitted)
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
pub(crate) enum CaAction {
    /// Generate CA material for the future S011 TLS-interception feature
    Init {
        /// Output directory for ca.crt and ca.key (default: ~/.outcall/ca/)
        #[arg(long)]
        out: Option<String>,
        /// Replace an existing CA (rotates trust and invalidates prior certificates)
        #[arg(long)]
        force: bool,
    },
    /// Export the CA certificate bundle for container distribution (S011-FR-018)
    Bundle,
    /// Show loaded CA status (S011-FR-001)
    Status,
}
