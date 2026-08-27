#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use tracing::info;

#[cfg(target_os = "linux")]
mod runtime;

#[derive(Parser)]
#[command(name = "outcalld", about = "Outcall security daemon", version)]
struct Args {
    /// Path for the host API Unix socket.
    #[arg(long, default_value = outcall_api::DEFAULT_HOST_SOCKET)]
    socket: String,

    /// Host UID allowed to own and access the host API Unix socket.
    #[arg(long, default_value_t = 0)]
    operator_uid: u32,

    /// Host GID assigned to the host API Unix socket.
    #[arg(long, default_value_t = 0)]
    operator_gid: u32,

    /// Bridge interface name.
    #[arg(long, default_value = outcall_api::DEFAULT_BRIDGE_NAME)]
    bridge: String,

    /// Directory containing rule YAML files.
    #[arg(long, default_value = "/etc/outcall/rules.d")]
    rules_dir: String,

    /// DNS filter listen address (IP only; port set by --dns-port).
    #[arg(long, default_value = "10.200.0.1")]
    dns_listen: String,

    /// DNS filter listen port.
    #[arg(long, default_value_t = 53)]
    dns_port: u16,

    /// Upstream DNS resolvers, comma-separated IP[:port] (default: /etc/resolv.conf).
    #[arg(long, default_value = "")]
    dns_upstream: String,

    /// HTTP proxy listen address (host:port).
    #[arg(long, default_value = "10.200.0.1:8080")]
    proxy_addr: String,

    /// Disable the HTTP proxy entirely.
    #[arg(long)]
    no_proxy: bool,

    /// Host path of the agent Unix socket to bind-mount into containers.
    #[arg(
        long = "agent-socket",
        visible_alias = "agent-socket-host-path",
        default_value = outcall_api::DEFAULT_AGENT_SOCKET
    )]
    agent_socket_host_path: String,

    /// Host path of the outcall-agent shim binary to bind-mount into containers.
    #[arg(long, default_value = "/usr/local/bin/outcall-agent")]
    shim_host_path: String,

    /// Server-side timeout in seconds for permission-check rule evaluation.
    #[arg(
        long = "agent-timeout",
        visible_alias = "agent-timeout-secs",
        default_value_t = 5
    )]
    agent_timeout_secs: u64,

    /// Permission-check rate limit as `<count>/<seconds>`.
    #[arg(long, default_value = "100/10")]
    agent_perm_rate: String,

    /// Agent rule-submission rate limit as `<count>/<seconds>`.
    #[arg(long, default_value = "10/60")]
    agent_rule_rate: String,

    /// CIDR block used for Outcall network /24 auto-allocation.
    #[arg(long, default_value = outcall_api::SUBNET_BLOCK)]
    subnet_block: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("outcalld=info")),
        )
        .init();

    let args = Args::parse();
    info!("outcalld starting");

    #[cfg(target_os = "linux")]
    {
        runtime::run(args).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        Err(anyhow::anyhow!(
            "outcalld requires Linux; on macOS use `outcall daemon start` to run the managed Linux daemon container"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_timeout_uses_documented_flag_with_legacy_compatibility() {
        let canonical = Args::try_parse_from(["outcalld", "--agent-timeout", "7"]).unwrap();
        let legacy = Args::try_parse_from(["outcalld", "--agent-timeout-secs", "9"]).unwrap();

        assert_eq!(canonical.agent_timeout_secs, 7);
        assert_eq!(legacy.agent_timeout_secs, 9);
    }

    #[test]
    fn agent_socket_uses_documented_flag_with_legacy_compatibility() {
        let canonical =
            Args::try_parse_from(["outcalld", "--agent-socket", "/tmp/agent-a.sock"]).unwrap();
        let legacy =
            Args::try_parse_from(["outcalld", "--agent-socket-host-path", "/tmp/agent-b.sock"])
                .unwrap();

        assert_eq!(canonical.agent_socket_host_path, "/tmp/agent-a.sock");
        assert_eq!(legacy.agent_socket_host_path, "/tmp/agent-b.sock");
    }
}
