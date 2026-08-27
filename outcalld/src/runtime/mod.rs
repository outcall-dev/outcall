use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Mutex;
use tracing::info;

use outcalld::{agent_api, api, bridge, dns, docker, dynamic, network, proxy, rules};

use super::Args;

mod sockets;

pub(super) async fn run(args: Args) -> Result<()> {
    let ca_state = api::CaState::default();
    let rule_engine = Arc::new(rules::RuleEngine::load(&args.rules_dir)?);
    info!(rules_dir = %args.rules_dir, "rule engine loaded");

    if args.no_proxy && rule_engine.has_proxy_egress_rules().await {
        anyhow::bail!(
            "--no-proxy cannot be used while active rules require egress.mode: proxy; remove those rules or run the proxy"
        );
    }

    let dns_listen: SocketAddr = format!("{}:{}", args.dns_listen, args.dns_port)
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid DNS listen address: {error}"))?;
    let proxy_addr: SocketAddr = args
        .proxy_addr
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid --proxy-addr: {error}"))?;
    let mut api_sockets = sockets::ApiSockets::bind(
        Path::new(&args.socket),
        Path::new(&args.agent_socket_host_path),
        args.operator_uid,
        args.operator_gid,
    )
    .context("failed to bind daemon API sockets")?;

    let (bridge_gateway_ip, bridge_gateway_prefix_len) =
        bridge::first_gateway_from_subnet_block(&args.subnet_block)?;
    let host_services = bridge::HostServiceAccess::from_listeners(
        bridge_gateway_ip,
        dns_listen,
        (!args.no_proxy).then_some(proxy_addr),
    )?;
    let mut bridge_manager = bridge::BridgeManager::new(
        Some(&args.bridge),
        bridge_gateway_ip,
        bridge_gateway_prefix_len,
        host_services,
    )
    .await
    .context("failed to create bridge manager")?;
    bridge_manager
        .init()
        .await
        .context("failed to initialize bridge and base policy")?;
    let bridge = Arc::new(Mutex::new(bridge_manager));
    info!(bridge = %args.bridge, "bridge initialized");

    let docker_manager = docker::DockerManager::new(
        &args.agent_socket_host_path,
        &args.shim_host_path,
        &args.bridge,
        &args.socket,
    )
    .await;
    if docker_manager.is_unavailable() {
        info!("Docker Manager unavailable - continuing in degraded mode");
    } else {
        info!("Docker Manager initialized");
    }

    let dynamic_manager = dynamic::DynamicRuleManager::new(docker_manager.clone(), bridge.clone());
    info!("Dynamic Rule Manager initialized");

    info!(
        dns_listen = %args.dns_listen,
        dns_port = args.dns_port,
        "DNS filter bind configured"
    );
    info!(proxy_addr = %args.proxy_addr, "HTTP proxy bind configured");

    let upstreams = dns::parse_upstream_arg(&args.dns_upstream);
    let dns_server = dns::DnsServer::new(dns_listen, upstreams);
    dns_server
        .start(rule_engine.clone(), dynamic_manager.clone())
        .await
        .map_err(|error| anyhow::anyhow!("DNS filter failed to bind {dns_listen}: {error}"))?;
    info!("DNS filter started on {dns_listen}");

    let proxy_server = proxy::ProxyServer::new(proxy_addr, Some(docker_manager.clone()));
    if args.no_proxy {
        info!("HTTP proxy disabled (--no-proxy)");
    } else {
        proxy_server
            .start(rule_engine.clone())
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "HTTP proxy failed to bind {}: {error}. Set --no-proxy to run without the proxy.",
                    args.proxy_addr
                )
            })?;
        info!(addr = %args.proxy_addr, "HTTP proxy started");
    }

    let network_manager = network::NetworkManager::new(
        bridge.clone(),
        &args.bridge,
        &args.subnet_block,
        docker_manager.as_ref(),
    )?;
    info!(subnet_block = %args.subnet_block, "Network Manager initialized");

    let daemon_uid = rustix::process::geteuid().as_raw();
    let (permission_limit, permission_window) = outcalld::rate_limit::parse(&args.agent_perm_rate)?;
    let (rule_limit, rule_window) = outcalld::rate_limit::parse(&args.agent_rule_rate)?;
    let evaluation_timeout = outcalld::rate_limit::evaluation_timeout(args.agent_timeout_secs)?;
    std::fs::create_dir_all(outcall_api::DEFAULT_STATE_DIR)?;
    let rule_requests = agent_api::RuleRequestManager::new(format!(
        "{}/{}",
        outcall_api::DEFAULT_STATE_DIR,
        outcall_api::RULE_REQUESTS_FILE
    ))?;

    let host_app = api::router(
        api::AppState {
            bridge: bridge.clone(),
            rules: rule_engine.clone(),
            dns: dns_server.clone(),
            proxy: proxy_server.clone(),
            docker: docker_manager.clone(),
            dynamic: dynamic_manager.clone(),
            network: network_manager,
            lifecycle: Arc::new(Mutex::new(())),
            policy_barrier: dns_server.policy_barrier(),
            policy_update: Arc::new(Mutex::new(())),
            ca: Arc::new(ca_state),
            rule_requests: rule_requests.clone(),
            rules_dir: args.rules_dir.clone(),
        },
        daemon_uid,
        args.operator_uid,
    );
    let agent_app = agent_api::router(
        docker_manager.clone(),
        rule_engine,
        agent_api::AgentApiConfig {
            eval_timeout: evaluation_timeout,
            permission_rate: agent_api::RateLimitConfig {
                limit: permission_limit,
                window: permission_window,
            },
            rule_rate: agent_api::RateLimitConfig {
                limit: rule_limit,
                window: rule_window,
            },
        },
        rule_requests,
    );

    let host_listener = api_sockets.take_host()?;
    let agent_listener = api_sockets.take_agent()?;
    let mut agent_server = tokio::spawn(async move {
        let service = agent_app.into_make_service_with_connect_info::<agent_api::UnixPeerCred>();
        axum::serve(agent_listener, service).await
    });
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to register SIGTERM handler")?;
    let host_service = host_app.into_make_service_with_connect_info::<api::HostPeerCred>();

    let mut server_error = None;
    let mut agent_server_finished = false;
    tokio::select! {
        result = axum::serve(host_listener, host_service) => {
            server_error = Some(match result {
                Ok(()) => anyhow::anyhow!("host API server stopped unexpectedly"),
                Err(error) => anyhow::anyhow!("host API server failed: {error}"),
            });
        }
        result = &mut agent_server => {
            agent_server_finished = true;
            server_error = Some(match result {
                Ok(Ok(())) => anyhow::anyhow!("agent API server stopped unexpectedly"),
                Ok(Err(error)) => anyhow::anyhow!("agent API server failed: {error}"),
                Err(error) => anyhow::anyhow!("agent API server task failed: {error}"),
            });
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
        }
        _ = sigterm.recv() => {
            info!("received SIGTERM, shutting down");
        }
    }

    proxy_server.shutdown().await;
    dns_server.shutdown().await;
    if !agent_server_finished {
        agent_server.abort();
        match agent_server.await {
            Err(error) if error.is_cancelled() => {}
            Ok(Ok(())) => {
                tracing::warn!("agent API server stopped before shutdown cancellation completed");
            }
            Ok(Err(error)) => tracing::warn!(%error, "agent API server failed during shutdown"),
            Err(error) => tracing::warn!(%error, "agent API server task failed during shutdown"),
        }
    }
    if let Err(error) = dynamic_manager.shutdown().await {
        tracing::warn!(%error, "could not flush dynamic rules during shutdown");
    }
    if let Err(error) = bridge.lock().await.reset_policy().await {
        tracing::warn!(%error, "could not reset bridge to its base policy during shutdown");
    }
    bridge.lock().await.shutdown().await;
    docker_manager.shutdown().await;
    api_sockets.cleanup();
    info!("outcalld stopped");

    match server_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
