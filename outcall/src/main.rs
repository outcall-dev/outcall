#![forbid(unsafe_code)]

mod api_commands;
mod cli;
mod daemon_client;
mod daemon_commands;
mod docker_support;
mod host_broker;
mod process_control;
mod random_token;
mod recipe_auth;
mod recipe_commands;
mod recipe_runtime;
mod ui;

use api_commands::{
    cmd_bridge_down, cmd_bridge_status, cmd_bridge_up, cmd_ca_bundle, cmd_ca_init, cmd_ca_status,
    cmd_container_create, cmd_container_inspect, cmd_container_list, cmd_container_pull,
    cmd_container_remove, cmd_container_stop, cmd_dns_cache, cmd_dns_flush, cmd_dns_status,
    cmd_dns_test, cmd_network_create, cmd_network_destroy, cmd_network_list, cmd_network_status,
    cmd_proxy_status, cmd_requests_approve, cmd_requests_list, cmd_requests_reject,
    cmd_rules_reload,
};
#[cfg(test)]
use cli::RecipeAuthMode;
use cli::{
    BridgeAction, CaAction, Cli, Commands, ContainerAction, DaemonAction, DnsAction,
    HostBrokerAction, NetworkAction, PolicyAction, ProxyAction, RecipeAction, RequestsAction,
    RulesAction,
};
#[cfg(test)]
use daemon_commands::daemon_build_inputs;
use daemon_commands::{cmd_daemon_logs, cmd_daemon_start, cmd_daemon_status, cmd_daemon_stop};
#[cfg(test)]
use docker_support::{
    CommandTimeoutError, command_output_with_timeout, doctor_platform_line_for, retry_with_delay,
    runtime_bridge_netfilter_line,
};
#[cfg(test)]
use host_broker::{
    BrokerToolExecRequest, broker_error_status, broker_exec_tool, handle_broker_connection,
    host_broker_transport_rule_path, read_http_request, remove_invalid_host_broker_transport_rule,
    resolve_broker_auth_token, resolve_host_file_path, valid_host_broker_transport_rule,
    write_host_broker_transport_rule,
};
use host_broker::{cmd_host_broker_serve, cmd_host_broker_serve_tcp};
#[cfg(test)]
use recipe_auth::resolve_recipe_auth_mode;
#[cfg(test)]
use recipe_commands::ensure_recipe_setup_state;
use recipe_commands::{
    cmd_agent_attach, cmd_agent_logs, cmd_allow, cmd_auth, cmd_doctor, cmd_init, cmd_onboarding,
    cmd_policy_explain, cmd_recipe_doctor, cmd_recipe_init, cmd_recipe_list, cmd_recipe_show,
    cmd_run, cmd_setup,
};
use recipe_runtime::cmd_recipe_test;
#[cfg(test)]
use recipe_runtime::{
    automatic_name_retry_candidate, is_container_name_conflict, protected_outcall_mount,
    rewrite_container_output_path, rewrite_recipe_entrypoint_args,
};
use ui::cmd_ui;

use anyhow::Result;
use clap::Parser;

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
            include_global_config,
        }) => cmd_auth(&recipe, auth, force, include_global_config),
        Some(Commands::Allow { recipe, target }) => cmd_allow(&cli.socket, &recipe, &target),
        Some(Commands::Policy { action }) => match action {
            PolicyAction::Explain { recipe } => cmd_policy_explain(recipe.as_deref()),
        },
        Some(Commands::Ps) => cmd_container_list(&cli.socket),
        Some(Commands::Inspect { name }) => cmd_container_inspect(&cli.socket, &name),
        Some(Commands::Logs { name, follow }) => cmd_agent_logs(&cli.socket, &name, follow),
        Some(Commands::Attach { name }) => cmd_agent_attach(&cli.socket, &name),
        Some(Commands::Stop { name, keep }) => {
            cmd_container_stop(&cli.socket, &name, None)?;
            if keep {
                Ok(())
            } else {
                cmd_container_remove(&cli.socket, &name, false)
            }
        }
        Some(Commands::Setup {
            recipe,
            force,
            no_build,
            auth,
            force_auth_copy,
            include_global_config,
        }) => cmd_setup(
            &cli.socket,
            recipe.as_deref(),
            force,
            no_build,
            auth,
            force_auth_copy,
            include_global_config,
        ),
        Some(Commands::Run {
            recipe,
            force,
            no_build,
            auth,
            force_auth_copy,
            include_global_config,
            detach,
            keep,
            name,
            args,
        }) => cmd_run(
            &cli.socket,
            &recipe,
            force,
            no_build,
            auth,
            force_auth_copy,
            include_global_config,
            detach,
            keep,
            name,
            args,
        ),
        Some(Commands::Ca { action }) => match action {
            CaAction::Init { out, force } => cmd_ca_init(out, force),
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
                include_global_config,
            } => cmd_recipe_test(
                &cli.socket,
                &id,
                no_build,
                auth,
                force_auth_copy,
                include_global_config,
            ),
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

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
