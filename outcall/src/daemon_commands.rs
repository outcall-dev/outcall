mod command;
mod inspect;
mod lifecycle;
mod start;

pub(crate) const DEFAULT_DAEMON_IMAGE: &str =
    concat!("ghcr.io/outcall-dev/outcalld:v", env!("CARGO_PKG_VERSION"));

pub(crate) use inspect::{daemon_container_info, daemon_container_state};
pub(crate) use lifecycle::{
    cmd_daemon_logs, cmd_daemon_status, cmd_daemon_stop, daemon_container_logs,
};
pub(crate) use start::cmd_daemon_start;

#[cfg(test)]
pub(crate) use start::daemon_build_inputs;
