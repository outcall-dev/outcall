//! Outcall daemon library (S000).

#![forbid(unsafe_code)]

#[cfg(any(target_os = "linux", test))]
mod background_task;

#[cfg(any(target_os = "linux", test))]
pub(crate) mod address_policy;
pub mod bind_mount;
pub mod ca;
#[cfg(any(target_os = "linux", test))]
#[path = "dns/records.rs"]
pub(crate) mod dns_records;
pub mod managed_network;
#[cfg(any(target_os = "linux", test))]
pub(crate) mod network_cidr;
pub mod rate_limit;
pub mod state_file;
#[cfg(any(target_os = "linux", test))]
pub(crate) mod system_command;
#[cfg(any(target_os = "linux", test))]
pub(crate) mod timestamp;
pub mod unix_socket;

#[cfg(any(target_os = "linux", test))]
mod container_env;
#[cfg(any(target_os = "linux", test))]
mod container_request;

pub mod rules;

#[cfg(target_os = "linux")]
pub mod bridge;

#[cfg(any(target_os = "linux", test))]
pub mod agent_api;

#[cfg(target_os = "linux")]
pub mod api;

#[cfg(any(target_os = "linux", test))]
pub mod dns;

#[cfg(any(target_os = "linux", test))]
pub mod proxy;

#[cfg(any(target_os = "linux", test))]
pub mod docker;

#[cfg(any(target_os = "linux", test))]
pub mod dynamic;

#[cfg(target_os = "linux")]
pub mod network;
