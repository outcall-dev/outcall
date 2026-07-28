//! Outcall daemon library (S000).

#![forbid(unsafe_code)]

#[cfg(any(target_os = "linux", test))]
mod container_env;

pub mod rules;

#[cfg(target_os = "linux")]
pub mod bridge;

#[cfg(target_os = "linux")]
pub mod agent_api;

#[cfg(target_os = "linux")]
pub mod api;

#[cfg(target_os = "linux")]
pub mod dns;

#[cfg(target_os = "linux")]
pub mod proxy;

#[cfg(target_os = "linux")]
pub mod docker;

#[cfg(target_os = "linux")]
pub mod dynamic;

#[cfg(target_os = "linux")]
pub mod network;
