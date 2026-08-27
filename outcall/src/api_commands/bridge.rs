use anyhow::Result;
use outcall_api::BridgeStatus;

use super::{response, response_data};
use crate::daemon_client::{http_get, http_post};

pub(crate) fn cmd_bridge_status(socket: &str) -> Result<()> {
    let status: BridgeStatus = response_data(&http_get(socket, "/api/v1/bridge")?)?;
    println!("Bridge:    {}", status.name);
    println!("Status:    {}", if status.up { "up" } else { "down" });
    if let Some(index) = status.index {
        println!("Index:     {index}");
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

pub(crate) fn cmd_bridge_up(socket: &str) -> Result<()> {
    response(&http_post(socket, "/api/v1/bridge/up")?)?;
    println!("Bridge is up.");
    Ok(())
}

pub(crate) fn cmd_bridge_down(socket: &str) -> Result<()> {
    response(&http_post(socket, "/api/v1/bridge/down")?)?;
    println!("Bridge is down.");
    Ok(())
}
