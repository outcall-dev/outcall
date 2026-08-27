use anyhow::Result;
use outcall_api::ProxyStatus;

use super::response_data;
use crate::daemon_client::http_get;

pub(crate) fn cmd_proxy_status(socket: &str) -> Result<()> {
    let status: ProxyStatus = response_data(&http_get(socket, "/api/v1/proxy")?)?;
    if !status.running {
        println!("HTTP Proxy:     inactive");
        return Ok(());
    }

    println!("HTTP Proxy:     active");
    println!("Listen:         {}", status.listen_address);
    println!("Proxy URL:      {}", status.proxy_url);
    println!("Active conns:   {}", status.active_connections);
    println!(
        "Requests:       {} total ({} blocked)",
        status.total_requests, status.total_blocked
    );
    Ok(())
}
