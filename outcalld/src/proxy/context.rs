use std::collections::HashMap;
use std::net::IpAddr;

use outcall_api::{AgentContext, EvalContext, HttpContext, NetworkContext};

pub(super) fn http_context(
    method: &str,
    host: &str,
    path: &str,
    headers: &HashMap<String, String>,
    port: u16,
    body_size: u64,
    agent_name: Option<&str>,
) -> EvalContext {
    EvalContext {
        http: Some(HttpContext {
            method: method.to_uppercase(),
            path: path.to_string(),
            host: host.to_string(),
            headers: headers.clone(),
            body_size,
        }),
        network: Some(NetworkContext {
            hostname: Some(host.to_string()),
            ip: host
                .parse::<IpAddr>()
                .map_or_else(|_| String::new(), |ip| ip.to_string()),
            port,
            protocol: "tcp".into(),
        }),
        agent: agent_name.map(|name| AgentContext {
            name: name.to_string(),
        }),
        ..Default::default()
    }
}
