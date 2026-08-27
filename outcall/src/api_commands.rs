use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

use crate::daemon_client::Response;

mod bridge;
mod ca;
mod container;
mod dns;
mod network;
mod proxy;
mod rules;

pub(crate) use bridge::{cmd_bridge_down, cmd_bridge_status, cmd_bridge_up};
pub(crate) use ca::{cmd_ca_bundle, cmd_ca_init, cmd_ca_status};
pub(crate) use container::{
    cmd_container_create, cmd_container_inspect, cmd_container_list, cmd_container_pull,
    cmd_container_remove, cmd_container_stop, container_inspect_request, container_remove_request,
};
pub(crate) use dns::{cmd_dns_cache, cmd_dns_flush, cmd_dns_status, cmd_dns_test};
pub(crate) use network::{
    cmd_network_create, cmd_network_destroy, cmd_network_list, cmd_network_status,
};
pub(crate) use proxy::cmd_proxy_status;
pub(crate) use rules::{
    cmd_requests_approve, cmd_requests_list, cmd_requests_reject, cmd_rules_reload,
};

fn response(body: &str) -> Result<Response> {
    let response: Response = serde_json::from_str(body).context("failed to parse response")?;
    if !response.success {
        anyhow::bail!(
            "{}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        );
    }
    Ok(response)
}

fn response_data<T: DeserializeOwned>(body: &str) -> Result<T> {
    let response = response(body)?;
    serde_json::from_value(response.data.context("no data")?)
        .context("failed to parse response data")
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Fixture {
        value: u8,
    }

    #[test]
    fn response_data_decodes_success_envelope() {
        assert_eq!(
            response_data::<Fixture>(r#"{"success":true,"data":{"value":7}}"#).unwrap(),
            Fixture { value: 7 }
        );
    }

    #[test]
    fn response_preserves_daemon_error() {
        let error = response(r#"{"success":false,"error":"denied"}"#)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "denied");
    }

    #[test]
    fn response_data_rejects_missing_data() {
        let error = response_data::<Fixture>(r#"{"success":true}"#)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "no data");
    }
}
