use anyhow::Result;
use outcall::request_target;
use outcall_api::{
    ApproveRuleResult, PendingRuleRequest, RejectRuleRequest, RejectRuleResult, ReloadResult,
};

use super::response_data;
use crate::daemon_client::{http_get, http_post, http_post_json};

pub(crate) fn cmd_requests_list(socket: &str) -> Result<()> {
    let requests: Vec<PendingRuleRequest> =
        response_data(&http_get(socket, "/api/v1/requests/rules")?)?;
    if requests.is_empty() {
        println!("No pending rule requests.");
        return Ok(());
    }

    println!("{:<18} {:<32} STATUS", "ID", "CONTAINER");
    for request in requests {
        println!(
            "{:<18} {:<32} {:?}",
            request.id, request.container_id, request.status
        );
    }
    Ok(())
}

pub(crate) fn cmd_requests_approve(socket: &str, id: &str) -> Result<()> {
    let path = format!(
        "/api/v1/requests/rules/{}/approve",
        request_target::path_segment(id)
    );
    let result: ApproveRuleResult = response_data(&http_post(socket, &path)?)?;
    println!(
        "Rule request \"{}\" approved; {} rule(s) loaded.",
        result.id, result.rules_loaded
    );
    Ok(())
}

pub(crate) fn cmd_requests_reject(socket: &str, id: &str, reason: Option<String>) -> Result<()> {
    let path = format!(
        "/api/v1/requests/rules/{}/reject",
        request_target::path_segment(id)
    );
    let request = RejectRuleRequest { reason };
    let result: RejectRuleResult = response_data(&http_post_json(socket, &path, &request)?)?;
    println!("Rule request \"{}\" rejected.", result.id);
    Ok(())
}

pub(crate) fn cmd_rules_reload(socket: &str) -> Result<()> {
    let result: ReloadResult = response_data(&http_post(socket, "/api/v1/rules/reload")?)?;
    println!(
        "Reloaded {} rule(s) from {} file(s).",
        result.rules_loaded, result.files_loaded
    );
    for warning in result.warnings {
        println!("  warning: {warning}");
    }
    Ok(())
}
