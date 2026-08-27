use std::collections::HashMap;

use anyhow::{Context, Result};
use outcall_api::{MANAGED_BY_LABEL, MANAGED_BY_VALUE, NETWORK_LABEL};

pub(super) fn has_managed_label(labels: Option<&HashMap<String, String>>) -> bool {
    labels.and_then(|labels| labels.get(MANAGED_BY_LABEL).map(String::as_str))
        == Some(MANAGED_BY_VALUE)
}

pub(super) fn managed_network_label(labels: Option<&HashMap<String, String>>) -> Result<&str> {
    let labels = labels.context("managed container had no labels")?;
    if !has_managed_label(Some(labels)) {
        anyhow::bail!("container is not managed by outcalld");
    }
    required_text(
        labels.get(NETWORK_LABEL).map(String::as_str),
        "managed container network label",
    )
}

pub(super) fn container_name(raw: Option<&str>) -> Result<String> {
    let normalized = required_text(raw, "managed container name")?.trim_start_matches('/');
    Ok(required_text(Some(normalized), "managed container name")?.to_string())
}

pub(super) fn required_text<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str> {
    value
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("{field} was missing or empty"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_managed_labels_and_network() {
        let labels = HashMap::from([
            (MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string()),
            (NETWORK_LABEL.to_string(), "outcall-default".to_string()),
        ]);
        assert!(has_managed_label(Some(&labels)));
        assert_eq!(
            managed_network_label(Some(&labels)).unwrap(),
            "outcall-default"
        );

        let missing_network =
            HashMap::from([(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string())]);
        assert!(managed_network_label(Some(&missing_network)).is_err());
    }

    #[test]
    fn normalizes_and_requires_container_names() {
        assert_eq!(container_name(Some("/agent-1")).unwrap(), "agent-1");
        assert!(container_name(Some("/")).is_err());
        assert!(container_name(None).is_err());
    }
}
