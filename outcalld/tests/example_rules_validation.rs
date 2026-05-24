//! Validate the shipped example rule sets actually load.
//!
//! Catches the class of bug demonstrated by the original
//! `rules.d/10-allow-dns-ports-ubuntu-com.yaml` (referenced `ip.dst`, an
//! undefined CEL field, and silently never matched). Examples that ship
//! in the repo are the operator's first contact with the rule language —
//! if they don't load, the deny-by-default is hiding a docs failure.

use outcalld::rules::RuleEngine;
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is application/outcalld
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
#[ignore = "expects rules.d/examples/ in the parent repo (Outcall-dev/root) working tree; not present in the standalone outcall checkout"]
fn sentry_github_agent_example_rules_load() {
    let dir = repo_root().join("rules.d/examples/sentry-github-agent");
    assert!(dir.is_dir(), "expected example dir at {}", dir.display());

    let mut count = 0;
    let mut errors = Vec::new();

    for entry in fs::read_dir(&dir).expect("read example dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|x| x.to_str()) != Some("yaml") {
            continue;
        }
        count += 1;
        let content = fs::read_to_string(&path).expect("read yaml");
        if let Err(err) = RuleEngine::validate_rule_file(&content) {
            errors.push(format!("{}: {}", path.display(), err));
        }
    }

    assert!(
        count >= 7,
        "expected 7+ example rule files, found {count} in {}",
        dir.display()
    );
    assert!(
        errors.is_empty(),
        "{} of {} example rule files failed validation:\n  {}",
        errors.len(),
        count,
        errors.join("\n  ")
    );
}

#[test]
fn root_rules_d_examples_load() {
    // Every .yaml at the top of rules.d/ (i.e. shipped defaults that
    // operators inherit) must parse and compile, or we ship a broken
    // example.
    let dir = repo_root().join("rules.d");
    if !dir.is_dir() {
        // No top-level rules.d in this checkout — skip rather than fail.
        return;
    }

    let mut errors = Vec::new();
    for entry in fs::read_dir(&dir).expect("read rules.d") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        if path.extension().and_then(|x| x.to_str()) != Some("yaml") {
            continue;
        }
        let content = fs::read_to_string(&path).expect("read yaml");
        if let Err(err) = RuleEngine::validate_rule_file(&content) {
            errors.push(format!("{}: {}", path.display(), err));
        }
    }

    assert!(
        errors.is_empty(),
        "shipped rules.d/ examples failed validation:\n  {}",
        errors.join("\n  ")
    );
}
