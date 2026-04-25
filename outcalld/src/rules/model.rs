//! YAML rule file schema types (S003-IF-012).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use outcall_api::RuleAction;

/// Top-level structure of a rule YAML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFile {
    /// Must be "1".
    pub version: String,
    /// Optional CEL sub-expression definitions, keyed by name.
    #[serde(default)]
    pub definitions: HashMap<String, String>,
    /// The list of rules in evaluation order.
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
}

/// A single rule entry within a rule file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSpec {
    /// Unique identifier across all loaded rule files.
    pub id: String,
    /// CEL expression (may reference `$name` definitions).
    pub condition: String,
    /// What to do when the condition matches.
    pub action: RuleAction,
    /// Whether to emit a structured log entry when this rule matches.
    #[serde(default)]
    pub log: bool,
    /// Human-readable description (no effect on evaluation).
    pub description: Option<String>,
    /// Evaluation priority (lower = higher priority; default 100).
    pub priority: Option<i32>,
    /// Enrich hook configuration (only valid when action = enrich).
    pub enrich: Option<EnrichSpec>,
}

/// Configuration for an enrich hook script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichSpec {
    /// Script path relative to the rules directory.
    pub script: String,
    /// Timeout in milliseconds (default: 5000).
    pub timeout_ms: Option<u64>,
}

/// A compiled rule, ready for evaluation.
#[derive(Debug)]
pub struct CompiledRule {
    pub id: String,
    pub file: String,
    /// The expanded CEL expression (definitions resolved).
    pub condition_expanded: String,
    pub action: RuleAction,
    pub log: bool,
    pub description: Option<String>,
    pub priority: i32,
    pub program: cel_interpreter::Program,
}

/// The entire compiled rule set, held in an Arc for concurrent evaluation.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<CompiledRule>,
}
