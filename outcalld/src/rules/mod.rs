//! Rule engine modules (S003).

pub mod engine;
mod loader;
pub mod model;

#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
pub use engine::RuleEngine;
