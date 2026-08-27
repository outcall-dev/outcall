use std::process::ExitStatus;

use anyhow::{Context, Result};

pub(crate) fn attach_container(reference: &str, display_name: &str) -> Result<ExitStatus> {
    println!("Attaching to managed agent '{display_name}'.");
    println!("Detach without stopping it: Ctrl+P, then Ctrl+Q.");
    println!();

    std::process::Command::new("docker")
        .args(["attach", reference])
        .status()
        .context("failed to invoke docker attach")
}
