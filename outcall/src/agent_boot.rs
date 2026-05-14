use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::agent_config::{AgentCliFlags, AgentConfig};

//! Agent boot command implementation (S014).

/// Boot an agent container for the current project (S014-FR-001..008).
pub fn boot_agent(
    project_dir: &Path,
    cli_flags: AgentCliFlags,
    entrypoint_args: Vec<String>,
) -> Result<()> {
    // Load configuration
    let mut config = AgentConfig::load(project_dir)?;
    config.merge(&cli_flags);
    
    let image = config.effective_image();
    let name = config.effective_name(project_dir);
    let workspace = &config.workspace;
    
    println!("Booting agent '{}' for project '{}'...", name, project_dir.display());
    println!("  Image: {}", image);
    println!("  Workspace: {} -> {}", project_dir.display(), workspace);
    
    // Check if daemon is running
    ensure_daemon_running()?;
    
    // Pull image if needed
    if config.auto_pull {
        ensure_image(&image)?;
    }
    
    // Stop existing container with same name
    let _ = Command::new("docker")
        .args(["rm", "-f", &name])
        .output();
    
    // Build docker run arguments
    let mut args = vec!["run".to_string()];
    
    // Name
    args.extend_from_slice(&["--name".to_string(), name.clone()]);
    
    // Network
    args.extend_from_slice(&["--network".to_string(), config.network.clone()]);
    
    // Mount project directory
    let abs_project_dir = std::fs::canonicalize(project_dir)
        .with_context(|| format!("failed to canonicalize {}", project_dir.display()))?;
    args.extend_from_slice(&[
        "-v".to_string(),
        format!("{}:{}", abs_project_dir.display(), workspace),
    ]);
    
    // Set working directory
    args.extend_from_slice(&["-w".to_string(), workspace.clone()]);
    
    // Additional volumes from config
    for vol in &config.volumes {
        args.extend_from_slice(&["-v".to_string(), vol.clone()]);
    }
    
    // Environment variables
    for (key, value) in &config.env {
        args.extend_from_slice(&["-e".to_string(), format!("{}={}", key, value)]);
    }
    
    // Port forwarding
    for port in &config.ports {
        args.extend_from_slice(&["-p".to_string(), port.clone()]);
    }
    
    // Capabilities
    for cap in &config.capabilities {
        args.extend_from_slice(&["--cap-add".to_string(), cap.clone()]);
    }
    
    // Resource limits
    if let Some(ref resources) = config.resources {
        if let Some(ref memory) = resources.memory {
            args.extend_from_slice(&["--memory".to_string(), memory.clone()]);
        }
        if let Some(ref cpus) = resources.cpus {
            args.extend_from_slice(&["--cpus".to_string(), cpus.clone()]);
        }
    }
    
    // Detached mode
    if config.detach {
        args.push("-d".to_string());
    } else {
        // Interactive mode: allocate TTY and keep stdin open
        args.push("-it".to_string());
    }
    
    // Labels for tracking
    args.extend_from_slice(&[
        "--label".to_string(),
        "outcall.agent=true".to_string(),
    ]);
    args.extend_from_slice(&[
        "--label".to_string(),
        format!("outcall.project={}", abs_project_dir.display()),
    ]);
    args.extend_from_slice(&[
        "--label".to_string(),
        format!("outcall.name={}", name),
    ]);
    
    // Entrypoint override
    if let Some(ref entrypoint) = config.entrypoint {
        args.push("--entrypoint".to_string());
        args.push(entrypoint.join(" "));
    }
    
    // Add the image
    args.push(image.clone());
    
    // Add entrypoint arguments (e.g., "build me a rocket")
    if !entrypoint_args.is_empty() {
        // If no custom entrypoint is set, default to passing args to claude
        if config.entrypoint.is_none() {
            // Default: run claude with the provided prompt
            args.push("claude".to_string());
        }
        for arg in entrypoint_args {
            args.push(arg);
        }
    } else if config.command.is_some() {
        // Use configured command if no args provided
        for cmd in config.command.as_ref().unwrap() {
            args.push(cmd.clone());
        }
    }
    
    // Run the container
    println!("  Starting container...");
    let mut cmd = Command::new("docker");
    cmd.args(&args);
    
    if config.detach {
        let output = cmd.output()
            .context("failed to invoke docker run")?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("docker run failed: {}", stderr.trim());
        }
        
        let cid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("Agent '{}' started ({}) in detached mode.", name, &cid[..12.min(cid.len())]);
        println!("  Attach: docker attach {}", name);
        println!("  Logs:   docker logs -f {}", name);
        println!("  Stop:   outcall agent --stop {}", name);
    } else {
        // Interactive mode: run in foreground, Ctrl+C stops container
        println!("  Container running. Press Ctrl+C to stop.");
        println!();
        
        let status = cmd.status()
            .context("failed to invoke docker run")?;
        
        if !status.success() {
            anyhow::bail!("agent exited with code {:?}", status.code());
        }
        
        println!("\nAgent '{}' stopped.", name);
    }
    
    Ok(())
}

/// Stop a running agent
pub fn stop_agent(name: &str) -> Result<()> {
    println!("Stopping agent '{}'...", name);
    
    let output = Command::new("docker")
        .args(["rm", "-f", name])
        .output()
        .context("failed to invoke docker rm")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such container") {
            println!("Agent '{}' was not running.", name);
            return Ok(());
        }
        anyhow::bail!("docker rm failed: {}", stderr.trim());
    }
    
    println!("Agent '{}' stopped.", name);
    Ok(())
}

/// List running outcall agents
pub fn list_agents() -> Result<()> {
    let output = Command::new("docker")
        .args([
            "ps",
            "--filter", "label=outcall.agent=true",
            "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
        ])
        .output()
        .context("failed to invoke docker ps")?;
    
    if !output.status.success() {
        anyhow::bail!("docker ps failed");
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    
    if lines.is_empty() {
        println!("No running agents found.");
        return Ok(());
    }
    
    println!("{:<30} {:<30} {:<20} {}", "NAME", "IMAGE", "STATUS", "PORTS");
    for line in lines {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 3 {
            let name = parts[0];
            let image = parts[1];
            let status = parts[2];
            let ports = parts.get(3).unwrap_or(&"");
            println!("{:<30} {:<30} {:<20} {}", name, image, status, ports);
        }
    }
    
    Ok(())
}

/// Show agent logs
pub fn agent_logs(name: &str, follow: bool) -> Result<()> {
    let mut args = vec!["logs".to_string()];
    if follow {
        args.push("-f".to_string());
    }
    args.push(name.to_string());
    
    let status = Command::new("docker")
        .args(&args)
        .status()
        .context("failed to invoke docker logs")?;
    
    if !status.success() {
        anyhow::bail!("docker logs failed");
    }
    
    Ok(())
}

/// Initialize .outcall directory with template config
pub fn init_outcall(project_dir: &Path) -> Result<PathBuf> {
    let config_path = AgentConfig::save_template(project_dir)?;
    println!("Created Outcall config template: {}", config_path.display());
    println!("Edit this file to customize your agent configuration.");
    Ok(config_path)
}

/// Auto-detect agent name from current directory
pub fn auto_detect_name() -> String {
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("unknown"));
    let folder_name = current_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    format!("{}-agent", folder_name)
}

/// Ensure the daemon is running
fn ensure_daemon_running() -> Result<()> {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Running}}", "outcall-daemon"])
        .output();
    
    match output {
        Ok(output) if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true" => {
            Ok(())
        }
        _ => {
            println!("  Note: outcall-daemon is not running. Starting it...");
            let status = Command::new("outcall")
                .args(["daemon", "start"])
                .status()
                .context("failed to start outcall-daemon")?;
            
            if !status.success() {
                anyhow::bail!("failed to start outcall-daemon");
            }
            
            // Wait a moment for daemon to initialize
            std::thread::sleep(std::time::Duration::from_secs(2));
            Ok(())
        }
    }
}

/// Ensure Docker image is available
fn ensure_image(image: &str) -> Result<()> {
    let output = Command::new("docker")
        .args(["image", "inspect", "--format", "exists", image])
        .output();
    
    match output {
        Ok(output) if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "exists" => {
            Ok(())
        }
        _ => {
            println!("  Pulling image '{}'...", image);
            let status = Command::new("docker")
                .args(["pull", image])
                .status()
                .context("failed to invoke docker pull")?;
            
            if !status.success() {
                anyhow::bail!("failed to pull image '{}'", image);
            }
            
            Ok(())
        }
    }
}
