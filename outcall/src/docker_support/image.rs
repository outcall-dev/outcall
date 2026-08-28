use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::command::{
    CommandTimeoutError, command_output_with_timeout, command_status_with_timeout,
};
use crate::daemon_commands::DEFAULT_DAEMON_IMAGE;
use outcall::secure_fs::{
    existing_secure_subdir, read_regular_string, regular_file_exists, write_runtime_file,
};

const IMAGE_INSPECT_TIMEOUT: Duration = Duration::from_secs(10);
const BUILD_HELP_TIMEOUT: Duration = Duration::from_secs(10);
const IMAGE_PULL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const IMAGE_BUILD_TIMEOUT: Duration = Duration::from_secs(60 * 60);

pub(crate) fn ensure_daemon_image_available() -> Result<()> {
    if docker_image_exists(DEFAULT_DAEMON_IMAGE)? {
        println!("  PASS daemon image: {DEFAULT_DAEMON_IMAGE}");
        return Ok(());
    }

    println!("  Pulling daemon image: {DEFAULT_DAEMON_IMAGE}");
    run_interactive_docker(
        Command::new("docker").args(["pull", DEFAULT_DAEMON_IMAGE]),
        IMAGE_PULL_TIMEOUT,
        &format!("pull daemon image {DEFAULT_DAEMON_IMAGE}"),
    )
}

fn build_recipe_image(
    project_dir: &Path,
    recipe: &outcall::recipes::Recipe,
    image: &str,
) -> Result<()> {
    let recipe_dir = existing_secure_subdir(
        project_dir,
        &PathBuf::from(".outcall").join("recipes").join(recipe.id),
    )?
    .with_context(|| format!("recipe {} is not initialized", recipe.id))?;
    let dockerfile = recipe_dir.join("Dockerfile");
    if !regular_file_exists(&dockerfile)? {
        anyhow::bail!("recipe Dockerfile {} does not exist", dockerfile.display());
    }
    let fingerprint = recipe_directory_fingerprint(&recipe_dir)
        .context("failed to compute recipe build fingerprint")?;
    let fingerprint_path = recipe_dir.join(".outcall-image-fingerprint");
    let image_exists = docker_image_exists(image)?;

    if image_exists && is_recipe_image_cached(&fingerprint_path, &fingerprint)? {
        println!("Recipe image {image} already up-to-date; skipping build.");
        return Ok(());
    }

    if image_exists {
        println!("Rebuilding recipe image {image} (recipe context changed).");
    }

    println!("Building recipe image {image}...");
    let supports_plain_progress = docker_build_supports_plain_progress()?;
    if !supports_plain_progress {
        println!("Docker builder does not support plain progress output; using compatible output.");
    }
    let mut command =
        recipe_build_command(&dockerfile, &recipe_dir, image, supports_plain_progress);
    run_interactive_docker(
        &mut command,
        IMAGE_BUILD_TIMEOUT,
        &format!("build recipe image {image}"),
    )?;

    write_runtime_file(&fingerprint_path, format!("{fingerprint}\n").as_bytes())
}

fn recipe_build_command(
    dockerfile: &Path,
    recipe_dir: &Path,
    image: &str,
    supports_plain_progress: bool,
) -> Command {
    let mut command = Command::new("docker");
    command.arg("build");
    if supports_plain_progress {
        command.arg("--progress=plain");
    }
    command
        .arg("-t")
        .arg(image)
        .arg("-f")
        .arg(dockerfile)
        .arg(recipe_dir);
    command
}

fn docker_build_supports_plain_progress() -> Result<bool> {
    let output = command_output_with_timeout("docker", &["build", "--help"], BUILD_HELP_TIMEOUT)
        .map_err(|error| command_error("inspect Docker builder capabilities", error))?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to inspect Docker builder capabilities (exit {:?})",
            output.status.code()
        );
    }
    Ok(build_help_supports_plain_progress(
        &output.stdout,
        &output.stderr,
    ))
}

fn build_help_supports_plain_progress(stdout: &[u8], stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stdout).contains("--progress")
        || String::from_utf8_lossy(stderr).contains("--progress")
}

#[derive(Debug, PartialEq, Eq)]
enum RecipeImageAction {
    BuildLocal,
    UseExisting,
    Pull { fallback_to_build: bool },
}

fn recipe_image_action(
    local_recipe_image: bool,
    built_in_recipe_image: bool,
    image_exists: bool,
    no_build: bool,
    auto_pull: bool,
) -> Result<RecipeImageAction> {
    if local_recipe_image && !no_build {
        return Ok(RecipeImageAction::BuildLocal);
    }
    if image_exists {
        return Ok(RecipeImageAction::UseExisting);
    }
    if local_recipe_image {
        anyhow::bail!(
            "recipe image is missing and --no-build was requested; rerun without --no-build"
        );
    }
    if auto_pull {
        return Ok(RecipeImageAction::Pull {
            fallback_to_build: built_in_recipe_image && !no_build,
        });
    }
    if built_in_recipe_image && !no_build {
        return Ok(RecipeImageAction::BuildLocal);
    }
    anyhow::bail!("configured image is missing and auto_pull is false")
}

pub(crate) fn prepare_recipe_image(
    project_dir: &Path,
    recipe: &outcall::recipes::Recipe,
    config: &outcall::agent_config::AgentConfig,
    no_build: bool,
) -> Result<()> {
    let image = config.effective_image();
    let built_in_image = outcall::recipes::recipe_image_name(recipe);
    let local_image = outcall::recipes::recipe_local_image_name(recipe);
    let exists = docker_image_exists(&image)?;
    match recipe_image_action(
        image == local_image,
        image == built_in_image,
        exists,
        no_build,
        config.auto_pull,
    )? {
        RecipeImageAction::BuildLocal => build_recipe_image(project_dir, recipe, &image),
        RecipeImageAction::UseExisting => Ok(()),
        RecipeImageAction::Pull { fallback_to_build } => {
            println!("Pulling configured recipe image {image}...");
            let pulled = run_interactive_docker(
                Command::new("docker").args(["pull", &image]),
                IMAGE_PULL_TIMEOUT,
                &format!("pull configured recipe image {image}"),
            );
            match (pulled, fallback_to_build) {
                (Ok(()), _) => Ok(()),
                (Err(error), true) => {
                    eprintln!(
                        "warning: prebuilt recipe image could not be pulled ({error}); building the bundled recipe locally"
                    );
                    build_recipe_image(project_dir, recipe, &image)
                }
                (Err(error), false) => Err(error),
            }
        }
    }
}

fn docker_image_exists(image: &str) -> Result<bool> {
    let output = command_output_with_timeout(
        "docker",
        &["image", "inspect", "--format", "{{.Id}}", image],
        IMAGE_INSPECT_TIMEOUT,
    )
    .map_err(|error| command_error("inspect Docker image", error))?;

    Ok(output.status.success())
}

fn run_interactive_docker(command: &mut Command, timeout: Duration, action: &str) -> Result<()> {
    let status = command_status_with_timeout(command, timeout)
        .map_err(|error| command_error(action, error))?;
    if !status.success() {
        anyhow::bail!("failed to {action} (exit {:?})", status.code());
    }
    Ok(())
}

fn command_error(action: &str, error: CommandTimeoutError) -> anyhow::Error {
    match error {
        CommandTimeoutError::TimedOut { timeout } => anyhow::anyhow!(
            "timed out after {} seconds while attempting to {action}",
            timeout.as_secs()
        ),
        CommandTimeoutError::Io(error) => error.context(format!("failed to {action}")),
    }
}

fn is_recipe_image_cached(fingerprint_path: &Path, fingerprint: &str) -> Result<bool> {
    let Some(existing) = read_regular_string(fingerprint_path)? else {
        return Ok(false);
    };
    Ok(existing.trim() == fingerprint)
}

fn recipe_directory_fingerprint(recipe_dir: &Path) -> Result<String> {
    let mut files = Vec::new();
    collect_files(recipe_dir, &mut files, recipe_dir)
        .with_context(|| format!("failed to collect files from {}", recipe_dir.display()))?;
    files.sort();

    let mut hasher = Sha256::new();
    for file in files {
        let relative = file
            .strip_prefix(recipe_dir)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        hasher.update((relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        hash_regular_file(&file, &mut hasher)?;
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_regular_file(path: &Path, hasher: &mut Sha256) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "recipe build context entry must be a real file: {}",
            path.display()
        );
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    if !file.metadata()?.is_file() {
        anyhow::bail!(
            "recipe build context entry must be a regular file: {}",
            path.display()
        );
    }

    hasher.update(metadata.len().to_le_bytes());
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(())
}

fn collect_files(dir: &Path, files: &mut Vec<PathBuf>, root: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir).context("failed to read recipe directory")? {
        let entry = entry.context("failed to read recipe directory entry")?;
        let path = entry.path();
        let relative = path.strip_prefix(root).unwrap_or(&path);
        if relative == Path::new(".outcall-image-fingerprint") {
            continue;
        }

        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if file_type.is_symlink() {
            anyhow::bail!(
                "recipe build context must not contain symlink {}",
                path.display()
            );
        }
        if file_type.is_dir() {
            collect_files(&path, files, root)?;
        } else if file_type.is_file() {
            files.push(path);
        } else {
            anyhow::bail!(
                "recipe build context contains unsupported filesystem entry {}",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipe_image_action_is_explicit_and_fail_closed() {
        assert_eq!(
            recipe_image_action(true, false, true, false, false).unwrap(),
            RecipeImageAction::BuildLocal
        );
        assert_eq!(
            recipe_image_action(true, false, true, true, false).unwrap(),
            RecipeImageAction::UseExisting
        );
        assert!(recipe_image_action(true, false, false, true, false).is_err());
        assert_eq!(
            recipe_image_action(false, true, false, false, true).unwrap(),
            RecipeImageAction::Pull {
                fallback_to_build: true
            }
        );
        assert_eq!(
            recipe_image_action(false, true, false, true, true).unwrap(),
            RecipeImageAction::Pull {
                fallback_to_build: false
            }
        );
        assert_eq!(
            recipe_image_action(false, true, false, false, false).unwrap(),
            RecipeImageAction::BuildLocal
        );
        assert!(recipe_image_action(false, false, false, false, false).is_err());
        assert_eq!(
            recipe_image_action(false, false, true, false, false).unwrap(),
            RecipeImageAction::UseExisting
        );
    }

    #[test]
    fn recipe_build_uses_plain_progress_when_supported() {
        let command = recipe_build_command(
            Path::new("/project/.outcall/recipes/codex/Dockerfile"),
            Path::new("/project/.outcall/recipes/codex"),
            "outcall-recipe-codex:local",
            true,
        );
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect();
        assert_eq!(
            args,
            [
                "build",
                "--progress=plain",
                "-t",
                "outcall-recipe-codex:local",
                "-f",
                "/project/.outcall/recipes/codex/Dockerfile",
                "/project/.outcall/recipes/codex",
            ]
        );
    }

    #[test]
    fn recipe_build_omits_plain_progress_for_legacy_builder() {
        let command = recipe_build_command(
            Path::new("/project/.outcall/recipes/codex/Dockerfile"),
            Path::new("/project/.outcall/recipes/codex"),
            "outcall-recipe-codex:local",
            false,
        );
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect();
        assert_eq!(
            args,
            [
                "build",
                "-t",
                "outcall-recipe-codex:local",
                "-f",
                "/project/.outcall/recipes/codex/Dockerfile",
                "/project/.outcall/recipes/codex",
            ]
        );
    }

    #[test]
    fn builder_capability_parser_handles_buildkit_and_legacy_help() {
        assert!(build_help_supports_plain_progress(
            b"Options:\n  --progress string",
            b""
        ));
        assert!(!build_help_supports_plain_progress(
            b"Options:\n  --quiet",
            b"legacy builder warning"
        ));
    }

    #[test]
    fn recipe_fingerprint_is_stable_and_tracks_content() {
        let recipe = tempfile::tempdir().unwrap();
        std::fs::write(recipe.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        std::fs::create_dir(recipe.path().join("config")).unwrap();
        std::fs::write(recipe.path().join("config/agent"), "v1").unwrap();

        let first = recipe_directory_fingerprint(recipe.path()).unwrap();
        let second = recipe_directory_fingerprint(recipe.path()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);

        std::fs::write(recipe.path().join("config/agent"), "v2").unwrap();
        assert_ne!(first, recipe_directory_fingerprint(recipe.path()).unwrap());
    }

    #[test]
    fn recipe_fingerprint_ignores_its_cache_file() {
        let recipe = tempfile::tempdir().unwrap();
        std::fs::write(recipe.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        let first = recipe_directory_fingerprint(recipe.path()).unwrap();
        std::fs::write(recipe.path().join(".outcall-image-fingerprint"), "old\n").unwrap();
        assert_eq!(first, recipe_directory_fingerprint(recipe.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn recipe_fingerprint_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let recipe = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        symlink(outside.path(), recipe.path().join("outside-link")).unwrap();

        let error = format!(
            "{:#}",
            recipe_directory_fingerprint(recipe.path()).unwrap_err()
        );
        assert!(error.contains("symlink"));
    }
}
