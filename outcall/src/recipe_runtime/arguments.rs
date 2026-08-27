use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub(crate) fn rewrite_recipe_entrypoint_args(
    project_dir: &Path,
    workspace: &str,
    args: Vec<String>,
) -> Result<Vec<String>> {
    let project_dir = std::fs::canonicalize(project_dir)
        .with_context(|| format!("failed to canonicalize {}", project_dir.display()))?;
    let mut rewritten = Vec::with_capacity(args.len());
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if matches!(arg.as_str(), "-o" | "--output-last-message") {
            let path = args
                .next()
                .with_context(|| format!("missing value for {arg}"))?;
            rewritten.push(arg);
            rewritten.push(rewrite_container_output_path(
                &project_dir,
                workspace,
                &path,
            )?);
            continue;
        }
        if let Some((flag, value)) = arg.split_once('=')
            && flag == "--output-last-message"
        {
            let value = rewrite_container_output_path(&project_dir, workspace, value)?;
            rewritten.push(format!("{flag}={value}"));
            continue;
        }
        rewritten.push(arg);
    }
    Ok(rewritten)
}

pub(crate) fn rewrite_container_output_path(
    project_dir: &Path,
    workspace: &str,
    path: &str,
) -> Result<String> {
    let candidate = Path::new(path);
    if !candidate.is_absolute() {
        return Ok(path.to_string());
    }
    if let Ok(relative) = candidate.strip_prefix(project_dir) {
        return workspace_output_path(workspace, candidate, relative);
    }

    if let Some(resolved) = resolve_output_path_for_workspace(candidate)?
        && let Ok(relative) = resolved.strip_prefix(project_dir)
    {
        return workspace_output_path(workspace, candidate, relative);
    }
    anyhow::bail!(
        "output path {} is outside the mounted workspace; use a relative path or a file inside {}",
        candidate.display(),
        project_dir.display()
    );
}

fn resolve_output_path_for_workspace(candidate: &Path) -> Result<Option<PathBuf>> {
    let Some(parent) = candidate.parent() else {
        return Ok(None);
    };
    if !parent.exists() {
        return Ok(None);
    }
    let resolved_parent = std::fs::canonicalize(parent)
        .with_context(|| format!("failed to canonicalize {}", parent.display()))?;
    Ok(candidate.file_name().map(|name| resolved_parent.join(name)))
}

fn workspace_output_path(workspace: &str, original: &Path, relative: &Path) -> Result<String> {
    let relative = relative
        .to_str()
        .with_context(|| format!("non-utf8 output path: {}", original.display()))?
        .trim_start_matches('/');
    if relative.is_empty() {
        anyhow::bail!(
            "output path {} resolves to the project root; choose a file path inside the workspace",
            original.display()
        );
    }
    Ok(format!("{}/{}", workspace.trim_end_matches('/'), relative))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_output_flags_without_touching_other_arguments() {
        let project = tempfile::tempdir().unwrap();
        let output = project.path().join("result.txt");
        let args = vec![
            "exec".to_string(),
            "-o".to_string(),
            output.display().to_string(),
            "prompt".to_string(),
        ];

        assert_eq!(
            rewrite_recipe_entrypoint_args(project.path(), "/workspace", args).unwrap(),
            ["exec", "-o", "/workspace/result.txt", "prompt"]
        );
    }

    #[test]
    fn rejects_output_path_outside_workspace() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let error = rewrite_container_output_path(
            &std::fs::canonicalize(project.path()).unwrap(),
            "/workspace",
            &outside.path().join("result.txt").display().to_string(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("outside the mounted workspace"));
    }
}
