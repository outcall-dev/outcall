use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use outcall::secure_fs::{existing_secure_subdir, regular_file_exists};

pub(crate) fn recipe_or_bail(id: &str) -> Result<&'static outcall::recipes::Recipe> {
    outcall::recipes::get_recipe(id).with_context(|| {
        let ids = outcall::recipes::recipe_ids()
            .collect::<Vec<_>>()
            .join(", ");
        format!("unknown recipe \"{id}\"; available recipes: {ids}")
    })
}

pub(crate) fn recipe_setup_is_complete(
    project_dir: &Path,
    recipe: &outcall::recipes::Recipe,
) -> Result<bool> {
    let Some(outcall_dir) = existing_secure_subdir(project_dir, Path::new(".outcall"))? else {
        return Ok(false);
    };
    let Some(recipe_dir) = existing_secure_subdir(
        project_dir,
        &PathBuf::from(".outcall").join("recipes").join(recipe.id),
    )?
    else {
        return Ok(false);
    };
    let Some(rules_dir) = existing_secure_subdir(project_dir, Path::new(".outcall/rules"))? else {
        return Ok(false);
    };
    Ok(regular_file_exists(&recipe_dir.join("Dockerfile"))?
        && regular_file_exists(&rules_dir.join(format!("{}.yaml", recipe.id)))?
        && regular_file_exists(&outcall_dir.join("agent.yaml"))?
        && regular_file_exists(&outcall_dir.join("host-resources.yaml"))?)
}

pub(crate) fn ensure_recipe_initialized(
    project_dir: &Path,
    recipe: &outcall::recipes::Recipe,
) -> Result<()> {
    let dockerfile = outcall::recipes::recipe_dockerfile(project_dir, recipe);
    if regular_file_exists(&dockerfile)? {
        return Ok(());
    }

    println!(
        "Recipe files for \"{}\" are missing; initializing defaults.",
        recipe.id
    );
    let written = outcall::recipes::init_recipe(project_dir, recipe, false)?;
    for path in written {
        println!("  wrote {}", path.display());
    }
    Ok(())
}
