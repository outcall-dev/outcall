use anyhow::{Context, Result};

use super::selection::recommended_recipe_command;
use crate::recipe_runtime::recipe_or_bail;

pub(crate) fn cmd_recipe_list() -> Result<()> {
    println!("{:<12} {:<18} SUMMARY", "ID", "NAME");
    for recipe in outcall::recipes::RECIPES {
        println!("{:<12} {:<18} {}", recipe.id, recipe.name, recipe.summary);
    }
    Ok(())
}

pub(crate) fn cmd_recipe_show(id: &str) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    println!("Recipe:       {}", recipe.id);
    println!("Name:         {}", recipe.name);
    println!("Summary:      {}", recipe.summary);
    println!("Auth env:     {}", recipe.auth_env.join(", "));
    println!("Default copy: {}", recipe.user_paths.join(", "));
    println!(
        "Global config: {} (--include-global-config)",
        recipe.global_config_paths.join(", ")
    );
    println!("Mount paths:  {}", recipe.mount_paths.join(", "));
    println!("Project paths: {}", recipe.project_paths.join(", "));
    println!();
    println!("Generated files:");
    println!("  .outcall/recipes/{}/recipe.yaml", recipe.id);
    println!("  .outcall/recipes/{}/Dockerfile", recipe.id);
    println!("  .outcall/recipes/{}/README.md", recipe.id);
    println!("  .outcall/recipes/{}/context.md", recipe.id);
    println!("  .outcall/rules/{}.yaml", recipe.id);
    println!("  .outcall/agent.yaml");
    println!();
    println!("Manifest:");
    print!("{}", recipe.manifest);
    Ok(())
}

pub(crate) fn cmd_recipe_init(id: &str, force: bool) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let written = outcall::recipes::init_recipe(&project_dir, recipe, force)?;

    println!(
        "Initialized recipe \"{}\" in {}.",
        recipe.id,
        project_dir.display()
    );
    for path in written {
        println!("  wrote {}", path.display());
    }
    println!();
    println!("Next:");
    println!("  {}", recommended_recipe_command(recipe));
    Ok(())
}
