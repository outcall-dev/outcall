mod catalog;
mod doctor;
mod onboarding;
mod policy;
mod run;
mod selection;

pub(crate) use catalog::{cmd_recipe_init, cmd_recipe_list, cmd_recipe_show};
pub(crate) use doctor::{cmd_doctor, cmd_recipe_doctor};
#[cfg(test)]
pub(crate) use onboarding::ensure_recipe_setup_state;
pub(crate) use onboarding::{cmd_init, cmd_onboarding};
pub(crate) use policy::{cmd_allow, cmd_auth, cmd_policy_explain};
pub(crate) use run::{cmd_agent_attach, cmd_agent_logs, cmd_run, cmd_setup};
