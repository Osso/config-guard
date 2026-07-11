use crate::policy::{AccessKind, Decision, DecisionReason, ProcessSubject};
use crate::prompt::{Prompt, PromptRequest};
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct PromptDecisionCache {
    decisions: HashMap<PromptDecisionKey, Decision>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PromptDecisionKey {
    executable: Option<PathBuf>,
    access: AccessKind,
    reason: DecisionReason,
    scope: PathBuf,
}

impl PromptDecisionCache {
    fn get(&self, key: &PromptDecisionKey) -> Option<Decision> {
        self.decisions.get(key).cloned()
    }

    fn insert(&mut self, key: PromptDecisionKey, decision: Decision) {
        if !matches!(decision, Decision::Allow) {
            return;
        }

        self.decisions.insert(key, decision);
    }
}

pub fn has_graphical_session(env: &HashMap<String, String>) -> bool {
    env.get("WAYLAND_DISPLAY")
        .is_some_and(|value| !value.is_empty())
}

pub fn resolve_policy_decision(
    prompt: &dyn Prompt,
    prompt_cache: &mut PromptDecisionCache,
    prompt_key: Option<PromptDecisionKey>,
    subject: &ProcessSubject,
    target_path: &Path,
    env: HashMap<String, String>,
    decision: Decision,
) -> Result<Decision> {
    let Decision::Prompt {
        reason,
        default,
        scope: _,
    } = decision
    else {
        return Ok(decision);
    };

    if let Some(decision) = cached_prompt_decision(prompt_cache, prompt_key.as_ref()) {
        return Ok(decision);
    }

    if !has_graphical_session(&env) {
        return Ok(apply_default_decision(prompt_cache, prompt_key, *default));
    }

    let default_decision = *default;
    let request = PromptRequest {
        subject,
        target_path,
        reason,
        default_decision: default_decision.clone(),
        env,
    };

    match prompt.ask(&request) {
        Ok(decision) => {
            cache_prompt_decision(prompt_cache, prompt_key, &decision);
            Ok(decision)
        }
        Err(error) => Ok(prompt_failure_decision(
            subject,
            target_path,
            reason,
            default_decision,
            error,
        )),
    }
}

fn apply_default_decision(
    prompt_cache: &mut PromptDecisionCache,
    prompt_key: Option<PromptDecisionKey>,
    default_decision: Decision,
) -> Decision {
    cache_prompt_decision(prompt_cache, prompt_key, &default_decision);
    default_decision
}

fn cached_prompt_decision(
    prompt_cache: &PromptDecisionCache,
    prompt_key: Option<&PromptDecisionKey>,
) -> Option<Decision> {
    prompt_key.and_then(|key| prompt_cache.get(key))
}

fn cache_prompt_decision(
    prompt_cache: &mut PromptDecisionCache,
    prompt_key: Option<PromptDecisionKey>,
    decision: &Decision,
) {
    if let Some(key) = prompt_key {
        prompt_cache.insert(key, decision.clone());
    }
}

impl PromptDecisionKey {
    pub(super) fn new(
        executable: Option<PathBuf>,
        access: AccessKind,
        decision: &Decision,
    ) -> Option<Self> {
        let executable = executable?;
        let Decision::Prompt { reason, scope, .. } = decision else {
            return None;
        };

        Some(Self {
            executable: Some(executable),
            access,
            reason: *reason,
            scope: scope.clone(),
        })
    }
}

fn prompt_failure_decision(
    subject: &ProcessSubject,
    target_path: &Path,
    reason: DecisionReason,
    default_decision: Decision,
    error: anyhow::Error,
) -> Decision {
    eprintln!(
        "prompt failed subject={} path={} reason={reason:?}: {error:#}; using default {default_decision:?}",
        subject.executable.display(),
        target_path.display(),
    );

    default_decision
}
