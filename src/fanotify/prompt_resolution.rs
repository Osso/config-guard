use crate::policy::{AccessKind, Decision, DecisionReason, ProcessSubject};
use crate::process::{ProcessIdentity, is_process_generation_current};
use crate::prompt::{AncestryAuthorization, Prompt, PromptRequest};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct PromptDecisionCache {
    decisions: HashMap<PromptDecisionKey, Decision>,
    ancestry_authorizations: HashSet<AncestryAuthorization>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PromptDecisionKey {
    pid: i32,
    start_time_ticks: u64,
    executable: PathBuf,
    access: AccessKind,
    reason: DecisionReason,
}

pub struct PolicyPromptRequest<'a> {
    pub authorization: Option<AncestryAuthorization>,
    pub subject: &'a ProcessSubject,
    pub target_path: &'a Path,
    pub env: HashMap<String, String>,
    pub decision: Decision,
}

impl PromptDecisionCache {
    fn get(&self, key: &PromptDecisionKey) -> Option<Decision> {
        self.decisions.get(key).cloned()
    }

    fn insert_decision(&mut self, key: PromptDecisionKey, decision: Decision) {
        if matches!(decision, Decision::Allow | Decision::Deny) {
            self.decisions.insert(key, decision);
        }
    }

    fn allows_authorization(&self, authorization: Option<&AncestryAuthorization>) -> bool {
        authorization
            .is_some_and(|authorization| self.ancestry_authorizations.contains(authorization))
    }

    fn insert_authorization(&mut self, authorization: AncestryAuthorization) {
        self.ancestry_authorizations.insert(authorization);
    }
}

pub fn has_graphical_session(env: &HashMap<String, String>) -> bool {
    env.get("WAYLAND_DISPLAY")
        .is_some_and(|value| !value.is_empty())
}

pub fn prompt_for_policy_decision(
    prompt: &dyn Prompt,
    prompt_cache: &mut PromptDecisionCache,
    prompt_key: Option<PromptDecisionKey>,
    subject: &ProcessSubject,
    target_path: &Path,
    env: HashMap<String, String>,
    decision: Decision,
) -> Result<Decision> {
    prompt_for_policy_decision_with_authorization(
        prompt,
        prompt_cache,
        prompt_key,
        PolicyPromptRequest {
            authorization: None,
            subject,
            target_path,
            env,
            decision,
        },
    )
}

pub fn prompt_for_policy_decision_with_authorization(
    prompt: &dyn Prompt,
    prompt_cache: &mut PromptDecisionCache,
    prompt_key: Option<PromptDecisionKey>,
    request: PolicyPromptRequest<'_>,
) -> Result<Decision> {
    let PolicyPromptRequest {
        authorization,
        subject,
        target_path,
        env,
        decision,
    } = request;
    if let Some(decision) = immediate_prompt_decision(
        prompt,
        prompt_cache,
        prompt_key.as_ref(),
        authorization.as_ref(),
        &env,
        &decision,
    ) {
        return Ok(decision);
    }

    let Decision::Prompt {
        reason,
        default,
        scope: _,
    } = decision
    else {
        unreachable!("non-prompt decisions resolve immediately")
    };
    let request = build_prompt_request(
        subject,
        target_path,
        reason,
        *default,
        env,
        authorization.as_ref(),
    );

    match ask_prompt(prompt, &request) {
        PromptOutcome::Answer { decision, explicit } => {
            cache_prompt_answer(prompt_cache, prompt_key, authorization, &decision, explicit);
            Ok(decision)
        }
        PromptOutcome::Failure => Ok(request.default_decision),
    }
}

pub(super) fn immediate_prompt_decision(
    prompt: &dyn Prompt,
    prompt_cache: &mut PromptDecisionCache,
    prompt_key: Option<&PromptDecisionKey>,
    authorization: Option<&AncestryAuthorization>,
    env: &HashMap<String, String>,
    decision: &Decision,
) -> Option<Decision> {
    let Decision::Prompt { default, .. } = decision else {
        return Some(decision.clone());
    };

    if prompt_cache.allows_authorization(authorization) {
        return Some(Decision::Allow);
    }

    if let Some(decision) = cached_prompt_decision(prompt_cache, prompt_key) {
        return Some(decision);
    }

    if prompt.requires_graphical_session() && !has_graphical_session(env) {
        let default_decision = default.as_ref().clone();
        cache_prompt_decision(prompt_cache, prompt_key.cloned(), &default_decision);
        return Some(default_decision);
    }

    None
}

fn build_prompt_request<'a>(
    subject: &'a ProcessSubject,
    target_path: &'a Path,
    reason: DecisionReason,
    default_decision: Decision,
    env: HashMap<String, String>,
    authorization: Option<&'a AncestryAuthorization>,
) -> PromptRequest<'a> {
    PromptRequest {
        subject,
        target_path,
        reason,
        default_decision,
        env,
        authorization,
    }
}

pub(super) enum PromptOutcome {
    Answer { decision: Decision, explicit: bool },
    Failure,
}

pub(super) fn ask_prompt(prompt: &dyn Prompt, request: &PromptRequest<'_>) -> PromptOutcome {
    match prompt.ask_answer(request) {
        Ok(answer) => PromptOutcome::Answer {
            explicit: answer.is_explicit(),
            decision: answer.into_decision(),
        },
        Err(error) => {
            prompt_failure_decision(
                request.subject,
                request.target_path,
                request.reason,
                request.default_decision.clone(),
                error,
            );
            PromptOutcome::Failure
        }
    }
}

fn cached_prompt_decision(
    prompt_cache: &PromptDecisionCache,
    prompt_key: Option<&PromptDecisionKey>,
) -> Option<Decision> {
    prompt_key.and_then(|key| prompt_cache.get(key))
}

pub(super) fn cache_prompt_answer(
    prompt_cache: &mut PromptDecisionCache,
    prompt_key: Option<PromptDecisionKey>,
    authorization: Option<AncestryAuthorization>,
    decision: &Decision,
    explicit: bool,
) {
    cache_prompt_decision(prompt_cache, prompt_key, decision);
    if explicit
        && matches!(decision, Decision::Allow)
        && let Some(authorization) = authorization
    {
        prompt_cache.insert_authorization(authorization);
    }
}

fn cache_prompt_decision(
    prompt_cache: &mut PromptDecisionCache,
    prompt_key: Option<PromptDecisionKey>,
    decision: &Decision,
) {
    if let Some(key) = prompt_key {
        prompt_cache.insert_decision(key, decision.clone());
    }
}

impl PromptDecisionKey {
    pub(super) fn is_current_process(&self) -> bool {
        is_process_generation_current(self.pid, self.start_time_ticks)
    }

    pub(super) fn new(
        process: &ProcessIdentity,
        access: AccessKind,
        decision: &Decision,
    ) -> Option<Self> {
        let executable = process.executable.clone()?;
        let start_time_ticks = process.start_time_ticks?;
        let Decision::Prompt { reason, .. } = decision else {
            return None;
        };

        Some(Self {
            pid: process.pid,
            start_time_ticks,
            executable,
            access,
            reason: *reason,
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
