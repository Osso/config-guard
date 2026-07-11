use super::{
    AccessPolicy, AuditIdentityCache, AuditObjectId, AuditProcessCache, ProcessGeneration, Prompt,
    PromptDecisionCache, inspect_process_or_unknown,
};
use crate::learning::AuditLearner;
use crate::policy::{AccessKind, Decision};
use crate::process::{ProcessIdentity, inspect_process};
use anyhow::Result;
use libc::{FAN_CLOSE_NOWRITE, FAN_CLOSE_WRITE, FAN_OPEN, fanotify_event_metadata};
use std::path::Path;

pub(super) struct AuditEvaluation<'learner, 'prompt> {
    learner: &'learner mut Option<AuditLearner>,
    prompt: Option<&'prompt dyn Prompt>,
    prompt_cache: &'prompt mut PromptDecisionCache,
}

impl<'learner, 'prompt> AuditEvaluation<'learner, 'prompt> {
    pub(super) fn new(
        learner: &'learner mut Option<AuditLearner>,
        prompt: Option<&'prompt dyn Prompt>,
        prompt_cache: &'prompt mut PromptDecisionCache,
    ) -> Self {
        Self {
            learner,
            prompt,
            prompt_cache,
        }
    }
}

pub(super) struct AuditCaches<'a> {
    identities: &'a mut AuditIdentityCache,
    processes: &'a mut AuditProcessCache,
}

impl<'a> AuditCaches<'a> {
    pub(super) fn new(
        identities: &'a mut AuditIdentityCache,
        processes: &'a mut AuditProcessCache,
    ) -> Self {
        Self {
            identities,
            processes,
        }
    }
}

pub(super) fn decide_metadata(
    metadata: &fanotify_event_metadata,
    target_path: &Path,
    object: AuditObjectId,
    generation: Option<ProcessGeneration>,
    learner: &mut Option<AuditLearner>,
    policy: &mut Option<&mut dyn AccessPolicy>,
    caches: AuditCaches<'_>,
) -> Result<Decision> {
    record_open_identity(
        metadata,
        target_path,
        object,
        generation,
        caches.identities,
        caches.processes,
    );
    let access_kinds = access_kinds(metadata.mask);
    let Some(first_access) = access_kinds.first().copied() else {
        return Ok(Decision::Allow);
    };

    let process = caches
        .identities
        .take(metadata.pid, object)
        .or_else(|| generation.and_then(|generation| caches.processes.get(generation)))
        .unwrap_or_else(|| inspect_process_or_unknown(metadata.pid, target_path, first_access));
    for access in access_kinds {
        decide_event(metadata.pid, &process, target_path, access, learner, policy)?;
    }

    Ok(Decision::Allow)
}

pub(super) fn decide_metadata_prompt(
    metadata: &fanotify_event_metadata,
    target_path: &Path,
    object: AuditObjectId,
    generation: Option<ProcessGeneration>,
    evaluation: &mut AuditEvaluation<'_, '_>,
    policy: &mut dyn AccessPolicy,
    caches: AuditCaches<'_>,
) -> Result<Decision> {
    record_open_identity(
        metadata,
        target_path,
        object,
        generation,
        caches.identities,
        caches.processes,
    );
    let access_kinds = access_kinds(metadata.mask);
    let Some(first_access) = access_kinds.first().copied() else {
        return Ok(Decision::Allow);
    };

    let process = caches
        .identities
        .take(metadata.pid, object)
        .or_else(|| generation.and_then(|generation| caches.processes.get(generation)))
        .unwrap_or_else(|| inspect_process_or_unknown(metadata.pid, target_path, first_access));
    for access in access_kinds {
        decide_prompt_event(
            metadata.pid,
            &process,
            target_path,
            access,
            evaluation,
            policy,
        )?;
    }

    Ok(Decision::Allow)
}

fn record_open_identity(
    metadata: &fanotify_event_metadata,
    target_path: &Path,
    object: AuditObjectId,
    generation: Option<ProcessGeneration>,
    identities: &mut AuditIdentityCache,
    processes: &mut AuditProcessCache,
) {
    if metadata.mask & FAN_OPEN == 0 {
        return;
    }

    match inspect_process(metadata.pid) {
        Ok(process) => identities.insert(metadata.pid, object, process),
        Err(error) => match generation.and_then(|generation| processes.get(generation)) {
            Some(process) => identities.insert(metadata.pid, object, process),
            None => {
                identities.invalidate(metadata.pid, object);
                eprintln!(
                    "IDENTITY unavailable at open pid={} path={} reason={error:#}; retrying at close",
                    metadata.pid,
                    target_path.display()
                );
            }
        },
    }
}

pub(super) fn record_exec_identity(
    pid: i32,
    executable_path: &Path,
    generation: Option<ProcessGeneration>,
    processes: &mut AuditProcessCache,
) {
    let Some(generation) = generation else {
        return;
    };
    let identity = inspect_process(pid)
        .unwrap_or_else(|_| ProcessIdentity::from_executable(pid, executable_path.to_path_buf()));
    processes.insert_exec(generation, identity);
}

pub(super) fn access_kinds(mask: u64) -> Vec<AccessKind> {
    let mut accesses = Vec::with_capacity(2);
    if mask & FAN_CLOSE_NOWRITE != 0 {
        accesses.push(AccessKind::Read);
    }
    if mask & FAN_CLOSE_WRITE != 0 {
        accesses.push(AccessKind::Write);
    }
    accesses
}

pub(super) fn decide_event(
    pid: i32,
    process: &ProcessIdentity,
    target_path: &Path,
    access: AccessKind,
    learner: &mut Option<AuditLearner>,
    policy: &mut Option<&mut dyn AccessPolicy>,
) -> Result<Decision> {
    let subject = process.subject();
    if let Some(policy) = policy.as_deref_mut() {
        let policy_decision = policy.decide(&subject, target_path, access)?;
        super::log_audit_decision(
            pid,
            &subject.executable,
            target_path,
            access,
            policy_decision,
        );
    }
    if let Some(learner) = learner.as_mut() {
        learner.observe(&subject, target_path, access)?;
    }

    Ok(Decision::Allow)
}

fn decide_prompt_event(
    pid: i32,
    process: &ProcessIdentity,
    target_path: &Path,
    access: AccessKind,
    evaluation: &mut AuditEvaluation<'_, '_>,
    policy: &mut dyn AccessPolicy,
) -> Result<Decision> {
    let subject = process.subject();
    let policy_decision = policy.decide(&subject, target_path, access)?;
    super::log_audit_decision(
        pid,
        &subject.executable,
        target_path,
        access,
        policy_decision.clone(),
    );
    if let (Decision::Prompt { .. }, Some(prompt)) = (&policy_decision, evaluation.prompt) {
        let prompt_key =
            super::PromptDecisionKey::new(process.executable.clone(), access, &policy_decision);
        let user_decision = super::resolve_policy_decision(
            prompt,
            evaluation.prompt_cache,
            prompt_key,
            &subject,
            target_path,
            super::read_wayland_env(pid),
            policy_decision.clone(),
        )?;
        super::log_audit_prompt_decision(
            pid,
            &subject.executable,
            target_path,
            access,
            policy_decision,
            user_decision,
        );
    }
    if let Some(learner) = evaluation.learner.as_mut() {
        learner.observe(&subject, target_path, access)?;
    }

    Ok(Decision::Allow)
}
