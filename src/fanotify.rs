use crate::learning::AuditLearner;
#[cfg(not(coverage))]
use crate::policy::executable_label;
use crate::policy::{AccessKind, Decision, DecisionReason, ProcessSubject};
#[cfg(not(coverage))]
use crate::process::ProcessIdentity;
#[cfg(not(coverage))]
use crate::process::{inspect_process, read_wayland_env};
use crate::prompt::{Prompt, PromptRequest};
use anyhow::{Context, Result, anyhow};
#[cfg(not(coverage))]
use libc::fanotify_event_metadata;
#[cfg(not(coverage))]
use libc::{
    AT_FDCWD, FAN_CLASS_CONTENT, FAN_CLOEXEC, FAN_EVENT_ON_CHILD, FAN_MARK_ADD, O_CLOEXEC,
    O_RDONLY, c_void, close, fanotify_response, read, write,
};
use libc::{FAN_ACCESS_PERM, FAN_ALLOW, FAN_CLOSE_WRITE, FAN_DENY, FAN_OPEN_PERM};
use std::collections::HashMap;
#[cfg(not(coverage))]
use std::ffi::CString;
use std::fs;
#[cfg(not(coverage))]
use std::mem;
#[cfg(not(coverage))]
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

#[cfg(not(coverage))]
const EVENT_BUFFER_SIZE: usize = 8192;

pub enum Mode<'a> {
    Audit {
        learner: Option<AuditLearner>,
        policy: Option<&'a mut dyn AccessPolicy>,
    },
    Guard {
        policy: &'a mut dyn AccessPolicy,
        prompt: &'a dyn Prompt,
        prompt_cache: PromptDecisionCache,
    },
}

pub trait AccessPolicy {
    fn decide(
        &mut self,
        subject: &ProcessSubject,
        target_path: &Path,
        access: AccessKind,
    ) -> Result<Decision>;
}

#[derive(Default)]
pub struct PromptDecisionCache {
    decisions: HashMap<PromptDecisionKey, Decision>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PromptDecisionKey {
    executable: Option<PathBuf>,
    access: AccessKind,
    reason: DecisionReason,
    scope: PathBuf,
}

impl PromptDecisionCache {
    #[cfg(any(test, not(coverage)))]
    fn get(&self, key: &PromptDecisionKey) -> Option<Decision> {
        self.decisions.get(key).cloned()
    }

    #[cfg(any(test, not(coverage)))]
    fn insert(&mut self, key: PromptDecisionKey, decision: Decision) {
        if !matches!(decision, Decision::Allow) {
            return;
        }

        self.decisions.insert(key, decision);
    }
}

#[cfg(not(coverage))]
pub fn run(paths: &[PathBuf], excluded_paths: &[PathBuf], mode: Mode<'_>) -> Result<()> {
    let fanotify_fd = create_fanotify_fd()?;
    let marked_paths = mark_path_trees(fanotify_fd, paths, excluded_paths)?;
    let watch_list = paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!("watching {watch_list} ({marked_paths} directories marked)");
    let mut mode = mode;

    loop {
        read_events(fanotify_fd, &mut mode)?;
    }
}

#[cfg(coverage)]
pub fn run(paths: &[PathBuf], _excluded_paths: &[PathBuf], _mode: Mode<'_>) -> Result<()> {
    for path in paths {
        ensure_path_exists(path)?;
    }
    Ok(())
}

#[cfg(not(coverage))]
fn create_fanotify_fd() -> Result<RawFd> {
    let event_flags = (O_RDONLY | O_CLOEXEC) as u32;
    let fd = unsafe { libc::fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, event_flags) };

    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("fanotify_init failed; permission events usually require CAP_SYS_ADMIN");
    }

    Ok(fd)
}

#[cfg(not(coverage))]
fn mark_path(fanotify_fd: RawFd, path: &Path) -> Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .context("watch path contains an interior nul byte")?;
    let mask = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD;
    let result =
        unsafe { libc::fanotify_mark(fanotify_fd, FAN_MARK_ADD, mask, AT_FDCWD, path.as_ptr()) };

    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("fanotify_mark failed");
    }

    Ok(())
}

#[cfg(not(coverage))]
fn mark_path_trees(
    fanotify_fd: RawFd,
    paths: &[PathBuf],
    excluded_paths: &[PathBuf],
) -> Result<usize> {
    paths
        .iter()
        .filter(|path| !is_excluded(path, excluded_paths))
        .map(|path| mark_path_tree(fanotify_fd, path, excluded_paths))
        .try_fold(0, |marked_paths, result| {
            result.map(|path_count| marked_paths + path_count)
        })
}

#[cfg(not(coverage))]
fn mark_path_tree(fanotify_fd: RawFd, path: &Path, excluded_paths: &[PathBuf]) -> Result<usize> {
    if !path.is_dir() {
        mark_path(fanotify_fd, path)?;
        return Ok(1);
    }

    let mut marked_paths = 0;
    let mut pending_paths = vec![path.to_path_buf()];

    while let Some(current_path) = pending_paths.pop() {
        mark_path(fanotify_fd, &current_path)
            .with_context(|| format!("marking {}", current_path.display()))?;
        marked_paths += 1;

        for child_path in child_directories(&current_path, excluded_paths)? {
            pending_paths.push(child_path);
        }
    }

    Ok(marked_paths)
}

#[cfg(any(test, not(coverage)))]
fn child_directories(path: &Path, excluded_paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut directories = Vec::new();

    for entry in fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
        let entry = entry.with_context(|| format!("reading entry under {}", path.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading file type for {}", entry.path().display()))?;

        let child_path = entry.path();

        if file_type.is_dir() && !is_excluded(&child_path, excluded_paths) {
            directories.push(child_path);
        }
    }

    Ok(directories)
}

#[cfg(any(test, not(coverage)))]
fn is_excluded(path: &Path, excluded_paths: &[PathBuf]) -> bool {
    excluded_paths
        .iter()
        .any(|excluded_path| path.starts_with(excluded_path))
}

#[cfg(not(coverage))]
fn read_events(fanotify_fd: RawFd, mode: &mut Mode<'_>) -> Result<()> {
    let mut buffer = [0u8; EVENT_BUFFER_SIZE];
    let bytes_read = unsafe {
        read(
            fanotify_fd,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.len(),
        )
    };

    if bytes_read < 0 {
        return Err(std::io::Error::last_os_error()).context("reading fanotify events failed");
    }

    handle_event_buffer(fanotify_fd, &buffer[..bytes_read as usize], mode)
}

#[cfg(not(coverage))]
fn handle_event_buffer(fanotify_fd: RawFd, buffer: &[u8], mode: &mut Mode<'_>) -> Result<()> {
    let mut offset = 0;

    while offset + mem::size_of::<fanotify_event_metadata>() <= buffer.len() {
        let metadata = read_metadata(buffer, offset);

        if metadata.event_len == 0 {
            break;
        }

        handle_event(fanotify_fd, &metadata, mode)?;
        offset += metadata.event_len as usize;
    }

    Ok(())
}

#[cfg(not(coverage))]
fn read_metadata(buffer: &[u8], offset: usize) -> fanotify_event_metadata {
    unsafe { std::ptr::read_unaligned(buffer[offset..].as_ptr().cast()) }
}

#[cfg(not(coverage))]
fn handle_event(
    fanotify_fd: RawFd,
    metadata: &fanotify_event_metadata,
    mode: &mut Mode<'_>,
) -> Result<()> {
    if metadata.fd < 0 {
        return Ok(());
    }

    let target_path = event_target_path(metadata.fd).unwrap_or_else(|_| PathBuf::from("<unknown>"));
    let decision = decide_event(metadata, &target_path, mode)?;

    respond_to_permission_event(fanotify_fd, metadata, decision)?;
    unsafe {
        close(metadata.fd);
    }

    Ok(())
}

#[cfg(not(coverage))]
fn decide_event(
    metadata: &fanotify_event_metadata,
    target_path: &Path,
    mode: &mut Mode<'_>,
) -> Result<Decision> {
    let access = access_kind(metadata.mask);
    let process = match inspect_process(metadata.pid) {
        Ok(process) => process,
        Err(error) => {
            eprintln!(
                "ALLOW fail-open pid={} access={:?} path={} reason={error:#}",
                metadata.pid,
                access,
                target_path.display()
            );
            return Ok(Decision::Allow);
        }
    };

    match mode {
        Mode::Audit { learner, policy } => {
            decide_audit_event(metadata.pid, &process, target_path, access, learner, policy)
        }
        Mode::Guard {
            policy,
            prompt,
            prompt_cache,
        } => decide_guard_event(
            metadata.pid,
            &process,
            target_path,
            access,
            *policy,
            *prompt,
            prompt_cache,
        ),
    }
}

#[cfg(not(coverage))]
fn decide_audit_event(
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
        log_audit_decision(
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

#[cfg(not(coverage))]
fn decide_guard_event(
    pid: i32,
    process: &ProcessIdentity,
    target_path: &Path,
    access: AccessKind,
    policy: &mut dyn AccessPolicy,
    prompt: &dyn Prompt,
    prompt_cache: &mut PromptDecisionCache,
) -> Result<Decision> {
    let subject = process.subject();
    let policy_decision = policy.decide(&subject, target_path, access)?;
    log_audit_decision(
        pid,
        &subject.executable,
        target_path,
        access,
        policy_decision.clone(),
    );

    resolve_policy_decision(
        prompt,
        prompt_cache,
        PromptDecisionKey::new(process.executable.clone(), access, &policy_decision),
        &subject,
        target_path,
        read_wayland_env(pid),
        policy_decision,
    )
}

#[cfg(not(coverage))]
fn log_audit_decision(
    pid: i32,
    executable: &Path,
    target_path: &Path,
    access: AccessKind,
    decision: Decision,
) {
    match decision {
        Decision::Allow => {}
        Decision::Deny => eprintln!(
            "FORBID audit pid={} exe={} access={:?} path={} decision=Deny",
            pid,
            executable_label(executable),
            access,
            target_path.display()
        ),
        Decision::Prompt {
            reason,
            default,
            scope,
        } => eprintln!(
            "FORBID audit pid={} exe={} access={:?} path={} decision=Prompt reason={:?} default={:?} scope={}",
            pid,
            executable_label(executable),
            access,
            target_path.display(),
            reason,
            default,
            scope.display()
        ),
    }
}

/// Whether the accessing process belongs to a graphical session we can show a
/// confirmation dialog in. Without a Wayland display there is no session to
/// prompt, so the guard must fall back to its default rather than flood the
/// prompt backend with dialogs no one can answer.
#[cfg(any(test, not(coverage)))]
fn has_graphical_session(env: &std::collections::HashMap<String, String>) -> bool {
    env.get("WAYLAND_DISPLAY")
        .is_some_and(|value| !value.is_empty())
}

#[cfg(any(test, not(coverage)))]
fn resolve_policy_decision(
    prompt: &dyn Prompt,
    prompt_cache: &mut PromptDecisionCache,
    prompt_key: Option<PromptDecisionKey>,
    subject: &crate::policy::ProcessSubject,
    target_path: &Path,
    env: std::collections::HashMap<String, String>,
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

    // An interactive prompt only makes sense when the accessing process has a
    // graphical session to show the dialog in. System daemons (getty, dbus
    // services, …) carry no Wayland environment; prompting for them is
    // impossible and floods the prompt backend until the session wedges, so
    // apply the configured default instead. The event is already audit-logged
    // by the caller, so this stays visible without prompting.
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

#[cfg(any(test, not(coverage)))]
fn apply_default_decision(
    prompt_cache: &mut PromptDecisionCache,
    prompt_key: Option<PromptDecisionKey>,
    default_decision: Decision,
) -> Decision {
    cache_prompt_decision(prompt_cache, prompt_key, &default_decision);
    default_decision
}

#[cfg(any(test, not(coverage)))]
fn cached_prompt_decision(
    prompt_cache: &PromptDecisionCache,
    prompt_key: Option<&PromptDecisionKey>,
) -> Option<Decision> {
    prompt_key.and_then(|key| prompt_cache.get(key))
}

#[cfg(any(test, not(coverage)))]
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
    #[cfg(any(test, not(coverage)))]
    fn new(executable: Option<PathBuf>, access: AccessKind, decision: &Decision) -> Option<Self> {
        let Decision::Prompt { reason, scope, .. } = decision else {
            return None;
        };

        Some(Self {
            executable,
            access,
            reason: *reason,
            scope: scope.clone(),
        })
    }
}

#[cfg(any(test, not(coverage)))]
fn prompt_failure_decision(
    subject: &ProcessSubject,
    target_path: &Path,
    reason: crate::policy::DecisionReason,
    default_decision: Decision,
    error: anyhow::Error,
) -> Decision {
    eprintln!(
        "prompt failed subject={} path={} reason={:?}: {error:#}; using default {:?}",
        subject.executable.display(),
        target_path.display(),
        reason,
        default_decision
    );

    default_decision
}

#[cfg(not(coverage))]
fn respond_to_permission_event(
    fanotify_fd: RawFd,
    metadata: &fanotify_event_metadata,
    decision: Decision,
) -> Result<()> {
    if !is_permission_event(metadata.mask) {
        return Ok(());
    }

    let response = fanotify_response {
        fd: metadata.fd,
        response: response_code(decision),
    };
    let written = unsafe {
        write(
            fanotify_fd,
            (&response as *const fanotify_response).cast::<c_void>(),
            mem::size_of::<fanotify_response>(),
        )
    };

    if written < 0 {
        return Err(std::io::Error::last_os_error()).context("writing fanotify response failed");
    }

    Ok(())
}

#[cfg(not(coverage))]
fn event_target_path(event_fd: RawFd) -> Result<PathBuf> {
    fs::read_link(format!("/proc/self/fd/{event_fd}"))
        .with_context(|| format!("resolving fanotify event fd {event_fd}"))
}

#[cfg(any(test, not(coverage)))]
fn access_kind(mask: u64) -> AccessKind {
    if mask & FAN_CLOSE_WRITE != 0 {
        AccessKind::Write
    } else {
        AccessKind::Read
    }
}

#[cfg(any(test, not(coverage)))]
fn is_permission_event(mask: u64) -> bool {
    mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM) != 0
}

#[cfg(any(test, not(coverage)))]
fn response_code(decision: Decision) -> u32 {
    match decision {
        Decision::Allow => FAN_ALLOW,
        Decision::Deny => FAN_DENY,
        Decision::Prompt { .. } => FAN_ALLOW,
    }
}

pub fn ensure_path_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(anyhow!("watch path does not exist: {}", path.display()));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
