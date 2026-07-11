#[cfg(not(coverage))]
mod audit;
#[cfg(any(test, not(coverage)))]
mod audit_identity;
#[cfg(any(test, not(coverage)))]
mod audit_process;
#[cfg(not(coverage))]
mod event;
#[cfg(any(test, not(coverage)))]
mod prompt_resolution;
#[cfg(any(test, not(coverage)))]
mod watch;

use crate::learning::AuditLearner;
#[cfg(not(coverage))]
use crate::policy::executable_label;
use crate::policy::{AccessKind, Decision, ProcessSubject};
#[cfg(not(coverage))]
use crate::process::ProcessIdentity;
#[cfg(not(coverage))]
use crate::process::{inspect_process, read_wayland_env};
use crate::prompt::Prompt;
#[cfg(not(coverage))]
use anyhow::Context;
use anyhow::{Result, anyhow};
#[cfg(not(coverage))]
use audit_identity::{AuditIdentityCache, AuditObjectId};
#[cfg(not(coverage))]
use audit_process::{AuditProcessCache, ProcessGeneration};
#[cfg(not(coverage))]
use libc::fanotify_event_metadata;
#[cfg(any(test, not(coverage)))]
use libc::{
    FAN_ALLOW, FAN_CLOSE_NOWRITE, FAN_CLOSE_WRITE, FAN_DENY, FAN_EVENT_ON_CHILD, FAN_NOFD,
    FAN_OPEN, FAN_OPEN_EXEC, FAN_OPEN_PERM, FAN_Q_OVERFLOW,
};
#[cfg(not(coverage))]
use libc::{
    FAN_CLASS_CONTENT, FAN_CLASS_NOTIF, FAN_CLOEXEC, FAN_UNLIMITED_QUEUE, O_CLOEXEC, O_RDONLY,
    c_void, fanotify_response, read, write,
};
#[cfg(any(test, not(coverage)))]
pub use prompt_resolution::PromptDecisionCache;
#[cfg(all(coverage, not(test)))]
#[derive(Default)]
pub struct PromptDecisionCache;
#[cfg(test)]
pub(super) use prompt_resolution::has_graphical_session;
#[cfg(any(test, not(coverage)))]
pub(super) use prompt_resolution::{PromptDecisionKey, resolve_policy_decision};
#[cfg(not(coverage))]
use std::mem;
#[cfg(any(test, not(coverage)))]
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
#[cfg(test)]
use watch::child_directories;

#[cfg(not(coverage))]
const EVENT_BUFFER_SIZE: usize = 8192;
#[cfg(not(coverage))]
const FAN_REPORT_PIDFD: u32 = 0x0000_0080;

#[cfg(not(coverage))]
#[derive(Default)]
struct EventRuntime {
    audit_identities: AuditIdentityCache,
    audit_processes: AuditProcessCache,
}

pub enum Mode<'a> {
    Audit {
        learner: Option<AuditLearner>,
        policy: Option<&'a mut dyn AccessPolicy>,
    },
    AuditPrompt {
        learner: Option<AuditLearner>,
        policy: Box<dyn AccessPolicy>,
        prompt: &'a dyn Prompt,
        prompt_cache: PromptDecisionCache,
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

#[cfg(not(coverage))]
pub fn run(paths: &[PathBuf], excluded_paths: &[PathBuf], mode: Mode<'_>) -> Result<()> {
    let fanotify_fd = create_fanotify_fd(&mode)?;
    let status = watch::install(fanotify_fd, paths, excluded_paths, &mode)?;
    eprintln!("{status}");
    crate::systemd_notify::notify_ready(std::env::var_os("NOTIFY_SOCKET").as_deref(), &status)?;
    let mut mode = mode;
    let mut runtime = EventRuntime::default();

    loop {
        read_events(fanotify_fd, paths, excluded_paths, &mut mode, &mut runtime)?;
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
fn create_fanotify_fd(mode: &Mode<'_>) -> Result<RawFd> {
    let event_flags = (O_RDONLY | O_CLOEXEC) as u32;
    let init_flags = match mode {
        Mode::Audit { .. } | Mode::AuditPrompt { .. } => {
            FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE | FAN_REPORT_PIDFD
        }
        Mode::Guard { .. } => FAN_CLASS_CONTENT | FAN_CLOEXEC,
    };
    let fd = unsafe { libc::fanotify_init(init_flags, event_flags) };

    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("fanotify_init failed; monitoring usually requires CAP_SYS_ADMIN");
    }

    Ok(fd)
}

#[cfg(any(test, not(coverage)))]
fn is_excluded(path: &Path, excluded_paths: &[PathBuf]) -> bool {
    excluded_paths
        .iter()
        .any(|excluded_path| path.starts_with(excluded_path))
}

#[cfg(not(coverage))]
fn read_events(
    fanotify_fd: RawFd,
    paths: &[PathBuf],
    excluded_paths: &[PathBuf],
    mode: &mut Mode<'_>,
    runtime: &mut EventRuntime,
) -> Result<()> {
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

    handle_event_buffer(
        fanotify_fd,
        &buffer[..bytes_read as usize],
        paths,
        excluded_paths,
        mode,
        runtime,
    )
}

#[cfg(not(coverage))]
fn handle_event_buffer(
    fanotify_fd: RawFd,
    buffer: &[u8],
    paths: &[PathBuf],
    excluded_paths: &[PathBuf],
    mode: &mut Mode<'_>,
    runtime: &mut EventRuntime,
) -> Result<()> {
    let mut offset = 0;

    while offset + mem::size_of::<fanotify_event_metadata>() <= buffer.len() {
        let metadata = event::read_metadata(buffer, offset);
        event::validate_metadata_version(&metadata)?;

        if metadata.event_len == 0 {
            break;
        }

        let event_len = metadata.event_len as usize;
        let event_end = offset
            .checked_add(event_len)
            .context("fanotify event length overflow")?;
        if event_len < metadata.metadata_len as usize || event_end > buffer.len() {
            return Err(anyhow!(
                "invalid fanotify event length: event_len={} metadata_len={} remaining={}",
                event_len,
                metadata.metadata_len,
                buffer.len() - offset
            ));
        }
        let generation = event::process_generation(&buffer[offset..event_end], &metadata)?;
        handle_event(
            fanotify_fd,
            &metadata,
            generation,
            paths,
            excluded_paths,
            mode,
            runtime,
        )?;
        offset = event_end;
    }

    Ok(())
}

#[cfg(not(coverage))]
fn handle_event(
    fanotify_fd: RawFd,
    metadata: &fanotify_event_metadata,
    generation: Option<ProcessGeneration>,
    paths: &[PathBuf],
    excluded_paths: &[PathBuf],
    mode: &mut Mode<'_>,
    runtime: &mut EventRuntime,
) -> Result<()> {
    ensure_event_descriptor(metadata.mask, metadata.fd)?;
    let result = handle_event_with_descriptor(
        fanotify_fd,
        metadata,
        generation,
        paths,
        excluded_paths,
        mode,
        runtime,
    );
    let close_result = event::close_descriptor(metadata.fd);

    result.and(close_result)
}

#[cfg(not(coverage))]
fn handle_event_with_descriptor(
    fanotify_fd: RawFd,
    metadata: &fanotify_event_metadata,
    generation: Option<ProcessGeneration>,
    paths: &[PathBuf],
    excluded_paths: &[PathBuf],
    mode: &mut Mode<'_>,
    runtime: &mut EventRuntime,
) -> Result<()> {
    let target_path = event::target_path(metadata.fd)?;
    if matches!(mode, Mode::Audit { .. } | Mode::AuditPrompt { .. })
        && metadata.mask & FAN_OPEN_EXEC != 0
    {
        audit::record_exec_identity(
            metadata.pid,
            &target_path,
            generation,
            &mut runtime.audit_processes,
        );
        if metadata.mask & (FAN_CLOSE_NOWRITE | FAN_CLOSE_WRITE) == 0 {
            return respond_to_permission_event(fanotify_fd, metadata, Decision::Allow);
        }
    }
    if !is_watched_path(&target_path, paths, excluded_paths) {
        return respond_to_permission_event(fanotify_fd, metadata, Decision::Allow);
    }

    let object = if matches!(mode, Mode::Audit { .. } | Mode::AuditPrompt { .. }) {
        Some(event::object_id(metadata.fd)?)
    } else {
        None
    };
    let decision = decide_event(metadata, &target_path, object, generation, mode, runtime)?;
    respond_to_permission_event(fanotify_fd, metadata, decision)
}

#[cfg(not(coverage))]
fn decide_event(
    metadata: &fanotify_event_metadata,
    target_path: &Path,
    object: Option<AuditObjectId>,
    generation: Option<ProcessGeneration>,
    mode: &mut Mode<'_>,
    runtime: &mut EventRuntime,
) -> Result<Decision> {
    match mode {
        Mode::Audit { .. } | Mode::AuditPrompt { .. } => {
            decide_audit_mode(metadata, target_path, object, generation, mode, runtime)
        }
        Mode::Guard {
            policy,
            prompt,
            prompt_cache,
        } => {
            decide_guard_event_from_metadata(metadata, target_path, *policy, *prompt, prompt_cache)
        }
    }
}

#[cfg(not(coverage))]
fn decide_audit_mode(
    metadata: &fanotify_event_metadata,
    target_path: &Path,
    object: Option<AuditObjectId>,
    generation: Option<ProcessGeneration>,
    mode: &mut Mode<'_>,
    runtime: &mut EventRuntime,
) -> Result<Decision> {
    match mode {
        Mode::Audit { learner, policy } => decide_passive_audit_event(
            metadata,
            target_path,
            object,
            generation,
            learner,
            policy,
            runtime,
        ),
        Mode::AuditPrompt {
            learner,
            policy,
            prompt,
            prompt_cache,
        } => {
            let context = PromptAuditContext {
                learner,
                policy,
                prompt: *prompt,
                prompt_cache,
                runtime,
            };
            decide_prompt_audit_event(metadata, target_path, object, generation, context)
        }
        Mode::Guard { .. } => unreachable!("decide_audit_mode called with guard mode"),
    }
}

#[cfg(not(coverage))]
fn decide_guard_event_from_metadata(
    metadata: &fanotify_event_metadata,
    target_path: &Path,
    policy: &mut dyn AccessPolicy,
    prompt: &dyn Prompt,
    prompt_cache: &mut PromptDecisionCache,
) -> Result<Decision> {
    let access = access_kind(metadata.mask);
    let process = inspect_process_or_unknown(metadata.pid, target_path, access);
    decide_guard_event(
        metadata.pid,
        &process,
        target_path,
        access,
        policy,
        prompt,
        prompt_cache,
    )
}

#[cfg(not(coverage))]
fn decide_passive_audit_event(
    metadata: &fanotify_event_metadata,
    target_path: &Path,
    object: Option<AuditObjectId>,
    generation: Option<ProcessGeneration>,
    learner: &mut Option<AuditLearner>,
    policy: &mut Option<&mut dyn AccessPolicy>,
    runtime: &mut EventRuntime,
) -> Result<Decision> {
    audit::decide_metadata(
        metadata,
        target_path,
        object.context("audit event is missing object identity")?,
        generation,
        learner,
        policy,
        audit::AuditCaches::new(&mut runtime.audit_identities, &mut runtime.audit_processes),
    )
}

#[cfg(not(coverage))]
struct PromptAuditContext<'a> {
    learner: &'a mut Option<AuditLearner>,
    policy: &'a mut Box<dyn AccessPolicy>,
    prompt: &'a dyn Prompt,
    prompt_cache: &'a mut PromptDecisionCache,
    runtime: &'a mut EventRuntime,
}

#[cfg(not(coverage))]
fn decide_prompt_audit_event(
    metadata: &fanotify_event_metadata,
    target_path: &Path,
    object: Option<AuditObjectId>,
    generation: Option<ProcessGeneration>,
    context: PromptAuditContext<'_>,
) -> Result<Decision> {
    audit::decide_metadata_prompt(
        metadata,
        target_path,
        object.context("audit event is missing object identity")?,
        generation,
        &mut audit::AuditEvaluation::new(
            context.learner,
            Some(context.prompt),
            context.prompt_cache,
        ),
        context.policy.as_mut(),
        audit::AuditCaches::new(
            &mut context.runtime.audit_identities,
            &mut context.runtime.audit_processes,
        ),
    )
}

#[cfg(not(coverage))]
fn inspect_process_or_unknown(pid: i32, target_path: &Path, access: AccessKind) -> ProcessIdentity {
    match inspect_process(pid) {
        Ok(process) => process,
        Err(error) => {
            eprintln!(
                "IDENTITY unavailable pid={} access={:?} path={} reason={error:#}; evaluating as unknown subject",
                pid,
                access,
                target_path.display()
            );
            ProcessIdentity::unknown(pid)
        }
    }
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

#[cfg(not(coverage))]
fn log_audit_prompt_decision(
    pid: i32,
    executable: &Path,
    target_path: &Path,
    access: AccessKind,
    policy_decision: Decision,
    user_decision: Decision,
) {
    eprintln!(
        "FORBID audit-prompt pid={} exe={} access={:?} path={} policy={:?} user_decision={:?}",
        pid,
        executable_label(executable),
        access,
        target_path.display(),
        policy_decision,
        user_decision
    );
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

#[cfg(any(test, not(coverage)))]
fn audit_watch_mask() -> u64 {
    FAN_OPEN | FAN_OPEN_EXEC | FAN_CLOSE_NOWRITE | FAN_CLOSE_WRITE
}

#[cfg(any(test, not(coverage)))]
fn guard_watch_mask() -> u64 {
    FAN_OPEN_PERM | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD
}

#[cfg(any(test, not(coverage)))]
fn ensure_event_descriptor(mask: u64, event_fd: RawFd) -> Result<()> {
    if mask & FAN_Q_OVERFLOW != 0 {
        return Err(anyhow!(
            "fanotify event queue overflow; audit coverage was lost"
        ));
    }
    if event_fd == FAN_NOFD || event_fd < 0 {
        return Err(anyhow!("invalid fanotify event descriptor {event_fd}"));
    }

    Ok(())
}

#[cfg(any(test, not(coverage)))]
fn is_watched_path(path: &Path, paths: &[PathBuf], excluded_paths: &[PathBuf]) -> bool {
    paths.iter().any(|root| path.starts_with(root)) && !is_excluded(path, excluded_paths)
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
    mask & FAN_OPEN_PERM != 0
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
