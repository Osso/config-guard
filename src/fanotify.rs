use crate::learning::AuditLearner;
use crate::policy::{AccessKind, Decision, DecisionReason, ProcessSubject, executable_label};
use crate::process::{ProcessIdentity, inspect_process, read_wayland_env};
use crate::prompt::{Prompt, PromptRequest};
use anyhow::{Context, Result, anyhow};
use libc::{
    AT_FDCWD, FAN_ACCESS_PERM, FAN_ALLOW, FAN_CLASS_CONTENT, FAN_CLOEXEC, FAN_CLOSE_WRITE,
    FAN_DENY, FAN_EVENT_ON_CHILD, FAN_MARK_ADD, FAN_OPEN_PERM, O_CLOEXEC, O_RDONLY, c_void, close,
    fanotify_event_metadata, fanotify_response, read, write,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::mem;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

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
    pid: i32,
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
        self.decisions.insert(key, decision);
    }
}

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

fn create_fanotify_fd() -> Result<RawFd> {
    let event_flags = (O_RDONLY | O_CLOEXEC) as u32;
    let fd = unsafe { libc::fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, event_flags) };

    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("fanotify_init failed; permission events usually require CAP_SYS_ADMIN");
    }

    Ok(fd)
}

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

fn is_excluded(path: &Path, excluded_paths: &[PathBuf]) -> bool {
    excluded_paths
        .iter()
        .any(|excluded_path| path.starts_with(excluded_path))
}

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

fn read_metadata(buffer: &[u8], offset: usize) -> fanotify_event_metadata {
    unsafe { std::ptr::read_unaligned(buffer[offset..].as_ptr().cast()) }
}

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
            &process.executable,
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
        &process.executable,
        target_path,
        access,
        policy_decision.clone(),
    );

    resolve_policy_decision(
        prompt,
        prompt_cache,
        PromptDecisionKey::new(pid, process.executable.clone(), access, &policy_decision),
        &subject,
        target_path,
        read_wayland_env(pid),
        policy_decision,
    )
}

fn log_audit_decision(
    pid: i32,
    executable: &Option<PathBuf>,
    target_path: &Path,
    access: AccessKind,
    decision: Decision,
) {
    match decision {
        Decision::Allow => {}
        Decision::Deny => eprintln!(
            "FORBID audit pid={} exe={} access={:?} path={} decision=Deny",
            pid,
            display_executable(executable),
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
            display_executable(executable),
            access,
            target_path.display(),
            reason,
            default,
            scope.display()
        ),
    }
}

fn display_executable(executable: &Option<PathBuf>) -> String {
    executable
        .as_ref()
        .map(|path| executable_label(path))
        .unwrap_or_else(|| "<unknown>".to_string())
}

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

    if let Some(decision) = prompt_key.as_ref().and_then(|key| prompt_cache.get(key)) {
        return Ok(decision);
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
            if let Some(key) = prompt_key {
                prompt_cache.insert(key, decision.clone());
            }

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

impl PromptDecisionKey {
    fn new(
        pid: i32,
        executable: Option<PathBuf>,
        access: AccessKind,
        decision: &Decision,
    ) -> Option<Self> {
        let Decision::Prompt { reason, scope, .. } = decision else {
            return None;
        };

        Some(Self {
            pid,
            executable,
            access,
            reason: *reason,
            scope: scope.clone(),
        })
    }
}

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

fn event_target_path(event_fd: RawFd) -> Result<PathBuf> {
    fs::read_link(format!("/proc/self/fd/{event_fd}"))
        .with_context(|| format!("resolving fanotify event fd {event_fd}"))
}

fn access_kind(mask: u64) -> AccessKind {
    if mask & FAN_CLOSE_WRITE != 0 {
        AccessKind::Write
    } else {
        AccessKind::Read
    }
}

fn is_permission_event(mask: u64) -> bool {
    mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM) != 0
}

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
mod tests {
    use super::child_directories;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn child_directories_does_not_follow_symlinked_directories() {
        let root =
            std::env::temp_dir().join(format!("config-guard-symlink-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("real")).expect("create real dir");
        symlink(root.join("real"), root.join("linked")).expect("create symlinked dir");

        let children = child_directories(&root, &[]).expect("read child dirs");

        assert_eq!(children, vec![root.join("real")]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn child_directories_skips_excluded_directories() {
        let root =
            std::env::temp_dir().join(format!("config-guard-exclude-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("keep")).expect("create keep dir");
        fs::create_dir_all(root.join("skip")).expect("create skip dir");

        let children = child_directories(&root, &[root.join("skip")]).expect("read child dirs");

        assert_eq!(children, vec![root.join("keep")]);
        let _ = fs::remove_dir_all(root);
    }
}
