#[cfg(not(coverage))]
use super::AccessPolicy;
#[cfg(not(coverage))]
use super::audit::{access_kinds as audit_access_kinds, decide_event as decide_audit_event};
#[cfg(coverage)]
use super::{Mode, run};
use super::{
    PromptDecisionCache, access_kind, audit_watch_mask, child_directories, ensure_event_descriptor,
    ensure_path_exists, format_guard_decision, guard_watch_mask, has_graphical_session,
    is_permission_event, is_watched_path, prompt_for_policy_decision, response_code,
};
use crate::policy::{AccessKind, Decision, DecisionReason, ProcessSubject};
use crate::process::ProcessIdentity;
use crate::prompt::{Prompt, PromptRequest};
use std::cell::Cell;
#[cfg(not(coverage))]
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

struct PanicPrompt;

impl Prompt for PanicPrompt {
    fn ask(&self, _request: &PromptRequest<'_>) -> anyhow::Result<Decision> {
        panic!("prompt must not be invoked without a graphical session");
    }
}

#[cfg(coverage)]
struct PanicPolicy;

#[cfg(coverage)]
impl super::AccessPolicy for PanicPolicy {
    fn decide(
        &mut self,
        _subject: &ProcessSubject,
        _target_path: &Path,
        _access: AccessKind,
    ) -> anyhow::Result<Decision> {
        panic!("policy must not be invoked by coverage run stub");
    }
}

#[cfg(not(coverage))]
struct RecordingPolicy {
    executable: RefCell<Option<PathBuf>>,
}

#[cfg(not(coverage))]
impl AccessPolicy for RecordingPolicy {
    fn decide(
        &mut self,
        subject: &ProcessSubject,
        _target_path: &Path,
        _access: AccessKind,
    ) -> anyhow::Result<Decision> {
        self.executable.replace(Some(subject.executable.clone()));
        Ok(Decision::Allow)
    }
}

struct HeadlessPrompt;

impl Prompt for HeadlessPrompt {
    fn ask(&self, _request: &PromptRequest<'_>) -> anyhow::Result<Decision> {
        Ok(Decision::Deny)
    }

    fn requires_graphical_session(&self) -> bool {
        false
    }
}

struct CountingPrompt {
    decision: Decision,
    calls: Cell<usize>,
}

impl CountingPrompt {
    fn new(decision: Decision) -> Self {
        Self {
            decision,
            calls: Cell::new(0),
        }
    }
}

impl Prompt for CountingPrompt {
    fn ask(&self, _request: &PromptRequest<'_>) -> anyhow::Result<Decision> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.decision.clone())
    }
}

fn cat_subject() -> ProcessSubject {
    ProcessSubject {
        executable: PathBuf::from("/usr/bin/cat"),
        command: vec!["cat".to_string()],
        ancestors: Vec::new(),
    }
}

fn cat_process(pid: i32, start_time_ticks: u64) -> ProcessIdentity {
    ProcessIdentity {
        pid,
        executable: Some(PathBuf::from("/usr/bin/cat")),
        command: vec!["cat".to_string()],
        cwd: None,
        start_time_ticks: Some(start_time_ticks),
        ancestors: Vec::new(),
    }
}

fn prompt_decision(scope: &str) -> Decision {
    Decision::Prompt {
        reason: DecisionReason::CrossOwnerRead,
        default: Box::new(Decision::Allow),
        scope: PathBuf::from(scope),
    }
}

fn graphical_env() -> HashMap<String, String> {
    HashMap::from([("WAYLAND_DISPLAY".to_string(), "wayland-1".to_string())])
}

fn resolve_cat_prompt(
    prompt: &dyn Prompt,
    cache: &mut PromptDecisionCache,
    process: &ProcessIdentity,
    target_path: &str,
    scope: &str,
) -> Decision {
    let subject = process.subject();
    let policy_decision = prompt_decision(scope);
    prompt_for_policy_decision(
        prompt,
        cache,
        super::PromptDecisionKey::new(process, AccessKind::Read, &policy_decision),
        &subject,
        Path::new(target_path),
        graphical_env(),
        policy_decision,
    )
    .expect("resolve decision")
}

#[cfg(not(coverage))]
#[test]
fn audit_evaluates_unknown_processes_instead_of_bypassing_policy() {
    let process = ProcessIdentity::unknown(42);
    let mut recording_policy = RecordingPolicy {
        executable: RefCell::new(None),
    };
    let mut policy: Option<&mut dyn AccessPolicy> = Some(&mut recording_policy);
    let mut learner = None;

    let decision = decide_audit_event(
        42,
        &process,
        Path::new("/etc/config-guard/config.toml"),
        AccessKind::Read,
        &mut learner,
        &mut policy,
    )
    .expect("evaluate unknown process");

    assert_eq!(decision, Decision::Allow);
    assert_eq!(
        recording_policy.executable.into_inner(),
        Some(PathBuf::from("unknown"))
    );
}

#[test]
fn graphical_session_requires_a_nonempty_wayland_display() {
    let mut env = HashMap::new();
    assert!(!has_graphical_session(&env));

    env.insert("WAYLAND_DISPLAY".to_string(), String::new());
    assert!(!has_graphical_session(&env));

    env.insert("WAYLAND_DISPLAY".to_string(), "wayland-1".to_string());
    assert!(has_graphical_session(&env));
}

#[test]
fn resolve_applies_default_without_prompting_when_no_session() {
    let subject = cat_subject();
    let prompt = PanicPrompt;
    let mut cache = PromptDecisionCache::default();

    let decision = prompt_for_policy_decision(
        &prompt,
        &mut cache,
        None,
        &subject,
        Path::new("/etc/authd/policies.d/wheel.toml"),
        HashMap::new(),
        Decision::Prompt {
            reason: DecisionReason::CrossOwnerRead,
            default: Box::new(Decision::Deny),
            scope: PathBuf::from("/etc/authd"),
        },
    )
    .expect("resolve decision");

    assert_eq!(decision, Decision::Deny);
}

#[test]
fn resolve_invokes_headless_prompt_without_graphical_session() {
    let subject = cat_subject();
    let prompt = HeadlessPrompt;
    let mut cache = PromptDecisionCache::default();

    let decision = prompt_for_policy_decision(
        &prompt,
        &mut cache,
        None,
        &subject,
        Path::new("/etc/authd/policies.d/wheel.toml"),
        HashMap::new(),
        Decision::Prompt {
            reason: DecisionReason::CrossOwnerRead,
            default: Box::new(Decision::Allow),
            scope: PathBuf::from("/etc/authd"),
        },
    )
    .expect("resolve decision");

    assert_eq!(decision, Decision::Deny);
}

#[test]
fn resolve_reuses_approval_for_same_process_across_scopes() {
    let process = cat_process(42, 100);
    let prompt = CountingPrompt::new(Decision::Allow);
    let mut cache = PromptDecisionCache::default();

    let first = resolve_cat_prompt(
        &prompt,
        &mut cache,
        &process,
        "/etc/authd/policies.d/wheel.toml",
        "/etc/authd",
    );
    let second = resolve_cat_prompt(
        &prompt,
        &mut cache,
        &process,
        "/home/osso/.ssh/config",
        "/home/osso/.ssh",
    );

    assert_eq!(first, Decision::Allow);
    assert_eq!(second, Decision::Allow);
    assert_eq!(prompt.calls.get(), 1);
}

#[test]
fn resolve_reuses_denial_for_same_process_across_scopes() {
    let process = cat_process(42, 100);
    let prompt = CountingPrompt::new(Decision::Deny);
    let mut cache = PromptDecisionCache::default();

    let first = resolve_cat_prompt(
        &prompt,
        &mut cache,
        &process,
        "/etc/authd/policies.d/wheel.toml",
        "/etc/authd",
    );
    let second = resolve_cat_prompt(
        &prompt,
        &mut cache,
        &process,
        "/home/osso/.ssh/config",
        "/home/osso/.ssh",
    );

    assert_eq!(first, Decision::Deny);
    assert_eq!(second, Decision::Deny);
    assert_eq!(
        prompt.calls.get(),
        1,
        "one process denial must not trigger another prompt"
    );
}

#[test]
fn resolve_prompts_again_after_process_generation_changes() {
    let first_process = cat_process(42, 100);
    let next_process = cat_process(42, 200);
    let prompt = CountingPrompt::new(Decision::Allow);
    let mut cache = PromptDecisionCache::default();

    let first = resolve_cat_prompt(
        &prompt,
        &mut cache,
        &first_process,
        "/etc/authd/policies.d/wheel.toml",
        "/etc/authd",
    );
    let second = resolve_cat_prompt(
        &prompt,
        &mut cache,
        &next_process,
        "/etc/authd/policies.d/claude.toml",
        "/etc/authd",
    );

    assert_eq!(first, Decision::Allow);
    assert_eq!(second, Decision::Allow);
    assert_eq!(prompt.calls.get(), 2);
}

#[cfg(not(coverage))]
#[test]
fn guard_policy_log_line_uses_guard_mode() {
    let line = format_guard_decision(
        42,
        Path::new("/usr/bin/cat"),
        Path::new("/home/osso/.kube/config"),
        AccessKind::Read,
        Decision::Prompt {
            reason: DecisionReason::CrossOwnerRead,
            default: Box::new(Decision::Allow),
            scope: PathBuf::from("/home/osso/.kube"),
        },
    )
    .expect("prompt decisions should be logged");

    assert!(line.starts_with("FORBID guard "), "{line}");
    assert!(!line.starts_with("FORBID audit "), "{line}");
}

#[test]
fn permission_event_helpers_map_masks_and_responses() {
    assert_eq!(access_kind(libc::FAN_CLOSE_WRITE), AccessKind::Write);
    assert_eq!(access_kind(libc::FAN_CLOSE_NOWRITE), AccessKind::Read);
    assert_eq!(access_kind(libc::FAN_OPEN_PERM), AccessKind::Read);
    assert!(is_permission_event(libc::FAN_OPEN_PERM));
    assert!(!is_permission_event(libc::FAN_ACCESS_PERM));
    assert!(!is_permission_event(libc::FAN_CLOSE_WRITE));
    assert_eq!(
        audit_watch_mask(),
        libc::FAN_OPEN | libc::FAN_OPEN_EXEC | libc::FAN_CLOSE_NOWRITE | libc::FAN_CLOSE_WRITE
    );
    assert_ne!(guard_watch_mask() & libc::FAN_OPEN_PERM, 0);
    assert_ne!(guard_watch_mask() & libc::FAN_CLOSE_WRITE, 0);
    assert_eq!(guard_watch_mask() & libc::FAN_ACCESS_PERM, 0);
    let unknown_process = ProcessIdentity::unknown(42);
    let unverified_process = ProcessIdentity::from_executable(42, PathBuf::from("/usr/bin/cat"));
    assert!(
        super::PromptDecisionKey::new(
            &unknown_process,
            AccessKind::Read,
            &prompt_decision("/etc/authd")
        )
        .is_none()
    );
    assert!(
        super::PromptDecisionKey::new(
            &unverified_process,
            AccessKind::Read,
            &prompt_decision("/etc/authd")
        )
        .is_none()
    );
    assert_eq!(response_code(Decision::Allow), libc::FAN_ALLOW);
    assert_eq!(response_code(Decision::Deny), libc::FAN_DENY);
    assert_eq!(
        response_code(Decision::Prompt {
            reason: DecisionReason::CrossOwnerRead,
            default: Box::new(Decision::Deny),
            scope: PathBuf::from("/tmp"),
        }),
        libc::FAN_ALLOW
    );
}

#[cfg(not(coverage))]
#[test]
fn merged_audit_masks_preserve_both_read_and_write_classifications() {
    assert_eq!(
        audit_access_kinds(libc::FAN_CLOSE_NOWRITE | libc::FAN_CLOSE_WRITE),
        vec![AccessKind::Read, AccessKind::Write]
    );
    assert!(audit_access_kinds(libc::FAN_OPEN).is_empty());
}

#[test]
fn queue_overflow_and_invalid_descriptors_are_errors() {
    let overflow = ensure_event_descriptor(libc::FAN_Q_OVERFLOW, libc::FAN_NOFD)
        .expect_err("queue overflow must fail");
    assert!(overflow.to_string().contains("queue overflow"));

    let invalid =
        ensure_event_descriptor(0, libc::FAN_NOFD).expect_err("invalid descriptor must fail");
    assert!(
        invalid
            .to_string()
            .contains("invalid fanotify event descriptor")
    );

    assert!(ensure_event_descriptor(libc::FAN_CLOSE_WRITE, 4).is_ok());
}

#[test]
fn watch_scope_includes_roots_and_excludes_subtrees() {
    let roots = vec![PathBuf::from("/home/osso/.config"), PathBuf::from("/etc")];
    let excluded = vec![PathBuf::from("/home/osso/.config/archive")];

    assert!(is_watched_path(
        Path::new("/home/osso/.config/new-app/settings.toml"),
        &roots,
        &excluded
    ));
    assert!(is_watched_path(
        Path::new("/etc/systemd/system/example.service"),
        &roots,
        &excluded
    ));
    assert!(!is_watched_path(
        Path::new("/home/osso/.config/archive/old.toml"),
        &roots,
        &excluded
    ));
    assert!(!is_watched_path(
        Path::new("/home/osso/Documents/note.txt"),
        &roots,
        &excluded
    ));
}

#[test]
fn ensure_path_exists_reports_missing_paths() {
    let path = PathBuf::from("/definitely/missing/config-guard/path");

    let error = ensure_path_exists(&path).unwrap_err().to_string();

    assert!(error.contains("watch path does not exist"));
}

#[cfg(coverage)]
#[test]
fn coverage_run_stub_validates_watch_paths() {
    let mut policy = PanicPolicy;
    let prompt = PanicPrompt;
    let temp = std::env::temp_dir();

    assert!(
        run(
            std::slice::from_ref(&temp),
            &[],
            Mode::Guard {
                policy: &mut policy,
                prompt: &prompt,
                prompt_cache: PromptDecisionCache::default(),
            },
        )
        .is_ok()
    );
    assert!(
        run(
            &[PathBuf::from("/definitely/missing/config-guard/path")],
            &[],
            Mode::Audit {
                learner: None,
                policy: None,
            },
        )
        .is_err()
    );
}

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
