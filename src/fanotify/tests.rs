#[cfg(not(coverage))]
use super::AccessPolicy;
#[cfg(not(coverage))]
use super::audit::{access_kinds as audit_access_kinds, decide_event as decide_audit_event};
#[cfg(coverage)]
use super::{Mode, run};
use super::{
    PromptDecisionCache, access_kind, audit_watch_mask, child_directories, ensure_event_descriptor,
    ensure_path_exists, guard_watch_mask, has_graphical_session, is_permission_event,
    is_watched_path, prompt_for_policy_decision, response_code,
};
use crate::policy::{AccessKind, Decision, DecisionReason, ProcessSubject};
#[cfg(not(coverage))]
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
    subject: &ProcessSubject,
    target_path: &str,
) -> Decision {
    let policy_decision = prompt_decision("/etc/authd");
    prompt_for_policy_decision(
        prompt,
        cache,
        super::PromptDecisionKey::new(
            Some(subject.executable.clone()),
            AccessKind::Read,
            &policy_decision,
        ),
        subject,
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
fn resolve_reuses_approved_binary_for_same_scope() {
    let subject = cat_subject();
    let prompt = CountingPrompt::new(Decision::Allow);
    let mut cache = PromptDecisionCache::default();

    let first = resolve_cat_prompt(
        &prompt,
        &mut cache,
        &subject,
        "/etc/authd/policies.d/wheel.toml",
    );
    let second = resolve_cat_prompt(
        &prompt,
        &mut cache,
        &subject,
        "/etc/authd/policies.d/claude.toml",
    );

    assert_eq!(first, Decision::Allow);
    assert_eq!(second, Decision::Allow);
    assert_eq!(prompt.calls.get(), 1);
}

#[test]
fn resolve_does_not_cache_denials_for_binary() {
    let subject = cat_subject();
    let prompt = CountingPrompt::new(Decision::Deny);
    let mut cache = PromptDecisionCache::default();

    let first = resolve_cat_prompt(
        &prompt,
        &mut cache,
        &subject,
        "/etc/authd/policies.d/wheel.toml",
    );
    let second = resolve_cat_prompt(
        &prompt,
        &mut cache,
        &subject,
        "/etc/authd/policies.d/claude.toml",
    );

    assert_eq!(first, Decision::Deny);
    assert_eq!(second, Decision::Deny);
    assert_eq!(prompt.calls.get(), 2);
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
    assert!(
        super::PromptDecisionKey::new(None, AccessKind::Read, &prompt_decision("/etc/authd"))
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
