use config_guard::policy::{
    AccessKind, Decision, DecisionReason, OwnedPath, Policy, PolicyConfig, ProcessSubject,
    SharedPath, executable_label,
};
use std::path::PathBuf;

fn subject(name: &str) -> ProcessSubject {
    ProcessSubject {
        executable: PathBuf::from(format!("/usr/bin/{name}")),
        command: vec![name.to_string()],
    }
}

fn subject_executable(path: &str) -> ProcessSubject {
    ProcessSubject {
        executable: PathBuf::from(path),
        command: Vec::new(),
    }
}

#[test]
fn same_owner_access_is_allowed_without_prompt() {
    let policy = Policy::new(PolicyConfig::default());

    let decision = policy.decide(
        &subject("kitty"),
        "/home/osso/.config/kitty/kitty.conf",
        AccessKind::Read,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn claude_versioned_binary_requires_explicit_prefix_allow() {
    let mut config = PolicyConfig::default();
    config.owned_paths.push(OwnedPath {
        path: PathBuf::from("/home/osso/.config/claude"),
        owner: "claude".to_string(),
        allowed_subjects: vec!["exe-prefix:/home/osso/.local/share/claude/versions/".to_string()],
    });
    let policy = Policy::new(config);

    let decision = policy.decide(
        &subject_executable("/home/osso/.local/share/claude/versions/2.1.177"),
        "/home/osso/.config/claude/projects/session.jsonl",
        AccessKind::Write,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn claude_versioned_binary_does_not_implicitly_match_claude_owner() {
    let mut config = PolicyConfig::default();
    config.owned_paths.push(OwnedPath {
        path: PathBuf::from("/home/osso/.config/claude"),
        owner: "claude".to_string(),
        allowed_subjects: Vec::new(),
    });
    let policy = Policy::new(config);

    let decision = policy.decide(
        &subject_executable("/home/osso/.local/share/claude/versions/2.1.177"),
        "/home/osso/.config/claude/projects/session.jsonl",
        AccessKind::Write,
    );

    assert_eq!(
        decision,
        Decision::Prompt {
            reason: DecisionReason::CrossOwnerWrite,
            default: Box::new(Decision::Allow),
        }
    );
}

#[test]
fn claude_versioned_binary_can_be_classified_as_dev_tool_by_prefix() {
    let mut config = PolicyConfig::default();
    config.dev_tools = vec!["exe-prefix:/home/osso/.local/share/claude/versions/".to_string()];
    let policy = Policy::new(config);

    let decision = policy.decide(
        &subject_executable("/home/osso/.local/share/claude/versions/2.1.177"),
        "/home/osso/.config/gh/hosts.yml",
        AccessKind::Read,
    );

    assert_eq!(
        decision,
        Decision::Prompt {
            reason: DecisionReason::SensitiveReadByDevTool,
            default: Box::new(Decision::Allow),
        }
    );
}

#[test]
fn claude_versioned_binary_label_keeps_full_prefix() {
    assert_eq!(
        executable_label(&PathBuf::from(
            "/home/osso/.local/share/claude/versions/2.1.177"
        )),
        "claude:/home/osso/.local/share/claude/versions/2.1.177"
    );
}

#[test]
fn shared_paths_allow_common_desktop_processes() {
    let policy = Policy::new(PolicyConfig::default());

    let decision = policy.decide(
        &subject("gtk-launch"),
        "/home/osso/.config/mimeapps.list",
        AccessKind::Read,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn shared_paths_can_allow_all_subjects() {
    let mut config = PolicyConfig::default();
    config.shared_paths.push(SharedPath {
        path: PathBuf::from("/home/osso/.config/gtk-3.0"),
        allowed_subjects: vec!["*".to_string()],
    });
    let policy = Policy::new(config);

    let decision = policy.decide(
        &subject("any-gtk-app"),
        "/home/osso/.config/gtk-3.0/settings.ini",
        AccessKind::Read,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn owned_paths_can_allow_all_subjects() {
    let mut config = PolicyConfig::default();
    config.owned_paths.push(OwnedPath {
        path: PathBuf::from("/home/osso/.config/example"),
        owner: "example".to_string(),
        allowed_subjects: vec!["*".to_string()],
    });
    let policy = Policy::new(config);

    let decision = policy.decide(
        &subject("helper"),
        "/home/osso/.config/example/state.json",
        AccessKind::Write,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn cross_owner_read_prompts_with_fail_open_default() {
    let policy = Policy::new(PolicyConfig::default());

    let decision = policy.decide(
        &subject("codex"),
        "/home/osso/.config/kitty/kitty.conf",
        AccessKind::Read,
    );

    assert_eq!(
        decision,
        Decision::Prompt {
            reason: DecisionReason::CrossOwnerRead,
            default: Box::new(Decision::Allow),
        }
    );
}

#[test]
fn cross_owner_write_prompts_as_stronger_write_reason() {
    let policy = Policy::new(PolicyConfig::default());

    let decision = policy.decide(
        &subject("codex"),
        "/home/osso/.config/kitty/kitty.conf",
        AccessKind::Write,
    );

    assert_eq!(
        decision,
        Decision::Prompt {
            reason: DecisionReason::CrossOwnerWrite,
            default: Box::new(Decision::Allow),
        }
    );
}

#[test]
fn sensitive_paths_prompt_for_llm_tools_even_on_reads() {
    let policy = Policy::new(PolicyConfig::default());

    let decision = policy.decide(
        &subject("codex"),
        "/home/osso/.config/gh/hosts.yml",
        AccessKind::Read,
    );

    assert_eq!(
        decision,
        Decision::Prompt {
            reason: DecisionReason::SensitiveReadByDevTool,
            default: Box::new(Decision::Allow),
        }
    );
}

#[test]
fn explicit_prompt_deny_denies_only_current_event() {
    let policy = Policy::new(PolicyConfig::default());

    let denied = policy.apply_prompt_answer(Decision::Deny);
    let later_decision = policy.decide(
        &subject("codex"),
        "/home/osso/.config/kitty/kitty.conf",
        AccessKind::Read,
    );

    assert_eq!(denied, Decision::Deny);
    assert!(matches!(later_decision, Decision::Prompt { .. }));
}
