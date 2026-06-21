use config_guard::policy::{
    AccessKind, Decision, DecisionReason, OwnedPath, Policy, PolicyConfig, ProcessSubject,
    SharedPath, executable_label,
};
use std::path::PathBuf;

fn subject(name: &str) -> ProcessSubject {
    ProcessSubject {
        executable: PathBuf::from(format!("/usr/bin/{name}")),
        command: vec![name.to_string()],
        ancestors: Vec::new(),
    }
}

fn subject_executable(path: &str) -> ProcessSubject {
    ProcessSubject {
        executable: PathBuf::from(path),
        command: Vec::new(),
        ancestors: Vec::new(),
    }
}

fn subject_executable_with_ancestor(path: &str, ancestor: &str) -> ProcessSubject {
    ProcessSubject {
        executable: PathBuf::from(path),
        command: Vec::new(),
        ancestors: vec![PathBuf::from(ancestor)],
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
fn explicit_owner_allow_takes_precedence_over_sensitive_dev_tool_prompt() {
    let mut config = PolicyConfig::default();
    config.dev_tools = vec!["exe-prefix:/home/osso/.local/share/claude/versions/".to_string()];
    config.sensitive_paths.push(config_guard::policy::PathRule {
        path: PathBuf::from("/home/osso/.config/claude"),
    });
    config.owned_paths.push(OwnedPath {
        path: PathBuf::from("/home/osso/.config/claude"),
        owner: "claude".to_string(),
        allowed_subjects: vec!["exe-prefix:/home/osso/.local/share/claude/versions/".to_string()],
    });
    let policy = Policy::new(config);

    let decision = policy.decide(
        &subject_executable("/home/osso/.local/share/claude/versions/2.1.177"),
        "/home/osso/.config/claude/commands/sentry-fix.md",
        AccessKind::Read,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn ancestor_executable_prefix_can_allow_claude_spawned_bash_for_claude_config() {
    let mut config = PolicyConfig::default();
    config.owned_paths.push(OwnedPath {
        path: PathBuf::from("/home/osso/.config/claude"),
        owner: "claude".to_string(),
        allowed_subjects: vec![
            "exe-with-ancestor-prefix:/usr/bin/bash:/home/osso/.local/share/claude/versions/"
                .to_string(),
        ],
    });
    let policy = Policy::new(config);

    let decision = policy.decide(
        &subject_executable_with_ancestor(
            "/usr/bin/bash",
            "/home/osso/.local/share/claude/versions/2.1.177",
        ),
        "/home/osso/.config/claude/sessions/3653421.json",
        AccessKind::Write,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn ancestor_executable_prefix_does_not_allow_bash_without_claude_parent() {
    let mut config = PolicyConfig::default();
    config.owned_paths.push(OwnedPath {
        path: PathBuf::from("/home/osso/.config/claude"),
        owner: "claude".to_string(),
        allowed_subjects: vec![
            "exe-with-ancestor-prefix:/usr/bin/bash:/home/osso/.local/share/claude/versions/"
                .to_string(),
        ],
    });
    let policy = Policy::new(config);

    let decision = policy.decide(
        &subject_executable("/usr/bin/bash"),
        "/home/osso/.config/claude/sessions/3653421.json",
        AccessKind::Write,
    );

    assert_eq!(
        decision,
        Decision::Prompt {
            reason: DecisionReason::CrossOwnerWrite,
            default: Box::new(Decision::Allow),
            scope: PathBuf::from("/home/osso/.config/claude"),
        }
    );
}

#[test]
fn ancestor_rule_can_allow_helper_by_parent_name() {
    let mut config = PolicyConfig::default();
    config.owned_paths.push(OwnedPath {
        path: PathBuf::from("/home/osso/.config/claude"),
        owner: "claude".to_string(),
        allowed_subjects: vec!["with-ancestor:jq|codex".to_string()],
    });
    let policy = Policy::new(config);

    let decision = policy.decide(
        &subject_executable_with_ancestor("/usr/bin/jq", "/usr/bin/codex"),
        "/home/osso/.config/claude/projects/session.jsonl",
        AccessKind::Read,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn ancestor_rule_rejects_helper_without_matching_parent() {
    let mut config = PolicyConfig::default();
    config.owned_paths.push(OwnedPath {
        path: PathBuf::from("/home/osso/.config/claude"),
        owner: "claude".to_string(),
        allowed_subjects: vec!["with-ancestor:jq|codex".to_string()],
    });
    let policy = Policy::new(config);

    let decision = policy.decide(
        &subject_executable_with_ancestor("/usr/bin/jq", "/usr/bin/bash"),
        "/home/osso/.config/claude/projects/session.jsonl",
        AccessKind::Read,
    );

    assert_eq!(
        decision,
        Decision::Prompt {
            reason: DecisionReason::CrossOwnerRead,
            default: Box::new(Decision::Allow),
            scope: PathBuf::from("/home/osso/.config/claude"),
        }
    );
}

#[test]
fn most_specific_owned_path_rule_wins() {
    let mut config = PolicyConfig::default();
    config.owned_paths.push(OwnedPath {
        path: PathBuf::from("/home/osso/.config/claude"),
        owner: "claude".to_string(),
        allowed_subjects: Vec::new(),
    });
    config.owned_paths.push(OwnedPath {
        path: PathBuf::from("/home/osso/.config/claude/shell-snapshots"),
        owner: "claude-shell-snapshots".to_string(),
        allowed_subjects: vec![
            "exe-with-ancestor-prefix:/usr/bin/bash:/home/osso/.local/share/claude/versions/"
                .to_string(),
        ],
    });
    let policy = Policy::new(config);

    let decision = policy.decide(
        &subject_executable_with_ancestor(
            "/usr/bin/bash",
            "/home/osso/.local/share/claude/versions/2.1.177",
        ),
        "/home/osso/.config/claude/shell-snapshots/snapshot-bash-1781470485348-5s68tc.sh",
        AccessKind::Read,
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
            scope: PathBuf::from("/home/osso/.config/claude"),
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
            scope: PathBuf::from("/home/osso/.config/gh"),
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
        path_prefix: false,
        allowed_subjects: vec!["*".to_string()],
        access: vec![AccessKind::Read, AccessKind::Write],
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
fn shared_paths_can_be_read_only() {
    let mut config = PolicyConfig::default();
    config.shared_paths.push(SharedPath {
        path: PathBuf::from("/etc/ca-certificates"),
        path_prefix: false,
        allowed_subjects: vec!["*".to_string()],
        access: vec![AccessKind::Read],
    });
    config.owned_paths.push(OwnedPath {
        path: PathBuf::from("/etc"),
        owner: "root".to_string(),
        allowed_subjects: Vec::new(),
    });
    let policy = Policy::new(config);

    let read = policy.decide(
        &subject("codex"),
        "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
        AccessKind::Read,
    );
    let write = policy.decide(
        &subject("codex"),
        "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
        AccessKind::Write,
    );

    assert_eq!(read, Decision::Allow);
    assert_eq!(
        write,
        Decision::Prompt {
            reason: DecisionReason::CrossOwnerWrite,
            default: Box::new(Decision::Allow),
            scope: PathBuf::from("/etc"),
        }
    );
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
fn shared_paths_can_match_file_prefixes() {
    let mut config = PolicyConfig::default();
    config.shared_paths.push(SharedPath {
        path: PathBuf::from("/etc/resolv.conf."),
        path_prefix: true,
        allowed_subjects: vec!["NetworkManager".to_string()],
        access: vec![AccessKind::Read, AccessKind::Write],
    });
    config.owned_paths.push(OwnedPath {
        path: PathBuf::from("/etc"),
        owner: "root".to_string(),
        allowed_subjects: Vec::new(),
    });
    let policy = Policy::new(config);

    let temp_write = policy.decide(
        &subject("NetworkManager"),
        "/etc/resolv.conf.D9HAR3",
        AccessKind::Write,
    );
    let real_write = policy.decide(
        &subject("NetworkManager"),
        "/etc/resolv.conf",
        AccessKind::Write,
    );

    assert_eq!(temp_write, Decision::Allow);
    assert!(matches!(real_write, Decision::Prompt { .. }));
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
            scope: PathBuf::from("/home/osso/.config/kitty"),
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
            scope: PathBuf::from("/home/osso/.config/kitty"),
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
            scope: PathBuf::from("/home/osso/.config/gh"),
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
