use config_guard::policy::{
    AccessKind, Decision, DecisionReason, Policy, PolicyConfig, ProcessSubject,
};
use std::path::PathBuf;

fn subject(name: &str) -> ProcessSubject {
    ProcessSubject {
        executable: PathBuf::from(format!("/usr/bin/{name}")),
        command: vec![name.to_string()],
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
