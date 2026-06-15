use config_guard::policy::{Decision, DecisionReason, Policy, PolicyConfig, ProcessSubject};
use std::path::PathBuf;

#[test]
fn osso_config_file_parses() {
    parse_osso_config();
}

#[test]
fn osso_config_allows_known_owner() {
    let policy = Policy::new(parse_osso_config());
    let subject = subject("kubectl");

    let decision = policy.decide(
        &subject,
        "/home/osso/.kube/config",
        config_guard::policy::AccessKind::Read,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn osso_config_prompts_for_dev_tool_reading_sensitive_config() {
    let policy = Policy::new(parse_osso_config());
    let subject = subject("codex");

    let decision = policy.decide(
        &subject,
        "/home/osso/.config/github-cli/config.json",
        config_guard::policy::AccessKind::Read,
    );

    assert_eq!(
        decision,
        Decision::Prompt {
            reason: DecisionReason::SensitiveReadByDevTool,
            default: Box::new(Decision::Allow),
            scope: std::path::PathBuf::from("/home/osso/.config/github-cli"),
        }
    );
}

#[test]
fn osso_config_allows_claude_spawned_bash_for_claude_config() {
    let policy = Policy::new(parse_osso_config());
    let subject = subject_with_ancestor("bash", "/home/osso/.local/share/claude/versions/2.1.177");

    let decision = policy.decide(
        &subject,
        "/home/osso/.config/claude/sessions/3653421.json",
        config_guard::policy::AccessKind::Write,
    );

    assert_eq!(decision, Decision::Allow);
}

fn parse_osso_config() -> PolicyConfig {
    toml::from_str(include_str!("../config/osso.toml")).expect("config/osso.toml should parse")
}

fn subject(name: &str) -> ProcessSubject {
    ProcessSubject {
        executable: PathBuf::from(format!("/usr/bin/{name}")),
        command: vec![name.to_string()],
        ancestors: Vec::new(),
    }
}

fn subject_with_ancestor(name: &str, ancestor: &str) -> ProcessSubject {
    ProcessSubject {
        executable: PathBuf::from(format!("/usr/bin/{name}")),
        command: vec![name.to_string()],
        ancestors: vec![PathBuf::from(ancestor)],
    }
}
