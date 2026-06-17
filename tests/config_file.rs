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

#[test]
fn osso_config_allows_claude_spawned_snapshot_helpers() {
    let policy = Policy::new(parse_osso_config());
    let snapshot_path =
        "/home/osso/.config/claude/shell-snapshots/snapshot-bash-1781545515454-oh36tk.sh";

    for helper in ["bash", "cat", "head"] {
        let subject =
            subject_with_ancestor(helper, "/home/osso/.local/share/claude/versions/2.1.177");

        let decision = policy.decide(
            &subject,
            snapshot_path,
            config_guard::policy::AccessKind::Write,
        );

        assert_eq!(decision, Decision::Allow);
    }
}

#[test]
fn osso_config_allows_codex_desktop_electron_for_codex_state() {
    let policy = Policy::new(parse_osso_config());
    let subject = ProcessSubject {
        executable: PathBuf::from("/opt/codex-desktop/electron"),
        command: vec!["/opt/codex-desktop/electron".to_string()],
        ancestors: Vec::new(),
    };

    for path in [
        "/home/osso/.config/Codex/Cookies-journal",
        "/home/osso/.local/state/codex-update-manager/state.json",
    ] {
        let decision = policy.decide(&subject, path, config_guard::policy::AccessKind::Read);

        assert_eq!(decision, Decision::Allow);
    }
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
