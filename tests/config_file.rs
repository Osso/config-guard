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
fn osso_config_allows_jq_for_claude_config_only_with_trusted_ancestor() {
    let policy = Policy::new(parse_osso_config());
    let session_path = "/home/osso/.config/claude/projects/-home-osso-Repos-codex/session.jsonl";

    let allowed = policy.decide(
        &subject_with_ancestor("jq", "/usr/bin/codex"),
        session_path,
        config_guard::policy::AccessKind::Read,
    );
    let untrusted = policy.decide(
        &subject_with_ancestor("jq", "/usr/bin/bash"),
        session_path,
        config_guard::policy::AccessKind::Read,
    );

    assert_eq!(allowed, Decision::Allow);
    assert!(matches!(untrusted, Decision::Prompt { .. }));
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

#[test]
fn osso_config_allows_systemd_sleep_config_readers() {
    let policy = Policy::new(parse_osso_config());

    for reader in ["systemd-logind", "systemd-sleep"] {
        let decision = policy.decide(
            &subject(reader),
            "/etc/systemd/sleep.conf",
            config_guard::policy::AccessKind::Read,
        );

        assert_eq!(decision, Decision::Allow);
    }
}

#[test]
fn osso_config_allows_firefox_resolver_reads_after_replacement() {
    let policy = Policy::new(parse_osso_config());

    let decision = policy.decide(
        &subject("firefox"),
        "/etc/resolv.conf (deleted)",
        config_guard::policy::AccessKind::Read,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn osso_config_allows_wow_sim_state_access() {
    let policy = Policy::new(parse_osso_config());

    for (path, access) in [
        (
            "/home/osso/.local/share/wow-sim/cvars.json",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "/home/osso/.local/share/wow-sim/cvars.json",
            config_guard::policy::AccessKind::Write,
        ),
        (
            "/home/osso/.local/share/wow-sim/SavedVariables/Blizzard_AddOnList.lua",
            config_guard::policy::AccessKind::Write,
        ),
    ] {
        let decision = policy.decide(&subject("wow-sim"), path, access);

        assert_eq!(decision, Decision::Allow);
    }
}

#[test]
fn osso_config_allows_zed_editor_state_reads() {
    let policy = Policy::new(parse_osso_config());

    let decision = policy.decide(
        &subject("zed-editor"),
        "/home/osso/.local/share/zed/db/0-stable/db.sqlite",
        config_guard::policy::AccessKind::Read,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn osso_config_allows_k9s_state_access() {
    let policy = Policy::new(parse_osso_config());

    for (path, access) in [
        (
            "/home/osso/.local/share/k9s/clusters/do-nyc1-gc-kubernetes/do-nyc1-gc-kubernetes/config.yaml",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "/home/osso/.local/share/k9s/clusters/do-nyc1-gc-kubernetes/do-nyc1-gc-kubernetes/config.yaml",
            config_guard::policy::AccessKind::Write,
        ),
        (
            "/home/osso/.local/state/k9s/k9s.log",
            config_guard::policy::AccessKind::Write,
        ),
    ] {
        let decision = policy.decide(&subject("k9s"), path, access);

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
