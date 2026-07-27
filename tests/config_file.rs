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
fn osso_config_allows_flux_to_read_kube_config() {
    let policy = Policy::new(parse_osso_config());

    let decision = policy.decide(
        &subject("flux"),
        "/home/osso/.kube/config",
        config_guard::policy::AccessKind::Read,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn osso_config_allows_git_to_read_tracked_credential_trees() {
    let policy = Policy::new(parse_osso_config());

    for path in [
        "/home/osso/.config/gc/token.json",
        "/home/osso/.config/gmail-cli/tokens.json",
    ] {
        let decision = policy.decide(
            &subject("git"),
            path,
            config_guard::policy::AccessKind::Read,
        );

        assert_eq!(decision, Decision::Allow, "git should read {path}");
    }
}

#[test]
fn osso_config_prompts_for_git_writes_to_tracked_credential_trees() {
    let policy = Policy::new(parse_osso_config());

    for path in [
        "/home/osso/.config/gc/token.json",
        "/home/osso/.config/gmail-cli/tokens.json",
    ] {
        let decision = policy.decide(
            &subject("git"),
            path,
            config_guard::policy::AccessKind::Write,
        );

        assert!(
            matches!(decision, Decision::Prompt { .. }),
            "git write should prompt for {path}"
        );
    }
}

#[test]
fn osso_config_prompts_for_git_helpers_on_tracked_credential_trees() {
    let policy = Policy::new(parse_osso_config());

    for helper in ["git-remote-http", "git-remote-https"] {
        let decision = policy.decide(
            &subject(helper),
            "/home/osso/.config/gc/token.json",
            config_guard::policy::AccessKind::Read,
        );

        assert!(
            matches!(decision, Decision::Prompt { .. }),
            "{helper} read should prompt"
        );
    }
}

#[test]
fn osso_config_does_not_extend_git_access_to_adjacent_paths() {
    let policy = Policy::new(parse_osso_config());

    let decision = policy.decide(
        &subject("git"),
        "/home/osso/.config/gcloud/configurations/config_default",
        config_guard::policy::AccessKind::Read,
    );

    assert!(matches!(decision, Decision::Prompt { .. }));
}

#[test]
fn osso_config_allows_all_access_to_networkmanager_dispatcher_scripts() {
    let policy = Policy::new(parse_osso_config());

    for path in [
        "/etc/NetworkManager/dispatcher.d",
        "/etc/NetworkManager/dispatcher.d/90-disable-wifi-powersave",
    ] {
        for access in [
            config_guard::policy::AccessKind::Read,
            config_guard::policy::AccessKind::Write,
            config_guard::policy::AccessKind::DestructiveWrite,
        ] {
            let decision = policy.decide(&subject("bash"), path, access);

            assert_eq!(
                decision,
                Decision::Allow,
                "bash {access:?} should access {path}"
            );
        }
    }
}

#[test]
fn osso_config_keeps_other_networkmanager_paths_owned() {
    let policy = Policy::new(parse_osso_config());

    for path in [
        "/etc/NetworkManager/NetworkManager.conf",
        "/etc/NetworkManager/conf.d/wifi.conf",
    ] {
        let decision = policy.decide(
            &subject("bash"),
            path,
            config_guard::policy::AccessKind::Read,
        );

        assert!(
            matches!(decision, Decision::Prompt { .. }),
            "bash read should prompt for {path}"
        );
    }
}

#[test]
fn osso_config_allows_pi_state_access() {
    let policy = Policy::new(parse_osso_config());

    let decision = policy.decide(
        &subject("pi"),
        "/home/osso/.local/state/pi/control.sqlite-wal",
        config_guard::policy::AccessKind::Write,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn osso_config_allows_pi_installation_access() {
    let policy = Policy::new(parse_osso_config());

    let decision = policy.decide(
        &subject("pi"),
        "/home/osso/.local/share/pi/package.json",
        config_guard::policy::AccessKind::Read,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn osso_config_does_not_allow_generic_node_for_pi_state() {
    let policy = Policy::new(parse_osso_config());

    let decision = policy.decide(
        &subject("node"),
        "/home/osso/.local/state/pi/control.sqlite-wal",
        config_guard::policy::AccessKind::Write,
    );

    assert!(matches!(
        decision,
        Decision::Prompt {
            reason: DecisionReason::CrossOwnerWrite,
            ..
        }
    ));
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

#[test]
fn osso_config_allows_syncthing_cli_config_reads() {
    let policy = Policy::new(parse_osso_config());

    for path in [
        "/home/osso/.config/syncthing-cli/config.json",
        "/home/osso/.config/syncthing/config.xml",
    ] {
        let decision = policy.decide(
            &subject("syncthing-cli"),
            path,
            config_guard::policy::AccessKind::Read,
        );

        assert_eq!(
            decision,
            Decision::Allow,
            "syncthing-cli should read {path}"
        );
    }
}

#[test]
fn osso_config_allows_observed_application_workflows() {
    let policy = Policy::new(parse_osso_config());

    let cases = [
        (
            "pyrun-jsonl",
            "/home/osso/.local/share/uv/python/cpython/bin/python3.12",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "pi",
            "/home/osso/.local/share/uv/tools/pyrun/bin/pyrun-jsonl",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "claude-bash-hoo",
            "/home/osso/.config/claude-bash-hook/hostrun.toml",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "php",
            "/home/osso/.config/composer/auth.json",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "groundcover-cli",
            "/home/osso/.config/groundcover/config.json",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "Enpass",
            "/home/osso/.config/sinew.in/Enpass.conf.lock",
            config_guard::policy::AccessKind::Write,
        ),
        (
            "chrome_crashpad_handler",
            "/home/osso/.config/chromium/Crash",
            config_guard::policy::AccessKind::Write,
        ),
        (
            "chrome_crashpad_handler",
            "/home/osso/.config/vivaldi/Crash",
            config_guard::policy::AccessKind::Write,
        ),
        (
            "firefox-profile-backup",
            "/home/osso/.local/share/firefox-backup/.tmp/key4.db",
            config_guard::policy::AccessKind::Write,
        ),
        (
            "tradebot",
            "/home/osso/.local/share/tradebot/tradebot.sqlite3-journal",
            config_guard::policy::AccessKind::Write,
        ),
        (
            "tradebot-desktop",
            "/home/osso/.local/share/tradebot/tradebot.sqlite3",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "tradebot-desktop",
            "/home/osso/.local/share/gvfs-metadata/root",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "tradebot-desktop",
            "/home/osso/.config/dconf/user",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "tradebot-desktop",
            "/home/osso/.local/share/mime/mime.cache",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "WebKitNetworkProcess",
            "/home/osso/.local/share/com.ossonet.tradebot.performance/hsts-storage.sqlite",
            config_guard::policy::AccessKind::Write,
        ),
        (
            "WebKitNetworkProcess",
            "/home/osso/.config/dconf/user",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "containerd",
            "/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/test",
            config_guard::policy::AccessKind::Write,
        ),
    ];

    for (owner, path, access) in cases {
        assert_eq!(
            policy.decide(&subject(owner), path, access),
            Decision::Allow,
            "{owner} should access {path}",
        );
    }
}

#[test]
fn osso_config_allows_observed_system_workflows() {
    let policy = Policy::new(parse_osso_config());

    let cases = [
        (
            "utempter",
            "/var/log/wtmp",
            config_guard::policy::AccessKind::Write,
        ),
        (
            "systemd-xdg-autostart-generator",
            "/etc/xdg/autostart/blueman.desktop",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "30-systemd-environment-d-generator",
            "/etc/environment",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "appfw",
            "/etc/appfw/rules.d/defaults.toml",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "sudo",
            "/etc/sudo.conf",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "sudo",
            "/etc/sudoers",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "sudo",
            "/etc/pam.d/system-auth",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "runuser",
            "/etc/pam.d/runuser",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "runuser",
            "/var/lib/lastlog/lastlog2.db-journal",
            config_guard::policy::AccessKind::Write,
        ),
        (
            "quickshell",
            "/etc/pam.d/system-login",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "unix_chkpwd",
            "/etc/shadow",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "pacman-conf",
            "/etc/pacman.conf",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "pacman-conf",
            "/etc/pacman.d/mirrorlist",
            config_guard::policy::AccessKind::Read,
        ),
        (
            "sensors",
            "/etc/sensors3.conf",
            config_guard::policy::AccessKind::Read,
        ),
    ];

    for (owner, path, access) in cases {
        assert_eq!(
            policy.decide(&subject(owner), path, access),
            Decision::Allow,
            "{owner} should access {path}",
        );
    }
}

#[test]
fn osso_config_allows_firefox_backup_sqlite_only_with_backup_ancestor() {
    let policy = Policy::new(parse_osso_config());
    let path = "/home/osso/.local/share/firefox-backup/current/cookies.sqlite";

    let allowed = policy.decide(
        &subject_with_ancestor("sqlite3", "/usr/bin/firefox-profile-backup"),
        path,
        config_guard::policy::AccessKind::Write,
    );
    let untrusted = policy.decide(
        &subject_with_ancestor("sqlite3", "/usr/bin/bash"),
        path,
        config_guard::policy::AccessKind::Write,
    );

    assert_eq!(allowed, Decision::Allow);
    assert!(matches!(untrusted, Decision::Prompt { .. }));
}

#[test]
fn osso_config_keeps_ad_hoc_tools_prompted_for_explicit_protected_paths() {
    let policy = Policy::new(parse_osso_config());

    for (tool, path, access) in [
        (
            "cp",
            "/etc/config-guard/config.toml",
            config_guard::policy::AccessKind::Write,
        ),
        (
            "cp",
            "/var/lib/pacman/local/example/desc",
            config_guard::policy::AccessKind::Write,
        ),
        (
            "rg",
            "/home/osso/.config/chromium/Local State",
            config_guard::policy::AccessKind::Read,
        ),
    ] {
        assert!(
            matches!(
                policy.decide(&subject(tool), path, access),
                Decision::Prompt { .. }
            ),
            "{tool} should still prompt for {path}",
        );
    }
}

#[test]
fn osso_config_allows_unlisted_paths_inside_monitored_roots() {
    let policy = Policy::new(parse_osso_config());

    for path in [
        "/home/osso/.local/share/unlisted-app/state.db",
        "/home/osso/.local/state/unlisted-app/state.json",
        "/etc/example.conf",
        "/var/lib/unlisted-app/state.db",
        "/var/log/unlisted-app.log",
    ] {
        let decision = policy.decide(
            &subject("cp"),
            path,
            config_guard::policy::AccessKind::Write,
        );

        assert_eq!(decision, Decision::Allow, "{path} should be unowned");
    }
}

#[test]
fn osso_config_guards_db_credential_dirs() {
    let policy = Policy::new(parse_osso_config());

    let cases = [
        ("mysql-gc", "/home/osso/.config/mysql-gc/prod.cnf"),
        (
            "mariadb-mysql-cdc",
            "/home/osso/.config/mariadb-mysql-cdc/config.json",
        ),
    ];

    for (owner, path) in cases {
        // The owning tool reads its own credentials without a prompt.
        assert_eq!(
            policy.decide(
                &subject(owner),
                path,
                config_guard::policy::AccessKind::Read
            ),
            Decision::Allow,
            "{owner} should access its own credentials",
        );

        // A dev tool reading the same credentials must prompt.
        assert!(
            matches!(
                policy.decide(
                    &subject("claude"),
                    path,
                    config_guard::policy::AccessKind::Read
                ),
                Decision::Prompt {
                    reason: DecisionReason::SensitiveReadByDevTool,
                    ..
                }
            ),
            "dev tool reading {path} should prompt",
        );
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
