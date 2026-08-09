use super::{parse_osso_config, subject};
use config_guard::policy::{Decision, DecisionReason, Policy};

#[test]
fn osso_config_allows_incident_readers_to_read_only_exact_policy_file() {
    let policy = Policy::new(parse_osso_config());
    let policy_path = "/home/osso/.config/config-guard/config.toml";
    let adjacent_path = "/home/osso/.config/config-guard/adjacent.toml";

    for reader in ["rg", "pi", "sha256sum", "cmp", "python3.12"] {
        assert_eq!(
            policy.decide(
                &subject(reader),
                policy_path,
                config_guard::policy::AccessKind::Read,
            ),
            Decision::Allow,
            "{reader} should read the exact policy file without prompting",
        );

        assert!(
            matches!(
                policy.decide(
                    &subject(reader),
                    policy_path,
                    config_guard::policy::AccessKind::Write,
                ),
                Decision::Prompt {
                    reason: DecisionReason::CrossOwnerWrite,
                    ..
                }
            ),
            "{reader} should prompt when writing the exact policy file",
        );

        assert!(
            matches!(
                policy.decide(
                    &subject(reader),
                    adjacent_path,
                    config_guard::policy::AccessKind::Read,
                ),
                Decision::Prompt {
                    reason: DecisionReason::CrossOwnerRead,
                    ..
                }
            ),
            "{reader} should prompt when reading an adjacent policy-directory file",
        );
    }
}

#[test]
fn osso_config_leaves_uv_unowned_while_protecting_local_share_siblings() {
    let policy = Policy::new(parse_osso_config());

    for path in [
        "/home/osso/.local/share/uv",
        "/home/osso/.local/share/uv/tools/pyrun/bin/pyrun-jsonl",
    ] {
        let decision = policy.decide(
            &subject("cp"),
            path,
            config_guard::policy::AccessKind::Write,
        );

        assert_eq!(decision, Decision::Allow, "cp should write unowned {path}");
    }

    for path in [
        "/home/osso/.local/share/firefox-backup/current/cookies.sqlite",
        "/home/osso/.local/share/keyrings/login.keyring",
    ] {
        let decision = policy.decide(
            &subject("cp"),
            path,
            config_guard::policy::AccessKind::Write,
        );

        assert!(
            matches!(decision, Decision::Prompt { .. }),
            "cp should prompt for protected {path}"
        );
    }
}
