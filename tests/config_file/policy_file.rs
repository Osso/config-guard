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
