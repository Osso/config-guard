use super::{parse_osso_config, subject};
use config_guard::policy::{AccessKind, Decision, Policy};

#[test]
fn osso_config_allows_noctalia_niri_helpers() {
    let policy = Policy::new(parse_osso_config());

    for helper in ["cp", "sed"] {
        for access in [AccessKind::Read, AccessKind::Write] {
            let decision = policy.decide(
                &subject(helper),
                "/home/osso/.config/niri/noctalia.kdl",
                access,
            );

            assert_eq!(decision, Decision::Allow, "{helper} {access:?}");
        }
    }

    let grep_read = policy.decide(
        &subject("grep"),
        "/home/osso/.config/niri/config.kdl",
        AccessKind::Read,
    );

    assert_eq!(grep_read, Decision::Allow);
}

#[test]
fn osso_config_keeps_noctalia_niri_helpers_scoped() {
    let policy = Policy::new(parse_osso_config());
    let restricted_access = [
        (
            "grep",
            "/home/osso/.config/niri/config.kdl",
            AccessKind::Write,
        ),
        ("cp", "/home/osso/.config/niri/other.kdl", AccessKind::Write),
        (
            "sed",
            "/home/osso/.config/niri/config.kdl",
            AccessKind::Write,
        ),
        (
            "bash",
            "/home/osso/.config/niri/noctalia.kdl",
            AccessKind::Read,
        ),
    ];

    for (helper, path, access) in restricted_access {
        let decision = policy.decide(&subject(helper), path, access);

        assert!(
            matches!(decision, Decision::Prompt { .. }),
            "{helper} {access:?} {path}"
        );
    }
}
