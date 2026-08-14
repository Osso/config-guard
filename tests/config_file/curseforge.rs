use super::{parse_osso_config, subject};
use config_guard::policy::{AccessKind, Decision, Policy};

#[test]
fn osso_config_allows_curseforge_owner_all_access() {
    let policy = Policy::new(parse_osso_config());
    let path = "/home/osso/.config/curseforge/credentials.toml";

    for access in [
        AccessKind::Read,
        AccessKind::Write,
        AccessKind::DestructiveWrite,
    ] {
        assert_eq!(
            policy.decide(&subject("curseforge"), path, access),
            Decision::Allow,
            "curseforge should access {path} with {access:?}",
        );
    }
}

#[test]
fn osso_config_denies_non_owner_curseforge_access() {
    let policy = Policy::new(parse_osso_config());
    let path = "/home/osso/.config/curseforge/credentials.toml";
    let non_owners = [
        "bash", "zsh", "cat", "git", "pi", "python", "nvim", "vim", "nano", "emacs", "code",
    ];

    for subject_name in non_owners {
        for access in [
            AccessKind::Read,
            AccessKind::Write,
            AccessKind::DestructiveWrite,
        ] {
            assert_eq!(
                policy.decide(&subject(subject_name), path, access),
                Decision::Deny,
                "{subject_name} should be denied for {path} with {access:?}",
            );
        }
    }
}

#[test]
fn osso_config_leaves_curseforge_sibling_unowned() {
    let policy = Policy::new(parse_osso_config());
    let sibling_path = "/home/osso/.config/curseforge-helper/credentials.toml";

    for access in [
        AccessKind::Read,
        AccessKind::Write,
        AccessKind::DestructiveWrite,
    ] {
        assert_eq!(
            policy.decide(&subject("bash"), sibling_path, access),
            Decision::Allow,
            "sibling behavior should remain unchanged for {access:?}",
        );
    }
}
