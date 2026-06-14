use config_guard::learning::config_root_for;
use std::path::PathBuf;

#[test]
fn learns_config_subdirectory_root() {
    let path = home_path(".config/gh/hosts.yml");

    let root = config_root_for(&path);

    assert_eq!(root, Some(home_path(".config/gh")));
}

#[test]
fn learns_ssh_as_sensitive_root() {
    let path = home_path(".ssh/id_ed25519");

    let root = config_root_for(&path);

    assert_eq!(root, Some(home_path(".ssh")));
}

#[test]
fn ignores_paths_outside_known_config_roots() {
    let root = config_root_for(&PathBuf::from("/tmp/not-config"));

    assert_eq!(root, None);
}

fn home_path(suffix: &str) -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/osso"))
        .join(suffix)
}
