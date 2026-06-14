use config_guard::learning::{PathAlias, config_root_for, config_root_for_home_or_alias};
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
fn learns_kube_as_config_root() {
    let path = home_path(".kube/config");

    let root = config_root_for(&path);

    assert_eq!(root, Some(home_path(".kube")));
}

#[test]
fn ignores_paths_outside_known_config_roots() {
    let root = config_root_for(&PathBuf::from("/tmp/not-config"));

    assert_eq!(root, None);
}

#[test]
fn maps_symlinked_config_targets_back_to_logical_config_root() {
    let home = PathBuf::from("/home/osso");
    let aliases = vec![PathAlias {
        real_root: PathBuf::from("/syncthing/Sync/Provisioning/config/gmail-cli"),
        logical_root: home.join(".config/gmail-cli"),
    }];
    let target = PathBuf::from("/syncthing/Sync/Provisioning/config/gmail-cli/tokens.json");

    let root = config_root_for_home_or_alias(&target, &home, &aliases);

    assert_eq!(root, Some(home.join(".config/gmail-cli")));
}

fn home_path(suffix: &str) -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/osso"))
        .join(suffix)
}
