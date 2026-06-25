use config_guard::learning::{
    AuditLearner, PathAlias, config_root_for, config_root_for_home, config_root_for_home_or_alias,
};
use config_guard::policy::{AccessKind, ProcessSubject};
use std::fs;
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
fn learns_codex_as_config_root() {
    let path = home_path(".codex/config.toml");

    let root = config_root_for(&path);

    assert_eq!(root, Some(home_path(".codex")));
}

#[test]
fn ignores_paths_outside_known_config_roots() {
    let root = config_root_for(&PathBuf::from("/tmp/not-config"));

    assert_eq!(root, None);
}

#[test]
fn config_root_for_home_rejects_empty_config_subdir() {
    let home = PathBuf::from("/home/osso");

    assert_eq!(config_root_for_home(&home.join(".config"), &home), None);
    assert_eq!(
        config_root_for_home(&home.join("Downloads/file"), &home),
        None
    );
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

#[test]
fn audit_learner_writes_observations_and_owned_path_candidates() {
    let root =
        std::env::temp_dir().join(format!("config-guard-learning-test-{}", std::process::id()));
    let home = root.join("home");
    let output = root.join("learned.toml");
    fs::create_dir_all(home.join(".config/gh")).expect("create config root");
    let subject = ProcessSubject {
        executable: PathBuf::from("/usr/bin/gh"),
        command: vec!["gh".to_string()],
        ancestors: Vec::new(),
    };
    let mut learner = AuditLearner::new(output.clone(), home.clone());

    learner
        .observe(
            &subject,
            &home.join(".config/gh/hosts.yml"),
            AccessKind::Read,
        )
        .expect("write learned output");
    learner
        .observe(
            &subject,
            &home.join(".config/gh/config.yml"),
            AccessKind::Write,
        )
        .expect("write learned output");
    learner
        .observe(&subject, &home.join("Downloads/file"), AccessKind::Read)
        .expect("ignore unknown root");

    let content = fs::read_to_string(&output).expect("read learned output");
    assert!(content.contains("owner = \"gh\""));
    assert!(content.contains("access = \"read\""));
    assert!(content.contains("access = \"write\""));
    assert!(!content.contains("Downloads"));

    let _ = fs::remove_dir_all(root);
}

fn home_path(suffix: &str) -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/osso"))
        .join(suffix)
}
