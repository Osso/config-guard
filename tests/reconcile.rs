use config_guard::policy::{AccessKind, OwnedPath, PathRule, PolicyConfig, SharedPath};
use config_guard::reconcile::{ActionKind, ReconcileOptions, plan_reconcile};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn configured_directories_are_kept() {
    let temp = TempConfigHome::new("configured_directories_are_kept");
    temp.create_dir("gh");
    let config = policy_with_owned_path(temp.path().join("gh"), "gh");

    let plan = plan_reconcile(ReconcileOptions::new(temp.path().to_path_buf(), &config))
        .expect("reconcile should plan");

    assert_eq!(plan.actions[0].kind, ActionKind::KeepConfigured);
}

#[test]
fn unconfigured_directories_with_matching_binary_are_association_candidates() {
    let temp = TempConfigHome::new(
        "unconfigured_directories_with_matching_binary_are_association_candidates",
    );
    temp.create_dir("new-tool");
    temp.create_bin("new-tool");
    let config = PolicyConfig::default();
    let options = ReconcileOptions::new(temp.path().to_path_buf(), &config)
        .with_binary_dirs(vec![temp.bin_path()]);

    let plan = plan_reconcile(options).expect("reconcile should plan");

    assert_eq!(plan.actions[0].kind, ActionKind::AssociateCandidate);
    assert_eq!(plan.actions[0].source, temp.path().join("new-tool"));
    assert_eq!(plan.actions[0].owner.as_deref(), Some("new-tool"));
}

#[test]
fn association_matching_handles_uppercase_config_dirs() {
    let temp = TempConfigHome::new("association_matching_handles_uppercase_config_dirs");
    temp.create_dir("Slack");
    temp.create_bin("slack");
    let config = PolicyConfig::default();
    let options = ReconcileOptions::new(temp.path().to_path_buf(), &config)
        .with_binary_dirs(vec![temp.bin_path()]);

    let plan = plan_reconcile(options).expect("reconcile should plan");

    assert_eq!(plan.actions[0].kind, ActionKind::AssociateCandidate);
    assert_eq!(plan.actions[0].owner.as_deref(), Some("slack"));
}

#[test]
fn association_matching_handles_scoped_config_dirs() {
    let temp = TempConfigHome::new("association_matching_handles_scoped_config_dirs");
    temp.create_dir("@checkly");
    temp.create_bin("checkly");
    let config = PolicyConfig::default();
    let options = ReconcileOptions::new(temp.path().to_path_buf(), &config)
        .with_binary_dirs(vec![temp.bin_path()]);

    let plan = plan_reconcile(options).expect("reconcile should plan");

    assert_eq!(plan.actions[0].kind, ActionKind::AssociateCandidate);
    assert_eq!(plan.actions[0].owner.as_deref(), Some("checkly"));
}

#[test]
fn association_matching_handles_dot_prefixed_config_dirs() {
    let temp = TempConfigHome::new("association_matching_handles_dot_prefixed_config_dirs");
    temp.create_dir(".aws");
    temp.create_bin("aws");
    let config = PolicyConfig::default();
    let options = ReconcileOptions::new(temp.path().to_path_buf(), &config)
        .with_binary_dirs(vec![temp.bin_path()]);

    let plan = plan_reconcile(options).expect("reconcile should plan");

    assert_eq!(plan.actions[0].kind, ActionKind::AssociateCandidate);
    assert_eq!(plan.actions[0].owner.as_deref(), Some("aws"));
}

#[test]
fn configured_shared_and_sensitive_paths_are_kept() {
    let temp = TempConfigHome::new("configured_shared_and_sensitive_paths_are_kept");
    temp.create_dir("shared");
    temp.create_dir("secret");
    let config = PolicyConfig {
        owned_paths: Vec::new(),
        shared_paths: vec![SharedPath {
            path: temp.path().join("shared"),
            path_prefix: false,
            access: vec![AccessKind::Read],
            allowed_subjects: Vec::new(),
        }],
        sensitive_paths: vec![PathRule {
            path: temp.path().join("secret"),
        }],
        dev_tools: Vec::new(),
        fail_open: true,
    };

    let plan = plan_reconcile(ReconcileOptions::new(temp.path().to_path_buf(), &config))
        .expect("reconcile should plan");

    assert_eq!(plan.actions.len(), 2);
    assert!(
        plan.actions
            .iter()
            .all(|action| action.kind == ActionKind::KeepConfigured)
    );
}

#[test]
fn archive_target_uses_suffix_when_name_already_exists() {
    let temp = TempConfigHome::new("archive_target_uses_suffix_when_name_already_exists");
    temp.create_dir("old-tool");
    fs::create_dir_all(temp.path().join("archive/old-tool")).expect("create archive collision");
    let config = PolicyConfig::default();

    let plan = plan_reconcile(ReconcileOptions::new(temp.path().to_path_buf(), &config))
        .expect("reconcile should plan");

    let target = plan.actions[0].target.as_ref().expect("archive target");
    assert!(
        target
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("old-tool-"))
    );
}

#[test]
fn applying_association_requires_config_path() {
    let temp = TempConfigHome::new("applying_association_requires_config_path");
    temp.create_dir("new-tool");
    temp.create_bin("new-tool");
    let config = PolicyConfig::default();
    let options = ReconcileOptions::new(temp.path().to_path_buf(), &config)
        .with_binary_dirs(vec![temp.bin_path()])
        .apply();

    let error = plan_reconcile(options).expect_err("missing config path should fail");

    assert!(error.to_string().contains("config path"));
}

#[test]
fn unconfigured_directories_without_matching_binary_are_archive_candidates() {
    let temp = TempConfigHome::new(
        "unconfigured_directories_without_matching_binary_are_archive_candidates",
    );
    temp.create_dir("old-tool");
    let config = PolicyConfig::default();
    let options = ReconcileOptions::new(temp.path().to_path_buf(), &config)
        .with_binary_dirs(vec![temp.bin_path()]);

    let plan = plan_reconcile(options).expect("reconcile should plan");

    assert_eq!(plan.actions[0].kind, ActionKind::ArchiveCandidate);
    assert_eq!(plan.actions[0].source, temp.path().join("old-tool"));
    assert_eq!(
        plan.actions[0].target,
        Some(temp.path().join("archive/old-tool"))
    );
}

#[test]
fn archive_directory_is_never_archived() {
    let temp = TempConfigHome::new("archive_directory_is_never_archived");
    temp.create_dir("archive");
    let config = PolicyConfig::default();

    let plan = plan_reconcile(ReconcileOptions::new(temp.path().to_path_buf(), &config))
        .expect("reconcile should plan");

    assert!(plan.actions.is_empty());
}

#[test]
fn apply_moves_unconfigured_directory_to_archive() {
    let temp = TempConfigHome::new("apply_moves_unconfigured_directory_to_archive");
    temp.create_dir("old-tool");
    let config = PolicyConfig::default();
    let options = ReconcileOptions::new(temp.path().to_path_buf(), &config)
        .with_binary_dirs(vec![temp.bin_path()])
        .apply();

    let plan = plan_reconcile(options).expect("reconcile should apply");

    assert_eq!(plan.actions[0].kind, ActionKind::Archived);
    assert!(!temp.path().join("old-tool").exists());
    assert!(temp.path().join("archive/old-tool").exists());
}

#[test]
fn apply_appends_association_to_config_file() {
    let temp = TempConfigHome::new("apply_appends_association_to_config_file");
    temp.create_dir("github-cli");
    temp.create_bin("github");
    let config = PolicyConfig::default();
    let config_path = temp.root_path().join("config.toml");
    fs::write(&config_path, "fail_open = true\n").expect("write temp config");
    let options = ReconcileOptions::new(temp.path().to_path_buf(), &config)
        .with_binary_dirs(vec![temp.bin_path()])
        .with_config_path(config_path.clone())
        .apply();

    let plan = plan_reconcile(options).expect("reconcile should apply");
    let config_content = fs::read_to_string(config_path).expect("read temp config");

    assert_eq!(plan.actions[0].kind, ActionKind::Associated);
    assert!(config_content.contains("path = \""));
    assert!(config_content.contains("github-cli"));
    assert!(config_content.contains("owner = \"github\""));
    assert!(temp.path().join("github-cli").exists());
}

fn policy_with_owned_path(path: PathBuf, owner: &str) -> PolicyConfig {
    PolicyConfig {
        owned_paths: vec![OwnedPath {
            path,
            owner: owner.to_string(),
            allowed_subjects: Vec::new(),
        }],
        shared_paths: Vec::<SharedPath>::new(),
        sensitive_paths: Vec::<PathRule>::new(),
        dev_tools: Vec::new(),
        fail_open: true,
    }
}

struct TempConfigHome {
    root: PathBuf,
    path: PathBuf,
    bin_path: PathBuf,
}

impl TempConfigHome {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("config-guard-{name}-{}", std::process::id()));
        let path = root.join("config");
        let bin_path = root.join("bin");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&path).expect("create temp config home");
        fs::create_dir_all(&bin_path).expect("create temp bin dir");

        Self {
            root,
            path,
            bin_path,
        }
    }

    fn root_path(&self) -> &Path {
        &self.root
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn bin_path(&self) -> PathBuf {
        self.bin_path.clone()
    }

    fn create_dir(&self, name: &str) {
        fs::create_dir_all(self.path.join(name)).expect("create temp config dir");
    }

    fn create_bin(&self, name: &str) {
        fs::write(self.bin_path.join(name), "").expect("create temp binary");
    }
}

impl Drop for TempConfigHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
