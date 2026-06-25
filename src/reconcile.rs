use crate::policy::PolicyConfig;
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionKind {
    KeepConfigured,
    AssociateCandidate,
    Associated,
    ArchiveCandidate,
    Archived,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconcileAction {
    pub kind: ActionKind,
    pub source: PathBuf,
    pub target: Option<PathBuf>,
    pub owner: Option<String>,
    pub binary: Option<PathBuf>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconcilePlan {
    pub actions: Vec<ReconcileAction>,
}

pub struct ReconcileOptions<'a> {
    config_home: PathBuf,
    archive_dir: PathBuf,
    policy_config: &'a PolicyConfig,
    binary_dirs: Vec<PathBuf>,
    config_path: Option<PathBuf>,
    apply: bool,
}

impl<'a> ReconcileOptions<'a> {
    pub fn new(config_home: PathBuf, policy_config: &'a PolicyConfig) -> Self {
        let archive_dir = config_home.join("archive");

        Self {
            config_home,
            archive_dir,
            policy_config,
            binary_dirs: path_binary_dirs(),
            config_path: None,
            apply: false,
        }
    }

    pub fn with_binary_dirs(mut self, binary_dirs: Vec<PathBuf>) -> Self {
        self.binary_dirs = binary_dirs;
        self
    }

    pub fn with_config_path(mut self, config_path: PathBuf) -> Self {
        self.config_path = Some(config_path);
        self
    }

    pub fn apply(mut self) -> Self {
        self.apply = true;
        self
    }
}

pub fn plan_reconcile(options: ReconcileOptions<'_>) -> Result<ReconcilePlan> {
    let mut actions = Vec::new();

    for entry in config_home_entries(&options.config_home)? {
        if is_archive_dir(&entry, &options.archive_dir) {
            continue;
        }

        if !entry.is_dir() {
            continue;
        }

        let action = plan_entry(&entry, &options)?;
        actions.push(action);
    }

    Ok(ReconcilePlan { actions })
}

fn config_home_entries(config_home: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = Vec::new();

    for entry in fs::read_dir(config_home)
        .with_context(|| format!("reading config home {}", config_home.display()))?
    {
        let entry =
            entry.with_context(|| format!("reading entry under {}", config_home.display()))?;
        entries.push(entry.path());
    }

    entries.sort();
    Ok(entries)
}

fn plan_entry(entry: &Path, options: &ReconcileOptions<'_>) -> Result<ReconcileAction> {
    if policy_covers_path(options.policy_config, entry) {
        return Ok(keep_configured_action(entry));
    }

    if let Some(match_result) = find_associated_binary(entry, &options.binary_dirs) {
        return association_action(entry, options, match_result);
    }

    archive_action(entry, options)
}

fn keep_configured_action(entry: &Path) -> ReconcileAction {
    ReconcileAction {
        kind: ActionKind::KeepConfigured,
        source: entry.to_path_buf(),
        target: None,
        owner: None,
        binary: None,
        reason: "covered by policy config".to_string(),
    }
}

fn association_action(
    entry: &Path,
    options: &ReconcileOptions<'_>,
    match_result: BinaryMatch,
) -> Result<ReconcileAction> {
    if options.apply {
        append_owned_path(options.config_path.as_deref(), entry, &match_result.owner)?;
    }

    Ok(ReconcileAction {
        kind: applied_kind(
            options.apply,
            ActionKind::Associated,
            ActionKind::AssociateCandidate,
        ),
        source: entry.to_path_buf(),
        target: None,
        owner: Some(match_result.owner),
        binary: Some(match_result.binary),
        reason: "associated binary found".to_string(),
    })
}

fn archive_action(entry: &Path, options: &ReconcileOptions<'_>) -> Result<ReconcileAction> {
    let target = archive_target(entry, &options.archive_dir);

    if options.apply {
        move_to_archive(entry, &target)?;
    }

    Ok(ReconcileAction {
        kind: applied_kind(
            options.apply,
            ActionKind::Archived,
            ActionKind::ArchiveCandidate,
        ),
        source: entry.to_path_buf(),
        target: Some(target),
        owner: None,
        binary: None,
        reason: "associated binary not found".to_string(),
    })
}

fn applied_kind(apply: bool, applied: ActionKind, dry_run: ActionKind) -> ActionKind {
    if apply { applied } else { dry_run }
}

fn policy_covers_path(config: &PolicyConfig, path: &Path) -> bool {
    config
        .owned_paths
        .iter()
        .any(|rule| paths_overlap(path, &rule.path))
        || config
            .shared_paths
            .iter()
            .any(|rule| paths_overlap(path, &rule.path))
        || config
            .sensitive_paths
            .iter()
            .any(|rule| paths_overlap(path, &rule.path))
}

fn paths_overlap(entry: &Path, rule: &Path) -> bool {
    entry.starts_with(rule) || rule.starts_with(entry)
}

fn is_archive_dir(entry: &Path, archive_dir: &Path) -> bool {
    entry == archive_dir
}

fn archive_target(entry: &Path, archive_dir: &Path) -> PathBuf {
    let name = entry
        .file_name()
        .map(|name| name.to_owned())
        .unwrap_or_else(|| "unknown".into());
    let target = archive_dir.join(name);

    if !target.exists() {
        return target;
    }

    archive_dir.join(format!(
        "{}-{}",
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown"),
        timestamp_suffix()
    ))
}

fn move_to_archive(entry: &Path, target: &Path) -> Result<()> {
    let parent = target
        .parent()
        .context("archive target should have parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    fs::rename(entry, target)
        .with_context(|| format!("moving {} to {}", entry.display(), target.display()))
}

struct BinaryMatch {
    owner: String,
    binary: PathBuf,
}

fn find_associated_binary(entry: &Path, binary_dirs: &[PathBuf]) -> Option<BinaryMatch> {
    for owner in owner_names_for_entry(entry)? {
        let binary = binary_dirs
            .iter()
            .map(|dir| dir.join(&owner))
            .find(|candidate| candidate.exists());

        if let Some(binary) = binary {
            return Some(BinaryMatch { owner, binary });
        }
    }

    None
}

fn owner_names_for_entry(entry: &Path) -> Option<Vec<String>> {
    let name = entry.file_name()?.to_str()?;
    let base_name = name.trim_start_matches(['.', '@']);
    let without_cli = base_name.strip_suffix("-cli").unwrap_or(base_name);
    let candidates = [
        without_cli.to_string(),
        without_cli.to_ascii_lowercase(),
        without_cli.replace(' ', "-").to_ascii_lowercase(),
        without_cli.replace(' ', "").to_ascii_lowercase(),
    ];
    let mut owners = Vec::new();
    let mut seen_owners = BTreeSet::new();

    for candidate in candidates {
        if !candidate.is_empty() && seen_owners.insert(candidate.clone()) {
            owners.push(candidate);
        }
    }

    if owners.is_empty() {
        return None;
    }

    Some(owners)
}

fn path_binary_dirs() -> Vec<PathBuf> {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default()
}

fn append_owned_path(config_path: Option<&Path>, path: &Path, owner: &str) -> Result<()> {
    let config_path = config_path.context("apply association requires a config path")?;
    let rule = format!(
        "\n[[owned_paths]]\npath = \"{}\"\nowner = \"{}\"\nallowed_subjects = []\n",
        path.display(),
        owner
    );

    let mut content = fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    content.push_str(&rule);
    fs::write(config_path, content).with_context(|| format!("writing {}", config_path.display()))
}

fn timestamp_suffix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AccessKind, OwnedPath, PathRule, SharedPath};

    #[test]
    fn helper_functions_cover_policy_and_action_branches() {
        let entry = PathBuf::from("/home/osso/.config/tool");
        let config = PolicyConfig {
            owned_paths: vec![OwnedPath {
                path: entry.clone(),
                owner: "tool".to_string(),
                allowed_subjects: Vec::new(),
            }],
            shared_paths: vec![SharedPath {
                path: PathBuf::from("/home/osso/.config/shared"),
                path_prefix: false,
                allowed_subjects: Vec::new(),
                access: vec![AccessKind::Read],
            }],
            sensitive_paths: vec![PathRule {
                path: PathBuf::from("/home/osso/.config/secret"),
            }],
            dev_tools: Vec::new(),
            fail_open: true,
        };

        assert_eq!(
            keep_configured_action(&entry).kind,
            ActionKind::KeepConfigured
        );
        assert_eq!(
            applied_kind(true, ActionKind::Archived, ActionKind::ArchiveCandidate),
            ActionKind::Archived
        );
        assert_eq!(
            applied_kind(false, ActionKind::Archived, ActionKind::ArchiveCandidate),
            ActionKind::ArchiveCandidate
        );
        assert!(policy_covers_path(&config, &entry));
        assert!(policy_covers_path(
            &config,
            Path::new("/home/osso/.config/shared")
        ));
        assert!(policy_covers_path(
            &config,
            Path::new("/home/osso/.config/secret/token")
        ));
        assert!(paths_overlap(&entry, Path::new("/home/osso/.config")));
        assert!(is_archive_dir(
            Path::new("/home/osso/.config/archive"),
            Path::new("/home/osso/.config/archive")
        ));
    }

    #[test]
    fn helper_functions_cover_archive_and_owner_branches() {
        let archive_dir = std::env::temp_dir().join(format!(
            "config-guard-reconcile-unit-{}",
            std::process::id()
        ));
        let entry = archive_dir.join("source");
        fs::create_dir_all(&entry).expect("create source dir");
        fs::create_dir_all(archive_dir.join("archive/source")).expect("create collision");

        let target = archive_target(&entry, &archive_dir.join("archive"));
        assert!(
            target
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("source-"))
        );
        assert_eq!(
            owner_names_for_entry(Path::new("@Vendor Tool-cli")).unwrap(),
            vec!["Vendor Tool", "vendor tool", "vendor-tool", "vendortool"]
        );
        assert!(owner_names_for_entry(Path::new("")).is_none());
        assert!(!path_binary_dirs().is_empty() || std::env::var_os("PATH").is_none());
        assert!(timestamp_suffix() > 0);

        let _ = fs::remove_dir_all(archive_dir);
    }

    #[test]
    fn helper_functions_cover_binary_and_apply_errors() {
        let root = std::env::temp_dir().join(format!(
            "config-guard-reconcile-binary-unit-{}",
            std::process::id()
        ));
        let bin = root.join("bin");
        let entry = root.join("config/new-tool");
        fs::create_dir_all(&entry).expect("create config dir");
        fs::create_dir_all(&bin).expect("create bin dir");
        fs::write(bin.join("new-tool"), "").expect("create bin");

        let found = find_associated_binary(&entry, &[bin]).expect("binary match");
        assert_eq!(found.owner, "new-tool");
        assert!(append_owned_path(None, &entry, "new-tool").is_err());

        let _ = fs::remove_dir_all(root);
    }
}
