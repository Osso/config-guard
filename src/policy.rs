use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessSubject {
    pub executable: PathBuf,
    pub command: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessKind {
    Read,
    Write,
    DestructiveWrite,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
    Prompt {
        reason: DecisionReason,
        default: Box<Decision>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionReason {
    CrossOwnerRead,
    CrossOwnerWrite,
    SensitiveReadByDevTool,
    SensitiveWrite,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub owned_paths: Vec<OwnedPath>,
    #[serde(default)]
    pub shared_paths: Vec<SharedPath>,
    #[serde(default)]
    pub sensitive_paths: Vec<PathRule>,
    #[serde(default = "default_dev_tools")]
    pub dev_tools: Vec<String>,
    #[serde(default = "default_fail_open")]
    pub fail_open: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OwnedPath {
    pub path: PathBuf,
    pub owner: String,
    #[serde(default)]
    pub allowed_subjects: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SharedPath {
    pub path: PathBuf,
    #[serde(default)]
    pub allowed_subjects: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PathRule {
    pub path: PathBuf,
}

pub struct Policy {
    config: PolicyConfig,
}

impl Policy {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    pub fn decide(
        &self,
        subject: &ProcessSubject,
        target_path: impl AsRef<Path>,
        access: AccessKind,
    ) -> Decision {
        let target_path = target_path.as_ref();
        let subject_name = subject_name(subject);

        if self.shared_path_allows(subject, &subject_name, target_path) {
            return Decision::Allow;
        }

        let owner = self.owner_for(target_path);
        if owner.is_some_and(|owner| owner.allows(subject, &subject_name)) {
            return Decision::Allow;
        }

        if self.is_sensitive_dev_tool_access(subject, &subject_name, target_path) {
            return self.prompt_for_sensitive_access(access);
        }

        match owner {
            Some(_) => self.prompt_for_cross_owner_access(access),
            None => Decision::Allow,
        }
    }

    pub fn apply_prompt_answer(&self, answer: Decision) -> Decision {
        answer
    }

    pub fn default_decision(&self) -> Decision {
        if self.config.fail_open {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }

    fn owner_for(&self, target_path: &Path) -> Option<&OwnedPath> {
        self.config
            .owned_paths
            .iter()
            .find(|owner| target_path.starts_with(&owner.path))
    }

    fn shared_path_allows(
        &self,
        subject: &ProcessSubject,
        subject_name: &str,
        target_path: &Path,
    ) -> bool {
        self.config.shared_paths.iter().any(|shared| {
            target_path.starts_with(&shared.path)
                && subjects_allow(&shared.allowed_subjects, subject, subject_name)
        })
    }

    fn is_sensitive_dev_tool_access(
        &self,
        subject: &ProcessSubject,
        subject_name: &str,
        target_path: &Path,
    ) -> bool {
        subjects_allow(&self.config.dev_tools, subject, subject_name)
            && self
                .config
                .sensitive_paths
                .iter()
                .any(|rule| target_path.starts_with(&rule.path))
    }

    fn prompt_for_sensitive_access(&self, access: AccessKind) -> Decision {
        let reason = match access {
            AccessKind::Read => DecisionReason::SensitiveReadByDevTool,
            AccessKind::Write | AccessKind::DestructiveWrite => DecisionReason::SensitiveWrite,
        };

        self.prompt(reason)
    }

    fn prompt_for_cross_owner_access(&self, access: AccessKind) -> Decision {
        let reason = match access {
            AccessKind::Read => DecisionReason::CrossOwnerRead,
            AccessKind::Write | AccessKind::DestructiveWrite => DecisionReason::CrossOwnerWrite,
        };

        self.prompt(reason)
    }

    fn prompt(&self, reason: DecisionReason) -> Decision {
        Decision::Prompt {
            reason,
            default: Box::new(self.default_decision()),
        }
    }
}

impl OwnedPath {
    fn allows(&self, subject: &ProcessSubject, subject_name: &str) -> bool {
        self.owner == subject_name || subjects_allow(&self.allowed_subjects, subject, subject_name)
    }
}

fn subjects_allow(
    allowed_subjects: &[String],
    subject: &ProcessSubject,
    subject_name: &str,
) -> bool {
    allowed_subjects
        .iter()
        .any(|allowed| subject_matches(allowed, subject, subject_name))
}

fn subject_matches(allowed: &str, subject: &ProcessSubject, subject_name: &str) -> bool {
    if allowed == "*" || allowed == subject_name {
        return true;
    }

    if let Some(prefix) = allowed.strip_prefix("exe-prefix:") {
        return subject.executable.starts_with(prefix);
    }

    if let Some(path) = allowed.strip_prefix("exe:") {
        return subject.executable == Path::new(path);
    }

    false
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            owned_paths: default_owned_paths(),
            shared_paths: default_shared_paths(),
            sensitive_paths: default_sensitive_paths(),
            dev_tools: default_dev_tools(),
            fail_open: default_fail_open(),
        }
    }
}

pub fn subject_name(subject: &ProcessSubject) -> String {
    subject
        .executable
        .file_name()
        .and_then(|name| name.to_str())
        .or_else(|| subject.command.first().map(String::as_str))
        .unwrap_or("unknown")
        .to_string()
}

pub fn executable_label(executable: &Path) -> String {
    if executable.starts_with("/home/osso/.local/share/claude/versions") {
        return format!("claude:{}", executable.display());
    }

    executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn default_fail_open() -> bool {
    true
}

fn default_dev_tools() -> Vec<String> {
    ["codex", "claude", "cursor", "node", "python", "python3"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_owned_paths() -> Vec<OwnedPath> {
    [
        ("kitty", ".config/kitty"),
        ("nvim", ".config/nvim"),
        ("gh", ".config/gh"),
        ("slack", ".config/Slack"),
        ("firefox", ".mozilla/firefox"),
        ("chromium", ".config/chromium"),
    ]
    .into_iter()
    .map(|(owner, suffix)| OwnedPath {
        path: home_relative_path(suffix),
        owner: owner.to_string(),
        allowed_subjects: Vec::new(),
    })
    .collect()
}

fn default_shared_paths() -> Vec<SharedPath> {
    [
        ".config/mimeapps.list",
        ".config/user-dirs.dirs",
        ".config/gtk-3.0",
        ".config/gtk-4.0",
        ".config/fontconfig",
    ]
    .into_iter()
    .map(|suffix| SharedPath {
        path: home_relative_path(suffix),
        allowed_subjects: default_shared_subjects(),
    })
    .collect()
}

fn default_sensitive_paths() -> Vec<PathRule> {
    [
        ".config/gh",
        ".config/gcloud",
        ".config/hass",
        ".config/sentry",
        ".ssh",
        ".mozilla/firefox",
    ]
    .into_iter()
    .map(|suffix| PathRule {
        path: home_relative_path(suffix),
    })
    .collect()
}

fn default_shared_subjects() -> Vec<String> {
    [
        "gtk-launch",
        "xdg-open",
        "xdg-desktop-portal",
        "xdg-desktop-portal-gtk",
        "xdg-desktop-portal-kde",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn home_relative_path(suffix: &str) -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/osso"))
        .join(suffix)
}
