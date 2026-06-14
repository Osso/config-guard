use crate::policy::{AccessKind, ProcessSubject, subject_name};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct AuditLearner {
    output_path: PathBuf,
    home_dir: PathBuf,
    observations: BTreeMap<ObservationKey, u64>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ObservationKey {
    subject: String,
    config_root: PathBuf,
    access: AccessLabel,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessLabel {
    Read,
    Write,
    DestructiveWrite,
}

#[derive(Serialize)]
struct LearnedConfig {
    owned_paths: Vec<LearnedOwnedPath>,
    observations: Vec<LearnedObservation>,
}

#[derive(Serialize)]
struct LearnedOwnedPath {
    path: PathBuf,
    owner: String,
    allowed_subjects: Vec<String>,
}

#[derive(Serialize)]
struct LearnedObservation {
    subject: String,
    config_root: PathBuf,
    access: AccessLabel,
    count: u64,
}

impl AuditLearner {
    pub fn new(output_path: PathBuf, home_dir: PathBuf) -> Self {
        Self {
            output_path,
            home_dir,
            observations: BTreeMap::new(),
        }
    }

    pub fn observe(
        &mut self,
        subject: &ProcessSubject,
        target_path: &Path,
        access: AccessKind,
    ) -> Result<()> {
        let Some(config_root) = config_root_for_home(target_path, &self.home_dir) else {
            return Ok(());
        };

        let key = ObservationKey {
            subject: subject_name(subject),
            config_root,
            access: access.into(),
        };
        *self.observations.entry(key).or_default() += 1;

        self.write_output()
    }

    fn write_output(&self) -> Result<()> {
        let learned = LearnedConfig {
            owned_paths: self.candidate_owned_paths(),
            observations: self.learned_observations(),
        };
        let content = toml::to_string_pretty(&learned).context("serializing learned config")?;

        std::fs::write(&self.output_path, content)
            .with_context(|| format!("writing {}", self.output_path.display()))
    }

    fn candidate_owned_paths(&self) -> Vec<LearnedOwnedPath> {
        subjects_by_root(&self.observations)
            .into_iter()
            .filter_map(candidate_owner_for_root)
            .collect()
    }

    fn learned_observations(&self) -> Vec<LearnedObservation> {
        self.observations
            .iter()
            .map(|(key, count)| LearnedObservation {
                subject: key.subject.clone(),
                config_root: key.config_root.clone(),
                access: key.access,
                count: *count,
            })
            .collect()
    }
}

impl From<AccessKind> for AccessLabel {
    fn from(access: AccessKind) -> Self {
        match access {
            AccessKind::Read => Self::Read,
            AccessKind::Write => Self::Write,
            AccessKind::DestructiveWrite => Self::DestructiveWrite,
        }
    }
}

pub fn config_root_for(path: &Path) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;

    config_root_for_home(path, &home)
}

pub fn config_root_for_home(path: &Path, home: &Path) -> Option<PathBuf> {
    let relative_path = path.strip_prefix(home).ok()?;
    let mut components = relative_path.components();
    let first = components.next()?.as_os_str();

    match first.to_str()? {
        ".config" => config_subdir_root(home, components.next()?.as_os_str().to_str()?),
        ".ssh" => Some(home.join(".ssh")),
        ".mozilla" => Some(home.join(".mozilla")),
        _ => None,
    }
}

fn config_subdir_root(home: &Path, subdir: &str) -> Option<PathBuf> {
    if subdir.is_empty() {
        return None;
    }

    Some(home.join(".config").join(subdir))
}

fn subjects_by_root(
    observations: &BTreeMap<ObservationKey, u64>,
) -> BTreeMap<PathBuf, BTreeSet<String>> {
    let mut subjects = BTreeMap::new();

    for key in observations.keys() {
        subjects
            .entry(key.config_root.clone())
            .or_insert_with(BTreeSet::new)
            .insert(key.subject.clone());
    }

    subjects
}

fn candidate_owner_for_root(
    (path, subjects): (PathBuf, BTreeSet<String>),
) -> Option<LearnedOwnedPath> {
    if subjects.len() != 1 {
        return None;
    }

    Some(LearnedOwnedPath {
        path,
        owner: subjects.into_iter().next()?,
        allowed_subjects: Vec::new(),
    })
}
