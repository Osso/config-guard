use super::is_excluded;
#[cfg(not(coverage))]
use super::{Mode, audit_watch_mask, guard_watch_mask};
use anyhow::{Context, Result};
#[cfg(not(coverage))]
use libc::{AT_FDCWD, FAN_MARK_ADD, FAN_MARK_MOUNT};
#[cfg(not(coverage))]
use std::ffi::CString;
use std::fs;
#[cfg(not(coverage))]
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

#[cfg(not(coverage))]
pub(super) fn install(
    fanotify_fd: RawFd,
    paths: &[PathBuf],
    excluded_paths: &[PathBuf],
    mode: &Mode<'_>,
) -> Result<String> {
    let watch_list = paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");

    match mode {
        Mode::Audit { .. } => {
            mark_audit_mounts(fanotify_fd, paths)?;
            Ok(format!(
                "watching {watch_list} with mount notifications ({} root requests installed)",
                paths.len()
            ))
        }
        Mode::Guard { .. } => {
            let marked_paths = mark_path_trees(fanotify_fd, paths, excluded_paths)?;
            Ok(format!(
                "watching {watch_list} ({marked_paths} directories marked)"
            ))
        }
    }
}

#[cfg(not(coverage))]
fn mark_audit_mounts(fanotify_fd: RawFd, paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        mark_path(
            fanotify_fd,
            path,
            FAN_MARK_ADD | FAN_MARK_MOUNT,
            audit_watch_mask(),
        )
        .with_context(|| format!("marking mount containing {}", path.display()))?;
    }

    Ok(())
}

#[cfg(not(coverage))]
fn mark_guard_path(fanotify_fd: RawFd, path: &Path) -> Result<()> {
    mark_path(fanotify_fd, path, FAN_MARK_ADD, guard_watch_mask())
}

#[cfg(not(coverage))]
fn mark_path(fanotify_fd: RawFd, path: &Path, flags: u32, mask: u64) -> Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .context("watch path contains an interior nul byte")?;
    let result = unsafe { libc::fanotify_mark(fanotify_fd, flags, mask, AT_FDCWD, path.as_ptr()) };

    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("fanotify_mark failed");
    }

    Ok(())
}

#[cfg(not(coverage))]
fn mark_path_trees(
    fanotify_fd: RawFd,
    paths: &[PathBuf],
    excluded_paths: &[PathBuf],
) -> Result<usize> {
    paths
        .iter()
        .filter(|path| !is_excluded(path, excluded_paths))
        .map(|path| mark_path_tree(fanotify_fd, path, excluded_paths))
        .try_fold(0, |marked_paths, result| {
            result.map(|path_count| marked_paths + path_count)
        })
}

#[cfg(not(coverage))]
fn mark_path_tree(fanotify_fd: RawFd, path: &Path, excluded_paths: &[PathBuf]) -> Result<usize> {
    if !path.is_dir() {
        mark_guard_path(fanotify_fd, path)?;
        return Ok(1);
    }

    let mut marked_paths = 0;
    let mut pending_paths = vec![path.to_path_buf()];

    while let Some(current_path) = pending_paths.pop() {
        mark_guard_path(fanotify_fd, &current_path)
            .with_context(|| format!("marking {}", current_path.display()))?;
        marked_paths += 1;

        for child_path in child_directories(&current_path, excluded_paths)? {
            pending_paths.push(child_path);
        }
    }

    Ok(marked_paths)
}

pub(super) fn child_directories(path: &Path, excluded_paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut directories = Vec::new();

    for entry in fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
        let entry = entry.with_context(|| format!("reading entry under {}", path.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading file type for {}", entry.path().display()))?;
        let child_path = entry.path();

        if file_type.is_dir() && !is_excluded(&child_path, excluded_paths) {
            directories.push(child_path);
        }
    }

    Ok(directories)
}
