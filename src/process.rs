use crate::policy::ProcessSubject;
use anyhow::Context;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
#[cfg(not(coverage))]
use std::fs;
#[cfg(not(coverage))]
use std::path::Path;
use std::path::PathBuf;

#[cfg(not(coverage))]
const WAYLAND_ENV_KEYS: &[&str] = &[
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "DBUS_SESSION_BUS_ADDRESS",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub executable: Option<PathBuf>,
    pub command: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub start_time_ticks: Option<u64>,
    pub ancestors: Vec<PathBuf>,
}

impl ProcessIdentity {
    pub fn subject(&self) -> ProcessSubject {
        let executable = self
            .executable
            .clone()
            .or_else(|| self.command.first().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("unknown"));

        ProcessSubject {
            executable,
            command: self.command.clone(),
            ancestors: self.ancestors.clone(),
        }
    }
}

pub fn inspect_process(pid: i32) -> Result<ProcessIdentity> {
    inspect_process_from_procfs(pid)
}

#[cfg(not(coverage))]
fn inspect_process_from_procfs(pid: i32) -> Result<ProcessIdentity> {
    let proc_dir = PathBuf::from("/proc").join(pid.to_string());
    let executable = read_exe_link(&proc_dir.join("exe"));
    let cwd = fs::read_link(proc_dir.join("cwd")).ok();
    let command = read_command(&proc_dir)?;
    let start_time_ticks = read_start_time_ticks(proc_dir.join("stat"))?;
    let ancestors = read_ancestor_executables(pid);

    Ok(ProcessIdentity {
        pid,
        executable,
        command,
        cwd,
        start_time_ticks,
        ancestors,
    })
}

#[cfg(coverage)]
fn inspect_process_from_procfs(pid: i32) -> Result<ProcessIdentity> {
    Err(anyhow!(
        "procfs inspection disabled in coverage build for pid {pid}"
    ))
}

/// Read a `/proc/<pid>/exe` link, trimming the kernel's `" (deleted)"` marker.
/// The kernel appends that suffix verbatim when the backing binary was replaced
/// (e.g. an in-place package upgrade) while the process keeps running; the
/// recorded path is otherwise the original launch path. Without trimming, a
/// long-running process whose binary was upgraded would present a subject like
/// `".../firefox (deleted)"` and fail to match its own owner rule.
#[cfg(not(coverage))]
fn read_exe_link(link: &Path) -> Option<PathBuf> {
    fs::read_link(link).ok().map(strip_deleted_suffix)
}

#[cfg(any(test, not(coverage)))]
fn strip_deleted_suffix(path: PathBuf) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    const DELETED_SUFFIX: &[u8] = b" (deleted)";
    match path.as_os_str().as_bytes().strip_suffix(DELETED_SUFFIX) {
        Some(trimmed) => PathBuf::from(std::ffi::OsStr::from_bytes(trimmed)),
        None => path,
    }
}

pub fn read_wayland_env(pid: i32) -> HashMap<String, String> {
    read_wayland_env_from_procfs(pid)
}

#[cfg(not(coverage))]
fn read_wayland_env_from_procfs(pid: i32) -> HashMap<String, String> {
    let path = PathBuf::from("/proc").join(pid.to_string()).join("environ");
    let Ok(bytes) = fs::read(path) else {
        return HashMap::new();
    };

    parse_environ(&bytes)
        .into_iter()
        .filter(|(key, _)| WAYLAND_ENV_KEYS.contains(&key.as_str()))
        .collect()
}

#[cfg(coverage)]
fn read_wayland_env_from_procfs(_pid: i32) -> HashMap<String, String> {
    HashMap::new()
}

pub fn parse_environ(bytes: &[u8]) -> HashMap<String, String> {
    bytes
        .split(|byte| *byte == 0)
        .filter_map(parse_env_entry)
        .collect()
}

fn parse_env_entry(entry: &[u8]) -> Option<(String, String)> {
    let separator = entry.iter().position(|byte| *byte == b'=')?;
    let key = String::from_utf8(entry[..separator].to_vec()).ok()?;
    let value = String::from_utf8(entry[separator + 1..].to_vec()).ok()?;

    Some((key, value))
}

pub fn parse_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .filter_map(|arg| String::from_utf8(arg.to_vec()).ok())
        .collect()
}

pub fn parse_start_time_ticks(stat: &str) -> Result<u64> {
    let fields_after_command = parse_stat_fields_after_command(stat)?;
    let start_time_index = 19;

    fields_after_command
        .get(start_time_index)
        .ok_or_else(|| anyhow!("proc stat is missing start time field"))?
        .parse()
        .context("proc stat start time is not an integer")
}

pub fn parse_parent_pid(stat: &str) -> Result<i32> {
    let fields_after_command = parse_stat_fields_after_command(stat)?;
    let parent_pid_index = 1;

    fields_after_command
        .get(parent_pid_index)
        .ok_or_else(|| anyhow!("proc stat is missing parent pid field"))?
        .parse()
        .context("proc stat parent pid is not an integer")
}

fn parse_stat_fields_after_command(stat: &str) -> Result<Vec<&str>> {
    let command_end = stat
        .rfind(") ")
        .ok_or_else(|| anyhow!("proc stat is missing closing command name"))?;

    Ok(stat[command_end + 2..].split_whitespace().collect())
}

#[cfg(not(coverage))]
fn read_cmdline(path: PathBuf) -> Result<Vec<String>> {
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;

    Ok(parse_cmdline(&bytes))
}

#[cfg(not(coverage))]
fn read_command(proc_dir: &Path) -> Result<Vec<String>> {
    let command = read_cmdline(proc_dir.join("cmdline"))?;
    if !command.is_empty() {
        return Ok(command);
    }

    let comm = fs::read_to_string(proc_dir.join("comm")).unwrap_or_default();
    Ok(parse_comm(&comm).into_iter().collect())
}

pub fn parse_comm(comm: &str) -> Option<String> {
    let name = comm.trim();
    if name.is_empty() {
        return None;
    }

    Some(name.to_string())
}

#[cfg(not(coverage))]
fn read_start_time_ticks(path: PathBuf) -> Result<Option<u64>> {
    let stat = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;

    Ok(Some(parse_start_time_ticks(&stat)?))
}

#[cfg(not(coverage))]
fn read_ancestor_executables(pid: i32) -> Vec<PathBuf> {
    let mut ancestors = Vec::new();
    let mut current_pid = pid;

    for _ in 0..32 {
        let proc_dir = PathBuf::from("/proc").join(current_pid.to_string());
        let Ok(stat) = fs::read_to_string(proc_dir.join("stat")) else {
            break;
        };
        let Ok(parent_pid) = parse_parent_pid(&stat) else {
            break;
        };
        if parent_pid <= 1 || parent_pid == current_pid {
            break;
        }

        let parent_proc_dir = PathBuf::from("/proc").join(parent_pid.to_string());
        if let Some(executable) = read_exe_link(&parent_proc_dir.join("exe")) {
            ancestors.push(executable);
        }
        current_pid = parent_pid;
    }

    ancestors
}

#[cfg(test)]
mod tests {
    #[cfg(coverage)]
    use super::{inspect_process, read_wayland_env};
    use super::{parse_environ, strip_deleted_suffix};
    use std::path::PathBuf;

    #[test]
    fn trims_kernel_deleted_marker() {
        assert_eq!(
            strip_deleted_suffix(PathBuf::from("/usr/lib/firefox/firefox (deleted)")),
            PathBuf::from("/usr/lib/firefox/firefox")
        );
    }

    #[test]
    fn leaves_normal_paths_untouched() {
        assert_eq!(
            strip_deleted_suffix(PathBuf::from("/usr/bin/arch")),
            PathBuf::from("/usr/bin/arch")
        );
    }

    #[test]
    fn only_trims_a_trailing_marker() {
        // A real path component that merely contains the word must survive.
        assert_eq!(
            strip_deleted_suffix(PathBuf::from("/opt/my (deleted) tool/bin")),
            PathBuf::from("/opt/my (deleted) tool/bin")
        );
    }

    #[test]
    fn parse_environ_keeps_valid_utf8_pairs() {
        let env = parse_environ(b"WAYLAND_DISPLAY=wayland-1\0NO_EQUALS\0BAD=\xff\0EMPTY=\0");

        assert_eq!(
            env.get("WAYLAND_DISPLAY").map(String::as_str),
            Some("wayland-1")
        );
        assert_eq!(env.get("EMPTY").map(String::as_str), Some(""));
        assert!(!env.contains_key("NO_EQUALS"));
        assert!(!env.contains_key("BAD"));
    }

    #[cfg(coverage)]
    #[test]
    fn coverage_procfs_stubs_do_not_touch_proc() {
        assert!(inspect_process(999_999).is_err());
        assert!(read_wayland_env(999_999).is_empty());
    }
}
