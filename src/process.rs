use crate::policy::ProcessSubject;
use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub executable: Option<PathBuf>,
    pub command: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub start_time_ticks: Option<u64>,
}

impl ProcessIdentity {
    pub fn subject(&self) -> ProcessSubject {
        ProcessSubject {
            executable: self
                .executable
                .clone()
                .unwrap_or_else(|| PathBuf::from("unknown")),
            command: self.command.clone(),
        }
    }
}

pub fn inspect_process(pid: i32) -> Result<ProcessIdentity> {
    let proc_dir = PathBuf::from("/proc").join(pid.to_string());
    let executable = fs::read_link(proc_dir.join("exe")).ok();
    let cwd = fs::read_link(proc_dir.join("cwd")).ok();
    let command = read_cmdline(proc_dir.join("cmdline"))?;
    let start_time_ticks = read_start_time_ticks(proc_dir.join("stat"))?;

    Ok(ProcessIdentity {
        pid,
        executable,
        command,
        cwd,
        start_time_ticks,
    })
}

pub fn parse_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .filter_map(|arg| String::from_utf8(arg.to_vec()).ok())
        .collect()
}

pub fn parse_start_time_ticks(stat: &str) -> Result<u64> {
    let command_end = stat
        .rfind(") ")
        .ok_or_else(|| anyhow!("proc stat is missing closing command name"))?;
    let fields_after_command: Vec<&str> = stat[command_end + 2..].split_whitespace().collect();
    let start_time_index = 19;

    fields_after_command
        .get(start_time_index)
        .ok_or_else(|| anyhow!("proc stat is missing start time field"))?
        .parse()
        .context("proc stat start time is not an integer")
}

fn read_cmdline(path: PathBuf) -> Result<Vec<String>> {
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;

    Ok(parse_cmdline(&bytes))
}

fn read_start_time_ticks(path: PathBuf) -> Result<Option<u64>> {
    let stat = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;

    Ok(Some(parse_start_time_ticks(&stat)?))
}
