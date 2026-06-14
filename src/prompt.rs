use crate::policy::{Decision, DecisionReason, ProcessSubject};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

pub struct PromptRequest<'a> {
    pub subject: &'a ProcessSubject,
    pub target_path: &'a Path,
    pub reason: DecisionReason,
    pub default_decision: Decision,
}

pub trait Prompt {
    fn ask(&self, request: &PromptRequest<'_>) -> Result<Decision>;
}

pub struct NonInteractivePrompt {
    timeout: Duration,
}

impl NonInteractivePrompt {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Prompt for NonInteractivePrompt {
    fn ask(&self, request: &PromptRequest<'_>) -> Result<Decision> {
        thread::sleep(self.timeout.min(Duration::from_millis(1)));

        Ok(request.default_decision.clone())
    }
}

pub struct CommandPrompt {
    command: PathBuf,
    timeout: Duration,
}

impl CommandPrompt {
    pub fn new(command: PathBuf, timeout: Duration) -> Self {
        Self { command, timeout }
    }
}

impl Prompt for CommandPrompt {
    fn ask(&self, request: &PromptRequest<'_>) -> Result<Decision> {
        let mut child = Command::new(&self.command)
            .arg("--subject")
            .arg(display_subject(request.subject))
            .arg("--path")
            .arg(request.target_path)
            .arg("--reason")
            .arg(format!("{:?}", request.reason))
            .spawn()
            .with_context(|| format!("starting prompt command {}", self.command.display()))?;

        wait_for_prompt(&mut child, self.timeout, &request.default_decision)
    }
}

fn wait_for_prompt(
    child: &mut std::process::Child,
    timeout: Duration,
    default_decision: &Decision,
) -> Result<Decision> {
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(decision_from_status(status, default_decision));
        }

        thread::sleep(Duration::from_millis(50));
    }

    let _ = child.kill();
    Ok(default_decision.clone())
}

fn decision_from_status(status: std::process::ExitStatus, default_decision: &Decision) -> Decision {
    match status.code() {
        Some(0) => Decision::Allow,
        Some(1) => Decision::Deny,
        _ => default_decision.clone(),
    }
}

fn display_subject(subject: &ProcessSubject) -> String {
    subject
        .executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}
