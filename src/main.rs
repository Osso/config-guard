use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config_guard::fanotify::{Mode, ensure_path_exists};
use config_guard::learning::AuditLearner;
use config_guard::policy::{Policy, PolicyConfig};
use config_guard::prompt::NonInteractivePrompt;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(version, about = "Interactive guard for sensitive config file access")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Audit {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        learn_output: Option<PathBuf>,
    },
    Guard {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        prompt_command: Option<PathBuf>,
        #[arg(long, default_value_t = 10)]
        timeout_seconds: u64,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Audit { path, learn_output } => run_audit(path, learn_output),
        Command::Guard {
            path,
            config,
            prompt_command,
            timeout_seconds,
        } => run_guard(path, config, prompt_command, timeout_seconds),
    }
}

fn run_audit(path: PathBuf, learn_output: Option<PathBuf>) -> Result<()> {
    ensure_path_exists(&path)?;
    let learner = learn_output.map(|output_path| AuditLearner::new(output_path, audit_home(&path)));

    config_guard::fanotify::run(&path, Mode::Audit { learner })
}

fn audit_home(path: &std::path::Path) -> PathBuf {
    path.parent()
        .filter(|_| path.file_name().is_some_and(|name| name == ".config"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/home/osso"))
}

fn run_guard(
    path: PathBuf,
    config: Option<PathBuf>,
    prompt_command: Option<PathBuf>,
    timeout_seconds: u64,
) -> Result<()> {
    ensure_path_exists(&path)?;
    let policy = Policy::new(load_policy_config(config)?);
    let timeout = Duration::from_secs(timeout_seconds);
    let prompt = build_prompt(prompt_command, timeout);

    config_guard::fanotify::run(
        &path,
        Mode::Guard {
            policy: &policy,
            prompt: prompt.as_ref(),
        },
    )
}

fn build_prompt(
    prompt_command: Option<PathBuf>,
    timeout: Duration,
) -> Box<dyn config_guard::prompt::Prompt> {
    match prompt_command {
        Some(command) => Box::new(config_guard::prompt::CommandPrompt::new(command, timeout)),
        None => Box::new(NonInteractivePrompt::new(timeout)),
    }
}

fn load_policy_config(config: Option<PathBuf>) -> Result<PolicyConfig> {
    let Some(config) = config else {
        return Ok(PolicyConfig::default());
    };

    let content = std::fs::read_to_string(&config)
        .with_context(|| format!("reading {}", config.display()))?;

    toml::from_str(&content).with_context(|| format!("parsing {}", config.display()))
}
