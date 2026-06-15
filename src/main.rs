use anyhow::{Context, Result, bail};
use authd_protocol::collect_wayland_env;
use clap::{Parser, Subcommand};
use config_guard::fanotify::{AccessPolicy, Mode, ensure_path_exists};
use config_guard::learning::{
    AuditLearner, PathAlias, config_root_for_home_or_alias, config_symlink_aliases,
};
use config_guard::policy::{
    AccessKind, Decision, DecisionReason, Policy, PolicyConfig, ProcessSubject,
};
use config_guard::prompt::{AuthdPrompt, Prompt, PromptRequest};
use config_guard::reconcile::{ActionKind, ReconcileOptions, plan_reconcile};
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
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
        config: Option<PathBuf>,
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
    Reconcile {
        #[arg(long)]
        config_home: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        apply: bool,
    },
    TestPrompt {
        #[arg(long, default_value = "/home/osso/.local/bin/config-guard")]
        subject_exe: PathBuf,
        #[arg(long)]
        path: PathBuf,
        #[arg(long, value_parser = parse_decision_reason, default_value = "CrossOwnerRead")]
        reason: DecisionReason,
        #[arg(long, value_parser = parse_decision, default_value = "Allow")]
        default_decision: Decision,
    },
}

fn main() -> Result<ExitCode> {
    let args = Args::parse();

    match args.command {
        Command::Audit {
            path,
            config,
            learn_output,
        } => {
            run_audit(path, config, learn_output)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Guard {
            path,
            config,
            prompt_command,
            timeout_seconds,
        } => {
            run_guard(path, config, prompt_command, timeout_seconds)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Reconcile {
            config_home,
            config,
            apply,
        } => {
            run_reconcile(config_home, config, apply)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::TestPrompt {
            subject_exe,
            path,
            reason,
            default_decision,
        } => run_test_prompt(subject_exe, path, reason, default_decision),
    }
}

fn run_test_prompt(
    subject_exe: PathBuf,
    path: PathBuf,
    reason: DecisionReason,
    default_decision: Decision,
) -> Result<ExitCode> {
    let subject = ProcessSubject {
        executable: subject_exe,
        command: vec!["config-guard".to_string(), "test-prompt".to_string()],
        ancestors: Vec::new(),
    };
    let request = PromptRequest {
        subject: &subject,
        target_path: &path,
        reason,
        default_decision,
        env: collect_wayland_env(),
    };
    let decision = AuthdPrompt::new().ask(&request)?;

    println!("decision={decision:?}");
    Ok(match decision {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Deny | Decision::Prompt { .. } => ExitCode::from(1),
    })
}

fn run_audit(path: PathBuf, config: Option<PathBuf>, learn_output: Option<PathBuf>) -> Result<()> {
    ensure_path_exists(&path)?;
    let learner = learn_output.map(|output_path| AuditLearner::new(output_path, audit_home(&path)));
    let config_path = resolve_config_path(config);
    let policy_config = load_policy_config(config_path)?;
    let mut policy = StaticPolicy::new(policy_config, audit_home(&path));

    config_guard::fanotify::run(
        &path,
        Mode::Audit {
            learner,
            policy: Some(&mut policy),
        },
    )
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
    let policy_config = load_policy_config(config)?;
    let mut policy = StaticPolicy::new(policy_config, audit_home(&path));
    let timeout = Duration::from_secs(timeout_seconds);
    let prompt = build_prompt(prompt_command, timeout);

    config_guard::fanotify::run(
        &path,
        Mode::Guard {
            policy: &mut policy,
            prompt: prompt.as_ref(),
        },
    )
}

struct StaticPolicy {
    policy: Policy,
    home_dir: PathBuf,
    path_aliases: Vec<PathAlias>,
}

impl StaticPolicy {
    fn new(config: PolicyConfig, home_dir: PathBuf) -> Self {
        let path_aliases = config_symlink_aliases(&home_dir);

        Self {
            policy: Policy::new(config),
            home_dir,
            path_aliases,
        }
    }

    fn decision_path<'a>(&'a self, target_path: &'a Path) -> std::borrow::Cow<'a, Path> {
        match config_root_for_home_or_alias(target_path, &self.home_dir, &self.path_aliases) {
            Some(config_root) => std::borrow::Cow::Owned(config_root),
            None => std::borrow::Cow::Borrowed(target_path),
        }
    }
}

impl AccessPolicy for StaticPolicy {
    fn decide(
        &mut self,
        subject: &ProcessSubject,
        target_path: &Path,
        access: AccessKind,
    ) -> Result<Decision> {
        Ok(self
            .policy
            .decide(subject, self.decision_path(target_path).as_ref(), access))
    }
}

fn build_prompt(
    prompt_command: Option<PathBuf>,
    timeout: Duration,
) -> Box<dyn config_guard::prompt::Prompt> {
    match prompt_command {
        Some(command) => Box::new(config_guard::prompt::CommandPrompt::new(command, timeout)),
        None => Box::new(config_guard::prompt::AuthdPrompt::new()),
    }
}

fn load_policy_config(config: Option<PathBuf>) -> Result<PolicyConfig> {
    let Some(config) = resolve_config_path(config) else {
        return Ok(PolicyConfig::default());
    };

    let content = std::fs::read_to_string(&config)
        .with_context(|| format!("reading {}", config.display()))?;

    toml::from_str(&content).with_context(|| format!("parsing {}", config.display()))
}

fn resolve_config_path(config: Option<PathBuf>) -> Option<PathBuf> {
    config.or_else(default_config_path)
}

fn run_reconcile(
    config_home_arg: Option<PathBuf>,
    config: Option<PathBuf>,
    apply: bool,
) -> Result<()> {
    let config_path = resolve_config_path(config);
    let policy_config = load_policy_config(config_path.clone())?;
    let config_home = config_home_arg
        .or_else(config_home)
        .context("could not determine config home")?;
    let options = ReconcileOptions::new(config_home, &policy_config);
    let options = match config_path {
        Some(config_path) => options.with_config_path(config_path),
        None => options,
    };
    let options = if apply { options.apply() } else { options };
    let plan = plan_reconcile(options)?;

    for action in plan.actions {
        print_reconcile_action(&action);
    }

    Ok(())
}

fn print_reconcile_action(action: &config_guard::reconcile::ReconcileAction) {
    let label = match action.kind {
        ActionKind::KeepConfigured => "keep",
        ActionKind::AssociateCandidate => "associate-candidate",
        ActionKind::Associated => "associated",
        ActionKind::ArchiveCandidate => "archive-candidate",
        ActionKind::Archived => "archived",
    };

    match (&action.target, &action.owner, &action.binary) {
        (Some(target), _, _) => println!(
            "{label}\t{}\t{}\t{}",
            action.source.display(),
            target.display(),
            action.reason
        ),
        (None, Some(owner), Some(binary)) => println!(
            "{label}\t{}\towner={owner}\tbinary={}\t{}",
            action.source.display(),
            binary.display(),
            action.reason
        ),
        _ => println!("{label}\t{}\t{}", action.source.display(), action.reason),
    }
}

fn default_config_path() -> Option<PathBuf> {
    default_config_path_in(config_home()?)
}

fn default_config_path_in(config_home: PathBuf) -> Option<PathBuf> {
    let path = config_home.join("config-guard").join("config.toml");

    path.exists().then_some(path)
}

fn config_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
}

fn parse_decision_reason(value: &str) -> Result<DecisionReason> {
    match value {
        "CrossOwnerRead" => Ok(DecisionReason::CrossOwnerRead),
        "CrossOwnerWrite" => Ok(DecisionReason::CrossOwnerWrite),
        "SensitiveReadByDevTool" => Ok(DecisionReason::SensitiveReadByDevTool),
        "SensitiveWrite" => Ok(DecisionReason::SensitiveWrite),
        _ => bail!("unknown decision reason {value}"),
    }
}

fn parse_decision(value: &str) -> Result<Decision> {
    match value {
        "Allow" => Ok(Decision::Allow),
        "Deny" => Ok(Decision::Deny),
        _ => bail!("unknown decision {value}; expected Allow or Deny"),
    }
}

#[cfg(test)]
mod tests {
    use super::default_config_path_in;
    use std::fs;

    #[test]
    fn default_config_path_uses_config_guard_config_toml() {
        let config_home =
            std::env::temp_dir().join(format!("config-guard-test-{}", std::process::id()));
        let config_path = config_home.join("config-guard").join("config.toml");
        fs::create_dir_all(config_path.parent().expect("config path has parent"))
            .expect("create temp config dir");
        fs::write(&config_path, "").expect("write temp config");

        assert_eq!(
            default_config_path_in(config_home.clone()),
            Some(config_path)
        );

        let _ = fs::remove_dir_all(config_home);
    }
}
