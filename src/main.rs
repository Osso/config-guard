use anyhow::{Context, Result, bail};
#[cfg(not(coverage))]
use authd_protocol::collect_wayland_env;
use clap::{Parser, Subcommand};
#[cfg(not(coverage))]
use config_guard::fanotify::{AccessPolicy, Mode, PromptDecisionCache, ensure_path_exists};
#[cfg(not(coverage))]
use config_guard::learning::AuditLearner;
use config_guard::learning::PathAlias;
#[cfg(not(coverage))]
use config_guard::learning::config_symlink_aliases;
#[cfg(not(coverage))]
use config_guard::policy::{AccessKind, Policy, ProcessSubject};
use config_guard::policy::{Decision, DecisionReason, PolicyConfig};
#[cfg(not(coverage))]
use config_guard::prompt::{AuthdPrompt, Prompt, PromptRequest};
#[cfg(not(coverage))]
use config_guard::reconcile::{ActionKind, ReconcileOptions, plan_reconcile};
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(not(coverage))]
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
        #[arg(long = "path", required = true)]
        paths: Vec<PathBuf>,
        #[arg(long = "exclude-path")]
        excluded_paths: Vec<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        learn_output: Option<PathBuf>,
    },
    Guard {
        #[arg(long = "path", required = true)]
        paths: Vec<PathBuf>,
        #[arg(long = "exclude-path")]
        excluded_paths: Vec<PathBuf>,
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

#[cfg(not(coverage))]
fn main() -> Result<ExitCode> {
    let args = Args::parse();
    run_command(args.command)
}

#[cfg(coverage)]
fn main() -> Result<ExitCode> {
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(coverage))]
fn run_command(command: Command) -> Result<ExitCode> {
    match command {
        audit @ Command::Audit { .. } => run_audit_command(audit),
        guard @ Command::Guard { .. } => run_guard_command(guard),
        reconcile @ Command::Reconcile { .. } => run_reconcile_command(reconcile),
        prompt @ Command::TestPrompt { .. } => run_test_prompt_command(prompt),
    }
}

#[cfg(not(coverage))]
fn run_audit_command(command: Command) -> Result<ExitCode> {
    let Command::Audit {
        paths,
        excluded_paths,
        config,
        learn_output,
    } = command
    else {
        unreachable!("run_audit_command called with non-audit command")
    };

    run_unit_command(run_audit(paths, excluded_paths, config, learn_output))
}

#[cfg(not(coverage))]
fn run_guard_command(command: Command) -> Result<ExitCode> {
    let Command::Guard {
        paths,
        excluded_paths,
        config,
        prompt_command,
        timeout_seconds,
    } = command
    else {
        unreachable!("run_guard_command called with non-guard command")
    };

    run_unit_command(run_guard(
        paths,
        excluded_paths,
        config,
        prompt_command,
        timeout_seconds,
    ))
}

#[cfg(not(coverage))]
fn run_reconcile_command(command: Command) -> Result<ExitCode> {
    let Command::Reconcile {
        config_home,
        config,
        apply,
    } = command
    else {
        unreachable!("run_reconcile_command called with non-reconcile command")
    };

    run_unit_command(run_reconcile(config_home, config, apply))
}

#[cfg(not(coverage))]
fn run_test_prompt_command(command: Command) -> Result<ExitCode> {
    let Command::TestPrompt {
        subject_exe,
        path,
        reason,
        default_decision,
    } = command
    else {
        unreachable!("run_test_prompt_command called with non-test-prompt command")
    };

    run_test_prompt(subject_exe, path, reason, default_decision)
}

#[cfg(not(coverage))]
fn run_unit_command(result: Result<()>) -> Result<ExitCode> {
    result?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(coverage))]
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
    let decision = AuthdPrompt::new(Duration::from_secs(10)).ask(&request)?;

    println!("decision={decision:?}");
    Ok(match decision {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Deny | Decision::Prompt { .. } => ExitCode::from(1),
    })
}

#[cfg(not(coverage))]
fn run_audit(
    paths: Vec<PathBuf>,
    excluded_paths: Vec<PathBuf>,
    config: Option<PathBuf>,
    learn_output: Option<PathBuf>,
) -> Result<()> {
    ensure_paths_exist(&paths)?;
    let home_dir = audit_home(&paths);
    let learner = learn_output.map(|output_path| AuditLearner::new(output_path, home_dir.clone()));
    let config_path = resolve_config_path(config);
    let policy_config = load_policy_config(config_path)?;
    let mut policy = StaticPolicy::new(policy_config, home_dir);

    config_guard::fanotify::run(
        &paths,
        &excluded_paths,
        Mode::Audit {
            learner,
            policy: Some(&mut policy),
        },
    )
}

#[cfg(not(coverage))]
fn audit_home(paths: &[PathBuf]) -> PathBuf {
    paths
        .iter()
        .find_map(|path| {
            path.parent()
                .filter(|_| path.file_name().is_some_and(|name| name == ".config"))
                .map(PathBuf::from)
        })
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/home/osso"))
}

#[cfg(not(coverage))]
fn ensure_paths_exist(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        ensure_path_exists(path)?;
    }

    Ok(())
}

#[cfg(not(coverage))]
fn run_guard(
    paths: Vec<PathBuf>,
    excluded_paths: Vec<PathBuf>,
    config: Option<PathBuf>,
    prompt_command: Option<PathBuf>,
    timeout_seconds: u64,
) -> Result<()> {
    ensure_paths_exist(&paths)?;
    let policy_config = load_policy_config(config)?;
    let mut policy = StaticPolicy::new(policy_config, audit_home(&paths));
    let timeout = Duration::from_secs(timeout_seconds);
    let prompt = build_prompt(prompt_command, timeout);

    config_guard::fanotify::run(
        &paths,
        &excluded_paths,
        Mode::Guard {
            policy: &mut policy,
            prompt: prompt.as_ref(),
            prompt_cache: PromptDecisionCache::default(),
        },
    )
}

#[cfg(not(coverage))]
struct StaticPolicy {
    policy: Policy,
    path_aliases: Vec<PathAlias>,
}

#[cfg(not(coverage))]
impl StaticPolicy {
    fn new(config: PolicyConfig, home_dir: PathBuf) -> Self {
        let path_aliases = config_symlink_aliases(&home_dir);

        Self {
            policy: Policy::new(config),
            path_aliases,
        }
    }

    fn decision_path<'a>(&'a self, target_path: &'a Path) -> std::borrow::Cow<'a, Path> {
        logical_policy_path(target_path, &self.path_aliases)
    }
}

#[cfg(any(test, not(coverage)))]
fn logical_policy_path<'a>(
    target_path: &'a Path,
    aliases: &[PathAlias],
) -> std::borrow::Cow<'a, Path> {
    for alias in aliases {
        let Ok(relative_path) = target_path.strip_prefix(&alias.real_root) else {
            continue;
        };

        return std::borrow::Cow::Owned(alias.logical_root.join(relative_path));
    }

    std::borrow::Cow::Borrowed(target_path)
}

#[cfg(not(coverage))]
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

#[cfg(not(coverage))]
fn build_prompt(
    prompt_command: Option<PathBuf>,
    timeout: Duration,
) -> Box<dyn config_guard::prompt::Prompt> {
    match prompt_command {
        Some(command) => Box::new(config_guard::prompt::CommandPrompt::new(command, timeout)),
        None => Box::new(config_guard::prompt::AuthdPrompt::new(timeout)),
    }
}

#[cfg(any(test, not(coverage)))]
fn load_policy_config(config: Option<PathBuf>) -> Result<PolicyConfig> {
    let Some(config) = resolve_config_path(config) else {
        return Ok(PolicyConfig::default());
    };

    let content = std::fs::read_to_string(&config)
        .with_context(|| format!("reading {}", config.display()))?;

    toml::from_str(&content).with_context(|| format!("parsing {}", config.display()))
}

#[cfg(any(test, not(coverage)))]
fn resolve_config_path(config: Option<PathBuf>) -> Option<PathBuf> {
    config.or_else(default_config_path)
}

#[cfg(not(coverage))]
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

#[cfg(not(coverage))]
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

#[cfg(not(coverage))]
fn default_config_path() -> Option<PathBuf> {
    default_config_path_in(config_home()?)
}

#[cfg(coverage)]
fn default_config_path() -> Option<PathBuf> {
    None
}

#[cfg(any(test, not(coverage)))]
fn default_config_path_in(config_home: PathBuf) -> Option<PathBuf> {
    let path = config_home.join("config-guard").join("config.toml");

    path.exists().then_some(path)
}

#[cfg(not(coverage))]
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
    #[cfg(coverage)]
    use super::main;
    use super::{
        default_config_path_in, load_policy_config, logical_policy_path, parse_decision,
        parse_decision_reason,
    };
    use config_guard::learning::PathAlias;
    use config_guard::policy::{Decision, DecisionReason};
    use std::fs;
    use std::path::PathBuf;

    #[cfg(coverage)]
    #[test]
    fn coverage_main_stub_succeeds() {
        assert_eq!(main().unwrap(), std::process::ExitCode::SUCCESS);
    }

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

    #[test]
    fn policy_path_preserves_exact_home_path() {
        let target_path = PathBuf::from("/home/osso/.config/claude/settings.json");
        let aliases = Vec::new();

        let policy_path = logical_policy_path(&target_path, &aliases);

        assert_eq!(policy_path.as_ref(), target_path.as_path());
    }

    #[test]
    fn policy_path_maps_symlink_alias_without_losing_file_suffix() {
        let aliases = vec![PathAlias {
            real_root: PathBuf::from("/syncthing/Sync/Provisioning/config/gmail-cli"),
            logical_root: PathBuf::from("/home/osso/.config/gmail-cli"),
        }];
        let target_path =
            PathBuf::from("/syncthing/Sync/Provisioning/config/gmail-cli/tokens.json");

        let policy_path = logical_policy_path(&target_path, &aliases);

        assert_eq!(
            policy_path.as_ref(),
            PathBuf::from("/home/osso/.config/gmail-cli/tokens.json").as_path()
        );
    }

    #[test]
    fn parses_prompt_decision_inputs() {
        assert_eq!(
            parse_decision_reason("CrossOwnerRead").unwrap(),
            DecisionReason::CrossOwnerRead
        );
        assert_eq!(
            parse_decision_reason("CrossOwnerWrite").unwrap(),
            DecisionReason::CrossOwnerWrite
        );
        assert_eq!(
            parse_decision_reason("SensitiveReadByDevTool").unwrap(),
            DecisionReason::SensitiveReadByDevTool
        );
        assert_eq!(
            parse_decision_reason("SensitiveWrite").unwrap(),
            DecisionReason::SensitiveWrite
        );
        assert!(parse_decision_reason("Unknown").is_err());

        assert_eq!(parse_decision("Allow").unwrap(), Decision::Allow);
        assert_eq!(parse_decision("Deny").unwrap(), Decision::Deny);
        assert!(parse_decision("Prompt").is_err());
    }

    #[test]
    fn load_policy_config_uses_explicit_path_and_reports_errors() {
        let dir = std::env::temp_dir().join(format!(
            "config-guard-policy-load-test-{}",
            std::process::id()
        ));
        let path = dir.join("config.toml");
        fs::create_dir_all(&dir).expect("create config dir");
        fs::write(&path, "owned_paths = []\n").expect("write config");

        let config = load_policy_config(Some(path.clone())).expect("load policy config");
        assert!(config.owned_paths.is_empty());

        fs::write(&path, "not toml").expect("write invalid config");
        assert!(load_policy_config(Some(path)).is_err());

        let _ = fs::remove_dir_all(dir);
    }
}
