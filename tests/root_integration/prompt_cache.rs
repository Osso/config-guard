use super::{
    ConfigGuardProcess, RootFixture, TIMEOUT, cat_probe_file, require_root, run_with_timeout,
};
use std::fs;
use std::process::Command;

#[test]
#[ignore = "requires root/CAP_SYS_ADMIN: run target test binary through authsudo"]
fn guard_prompts_once_for_one_rg_process_across_protected_policy_scopes() {
    require_root();
    let fixture =
        RootFixture::new("guard_prompts_once_for_one_rg_process_across_protected_policy_scopes");
    let mut guard = ConfigGuardProcess::start([
        "guard",
        "--path",
        fixture.watch_root().to_str().unwrap(),
        "--path",
        fixture.second_watch_root().to_str().unwrap(),
        "--config",
        fixture.config_path().to_str().unwrap(),
        "--prompt-command",
        fixture.prompt_command_path().to_str().unwrap(),
        "--timeout-seconds",
        "1",
    ]);

    guard.wait_for_line("watching ");
    let output = run_with_timeout(
        Command::new("rg")
            .arg("--hidden")
            .arg("--no-ignore")
            .arg("probe")
            .arg(fixture.watch_root())
            .arg(fixture.second_watch_root()),
        TIMEOUT,
        "one rg process reading across protected policy scopes",
    );

    assert!(
        output.status.success(),
        "one rg process should complete after the Allow prompt: {output:?}"
    );
    let prompt_log = fs::read_to_string(fixture.prompt_log_path()).expect("read prompt log");
    assert_eq!(
        prompt_log.matches("--subject\nrg\n").count(),
        1,
        "one rg process reading across protected policy scopes should prompt once: {prompt_log}"
    );
}

#[test]
#[ignore = "requires root/CAP_SYS_ADMIN: run target test binary through authsudo"]
fn guard_prompts_again_for_a_new_process_generation() {
    require_root();
    let fixture = RootFixture::new("guard_prompts_again_for_a_new_process_generation");
    let mut guard = ConfigGuardProcess::start([
        "guard",
        "--path",
        fixture.watch_root().to_str().unwrap(),
        "--config",
        fixture.config_path().to_str().unwrap(),
        "--prompt-command",
        fixture.prompt_command_path().to_str().unwrap(),
        "--timeout-seconds",
        "1",
    ]);

    guard.wait_for_line("watching ");
    cat_probe_file(&fixture);
    cat_probe_file(&fixture);

    let prompt_log = fs::read_to_string(fixture.prompt_log_path()).expect("read prompt log");
    assert_eq!(
        prompt_log.matches("--subject\ncat\n").count(),
        2,
        "a new process generation must require a new prompt: {prompt_log}"
    );
}
