use super::{
    ConfigGuardProcess, RootFixture, TIMEOUT, cat_probe_file, require_root, run_with_timeout,
};
use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

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
fn guard_discards_queued_prompt_after_process_exits() {
    require_root();
    let fixture = RootFixture::new("guard_discards_queued_prompt_after_process_exits");
    let python_executable =
        fs::canonicalize("/usr/bin/python3").expect("resolve python3 executable");
    fixture.configure_stale_prompt_regression(&python_executable);
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
        "4",
    ]);

    guard.wait_for_line("watching ");
    let script = format!(
        r#"
import threading
from pathlib import Path

paths = [Path({first:?}), Path({second:?})]
start = threading.Barrier(3)

def read_path(path):
    start.wait()
    try:
        path.read_text()
    except Exception:
        pass

threads = [threading.Thread(target=read_path, args=(path,)) for path in paths]
for worker in threads:
    worker.start()
start.wait()
for worker in threads:
    worker.join()
"#,
        first = fixture.probe_path().display().to_string(),
        second = fixture.other_probe_path().display().to_string(),
    );
    let mut reader = Command::new("python3")
        .args(["-c", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn concurrent protected reads");

    let forbid_lines = guard.wait_for_lines("FORBID guard", 2);
    assert!(
        forbid_lines
            .iter()
            .any(|line| line.contains("reason=CrossOwnerRead")),
        "missing cross-owner prompt: {forbid_lines:?}"
    );
    assert!(
        forbid_lines
            .iter()
            .any(|line| line.contains("reason=SensitiveReadByDevTool")),
        "missing sensitive-path prompt: {forbid_lines:?}"
    );
    wait_for_prompt_calls(&fixture, 1);

    reader.kill().expect("kill blocked reader process");
    reader.wait().expect("wait for killed reader process");
    thread::sleep(Duration::from_secs(3));

    let prompt_log = fs::read_to_string(fixture.prompt_log_path()).expect("read prompt log");
    assert_eq!(
        prompt_log.matches("--subject\npython").count(),
        1,
        "queued prompts for an exited process must be discarded: {prompt_log}"
    );
}

fn wait_for_prompt_calls(fixture: &RootFixture, expected: usize) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let calls = fs::read_to_string(fixture.prompt_log_path())
            .map(|log| log.matches("--subject\npython").count())
            .unwrap_or(0);
        if calls >= expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for prompt call"
        );
        thread::sleep(Duration::from_millis(25));
    }
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
