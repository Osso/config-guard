use super::{ConfigGuardProcess, RootFixture, TIMEOUT, make_executable, require_root};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires root/CAP_SYS_ADMIN: run target test binary through authsudo"]
fn guard_discards_queued_prompt_after_process_exits() {
    require_root();
    let fixture = RootFixture::new("guard_discards_queued_prompt_after_process_exits");
    let python_executable =
        fs::canonicalize("/usr/bin/python3").expect("resolve python3 executable");
    configure_stale_prompt_regression(&fixture, &python_executable);
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
    let script = concurrent_read_script(&fixture);
    let mut reader = Command::new("python3")
        .args(["-c", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn concurrent protected reads");

    assert_prompt_reasons(&mut guard);
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

fn concurrent_read_script(fixture: &RootFixture) -> String {
    format!(
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
    )
}

fn assert_prompt_reasons(guard: &mut ConfigGuardProcess) {
    let forbid_lines = [
        guard.wait_for_line("FORBID guard"),
        guard.wait_for_line("FORBID guard"),
    ];
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
}

fn configure_stale_prompt_regression(fixture: &RootFixture, python_executable: &Path) {
    fs::write(
        fixture.config_path(),
        format!(
            "fail_open = true\ndev_tools = [\"exe:{}\"]\n\n[[owned_paths]]\npath = \"{}\"\nowner = \"not-python\"\nallowed_subjects = []\n\n[[owned_paths]]\npath = \"{}\"\nowner = \"not-python\"\nallowed_subjects = []\n\n[[sensitive_paths]]\npath = \"{}\"\n",
            python_executable.display(),
            fixture.protected_dir().display(),
            fixture.other_protected_dir().display(),
            fixture.other_protected_dir().display(),
        ),
    )
    .expect("write stale prompt regression policy");
    fs::write(
        fixture.prompt_command_path(),
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nsleep 2\nexit 0\n",
            fixture.prompt_log_path().display(),
        ),
    )
    .expect("write delayed prompt command");
    make_executable(&fixture.prompt_command_path());
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
