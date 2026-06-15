use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(5);

#[test]
#[ignore = "requires root/CAP_SYS_ADMIN: run target test binary through authsudo"]
fn audit_logs_forbid_for_cross_owner_access() {
    require_root();
    let fixture = RootFixture::new("audit_logs_forbid_for_cross_owner_access");
    let mut guard = ConfigGuardProcess::start([
        "audit",
        "--path",
        fixture.watch_root().to_str().unwrap(),
        "--config",
        fixture.config_path().to_str().unwrap(),
    ]);

    guard.wait_for_line("watching ");
    cat_probe_file(&fixture);

    let forbid = guard.wait_for_line("FORBID audit");
    assert!(forbid.contains("exe=cat"), "{forbid}");
    assert!(forbid.contains("reason=CrossOwnerRead"), "{forbid}");
}

#[test]
#[ignore = "requires root/CAP_SYS_ADMIN: run target test binary through authsudo"]
fn guard_invokes_prompt_command_for_cross_owner_access() {
    require_root();
    let fixture = RootFixture::new("guard_invokes_prompt_command_for_cross_owner_access");
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
    let output = run_with_timeout(
        Command::new("cat").arg(fixture.probe_path()),
        TIMEOUT,
        "cat probe under guard",
    );

    assert!(
        output.status.success(),
        "cat should complete via fail-open prompt default: {output:?}"
    );
    let forbid = guard.wait_for_line("FORBID audit");
    assert!(forbid.contains("exe=cat"), "{forbid}");
    assert!(forbid.contains("reason=CrossOwnerRead"), "{forbid}");

    let prompt_log = fs::read_to_string(fixture.prompt_log_path()).expect("read prompt log");
    assert!(
        prompt_log.contains("--subject\ncat\n"),
        "prompt command should receive subject: {prompt_log}"
    );
    assert!(
        prompt_log.contains("--reason\nCrossOwnerRead\n"),
        "prompt command should receive reason: {prompt_log}"
    );
    assert!(
        prompt_log.contains(&fixture.probe_path().display().to_string()),
        "prompt command should receive target path: {prompt_log}"
    );
}

#[test]
#[ignore = "requires root/CAP_SYS_ADMIN: run target test binary through authsudo"]
fn guard_reuses_prompt_answer_for_same_process_and_scope() {
    require_root();
    let fixture = RootFixture::new("guard_reuses_prompt_answer_for_same_process_and_scope");
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
    let output = run_with_timeout(
        Command::new("cat")
            .arg(fixture.probe_path())
            .arg(fixture.second_probe_path()),
        TIMEOUT,
        "cat two protected files under guard",
    );

    assert!(
        output.status.success(),
        "cat should complete via cached prompt answer: {output:?}"
    );
    guard.wait_for_line("FORBID audit");

    let prompt_log = fs::read_to_string(fixture.prompt_log_path()).expect("read prompt log");
    assert_eq!(
        prompt_log.matches("--subject\ncat\n").count(),
        1,
        "same process and scope should prompt once: {prompt_log}"
    );
}

#[test]
#[ignore = "requires root/CAP_SYS_ADMIN: run target test binary through authsudo"]
fn audit_watches_multiple_roots_from_one_process() {
    require_root();
    let fixture = RootFixture::new("audit_watches_multiple_roots_from_one_process");
    let mut guard = ConfigGuardProcess::start([
        "audit",
        "--path",
        fixture.watch_root().to_str().unwrap(),
        "--path",
        fixture.second_watch_root().to_str().unwrap(),
        "--config",
        fixture.config_path().to_str().unwrap(),
    ]);

    guard.wait_for_line("watching ");
    let output = run_with_timeout(
        Command::new("cat").arg(fixture.other_probe_path()),
        TIMEOUT,
        "cat probe from second watch root",
    );

    assert!(output.status.success(), "cat failed: {output:?}");
    let forbid = guard.wait_for_line("FORBID audit");
    assert!(forbid.contains("exe=cat"), "{forbid}");
    assert!(
        forbid.contains(&fixture.other_probe_path().display().to_string()),
        "{forbid}"
    );
}

fn require_root() {
    let effective_uid = unsafe { libc::geteuid() };
    assert_eq!(
        effective_uid, 0,
        "root integration tests need CAP_SYS_ADMIN; build with `cargo test --test root_integration --no-run`, then run the produced test binary with authsudo and `--ignored --nocapture`"
    );
}

fn cat_probe_file(fixture: &RootFixture) {
    let output = run_with_timeout(
        Command::new("cat").arg(fixture.probe_path()),
        TIMEOUT,
        "cat probe file",
    );
    assert!(output.status.success(), "cat failed: {output:?}");
}

fn run_with_timeout(command: &mut Command, timeout: Duration, label: &str) -> std::process::Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {label}: {error}"));
    let deadline = Instant::now() + timeout;

    loop {
        if child
            .try_wait()
            .unwrap_or_else(|error| panic!("poll {label}: {error}"))
            .is_some()
        {
            return child
                .wait_with_output()
                .unwrap_or_else(|error| panic!("collect {label}: {error}"));
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{label} timed out after {timeout:?}");
        }

        thread::sleep(Duration::from_millis(25));
    }
}

struct ConfigGuardProcess {
    child: Child,
    stderr_lines: Receiver<String>,
}

impl ConfigGuardProcess {
    fn start<const N: usize>(args: [&str; N]) -> Self {
        let mut child = Command::new(config_guard_binary())
            .args(args)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn config-guard");
        let stderr = child
            .stderr
            .take()
            .expect("config-guard stderr should pipe");
        let (sender, stderr_lines) = mpsc::channel();

        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });

        Self {
            child,
            stderr_lines,
        }
    }

    fn wait_for_line(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + TIMEOUT;
        let mut seen = String::new();

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let line = self
                .stderr_lines
                .recv_timeout(remaining.min(Duration::from_millis(250)));

            match line {
                Ok(line) if line_matches(&line, needle) => return line,
                Ok(line) => append_seen_line(&mut seen, &line),
                Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {
                    assert_still_running(&mut self.child, &seen);
                }
                Err(_) => panic!("config-guard stderr closed before {needle}; seen: {seen:?}"),
            }

            if Instant::now() >= deadline {
                panic!("timed out waiting for {needle}; seen: {seen:?}");
            }
        }
    }
}

fn line_matches(line: &str, needle: &str) -> bool {
    line.contains(needle)
}

fn append_seen_line(seen: &mut String, line: &str) {
    seen.push_str(line);
    seen.push('\n');
}

impl Drop for ConfigGuardProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn assert_still_running(child: &mut Child, seen: &str) {
    match child.try_wait() {
        Ok(Some(status)) => panic!("config-guard exited early with {status}; stderr: {seen:?}"),
        Ok(None) => {}
        Err(error) => panic!("poll config-guard: {error}"),
    }
}

fn config_guard_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_config-guard"))
}

struct RootFixture {
    root: PathBuf,
}

impl RootFixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("config-guard-root-{name}-{}", std::process::id()));
        let fixture = Self { root };
        fixture.reset();
        fixture
    }

    fn reset(&self) {
        let _ = fs::remove_dir_all(&self.root);
        fs::create_dir_all(self.protected_dir()).expect("create protected dir");
        fs::create_dir_all(self.other_protected_dir()).expect("create other protected dir");
        fs::write(self.probe_path(), "probe\n").expect("write probe");
        fs::write(self.second_probe_path(), "second probe\n").expect("write second probe");
        fs::write(self.other_probe_path(), "other probe\n").expect("write other probe");
        fs::write(self.config_path(), self.config()).expect("write config");
        fs::write(self.prompt_command_path(), self.prompt_command()).expect("write prompt command");
        make_executable(&self.prompt_command_path());
    }

    fn watch_root(&self) -> PathBuf {
        self.root.join("watch")
    }

    fn second_watch_root(&self) -> PathBuf {
        self.root.join("second-watch")
    }

    fn protected_dir(&self) -> PathBuf {
        self.watch_root().join("protected")
    }

    fn other_protected_dir(&self) -> PathBuf {
        self.second_watch_root().join("protected")
    }

    fn probe_path(&self) -> PathBuf {
        self.protected_dir().join("probe.txt")
    }

    fn second_probe_path(&self) -> PathBuf {
        self.protected_dir().join("second-probe.txt")
    }

    fn other_probe_path(&self) -> PathBuf {
        self.other_protected_dir().join("probe.txt")
    }

    fn config_path(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    fn prompt_command_path(&self) -> PathBuf {
        self.root.join("prompt-command")
    }

    fn prompt_log_path(&self) -> PathBuf {
        self.root.join("prompt.log")
    }

    fn config(&self) -> String {
        format!(
            "fail_open = true\n\n[[owned_paths]]\npath = \"{}\"\nowner = \"not-cat\"\nallowed_subjects = []\n\n[[owned_paths]]\npath = \"{}\"\nowner = \"not-cat\"\nallowed_subjects = []\n",
            self.protected_dir().display(),
            self.other_protected_dir().display()
        )
    }

    fn prompt_command(&self) -> String {
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nexit 0\n",
            self.prompt_log_path().display()
        )
    }
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .expect("prompt command metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("make prompt command executable");
}

impl Drop for RootFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
