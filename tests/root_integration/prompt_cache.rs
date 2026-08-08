use super::{
    ConfigGuardProcess, RootFixture, TIMEOUT, cat_probe_file, require_root, run_with_timeout,
};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;

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

#[test]
#[ignore = "requires root/CAP_SYS_ADMIN: run target test binary through authsudo"]
fn guard_reuses_allow_for_one_owner_generation_and_scope_until_restart() {
    require_root();
    let fixture =
        RootFixture::new("guard_reuses_allow_for_one_owner_generation_and_scope_until_restart");
    configure_owned_scopes(&fixture, "bash");
    let database = fixture.protected_dir().join("control.sqlite");
    let write_ahead_log = fixture.protected_dir().join("control.sqlite-wal");
    let shared_memory = fixture.protected_dir().join("control.sqlite-shm");
    for path in [&database, &write_ahead_log, &shared_memory] {
        fs::write(path, "sqlite\n").expect("create sqlite fixture file");
    }

    let mut owner = HelperOwner::start();
    let mut other_owner = HelperOwner::start();
    {
        let mut guard = start_guard_for_both_scopes(&fixture);
        guard.wait_for_line("watching ");

        assert!(
            owner.access("read", &database),
            "initial database read failed"
        );
        assert!(
            owner.access("write", &write_ahead_log),
            "write-ahead log write failed"
        );
        assert!(
            owner.access("write", &shared_memory),
            "shared-memory write failed"
        );
        assert_eq!(
            prompt_count(&fixture),
            1,
            "same helper and owner generation should reuse one allow across access kinds and files"
        );

        assert!(
            owner.access("read", &fixture.other_probe_path()),
            "second policy scope read failed"
        );
        assert_eq!(
            prompt_count(&fixture),
            2,
            "a distinct owned scope must require its own approval"
        );

        assert!(
            other_owner.access("read", &database),
            "other owner generation database read failed"
        );
        assert_eq!(
            prompt_count(&fixture),
            3,
            "another owner process generation must not inherit the approval"
        );
    }

    fs::write(fixture.prompt_log_path(), "").expect("reset prompt log");
    let mut restarted_guard = start_guard_for_both_scopes(&fixture);
    restarted_guard.wait_for_line("watching ");
    assert!(
        owner.access("read", &database),
        "database read after guard restart failed"
    );
    assert_eq!(
        prompt_count(&fixture),
        1,
        "guard restart must clear runtime ancestry approvals"
    );
}

#[test]
#[ignore = "requires root/CAP_SYS_ADMIN: run target test binary through authsudo"]
fn guard_does_not_reuse_deny_for_owner_ancestry() {
    require_root();
    let fixture = RootFixture::new("guard_does_not_reuse_deny_for_owner_ancestry");
    configure_owned_scopes(&fixture, "bash");
    fixture.set_prompt_exit_code(1);
    let mut owner = HelperOwner::start();
    let mut guard = start_guard_for_both_scopes(&fixture);
    guard.wait_for_line("watching ");

    assert!(
        !owner.access("read", &fixture.probe_path()),
        "explicit denial should block the first helper"
    );
    fixture.set_prompt_exit_code(0);
    assert!(
        owner.access("read", &fixture.probe_path()),
        "a later helper under the same owner should receive a new prompt"
    );
    assert_eq!(
        prompt_count(&fixture),
        2,
        "denial must remain process-generation scoped"
    );
}

fn configure_owned_scopes(fixture: &RootFixture, owner: &str) {
    let config = format!(
        "fail_open = true\n\n[[owned_paths]]\npath = \"{}\"\nowner = \"{owner}\"\nallowed_subjects = []\n\n[[owned_paths]]\npath = \"{}\"\nowner = \"{owner}\"\nallowed_subjects = []\n",
        fixture.protected_dir().display(),
        fixture.other_protected_dir().display(),
    );
    fs::write(fixture.config_path(), config).expect("write owner-scoped config");
}

fn start_guard_for_both_scopes(fixture: &RootFixture) -> ConfigGuardProcess {
    ConfigGuardProcess::start([
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
    ])
}

fn prompt_count(fixture: &RootFixture) -> usize {
    fs::read_to_string(fixture.prompt_log_path())
        .expect("read prompt log")
        .matches("--subject\n")
        .count()
}

struct HelperOwner {
    child: Child,
    stdin: ChildStdin,
    responses: Receiver<String>,
}

impl HelperOwner {
    fn start() -> Self {
        let mut child = Command::new("bash")
            .args(["--noprofile", "--norc", "-c", helper_owner_script()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn helper owner");
        let stdin = child.stdin.take().expect("helper owner stdin");
        let stdout = child.stdout.take().expect("helper owner stdout");
        let (sender, responses) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });

        Self {
            child,
            stdin,
            responses,
        }
    }

    fn access(&mut self, action: &str, path: &Path) -> bool {
        writeln!(self.stdin, "{action}\t{}", path.display()).expect("send helper request");
        self.stdin.flush().expect("flush helper request");
        self.responses
            .recv_timeout(TIMEOUT)
            .expect("helper response before timeout")
            == "0"
    }
}

impl Drop for HelperOwner {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn helper_owner_script() -> &'static str {
    r#"
while IFS=$'\t' read -r action path; do
    case "$action" in
        read)
            python3 -c 'from pathlib import Path; import sys; Path(sys.argv[1]).read_bytes()' "$path"
            ;;
        write)
            python3 -c 'from pathlib import Path; import sys; path = Path(sys.argv[1]); path.write_bytes(path.read_bytes() + b"x")' "$path"
            ;;
        *)
            exit 2
            ;;
    esac
    printf '%s\n' "$?"
done
"#
}
