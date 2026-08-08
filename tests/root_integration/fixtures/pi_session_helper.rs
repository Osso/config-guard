use std::env;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::{Command, ExitCode};

fn run_python(code: &str, path: &str) -> bool {
    Command::new("python3")
        .args(["-c", code, path])
        .status()
        .is_ok_and(|status| status.success())
}

fn run_runner(args: &[String]) -> ExitCode {
    if args.len() != 4 {
        return ExitCode::from(2);
    }

    let read = "from pathlib import Path; import sys; Path(sys.argv[1]).read_bytes()";
    let write = "from pathlib import Path; import sys; p=Path(sys.argv[1]); p.write_bytes(p.read_bytes()+b'x')";
    let success =
        run_python(read, &args[1]) && run_python(write, &args[2]) && run_python(write, &args[3]);

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn spawn_runner(binary_path: &Path, paths: &[&str]) -> (u32, i32) {
    let mut runner = Command::new(binary_path)
        .args(["runner", paths[0], paths[1], paths[2]])
        .spawn()
        .expect("spawn Pi runner");
    let runner_pid = runner.id();
    let status = runner.wait().expect("wait Pi runner");
    (runner_pid, status.code().unwrap_or(1))
}

fn run_owner(binary_path: &Path) -> ExitCode {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines().map_while(Result::ok) {
        let mut fields = line.split('\t');
        match fields.next() {
            Some("quit") => break,
            Some("run") => {
                let paths: Vec<&str> = fields.collect();
                if paths.len() != 3 {
                    return ExitCode::from(2);
                }
                let (runner_pid, status) = spawn_runner(binary_path, &paths);
                writeln!(stdout, "{runner_pid}\t{status}").expect("write Pi runner result");
                stdout.flush().expect("flush Pi runner result");
            }
            _ => return ExitCode::from(2),
        }
    }

    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let binary_path = env::current_exe().expect("resolve Pi helper executable");
    match args.get(1).map(String::as_str) {
        Some("owner") => run_owner(&binary_path),
        Some("runner") => run_runner(&args[1..]),
        _ => ExitCode::from(2),
    }
}
