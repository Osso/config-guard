use crate::policy::{Decision, DecisionReason, ProcessSubject};
use anyhow::{Context, Result};
use authd_protocol::{AuthRequest, AuthResponse, DaemonRequest, SOCKET_PATH};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
#[cfg(not(coverage))]
use std::process::Command;
use std::thread;
use std::time::Duration;
#[cfg(not(coverage))]
use std::time::Instant;

const IPC_BUFFER_SIZE: usize = 64 * 1024;

pub struct PromptRequest<'a> {
    pub subject: &'a ProcessSubject,
    pub target_path: &'a Path,
    pub reason: DecisionReason,
    pub default_decision: Decision,
    pub env: HashMap<String, String>,
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

#[cfg(not(coverage))]
pub struct CommandPrompt {
    command: PathBuf,
    timeout: Duration,
}

#[cfg(not(coverage))]
impl CommandPrompt {
    pub fn new(command: PathBuf, timeout: Duration) -> Self {
        Self { command, timeout }
    }
}

pub struct AuthdPrompt {
    socket_path: PathBuf,
    timeout: Duration,
}

impl AuthdPrompt {
    pub fn new(timeout: Duration) -> Self {
        Self::with_socket_path(SOCKET_PATH, timeout)
    }

    pub fn with_socket_path(socket_path: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout,
        }
    }
}

impl Prompt for AuthdPrompt {
    fn ask(&self, request: &PromptRequest<'_>) -> Result<Decision> {
        let auth_request = AuthRequest {
            target: request.subject.executable.clone(),
            args: vec![
                format!("requests config access ({:?})", request.reason),
                request.target_path.display().to_string(),
            ],
            env: request.env.clone(),
            password: String::new(),
            confirm_only: true,
            prompt_title: Some("Config access request".to_string()),
            prompt_message: Some(format!(
                "Allow {} to access this config file?",
                display_subject(request.subject)
            )),
            prompt_detail: Some(format!(
                "{:?}\n{}",
                request.reason,
                request.target_path.display()
            )),
        };

        // authd reads a `DaemonRequest` envelope off the socket; the legacy
        // confirm/exec flow is the `Exec` variant. Sending a bare `AuthRequest`
        // deserializes as a sequence and authd rejects it ("expected variant
        // identifier"), silently falling through to the default decision.
        match call_authd(
            &self.socket_path,
            &DaemonRequest::Exec(auth_request),
            self.timeout,
        ) {
            Ok(AuthResponse::Success { .. }) => Ok(Decision::Allow),
            Ok(AuthResponse::Denied { .. }) => Ok(Decision::Deny),
            Ok(AuthResponse::AuthFailed) => Ok(Decision::Deny),
            Ok(AuthResponse::UnknownTarget | AuthResponse::Error { .. }) | Err(_) => {
                Ok(request.default_decision.clone())
            }
        }
    }
}

fn call_authd(
    socket_path: &Path,
    request: &DaemonRequest,
    timeout: Duration,
) -> Result<AuthResponse> {
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("connecting to authd socket {}", socket_path.display()))?;
    stream
        .set_read_timeout(Some(timeout))
        .context("setting authd read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("setting authd write timeout")?;

    let payload = rmp_serde::to_vec(request).context("encoding authd request")?;
    stream
        .write_all(&payload)
        .context("writing authd request")?;

    let mut buffer = vec![0u8; IPC_BUFFER_SIZE];
    let bytes_read = stream.read(&mut buffer).context("reading authd response")?;
    if bytes_read == 0 {
        anyhow::bail!("authd closed connection without response");
    }

    rmp_serde::from_slice(&buffer[..bytes_read]).context("decoding authd response")
}

#[cfg(not(coverage))]
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

#[cfg(not(coverage))]
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

#[cfg(not(coverage))]
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

#[cfg(test)]
mod tests {
    use super::{AuthdPrompt, NonInteractivePrompt, Prompt, PromptRequest};
    use crate::policy::{Decision, DecisionReason, ProcessSubject};
    use authd_protocol::{AuthResponse, DaemonRequest};
    use std::collections::HashMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn non_interactive_prompt_returns_default_decision() {
        let prompt = NonInteractivePrompt::new(Duration::from_millis(0));
        let subject = test_subject();
        let target_path = test_target_path();
        let allow_request = prompt_request(&subject, &target_path, Decision::Allow);
        let deny_request = prompt_request(&subject, &target_path, Decision::Deny);

        assert_eq!(prompt.ask(&allow_request).unwrap(), Decision::Allow);
        assert_eq!(prompt.ask(&deny_request).unwrap(), Decision::Deny);
    }

    #[test]
    fn authd_prompt_new_uses_default_socket_and_default_on_error() {
        let prompt = AuthdPrompt::new(Duration::from_millis(1));
        let subject = ProcessSubject {
            executable: PathBuf::from(""),
            command: Vec::new(),
            ancestors: Vec::new(),
        };
        let target_path = test_target_path();
        let request = prompt_request(&subject, &target_path, Decision::Deny);

        assert_eq!(prompt.ask(&request).unwrap(), Decision::Deny);
    }

    #[test]
    fn authd_prompt_uses_default_when_socket_stalls() {
        let socket_path = unique_socket_path("stall");
        let listener = bind_test_socket(&socket_path);
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept authd client");
            thread::sleep(Duration::from_millis(300));
        });

        let prompt = AuthdPrompt::with_socket_path(&socket_path, Duration::from_millis(50));
        let subject = test_subject();
        let target_path = test_target_path();
        let request = prompt_request(&subject, &target_path, Decision::Deny);
        let started = Instant::now();

        let decision = prompt.ask(&request).expect("prompt decision");

        assert_eq!(decision, Decision::Deny);
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "prompt should respect timeout instead of waiting for authd"
        );
        let _ = server.join();
        let _ = fs::remove_file(socket_path);
    }

    #[test]
    fn authd_prompt_sends_daemon_request_envelope() {
        let socket_path = unique_socket_path("success");
        let listener = bind_test_socket(&socket_path);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept authd client");
            let mut buffer = vec![0u8; 64 * 1024];
            let bytes_read = stream.read(&mut buffer).expect("read request");
            let request: DaemonRequest =
                rmp_serde::from_slice(&buffer[..bytes_read]).expect("decode request");
            assert!(matches!(request, DaemonRequest::Exec(_)));

            let response =
                rmp_serde::to_vec(&AuthResponse::Success { pid: 0 }).expect("encode response");
            stream.write_all(&response).expect("write response");
        });

        let prompt = AuthdPrompt::with_socket_path(&socket_path, Duration::from_secs(1));
        let subject = test_subject();
        let target_path = test_target_path();
        let request = prompt_request(&subject, &target_path, Decision::Deny);

        let decision = prompt.ask(&request).expect("prompt decision");

        assert_eq!(decision, Decision::Allow);
        server.join().expect("server thread");
        let _ = fs::remove_file(socket_path);
    }

    fn prompt_request<'a>(
        subject: &'a ProcessSubject,
        target_path: &'a Path,
        default_decision: Decision,
    ) -> PromptRequest<'a> {
        PromptRequest {
            subject,
            target_path,
            reason: DecisionReason::CrossOwnerRead,
            default_decision,
            env: HashMap::new(),
        }
    }

    fn test_subject() -> ProcessSubject {
        ProcessSubject {
            executable: PathBuf::from("/usr/bin/test-subject"),
            command: Vec::new(),
            ancestors: Vec::new(),
        }
    }

    fn test_target_path() -> PathBuf {
        PathBuf::from("/home/osso/.config/example")
    }

    fn bind_test_socket(socket_path: &Path) -> UnixListener {
        let _ = fs::remove_file(socket_path);
        UnixListener::bind(socket_path).expect("bind test socket")
    }

    fn unique_socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "config-guard-authd-{name}-{}.sock",
            std::process::id()
        ))
    }
}
