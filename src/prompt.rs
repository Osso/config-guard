use crate::policy::{Decision, DecisionReason, ProcessSubject};
use crate::process::{ProcessAncestor, ProcessIdentity, is_process_generation_current};
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AncestryAuthorization {
    pub subject_executable: PathBuf,
    pub owner_ancestor: ProcessAncestor,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct AncestryAuthorizationKey {
    subject_executable: PathBuf,
    owner_executable: PathBuf,
}

impl AncestryAuthorization {
    pub fn new(
        process: &ProcessIdentity,
        owner_subject: &str,
        decision: &Decision,
    ) -> Option<Self> {
        let Decision::Prompt { reason, .. } = decision else {
            return None;
        };
        if !matches!(
            reason,
            DecisionReason::CrossOwnerRead | DecisionReason::CrossOwnerWrite
        ) {
            return None;
        }

        let subject_executable = process.executable.clone()?;
        let owner_ancestor = owner_chain_root(process, owner_subject)?.clone();

        Some(Self {
            subject_executable,
            owner_ancestor,
        })
    }

    pub(crate) fn key(&self) -> AncestryAuthorizationKey {
        AncestryAuthorizationKey {
            subject_executable: self.subject_executable.clone(),
            owner_executable: self.owner_ancestor.executable.clone(),
        }
    }

    pub fn owner_is_current(&self) -> bool {
        self.owner_ancestor
            .start_time_ticks
            .is_some_and(|start_time_ticks| {
                is_process_generation_current(self.owner_ancestor.pid, start_time_ticks)
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PromptAnswer {
    Explicit(Decision),
    Default(Decision),
}

impl PromptAnswer {
    pub fn into_decision(self) -> Decision {
        match self {
            Self::Explicit(decision) | Self::Default(decision) => decision,
        }
    }

    pub fn is_explicit(&self) -> bool {
        matches!(self, Self::Explicit(_))
    }
}

pub struct PromptRequest<'a> {
    pub subject: &'a ProcessSubject,
    pub target_path: &'a Path,
    pub reason: DecisionReason,
    pub default_decision: Decision,
    pub env: HashMap<String, String>,
    pub authorization: Option<&'a AncestryAuthorization>,
}

pub trait Prompt {
    fn ask(&self, request: &PromptRequest<'_>) -> Result<Decision>;

    fn ask_answer(&self, request: &PromptRequest<'_>) -> Result<PromptAnswer> {
        self.ask(request).map(PromptAnswer::Explicit)
    }

    fn requires_graphical_session(&self) -> bool {
        true
    }
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

    fn ask_answer(&self, request: &PromptRequest<'_>) -> Result<PromptAnswer> {
        self.ask(request).map(PromptAnswer::Default)
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

#[cfg(not(coverage))]
pub fn build(prompt_command: Option<PathBuf>, timeout: Duration) -> Box<dyn Prompt + Sync> {
    match prompt_command {
        Some(command) => Box::new(CommandPrompt::new(command, timeout)),
        None => Box::new(AuthdPrompt::new(timeout)),
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
        self.ask_answer(request).map(PromptAnswer::into_decision)
    }

    fn ask_answer(&self, request: &PromptRequest<'_>) -> Result<PromptAnswer> {
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
            prompt_message: Some(prompt_message(request)),
            prompt_detail: Some(prompt_detail(request)),
        };

        // authd reads a `DaemonRequest` envelope off the socket; the legacy
        // confirm/exec flow is the `Exec` variant. Sending a bare `AuthRequest`
        // deserializes as a sequence and authd rejects it ("expected variant
        // identifier"), silently falling through to the default decision.
        let response = call_authd(
            &self.socket_path,
            &DaemonRequest::Exec(auth_request),
            self.timeout,
        );
        let answer = match response {
            Ok(AuthResponse::Success { .. }) => PromptAnswer::Explicit(Decision::Allow),
            Ok(AuthResponse::Denied { .. } | AuthResponse::AuthFailed) => {
                PromptAnswer::Explicit(Decision::Deny)
            }
            Ok(AuthResponse::UnknownTarget | AuthResponse::Error { .. }) | Err(_) => {
                PromptAnswer::Default(request.default_decision.clone())
            }
        };

        Ok(answer)
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
        self.ask_answer(request).map(PromptAnswer::into_decision)
    }

    fn ask_answer(&self, request: &PromptRequest<'_>) -> Result<PromptAnswer> {
        let mut child = Command::new(&self.command)
            .arg("--subject")
            .arg(display_subject(request.subject))
            .arg("--path")
            .arg(request.target_path)
            .arg("--reason")
            .arg(format!("{:?}", request.reason))
            .spawn()
            .with_context(|| format!("starting prompt command {}", self.command.display()))?;

        wait_for_prompt_answer(&mut child, self.timeout, &request.default_decision)
    }

    fn requires_graphical_session(&self) -> bool {
        false
    }
}

#[cfg(not(coverage))]
fn wait_for_prompt_answer(
    child: &mut std::process::Child,
    timeout: Duration,
    default_decision: &Decision,
) -> Result<PromptAnswer> {
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(answer_from_status(status, default_decision));
        }

        thread::sleep(Duration::from_millis(50));
    }

    let _ = child.kill();
    Ok(PromptAnswer::Default(default_decision.clone()))
}

#[cfg(not(coverage))]
fn answer_from_status(
    status: std::process::ExitStatus,
    default_decision: &Decision,
) -> PromptAnswer {
    match status.code() {
        Some(0) => PromptAnswer::Explicit(Decision::Allow),
        Some(1) => PromptAnswer::Explicit(Decision::Deny),
        _ => PromptAnswer::Default(default_decision.clone()),
    }
}

fn owner_chain_root<'a>(
    process: &'a ProcessIdentity,
    owner_subject: &str,
) -> Option<&'a ProcessAncestor> {
    let owner_chain = process
        .ancestor_processes
        .iter()
        .skip_while(|ancestor| !ancestor_matches_owner(ancestor, owner_subject))
        .take_while(|ancestor| ancestor_matches_owner(ancestor, owner_subject));
    let mut root = None;

    for ancestor in owner_chain {
        ancestor.start_time_ticks?;
        root = Some(ancestor);
    }

    root
}

fn ancestor_matches_owner(ancestor: &ProcessAncestor, owner_subject: &str) -> bool {
    executable_name(&ancestor.executable) == owner_subject
}

fn display_subject(subject: &ProcessSubject) -> String {
    executable_name(&subject.executable).to_string()
}

fn executable_name(executable: &Path) -> &str {
    executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
}

fn prompt_message(request: &PromptRequest<'_>) -> String {
    let subject = display_subject(request.subject);
    let Some(authorization) = request.authorization else {
        return format!("Allow {subject} to access this config file?");
    };
    let owner_executable = &authorization.owner_ancestor.executable;
    let owner = executable_name(owner_executable);

    format!(
        "Allow {subject} launched by {} to access all config owned by {owner} until Config Guard restarts?",
        owner_executable.display()
    )
}

fn prompt_detail(request: &PromptRequest<'_>) -> String {
    let mut detail = format!("{:?}\n{}", request.reason, request.target_path.display());
    let Some(authorization) = request.authorization else {
        return detail;
    };
    let owner_executable = &authorization.owner_ancestor.executable;
    let owner = executable_name(owner_executable);
    detail.push_str(&format!(
        "\n\nGrant: read and write across all config owned by {owner}\nOwner executable: {}\nCurrent owner process: PID {}",
        owner_executable.display(),
        authorization.owner_ancestor.pid
    ));

    detail
}

#[cfg(test)]
mod tests {
    use super::{
        AncestryAuthorization, AuthdPrompt, NonInteractivePrompt, Prompt, PromptAnswer,
        PromptRequest,
    };
    use crate::policy::{Decision, DecisionReason, ProcessSubject};
    use crate::process::ProcessAncestor;
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
        assert_eq!(
            prompt.ask_answer(&allow_request).unwrap(),
            PromptAnswer::Default(Decision::Allow)
        );
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

        let answer = prompt.ask_answer(&request).expect("prompt answer");

        assert_eq!(answer, PromptAnswer::Default(Decision::Deny));
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
            let DaemonRequest::Exec(request) = request else {
                panic!("expected authd Exec request")
            };
            assert_eq!(
                request.prompt_message.as_deref(),
                Some(
                    "Allow test-subject launched by /home/osso/.local/share/pi/pi to access all config owned by pi until Config Guard restarts?"
                )
            );
            let detail = request.prompt_detail.expect("prompt detail");
            assert!(detail.contains("Grant: read and write across all config owned by pi"));
            assert!(detail.contains("Owner executable: /home/osso/.local/share/pi/pi"));
            assert!(detail.contains("Current owner process: PID 7"));

            let response =
                rmp_serde::to_vec(&AuthResponse::Success { pid: 0 }).expect("encode response");
            stream.write_all(&response).expect("write response");
        });

        let prompt = AuthdPrompt::with_socket_path(&socket_path, Duration::from_secs(1));
        let subject = test_subject();
        let target_path = test_target_path();
        let authorization = test_authorization();
        let mut request = prompt_request(&subject, &target_path, Decision::Deny);
        request.authorization = Some(&authorization);

        let answer = prompt.ask_answer(&request).expect("prompt answer");

        assert_eq!(answer, PromptAnswer::Explicit(Decision::Allow));
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
            authorization: None,
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

    fn test_authorization() -> AncestryAuthorization {
        AncestryAuthorization {
            subject_executable: PathBuf::from("/usr/bin/test-subject"),
            owner_ancestor: ProcessAncestor {
                pid: 7,
                executable: PathBuf::from("/home/osso/.local/share/pi/pi"),
                start_time_ticks: Some(50),
            },
        }
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
