use super::prompt_resolution::{
    PromptOutcome, ask_prompt, cache_prompt_answer, immediate_prompt_decision,
};
use super::{
    AccessPolicy, PromptDecisionCache, PromptDecisionKey, access_kind, ensure_event_descriptor,
    format_guard_decision, inspect_process_or_unknown, is_watched_path, read_event_batch,
    respond_and_close_event,
};
use crate::policy::{AccessKind, Decision, DecisionReason, ProcessSubject};
use crate::process::read_wayland_env;
use crate::prompt::{AncestryAuthorization, Prompt, PromptRequest};
use anyhow::{Context, Result, anyhow};
use libc::{POLLERR, POLLHUP, POLLIN, POLLNVAL, fanotify_event_metadata, poll, pollfd};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;

const WAKE_BUFFER_SIZE: usize = 64;
const PROMPT_WAKE_BYTE: u8 = 1;

type PromptId = u64;

struct PromptJob {
    id: PromptId,
    key: Option<PromptDecisionKey>,
    authorization: Option<AncestryAuthorization>,
    subject: ProcessSubject,
    target_path: PathBuf,
    reason: DecisionReason,
    default_decision: Decision,
    env: HashMap<String, String>,
}

struct PromptCompletion {
    id: PromptId,
    outcome: PromptOutcome,
}

struct PendingEvent {
    fd: RawFd,
    mask: u64,
    default_decision: Decision,
}

struct PendingPrompt {
    key: Option<PromptDecisionKey>,
    authorization: Option<AncestryAuthorization>,
    events: Vec<PendingEvent>,
}

struct PromptSpec {
    key: Option<PromptDecisionKey>,
    authorization: Option<AncestryAuthorization>,
    subject: ProcessSubject,
    target_path: PathBuf,
    reason: DecisionReason,
    default_decision: Decision,
    env: HashMap<String, String>,
}

enum GuardAction {
    Respond(Decision),
    Prompt(Box<PromptSpec>),
}

struct GuardEvaluation {
    subject: ProcessSubject,
    prompt_key: Option<PromptDecisionKey>,
    authorization: Option<AncestryAuthorization>,
    policy_decision: Decision,
}

struct GuardActivity {
    fanotify_ready: bool,
    prompt_ready: bool,
    prompt_worker_closed: bool,
}

struct PromptCoordinator {
    job_sender: Sender<PromptJob>,
    completion_receiver: Receiver<PromptCompletion>,
    wake_reader: UnixStream,
    prompt_cache: PromptDecisionCache,
    pending: HashMap<PromptId, PendingPrompt>,
    pending_by_key: HashMap<PromptDecisionKey, PromptId>,
    next_id: PromptId,
}

pub(super) fn run(
    fanotify_fd: RawFd,
    paths: &[PathBuf],
    excluded_paths: &[PathBuf],
    policy: &mut dyn AccessPolicy,
    prompt: &(dyn Prompt + Sync),
    prompt_cache: PromptDecisionCache,
) -> Result<()> {
    let (job_sender, job_receiver) = mpsc::channel();
    let (completion_sender, completion_receiver) = mpsc::channel();
    let (wake_reader, wake_writer) =
        UnixStream::pair().context("creating guard prompt wake socket")?;
    wake_reader
        .set_nonblocking(true)
        .context("making guard prompt wake socket nonblocking")?;

    thread::scope(|scope| {
        let worker = thread::Builder::new()
            .name("config-guard-prompt".to_string())
            .spawn_scoped(scope, move || {
                if let Err(error) =
                    run_prompt_worker(prompt, job_receiver, completion_sender, wake_writer)
                {
                    eprintln!("guard prompt worker failed: {error:#}");
                }
            })
            .context("spawning guard prompt worker")?;
        let mut coordinator =
            PromptCoordinator::new(job_sender, completion_receiver, wake_reader, prompt_cache);

        let loop_result = run_event_loop(
            fanotify_fd,
            paths,
            excluded_paths,
            policy,
            prompt,
            &mut coordinator,
        );
        drop(coordinator);
        worker
            .join()
            .map_err(|_| anyhow!("guard prompt worker panicked"))?;
        loop_result
    })
}

impl PromptCoordinator {
    fn new(
        job_sender: Sender<PromptJob>,
        completion_receiver: Receiver<PromptCompletion>,
        wake_reader: UnixStream,
        prompt_cache: PromptDecisionCache,
    ) -> Self {
        Self {
            job_sender,
            completion_receiver,
            wake_reader,
            prompt_cache,
            pending: HashMap::new(),
            pending_by_key: HashMap::new(),
            next_id: 0,
        }
    }

    fn wake_fd(&self) -> RawFd {
        self.wake_reader.as_raw_fd()
    }

    fn immediate_decision(
        &mut self,
        prompt: &dyn Prompt,
        prompt_key: Option<&PromptDecisionKey>,
        authorization: Option<&AncestryAuthorization>,
        env: &HashMap<String, String>,
        decision: &Decision,
    ) -> Option<Decision> {
        immediate_prompt_decision(
            prompt,
            &mut self.prompt_cache,
            prompt_key,
            authorization,
            env,
            decision,
        )
    }

    fn queue_prompt(
        &mut self,
        fanotify_fd: RawFd,
        event_fd: RawFd,
        event_mask: u64,
        spec: PromptSpec,
    ) -> Result<()> {
        if let Some(id) = self.pending_prompt_id(spec.key.as_ref()) {
            return self.append_pending_event(id, event_fd, event_mask, spec.default_decision);
        }

        self.start_prompt(fanotify_fd, event_fd, event_mask, spec)
    }

    fn pending_prompt_id(&self, key: Option<&PromptDecisionKey>) -> Option<PromptId> {
        key.and_then(|key| self.pending_by_key.get(key)).copied()
    }

    fn append_pending_event(
        &mut self,
        id: PromptId,
        event_fd: RawFd,
        event_mask: u64,
        default_decision: Decision,
    ) -> Result<()> {
        let pending = self
            .pending
            .get_mut(&id)
            .context("prompt key references a missing pending request")?;
        pending.events.push(PendingEvent {
            fd: event_fd,
            mask: event_mask,
            default_decision,
        });
        Ok(())
    }

    fn start_prompt(
        &mut self,
        fanotify_fd: RawFd,
        event_fd: RawFd,
        event_mask: u64,
        spec: PromptSpec,
    ) -> Result<()> {
        let id = self.allocate_id()?;
        let pending_event = PendingEvent {
            fd: event_fd,
            mask: event_mask,
            default_decision: spec.default_decision.clone(),
        };
        let job = PromptJob {
            id,
            key: spec.key.clone(),
            authorization: spec.authorization.clone(),
            subject: spec.subject,
            target_path: spec.target_path,
            reason: spec.reason,
            default_decision: spec.default_decision,
            env: spec.env,
        };

        self.send_prompt_job(
            fanotify_fd,
            pending_event,
            job,
            spec.key,
            spec.authorization,
        )
    }

    fn send_prompt_job(
        &mut self,
        fanotify_fd: RawFd,
        pending_event: PendingEvent,
        job: PromptJob,
        key: Option<PromptDecisionKey>,
        authorization: Option<AncestryAuthorization>,
    ) -> Result<()> {
        let id = job.id;
        if let Err(error) = self.job_sender.send(job) {
            respond_and_close_event(
                fanotify_fd,
                pending_event.fd,
                pending_event.mask,
                pending_event.default_decision,
            )?;
            return Err(anyhow!("sending prompt request to worker: {error}"));
        }

        if let Some(key) = key.as_ref() {
            self.pending_by_key.insert(key.clone(), id);
        }
        self.pending.insert(
            id,
            PendingPrompt {
                key,
                authorization,
                events: vec![pending_event],
            },
        );
        Ok(())
    }

    fn process_completions(&mut self, fanotify_fd: RawFd, worker_closed_hint: bool) -> Result<()> {
        let wake_reader_closed = self.drain_wake_reader()?;
        let completion_channel_closed = self.drain_completion_channel(fanotify_fd)?;
        if worker_closed_hint || wake_reader_closed || completion_channel_closed {
            return self.fail_pending_prompts(fanotify_fd);
        }

        Ok(())
    }

    fn allocate_id(&mut self) -> Result<PromptId> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .context("guard prompt request id overflow")?;
        Ok(id)
    }

    fn drain_wake_reader(&mut self) -> Result<bool> {
        let mut buffer = [0u8; WAKE_BUFFER_SIZE];

        loop {
            match self.wake_reader.read(&mut buffer) {
                Ok(0) => return Ok(true),
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error).context("reading guard prompt wake socket"),
            }
        }
    }

    fn drain_completion_channel(&mut self, fanotify_fd: RawFd) -> Result<bool> {
        loop {
            match self.completion_receiver.try_recv() {
                Ok(completion) => self.complete_prompt(fanotify_fd, completion)?,
                Err(TryRecvError::Empty) => return Ok(false),
                Err(TryRecvError::Disconnected) => return Ok(true),
            }
        }
    }

    fn complete_prompt(&mut self, fanotify_fd: RawFd, completion: PromptCompletion) -> Result<()> {
        let pending = self
            .pending
            .remove(&completion.id)
            .with_context(|| format!("completion for unknown prompt {}", completion.id))?;
        self.remove_pending_key(completion.id, pending.key.as_ref())?;

        match completion.outcome {
            PromptOutcome::Answer { decision, explicit } => {
                cache_prompt_answer(
                    &mut self.prompt_cache,
                    pending.key,
                    pending.authorization,
                    &decision,
                    explicit,
                );
                respond_with_decision(fanotify_fd, pending.events, decision)
            }
            PromptOutcome::Failure => respond_with_defaults(fanotify_fd, pending.events),
        }
    }

    fn remove_pending_key(&mut self, id: PromptId, key: Option<&PromptDecisionKey>) -> Result<()> {
        let Some(key) = key else {
            return Ok(());
        };
        let mapped_id = self.pending_by_key.remove(key);
        if mapped_id != Some(id) {
            return Err(anyhow!(
                "prompt key mapping mismatch: expected {id}, found {mapped_id:?}"
            ));
        }

        Ok(())
    }

    fn fail_pending_prompts(&mut self, fanotify_fd: RawFd) -> Result<()> {
        self.pending_by_key.clear();
        let pending = std::mem::take(&mut self.pending);
        let fallback_result = pending
            .into_values()
            .try_for_each(|pending| respond_with_defaults(fanotify_fd, pending.events));
        fallback_result.context("guard prompt worker stopped while requests were pending")?;
        Err(anyhow!("guard prompt worker stopped unexpectedly"))
    }
}

fn run_event_loop(
    fanotify_fd: RawFd,
    paths: &[PathBuf],
    excluded_paths: &[PathBuf],
    policy: &mut dyn AccessPolicy,
    prompt: &dyn Prompt,
    coordinator: &mut PromptCoordinator,
) -> Result<()> {
    loop {
        let activity = wait_for_activity(fanotify_fd, coordinator.wake_fd())?;
        if activity.prompt_ready {
            coordinator.process_completions(fanotify_fd, activity.prompt_worker_closed)?;
        }
        if activity.fanotify_ready {
            read_event_batch(fanotify_fd, |metadata, _generation| {
                handle_event(
                    fanotify_fd,
                    metadata,
                    paths,
                    excluded_paths,
                    policy,
                    prompt,
                    coordinator,
                )
            })?;
        }
    }
}

fn wait_for_activity(fanotify_fd: RawFd, wake_fd: RawFd) -> Result<GuardActivity> {
    let mut descriptors = [
        pollfd {
            fd: fanotify_fd,
            events: POLLIN,
            revents: 0,
        },
        pollfd {
            fd: wake_fd,
            events: POLLIN,
            revents: 0,
        },
    ];

    loop {
        let ready = unsafe { poll(descriptors.as_mut_ptr(), descriptors.len() as _, -1) };
        if ready >= 0 {
            break;
        }

        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error).context("polling guard fanotify and prompt descriptors");
        }
    }

    reject_poll_errors("fanotify", descriptors[0].revents)?;
    reject_poll_errors("prompt worker", descriptors[1].revents)?;

    Ok(GuardActivity {
        fanotify_ready: descriptors[0].revents & POLLIN != 0,
        prompt_ready: descriptors[1].revents & (POLLIN | POLLHUP) != 0,
        prompt_worker_closed: descriptors[1].revents & POLLHUP != 0,
    })
}

fn reject_poll_errors(name: &str, revents: i16) -> Result<()> {
    let errors = revents & (POLLERR | POLLNVAL);
    if errors != 0 {
        return Err(anyhow!("{name} poll failed with flags {errors:#x}"));
    }

    Ok(())
}

fn handle_event(
    fanotify_fd: RawFd,
    metadata: &fanotify_event_metadata,
    paths: &[PathBuf],
    excluded_paths: &[PathBuf],
    policy: &mut dyn AccessPolicy,
    prompt: &dyn Prompt,
    coordinator: &mut PromptCoordinator,
) -> Result<()> {
    ensure_event_descriptor(metadata.mask, metadata.fd)?;
    let action = prepare_event_action(metadata, paths, excluded_paths, policy, prompt, coordinator);

    match action {
        Ok(GuardAction::Respond(decision)) => {
            respond_and_close_event(fanotify_fd, metadata.fd, metadata.mask, decision)
        }
        Ok(GuardAction::Prompt(spec)) => {
            coordinator.queue_prompt(fanotify_fd, metadata.fd, metadata.mask, *spec)
        }
        Err(error) => {
            let result: Result<()> = Err(error);
            let close_result = super::event::close_descriptor(metadata.fd);
            result.and(close_result)
        }
    }
}

fn prepare_event_action(
    metadata: &fanotify_event_metadata,
    paths: &[PathBuf],
    excluded_paths: &[PathBuf],
    policy: &mut dyn AccessPolicy,
    prompt: &dyn Prompt,
    coordinator: &mut PromptCoordinator,
) -> Result<GuardAction> {
    let target_path = super::event::target_path(metadata.fd)?;
    if !is_watched_path(&target_path, paths, excluded_paths) {
        return Ok(GuardAction::Respond(Decision::Allow));
    }

    let evaluation = evaluate_guard_access(metadata, &target_path, policy)?;
    Ok(resolve_guard_action(
        metadata.pid,
        target_path,
        evaluation,
        prompt,
        coordinator,
    ))
}

fn evaluate_guard_access(
    metadata: &fanotify_event_metadata,
    target_path: &Path,
    policy: &mut dyn AccessPolicy,
) -> Result<GuardEvaluation> {
    let access = access_kind(metadata.mask);
    let process = inspect_process_or_unknown(metadata.pid, target_path, access);
    let subject = process.subject();
    let policy_decision = policy.decide(&subject, target_path, access)?;
    let prompt_key = PromptDecisionKey::new(&process, access, &policy_decision);
    let authorization = policy
        .authorization_owner_subject(&subject)
        .and_then(|owner| AncestryAuthorization::new(&process, &owner, &policy_decision));
    log_guard_decision(
        metadata.pid,
        &subject.executable,
        target_path,
        access,
        policy_decision.clone(),
    );

    Ok(GuardEvaluation {
        subject,
        prompt_key,
        authorization,
        policy_decision,
    })
}

fn resolve_guard_action(
    pid: i32,
    target_path: PathBuf,
    evaluation: GuardEvaluation,
    prompt: &dyn Prompt,
    coordinator: &mut PromptCoordinator,
) -> GuardAction {
    let env = read_wayland_env(pid);
    if let Some(decision) = coordinator.immediate_decision(
        prompt,
        evaluation.prompt_key.as_ref(),
        evaluation.authorization.as_ref(),
        &env,
        &evaluation.policy_decision,
    ) {
        return GuardAction::Respond(decision);
    }

    GuardAction::Prompt(Box::new(prompt_spec(target_path, evaluation, env)))
}

fn prompt_spec(
    target_path: PathBuf,
    evaluation: GuardEvaluation,
    env: HashMap<String, String>,
) -> PromptSpec {
    let GuardEvaluation {
        subject,
        prompt_key,
        authorization,
        policy_decision,
    } = evaluation;
    let Decision::Prompt {
        reason,
        default,
        scope: _,
    } = policy_decision
    else {
        unreachable!("non-prompt guard decisions resolve immediately")
    };

    PromptSpec {
        key: prompt_key,
        authorization,
        subject,
        target_path,
        reason,
        default_decision: *default,
        env,
    }
}

fn log_guard_decision(
    pid: i32,
    executable: &Path,
    target_path: &Path,
    access: AccessKind,
    decision: Decision,
) {
    if let Some(line) = format_guard_decision(pid, executable, target_path, access, decision) {
        eprintln!("{line}");
    }
}

fn run_prompt_worker(
    prompt: &dyn Prompt,
    job_receiver: Receiver<PromptJob>,
    completion_sender: Sender<PromptCompletion>,
    mut wake_writer: UnixStream,
) -> Result<()> {
    while let Ok(job) = job_receiver.recv() {
        let completion = PromptCompletion {
            id: job.id,
            outcome: resolve_prompt_job(prompt, &job),
        };
        if completion_sender.send(completion).is_err() {
            return Ok(());
        }
        if let Err(error) = wake_writer.write_all(&[PROMPT_WAKE_BYTE]) {
            if error.kind() == ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(error).context("notifying guard loop of prompt completion");
        }
    }

    Ok(())
}

fn resolve_prompt_job(prompt: &dyn Prompt, job: &PromptJob) -> PromptOutcome {
    let helper_is_stale = job
        .key
        .as_ref()
        .is_some_and(|key| !key.is_current_process());
    let owner_is_stale = job
        .authorization
        .as_ref()
        .is_some_and(|authorization| !authorization.owner_is_current());
    if helper_is_stale || owner_is_stale {
        return PromptOutcome::Failure;
    }

    let request = PromptRequest {
        subject: &job.subject,
        target_path: &job.target_path,
        reason: job.reason,
        default_decision: job.default_decision.clone(),
        env: job.env.clone(),
        authorization: job.authorization.as_ref(),
    };
    ask_prompt(prompt, &request)
}

fn respond_with_decision(
    fanotify_fd: RawFd,
    events: Vec<PendingEvent>,
    decision: Decision,
) -> Result<()> {
    respond_to_events(events, |event| {
        respond_and_close_event(fanotify_fd, event.fd, event.mask, decision.clone())
    })
}

fn respond_with_defaults(fanotify_fd: RawFd, events: Vec<PendingEvent>) -> Result<()> {
    respond_to_events(events, |event| {
        respond_and_close_event(fanotify_fd, event.fd, event.mask, event.default_decision)
    })
}

fn respond_to_events(
    events: Vec<PendingEvent>,
    mut respond: impl FnMut(PendingEvent) -> Result<()>,
) -> Result<()> {
    let mut first_error = None;

    for event in events {
        if let Err(error) = respond(event)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
