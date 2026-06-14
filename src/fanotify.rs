use crate::policy::{AccessKind, Decision, Policy};
use crate::process::inspect_process;
use crate::prompt::{Prompt, PromptRequest};
use anyhow::{Context, Result, anyhow};
use libc::{
    AT_FDCWD, FAN_ACCESS_PERM, FAN_ALLOW, FAN_CLASS_CONTENT, FAN_CLOEXEC, FAN_CLOSE_WRITE,
    FAN_DENY, FAN_EVENT_ON_CHILD, FAN_MARK_ADD, FAN_OPEN_PERM, O_CLOEXEC, O_RDONLY, c_void, close,
    fanotify_event_metadata, fanotify_response, read, write,
};
use std::ffi::CString;
use std::fs;
use std::mem;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

const EVENT_BUFFER_SIZE: usize = 8192;

pub enum Mode<'a> {
    Audit,
    Guard {
        policy: &'a Policy,
        prompt: &'a dyn Prompt,
    },
}

pub fn run(path: &Path, mode: Mode<'_>) -> Result<()> {
    let fanotify_fd = create_fanotify_fd()?;
    mark_path(fanotify_fd, path)?;
    eprintln!("watching {}", path.display());

    loop {
        read_events(fanotify_fd, &mode)?;
    }
}

fn create_fanotify_fd() -> Result<RawFd> {
    let event_flags = (O_RDONLY | O_CLOEXEC) as u32;
    let fd = unsafe { libc::fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, event_flags) };

    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("fanotify_init failed; permission events usually require CAP_SYS_ADMIN");
    }

    Ok(fd)
}

fn mark_path(fanotify_fd: RawFd, path: &Path) -> Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .context("watch path contains an interior nul byte")?;
    let mask = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD;
    let result =
        unsafe { libc::fanotify_mark(fanotify_fd, FAN_MARK_ADD, mask, AT_FDCWD, path.as_ptr()) };

    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("fanotify_mark failed");
    }

    Ok(())
}

fn read_events(fanotify_fd: RawFd, mode: &Mode<'_>) -> Result<()> {
    let mut buffer = [0u8; EVENT_BUFFER_SIZE];
    let bytes_read = unsafe {
        read(
            fanotify_fd,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.len(),
        )
    };

    if bytes_read < 0 {
        return Err(std::io::Error::last_os_error()).context("reading fanotify events failed");
    }

    handle_event_buffer(fanotify_fd, &buffer[..bytes_read as usize], mode)
}

fn handle_event_buffer(fanotify_fd: RawFd, buffer: &[u8], mode: &Mode<'_>) -> Result<()> {
    let mut offset = 0;

    while offset + mem::size_of::<fanotify_event_metadata>() <= buffer.len() {
        let metadata = read_metadata(buffer, offset);

        if metadata.event_len == 0 {
            break;
        }

        handle_event(fanotify_fd, &metadata, mode)?;
        offset += metadata.event_len as usize;
    }

    Ok(())
}

fn read_metadata(buffer: &[u8], offset: usize) -> fanotify_event_metadata {
    unsafe { std::ptr::read_unaligned(buffer[offset..].as_ptr().cast()) }
}

fn handle_event(
    fanotify_fd: RawFd,
    metadata: &fanotify_event_metadata,
    mode: &Mode<'_>,
) -> Result<()> {
    if metadata.fd < 0 {
        return Ok(());
    }

    let target_path = event_target_path(metadata.fd).unwrap_or_else(|_| PathBuf::from("<unknown>"));
    let decision = decide_event(metadata, &target_path, mode)?;

    respond_to_permission_event(fanotify_fd, metadata, decision)?;
    unsafe {
        close(metadata.fd);
    }

    Ok(())
}

fn decide_event(
    metadata: &fanotify_event_metadata,
    target_path: &Path,
    mode: &Mode<'_>,
) -> Result<Decision> {
    let access = access_kind(metadata.mask);
    let process = match inspect_process(metadata.pid) {
        Ok(process) => process,
        Err(error) => {
            eprintln!(
                "ALLOW fail-open pid={} access={:?} path={} reason={error:#}",
                metadata.pid,
                access,
                target_path.display()
            );
            return Ok(Decision::Allow);
        }
    };

    match mode {
        Mode::Audit => {
            eprintln!(
                "ALLOW audit pid={} exe={} access={:?} path={}",
                metadata.pid,
                process
                    .executable
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<unknown>".to_string()),
                access,
                target_path.display()
            );
            Ok(Decision::Allow)
        }
        Mode::Guard { policy, prompt } => {
            let subject = process.subject();
            let policy_decision = policy.decide(&subject, target_path, access);
            resolve_policy_decision(*prompt, &subject, target_path, policy_decision)
        }
    }
}

fn resolve_policy_decision(
    prompt: &dyn Prompt,
    subject: &crate::policy::ProcessSubject,
    target_path: &Path,
    decision: Decision,
) -> Result<Decision> {
    match decision {
        Decision::Prompt { reason, default } => prompt.ask(&PromptRequest {
            subject,
            target_path,
            reason,
            default_decision: *default,
        }),
        other => Ok(other),
    }
}

fn respond_to_permission_event(
    fanotify_fd: RawFd,
    metadata: &fanotify_event_metadata,
    decision: Decision,
) -> Result<()> {
    if !is_permission_event(metadata.mask) {
        return Ok(());
    }

    let response = fanotify_response {
        fd: metadata.fd,
        response: response_code(decision),
    };
    let written = unsafe {
        write(
            fanotify_fd,
            (&response as *const fanotify_response).cast::<c_void>(),
            mem::size_of::<fanotify_response>(),
        )
    };

    if written < 0 {
        return Err(std::io::Error::last_os_error()).context("writing fanotify response failed");
    }

    Ok(())
}

fn event_target_path(event_fd: RawFd) -> Result<PathBuf> {
    fs::read_link(format!("/proc/self/fd/{event_fd}"))
        .with_context(|| format!("resolving fanotify event fd {event_fd}"))
}

fn access_kind(mask: u64) -> AccessKind {
    if mask & FAN_CLOSE_WRITE != 0 {
        AccessKind::Write
    } else {
        AccessKind::Read
    }
}

fn is_permission_event(mask: u64) -> bool {
    mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM) != 0
}

fn response_code(decision: Decision) -> u32 {
    match decision {
        Decision::Allow => FAN_ALLOW,
        Decision::Deny => FAN_DENY,
        Decision::Prompt { .. } => FAN_ALLOW,
    }
}

pub fn ensure_path_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(anyhow!("watch path does not exist: {}", path.display()));
    }

    Ok(())
}
