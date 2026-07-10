use super::{AuditObjectId, ProcessGeneration};
use anyhow::{Context, Result, anyhow};
use libc::{close, fanotify_event_metadata};
use std::fs;
use std::mem;
use std::os::fd::RawFd;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

const FAN_EVENT_INFO_TYPE_PIDFD: u8 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct FanotifyEventInfoHeader {
    info_type: u8,
    pad: u8,
    len: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FanotifyEventInfoPidfd {
    header: FanotifyEventInfoHeader,
    pidfd: i32,
}

pub(super) fn read_metadata(buffer: &[u8], offset: usize) -> fanotify_event_metadata {
    unsafe { std::ptr::read_unaligned(buffer[offset..].as_ptr().cast()) }
}

pub(super) fn process_generation(
    event: &[u8],
    metadata: &fanotify_event_metadata,
) -> Result<Option<ProcessGeneration>> {
    let mut offset = metadata.metadata_len as usize;
    while offset < event.len() {
        let remaining = &event[offset..];
        if remaining.len() < mem::size_of::<FanotifyEventInfoHeader>() {
            return Err(anyhow!("truncated fanotify event information header"));
        }
        let header: FanotifyEventInfoHeader =
            unsafe { std::ptr::read_unaligned(remaining.as_ptr().cast()) };
        let info_len = header.len as usize;
        if info_len < mem::size_of::<FanotifyEventInfoHeader>() || info_len > remaining.len() {
            return Err(anyhow!(
                "invalid fanotify event information length: {info_len}"
            ));
        }
        if header.info_type == FAN_EVENT_INFO_TYPE_PIDFD {
            if info_len < mem::size_of::<FanotifyEventInfoPidfd>() {
                return Err(anyhow!("truncated fanotify pidfd information"));
            }
            let info: FanotifyEventInfoPidfd =
                unsafe { std::ptr::read_unaligned(remaining.as_ptr().cast()) };
            return generation_from_pidfd(metadata.pid, info.pidfd);
        }
        offset += info_len;
    }

    Ok(None)
}

fn generation_from_pidfd(pid: i32, pidfd: RawFd) -> Result<Option<ProcessGeneration>> {
    if pidfd < 0 {
        return Ok(None);
    }

    let generation = match ProcessGeneration::from_pidfd(pidfd) {
        Ok(generation) => Some(generation),
        Err(error) => {
            eprintln!(
                "IDENTITY process generation unavailable pid={pid} reason={error:#}; executable fallback disabled"
            );
            None
        }
    };
    close_descriptor(pidfd)?;
    Ok(generation)
}

pub(super) fn target_path(event_fd: RawFd) -> Result<PathBuf> {
    fs::read_link(format!("/proc/self/fd/{event_fd}"))
        .with_context(|| format!("resolving fanotify event fd {event_fd}"))
}

pub(super) fn object_id(event_fd: RawFd) -> Result<AuditObjectId> {
    let metadata = fs::metadata(format!("/proc/self/fd/{event_fd}"))
        .with_context(|| format!("reading object identity for fanotify descriptor {event_fd}"))?;
    Ok(AuditObjectId::new(metadata.dev(), metadata.ino()))
}

pub(super) fn close_descriptor(event_fd: RawFd) -> Result<()> {
    if unsafe { close(event_fd) } < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("closing fanotify event descriptor {event_fd}"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FAN_EVENT_INFO_TYPE_PIDFD, FanotifyEventInfoHeader, FanotifyEventInfoPidfd,
        process_generation,
    };
    use crate::fanotify::ProcessGeneration;
    use std::{mem, slice};

    fn pidfd_event(pid: i32, pidfd: i32) -> (Vec<u8>, libc::fanotify_event_metadata) {
        let metadata_len = mem::size_of::<libc::fanotify_event_metadata>();
        let info = FanotifyEventInfoPidfd {
            header: FanotifyEventInfoHeader {
                info_type: FAN_EVENT_INFO_TYPE_PIDFD,
                pad: 0,
                len: mem::size_of::<FanotifyEventInfoPidfd>() as u16,
            },
            pidfd,
        };
        let mut event = vec![0; metadata_len];
        let info_bytes = unsafe {
            slice::from_raw_parts(
                (&info as *const FanotifyEventInfoPidfd).cast::<u8>(),
                mem::size_of::<FanotifyEventInfoPidfd>(),
            )
        };
        event.extend_from_slice(info_bytes);
        let metadata = libc::fanotify_event_metadata {
            event_len: event.len() as u32,
            vers: 3,
            reserved: 0,
            metadata_len: metadata_len as u16,
            mask: 0,
            fd: -1,
            pid,
        };
        (event, metadata)
    }

    #[test]
    fn extracts_process_generation_from_pidfd_information() {
        let first = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 };
        let second = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 };
        assert!(first >= 0 && second >= 0);
        let expected = ProcessGeneration::from_pidfd(second).expect("expected generation");
        unsafe { libc::close(second) };
        let (event, metadata) = pidfd_event(unsafe { libc::getpid() }, first);

        let actual = process_generation(&event, &metadata).expect("parse pidfd information");

        assert_eq!(actual, Some(expected));
    }

    #[test]
    fn unavailable_pidfd_disables_process_generation_fallback() {
        let (event, metadata) = pidfd_event(42, -1);

        assert_eq!(
            process_generation(&event, &metadata).expect("parse unavailable pidfd"),
            None
        );
    }
}
