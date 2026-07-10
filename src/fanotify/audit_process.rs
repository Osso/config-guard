use crate::process::ProcessIdentity;
use anyhow::{Context, Result};
use std::collections::{HashMap, VecDeque};
use std::mem::MaybeUninit;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

const DEFAULT_CAPACITY: usize = 4096;
const DEFAULT_TTL: Duration = Duration::from_secs(30);
const PID_FS_MAGIC: libc::c_long = 0x5049_4446;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct ProcessGeneration {
    device: u64,
    inode: u64,
}

impl ProcessGeneration {
    fn new(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }

    pub(super) fn from_pidfd(pidfd: RawFd) -> Result<Self> {
        validate_pidfs(pidfd)?;

        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(pidfd, stat.as_mut_ptr()) } < 0 {
            return Err(std::io::Error::last_os_error())
                .context("reading process generation from pidfd");
        }
        let stat = unsafe { stat.assume_init() };
        Ok(Self::new(stat.st_dev, stat.st_ino))
    }
}

fn validate_pidfs(pidfd: RawFd) -> Result<()> {
    let mut statfs = MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(pidfd, statfs.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error()).context("reading pidfd filesystem type");
    }
    let statfs = unsafe { statfs.assume_init() };
    ensure_pidfs_magic(statfs.f_type)
}

fn ensure_pidfs_magic(actual_magic: libc::c_long) -> Result<()> {
    if actual_magic != PID_FS_MAGIC {
        return Err(anyhow::anyhow!(
            "pidfd is not backed by pidfs: filesystem magic={actual_magic:#x} expected={PID_FS_MAGIC:#x}"
        ));
    }

    Ok(())
}

struct CachedIdentity {
    identity: ProcessIdentity,
    recorded_at: Instant,
}

pub(super) struct AuditProcessCache {
    capacity: usize,
    ttl: Duration,
    identities: HashMap<ProcessGeneration, CachedIdentity>,
    insertion_order: VecDeque<ProcessGeneration>,
}

impl Default for AuditProcessCache {
    fn default() -> Self {
        Self::with_limits(DEFAULT_CAPACITY, DEFAULT_TTL)
    }
}

impl AuditProcessCache {
    fn with_limits(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity,
            ttl,
            identities: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    #[cfg(not(coverage))]
    pub(super) fn insert_exec(&mut self, generation: ProcessGeneration, identity: ProcessIdentity) {
        self.insert_exec_at(generation, identity, Instant::now());
    }

    #[cfg(not(coverage))]
    pub(super) fn get(&mut self, generation: ProcessGeneration) -> Option<ProcessIdentity> {
        self.get_at(generation, Instant::now())
    }

    fn insert_exec_at(
        &mut self,
        generation: ProcessGeneration,
        identity: ProcessIdentity,
        now: Instant,
    ) {
        let keep_existing_main = is_dynamic_loader(&identity)
            && self
                .get_at(generation, now)
                .is_some_and(|cached| !is_dynamic_loader(&cached));
        if keep_existing_main {
            return;
        }

        self.insert_at(generation, identity, now);
    }

    fn insert_at(
        &mut self,
        generation: ProcessGeneration,
        identity: ProcessIdentity,
        now: Instant,
    ) {
        if self.capacity == 0 {
            return;
        }
        self.remove(generation);
        self.evict_oldest_if_full();
        self.identities.insert(
            generation,
            CachedIdentity {
                identity,
                recorded_at: now,
            },
        );
        self.insertion_order.push_back(generation);
    }

    fn get_at(&mut self, generation: ProcessGeneration, now: Instant) -> Option<ProcessIdentity> {
        let expired = self
            .identities
            .get(&generation)
            .is_some_and(|cached| now.duration_since(cached.recorded_at) > self.ttl);
        if expired {
            self.remove(generation);
            return None;
        }

        self.identities
            .get(&generation)
            .map(|cached| cached.identity.clone())
    }

    fn evict_oldest_if_full(&mut self) {
        while self.identities.len() >= self.capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.identities.remove(&oldest);
        }
    }

    fn remove(&mut self, generation: ProcessGeneration) {
        self.identities.remove(&generation);
        if let Some(position) = self
            .insertion_order
            .iter()
            .position(|queued| *queued == generation)
        {
            self.insertion_order.remove(position);
        }
    }
}

fn is_dynamic_loader(identity: &ProcessIdentity) -> bool {
    identity
        .executable
        .as_deref()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.starts_with("ld-linux") || name.starts_with("ld-musl") || name == "ld.so"
        })
}

#[cfg(test)]
mod tests {
    use super::{AuditProcessCache, PID_FS_MAGIC, ProcessGeneration, ensure_pidfs_magic};
    use crate::process::ProcessIdentity;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn identity(pid: i32, executable: &str) -> ProcessIdentity {
        ProcessIdentity::from_executable(pid, PathBuf::from(executable))
    }

    fn generation(inode: u64) -> ProcessGeneration {
        ProcessGeneration::new(6, inode)
    }

    #[test]
    fn rejects_pidfds_not_backed_by_pidfs() {
        let error = ensure_pidfs_magic(PID_FS_MAGIC + 1).expect_err("reject non-pidfs fd");

        assert!(error.to_string().contains("pidfd is not backed by pidfs"));
    }

    #[test]
    fn pidfds_for_same_process_have_same_generation() {
        let first = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 };
        let second = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 };
        assert!(first >= 0 && second >= 0);

        let first_generation =
            ProcessGeneration::from_pidfd(first).expect("first pidfd generation");
        let second_generation =
            ProcessGeneration::from_pidfd(second).expect("second pidfd generation");
        unsafe {
            libc::close(first);
            libc::close(second);
        }

        assert_eq!(first_generation, second_generation);
    }

    #[test]
    fn pidfds_for_different_processes_have_different_generations() {
        let mut child = Command::new("sleep")
            .arg("10")
            .spawn()
            .expect("spawn child");
        let current_pidfd =
            unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 };
        let child_pidfd =
            unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as i32, 0) as i32 };
        assert!(current_pidfd >= 0 && child_pidfd >= 0);

        let current_generation =
            ProcessGeneration::from_pidfd(current_pidfd).expect("current generation");
        let child_generation =
            ProcessGeneration::from_pidfd(child_pidfd).expect("child generation");
        unsafe {
            libc::close(current_pidfd);
            libc::close(child_pidfd);
        }
        child.kill().expect("kill child");
        child.wait().expect("wait for child");

        assert_ne!(current_generation, child_generation);
    }

    #[test]
    fn returns_recent_exec_identity_for_short_lived_process() {
        let now = Instant::now();
        let mut cache = AuditProcessCache::with_limits(2, Duration::from_secs(10));
        cache.insert_at(generation(42), identity(42, "/usr/bin/head"), now);

        assert_eq!(
            cache
                .get_at(generation(42), now + Duration::from_secs(1))
                .and_then(|value| value.executable),
            Some(PathBuf::from("/usr/bin/head"))
        );
    }

    #[test]
    fn expired_exec_identity_is_not_reused() {
        let now = Instant::now();
        let mut cache = AuditProcessCache::with_limits(2, Duration::from_secs(10));
        cache.insert_at(generation(42), identity(42, "/usr/bin/old"), now);

        assert!(
            cache
                .get_at(generation(42), now + Duration::from_secs(11))
                .is_none()
        );
    }

    #[test]
    fn dynamic_loader_does_not_overwrite_main_executable() {
        let now = Instant::now();
        let mut cache = AuditProcessCache::with_limits(2, Duration::from_secs(10));
        cache.insert_at(generation(42), identity(42, "/usr/bin/head"), now);
        cache.insert_exec_at(
            generation(42),
            identity(42, "/usr/lib/ld-linux-x86-64.so.2"),
            now + Duration::from_millis(1),
        );

        assert_eq!(
            cache
                .get_at(generation(42), now + Duration::from_secs(1))
                .and_then(|value| value.executable),
            Some(PathBuf::from("/usr/bin/head"))
        );
    }

    #[test]
    fn process_generation_prevents_reused_pid_attribution() {
        let now = Instant::now();
        let mut cache = AuditProcessCache::with_limits(2, Duration::from_secs(10));
        cache.insert_at(generation(100), identity(42, "/usr/bin/old"), now);
        cache.insert_at(
            generation(200),
            identity(42, "/usr/bin/new"),
            now + Duration::from_secs(1),
        );

        assert_eq!(
            cache
                .get_at(generation(200), now + Duration::from_secs(2))
                .and_then(|value| value.executable),
            Some(PathBuf::from("/usr/bin/new"))
        );
        assert_eq!(
            cache
                .get_at(generation(100), now + Duration::from_secs(2))
                .and_then(|value| value.executable),
            Some(PathBuf::from("/usr/bin/old"))
        );
    }

    #[test]
    fn evicts_oldest_generation_when_capacity_is_reached() {
        let now = Instant::now();
        let mut cache = AuditProcessCache::with_limits(2, Duration::from_secs(10));
        cache.insert_at(generation(1), identity(1, "/usr/bin/one"), now);
        cache.insert_at(generation(2), identity(2, "/usr/bin/two"), now);
        cache.insert_at(generation(3), identity(3, "/usr/bin/three"), now);

        assert!(cache.get_at(generation(1), now).is_none());
        assert!(cache.get_at(generation(2), now).is_some());
        assert!(cache.get_at(generation(3), now).is_some());
    }
}
