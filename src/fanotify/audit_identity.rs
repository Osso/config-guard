use crate::process::ProcessIdentity;
use std::collections::{HashMap, VecDeque};

const DEFAULT_CAPACITY: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct AuditObjectId {
    device: u64,
    inode: u64,
}

impl AuditObjectId {
    pub(super) fn new(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AuditIdentityKey {
    pid: i32,
    object: AuditObjectId,
}

pub(super) struct AuditIdentityCache {
    capacity: usize,
    entry_count: usize,
    identities: HashMap<AuditIdentityKey, VecDeque<ProcessIdentity>>,
    insertion_order: VecDeque<AuditIdentityKey>,
}

impl Default for AuditIdentityCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl AuditIdentityCache {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            entry_count: 0,
            identities: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    pub(super) fn insert(&mut self, pid: i32, object: AuditObjectId, identity: ProcessIdentity) {
        if self.capacity == 0 {
            return;
        }

        let key = AuditIdentityKey { pid, object };
        let generation_changed = self
            .identities
            .get(&key)
            .and_then(|identities| identities.back())
            .is_some_and(|cached| cached.start_time_ticks != identity.start_time_ticks);
        if generation_changed {
            self.invalidate_key(&key);
        }

        self.evict_oldest_if_full();
        self.identities
            .entry(key.clone())
            .or_default()
            .push_back(identity);
        self.insertion_order.push_back(key);
        self.entry_count += 1;
    }

    pub(super) fn take(&mut self, pid: i32, object: AuditObjectId) -> Option<ProcessIdentity> {
        let key = AuditIdentityKey { pid, object };
        let identity = self
            .identities
            .get_mut(&key)
            .and_then(VecDeque::pop_front)?;
        self.remove_first_order_entry(&key);
        self.entry_count -= 1;
        if self.identities.get(&key).is_some_and(VecDeque::is_empty) {
            self.identities.remove(&key);
        }

        Some(identity)
    }

    pub(super) fn invalidate(&mut self, pid: i32, object: AuditObjectId) {
        let key = AuditIdentityKey { pid, object };
        self.invalidate_key(&key);
    }

    fn invalidate_key(&mut self, key: &AuditIdentityKey) {
        if let Some(identities) = self.identities.remove(key) {
            self.entry_count -= identities.len();
        }
        self.insertion_order.retain(|queued| queued != key);
    }

    fn evict_oldest_if_full(&mut self) {
        while self.entry_count >= self.capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            if let Some(identities) = self.identities.get_mut(&oldest) {
                if identities.pop_front().is_some() {
                    self.entry_count -= 1;
                }
                if identities.is_empty() {
                    self.identities.remove(&oldest);
                }
            }
        }
    }

    fn remove_first_order_entry(&mut self, key: &AuditIdentityKey) {
        if let Some(position) = self.insertion_order.iter().position(|queued| queued == key) {
            self.insertion_order.remove(position);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AuditIdentityCache, AuditObjectId};
    use crate::process::ProcessIdentity;
    use std::path::PathBuf;

    fn object(inode: u64) -> AuditObjectId {
        AuditObjectId::new(1, inode)
    }

    fn identity(pid: i32, executable: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            executable: Some(PathBuf::from(executable)),
            command: vec![executable.to_string()],
            cwd: None,
            start_time_ticks: Some(pid as u64),
            ancestors: Vec::new(),
            ancestor_processes: Vec::new(),
        }
    }

    #[test]
    fn remembers_identity_from_open_until_close_decision() {
        let mut cache = AuditIdentityCache::with_capacity(2);
        cache.insert(42, object(10), identity(42, "/usr/bin/journalctl"));

        let cached = cache.take(42, object(10)).expect("cached identity");

        assert_eq!(
            cached.executable,
            Some(PathBuf::from("/usr/bin/journalctl"))
        );
        assert!(cache.take(42, object(10)).is_none());
    }

    #[test]
    fn evicts_oldest_identity_when_capacity_is_reached() {
        let mut cache = AuditIdentityCache::with_capacity(2);
        cache.insert(1, object(1), identity(1, "/usr/bin/one"));
        cache.insert(2, object(2), identity(2, "/usr/bin/two"));
        cache.insert(3, object(3), identity(3, "/usr/bin/three"));

        assert!(cache.take(1, object(1)).is_none());
        assert!(cache.take(2, object(2)).is_some());
        assert!(cache.take(3, object(3)).is_some());
    }

    #[test]
    fn queues_concurrent_opens_from_the_same_process_generation() {
        let mut cache = AuditIdentityCache::with_capacity(3);
        let object = object(7);
        cache.insert(7, object, identity(7, "/usr/bin/first"));
        cache.insert(7, object, identity(7, "/usr/bin/second"));

        assert_eq!(
            cache.take(7, object).and_then(|value| value.executable),
            Some(PathBuf::from("/usr/bin/first"))
        );
        assert_eq!(
            cache.take(7, object).and_then(|value| value.executable),
            Some(PathBuf::from("/usr/bin/second"))
        );
    }

    #[test]
    fn new_process_generation_replaces_stale_identity() {
        let mut cache = AuditIdentityCache::with_capacity(3);
        let object = object(9);
        let mut old = identity(9, "/usr/bin/old");
        old.start_time_ticks = Some(100);
        let mut new = identity(9, "/usr/bin/new");
        new.start_time_ticks = Some(200);
        cache.insert(9, object, old);
        cache.insert(9, object, new);

        assert_eq!(
            cache.take(9, object).and_then(|value| value.executable),
            Some(PathBuf::from("/usr/bin/new"))
        );
        assert!(cache.take(9, object).is_none());
    }

    #[test]
    fn invalidation_removes_identity_after_failed_open_inspection() {
        let mut cache = AuditIdentityCache::with_capacity(2);
        let object = object(11);
        cache.insert(11, object, identity(11, "/usr/bin/stale"));

        cache.invalidate(11, object);

        assert!(cache.take(11, object).is_none());
    }
}
