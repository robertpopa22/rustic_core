//! Lock files in restic's format.
//!
//! rustic itself is lock-free. When restic and rustic share a repository, rustic reads
//! restic's locks so that it does not run an operation that restic would refuse, and it can
//! (opt-in) write restic-compatible locks itself, so that restic sees rustic too.

use std::{
    str::FromStr,
    sync::{
        Arc, Mutex,
        mpsc::{self, RecvTimeoutError},
    },
    thread::JoinHandle,
    time::Duration,
};

use jiff::{SignedDuration, Timestamp};
use log::{debug, warn};
use serde::{Deserialize, Serialize};

use crate::{
    backend::{
        FileType, ReadBackend, WriteBackend,
        decrypt::{DecryptBackend, DecryptReadBackend, DecryptWriteBackend},
    },
    crypto::aespoly1305::Key,
    error::{ErrorKind, RusticError, RusticResult},
    id::Id,
};

/// After this time without refresh, restic considers a lock stale (restic `staleTimeout`).
pub const LOCK_STALE_TIMEOUT: SignedDuration = SignedDuration::from_mins(30);

/// restic refreshes its locks this often (restic `refreshInterval`).
pub const LOCK_REFRESH_INTERVAL: Duration = Duration::from_mins(5);

/// restic waits this long after creating a lock before checking for other locks again
/// (restic `waitBeforeLockCheck`), so that two clients locking at the same time see each other.
const WAIT_BEFORE_LOCK_CHECK: Duration = Duration::from_millis(200);

/// A lock file in the `locks/` directory, in restic's format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockFile {
    /// Time the lock was created or last refreshed (RFC 3339)
    pub time: String,
    /// Whether the lock is exclusive (e.g. held by `restic prune`)
    #[serde(default)]
    pub exclusive: bool,
    /// Host which holds the lock
    #[serde(default)]
    pub hostname: String,
    /// User who holds the lock
    #[serde(default)]
    pub username: String,
    /// Process ID which holds the lock
    #[serde(default)]
    pub pid: i64,
    /// User ID which holds the lock (0 on Windows)
    #[serde(default)]
    pub uid: u32,
    /// Group ID which holds the lock (0 on Windows)
    #[serde(default)]
    pub gid: u32,
}

impl LockFile {
    /// A lock for the current process, created now.
    #[must_use]
    pub fn new_for_this_process(exclusive: bool) -> Self {
        let hostname = gethostname::gethostname().to_string_lossy().to_string();
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_default();
        Self {
            time: Timestamp::now().to_string(),
            exclusive,
            hostname,
            username,
            pid: i64::from(std::process::id()),
            uid: current_uid(),
            gid: current_gid(),
        }
    }

    /// Returns true if restic would consider this lock stale at time `now`.
    ///
    /// restic also treats a lock from the same host whose process is gone as stale; rustic
    /// does not check processes and only uses the timeout, which is the more cautious
    /// choice. A lock with an unreadable time is never considered stale.
    #[must_use]
    pub fn is_stale(&self, now: Timestamp) -> bool {
        Timestamp::from_str(&self.time)
            .is_ok_and(|time| now.duration_since(time) > LOCK_STALE_TIMEOUT)
    }
}

#[cfg(unix)]
fn current_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}
#[cfg(unix)]
fn current_gid() -> u32 {
    nix::unistd::getgid().as_raw()
}
#[cfg(not(unix))]
const fn current_uid() -> u32 {
    0
}
#[cfg(not(unix))]
const fn current_gid() -> u32 {
    0
}

/// Read one lock file. Returns `None` for an empty file (restic skips those).
fn read_lock(be: &DecryptBackend<Key>, id: &Id, size: u32) -> Option<RusticResult<LockFile>> {
    if size == 0 {
        return None;
    }
    Some(be.read_encrypted_full(FileType::Lock, id).and_then(|data| {
        serde_json::from_slice(&data).map_err(|err| {
            RusticError::with_source(
                ErrorKind::Repository,
                "Could not read lock file `{id}`. Remove it with `rustic unlock` or `restic unlock` if it is stale, or use --ignore-restic-locks.",
                err,
            )
            .attach_context("id", id.to_string())
        })
    }))
}

/// Check the lock files in the repository, ignoring the lock files in `own`.
///
/// An `exclusive` operation is refused if any other lock exists; a non-exclusive operation
/// is refused if an exclusive lock exists. As in restic, stale locks also refuse until they
/// are removed, empty lock files are ignored, and a lock file that cannot be read refuses.
///
/// # Errors
///
/// * If a blocking lock exists, or the lock files cannot be listed or read.
pub(crate) fn check_locks(
    be: &DecryptBackend<Key>,
    exclusive: bool,
    own: &[Id],
) -> RusticResult<()> {
    let now = Timestamp::now();
    for (id, size) in be.list_with_size(FileType::Lock)? {
        if own.contains(&id) {
            continue;
        }
        let Some(lock) = read_lock(be, &id, size) else {
            continue;
        };
        let lock = lock?;
        if !(exclusive || lock.exclusive) {
            continue;
        }
        let stale = if lock.is_stale(now) {
            " It looks stale (older than 30 minutes); if no restic or rustic process is running, remove it with `rustic unlock` or `restic unlock`."
        } else {
            ""
        };
        return Err(RusticError::new(
            ErrorKind::Repository,
            "The repository is locked ({kind} lock {id}, created at {time} by {user}@{host}, PID {pid}). Wait for the other process to finish, or use --ignore-restic-locks if you know what you are doing.{stale}",
        )
        .attach_context("kind", if lock.exclusive { "exclusive" } else { "non-exclusive" })
        .attach_context("id", id.to_string())
        .attach_context("time", lock.time)
        .attach_context("user", lock.username)
        .attach_context("host", lock.hostname)
        .attach_context("pid", lock.pid.to_string())
        .attach_context("stale", stale));
    }
    Ok(())
}

/// Remove lock files: all of them if `all`, else only stale and unreadable ones, like
/// `restic unlock`. Lock files in `own` are never removed. Returns the number removed.
///
/// # Errors
///
/// * If the lock files cannot be listed or removed.
pub(crate) fn remove_locks(be: &DecryptBackend<Key>, all: bool, own: &[Id]) -> RusticResult<usize> {
    let now = Timestamp::now();
    let mut removed = 0;
    for (id, size) in be.list_with_size(FileType::Lock)? {
        if own.contains(&id) {
            continue;
        }
        let remove = all
            || match read_lock(be, &id, size) {
                None => false,
                Some(Err(_)) => true,
                Some(Ok(lock)) => lock.is_stale(now),
            };
        if remove {
            be.remove(FileType::Lock, &id, false)?;
            debug!("removed lock {id}");
            removed += 1;
        }
    }
    Ok(removed)
}

/// Locks held by this process; refreshed in the background and removed when dropped.
struct Held {
    be: DecryptBackend<Key>,
    locks: Mutex<Vec<(Id, LockFile)>>,
}

impl Held {
    fn ids(&self) -> Vec<Id> {
        self.locks
            .lock()
            .map(|l| l.iter().map(|(id, _)| *id).collect())
            .unwrap_or_default()
    }

    fn write(&self, lock: &LockFile) -> RusticResult<Id> {
        let data = serde_json::to_vec(lock).map_err(|err| {
            RusticError::with_source(ErrorKind::Internal, "Failed to serialize lock.", err)
        })?;
        self.be.hash_write_full(FileType::Lock, &data)
    }

    /// Create a lock and check for conflicting locks, like restic: check, create, wait, check
    /// again. On conflict, the new lock is removed again.
    fn add(&self, exclusive: bool) -> RusticResult<()> {
        let own = self.ids();
        check_locks(&self.be, exclusive, &own)?;
        let lock = LockFile::new_for_this_process(exclusive);
        let id = self.write(&lock)?;
        std::thread::sleep(WAIT_BEFORE_LOCK_CHECK);
        let mut own = own;
        own.push(id);
        if let Err(err) = check_locks(&self.be, exclusive, &own) {
            if let Err(err) = self.be.remove(FileType::Lock, &id, false) {
                warn!("could not remove lock {id}: {err}");
            }
            return Err(err);
        }
        debug!("created {} lock {id}", if exclusive { "exclusive" } else { "non-exclusive" });
        if let Ok(mut locks) = self.locks.lock() {
            locks.push((id, lock));
        }
        Ok(())
    }

    /// Write every held lock again with the current time and remove the old file, like
    /// restic's refresh.
    fn refresh(&self) {
        let Ok(mut locks) = self.locks.lock() else {
            return;
        };
        for (id, lock) in locks.iter_mut() {
            let mut new = lock.clone();
            new.time = Timestamp::now().to_string();
            match self.write(&new) {
                Ok(new_id) => {
                    if let Err(err) = self.be.remove(FileType::Lock, id, false) {
                        warn!("could not remove old lock {id}: {err}");
                    }
                    debug!("refreshed lock {id} as {new_id}");
                    *id = new_id;
                    *lock = new;
                }
                Err(err) => warn!("could not refresh lock {id}: {err}"),
            }
        }
    }

    fn remove_all(&self) {
        let Ok(mut locks) = self.locks.lock() else {
            return;
        };
        for (id, _) in locks.drain(..) {
            match self.be.remove(FileType::Lock, &id, false) {
                Ok(()) => debug!("removed lock {id}"),
                Err(err) => warn!("could not remove lock {id}: {err}; remove it with `rustic unlock`"),
            }
        }
    }
}

/// restic-compatible locks held by this process for one open repository.
///
/// Created with a non-exclusive lock; [`ResticLocks::exclusive`] adds an exclusive one before
/// an operation that restic runs exclusively. Locks are refreshed every 5 minutes and removed
/// when this value is dropped.
pub struct ResticLocks {
    held: Arc<Held>,
    stop: Option<mpsc::Sender<()>>,
    refresher: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ResticLocks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResticLocks")
            .field("locks", &self.held.ids())
            .finish_non_exhaustive()
    }
}

impl ResticLocks {
    /// Lock the repository like restic: create a lock, check for conflicting locks.
    ///
    /// # Errors
    ///
    /// * If a conflicting lock exists, or the lock cannot be written.
    pub(crate) fn acquire(be: DecryptBackend<Key>, exclusive: bool) -> RusticResult<Self> {
        let held = Arc::new(Held {
            be,
            locks: Mutex::new(Vec::new()),
        });
        held.add(exclusive)?;
        let (stop, rx) = mpsc::channel::<()>();
        let refresh = Arc::clone(&held);
        let refresher = std::thread::spawn(move || {
            while let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(LOCK_REFRESH_INTERVAL) {
                refresh.refresh();
            }
        });
        Ok(Self {
            held,
            stop: Some(stop),
            refresher: Some(refresher),
        })
    }

    /// Make sure an exclusive lock is held, adding one if needed.
    ///
    /// # Errors
    ///
    /// * If another lock exists, or the lock cannot be written.
    pub(crate) fn exclusive(&self) -> RusticResult<()> {
        let has_exclusive = self
            .held
            .locks
            .lock()
            .is_ok_and(|l| l.iter().any(|(_, lock)| lock.exclusive));
        if has_exclusive {
            return Ok(());
        }
        self.held.add(true)
    }

    /// Ids of the lock files held by this process.
    #[must_use]
    pub fn ids(&self) -> Vec<Id> {
        self.held.ids()
    }
}

impl Drop for ResticLocks {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(handle) = self.refresher.take() {
            _ = handle.join();
        }
        self.held.remove_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_restic_lock_and_detects_staleness() {
        let json = r#"{"time":"2026-11-12T19:31:11.1234567+02:00","exclusive":false,"hostname":"h","username":"u","pid":42,"uid":0,"gid":0}"#;
        let lock: LockFile = serde_json::from_str(json).unwrap();
        assert!(!lock.exclusive);
        assert_eq!(lock.pid, 42);
        let t: Timestamp = "2026-11-12T17:31:11Z".parse().unwrap();
        assert!(!lock.is_stale(t + SignedDuration::from_mins(29)));
        assert!(lock.is_stale(t + SignedDuration::from_mins(31)));
    }

    #[test]
    fn unreadable_time_is_never_stale() {
        let mut lock = LockFile::new_for_this_process(true);
        lock.time = "garbage".into();
        assert!(!lock.is_stale(Timestamp::now()));
    }

    #[test]
    fn own_lock_is_rfc3339_and_fresh() {
        let lock = LockFile::new_for_this_process(false);
        let json = serde_json::to_string(&lock).unwrap();
        assert!(json.contains(r#""time":""#) && json.contains(r#""uid":"#));
        assert!(lock.time.ends_with('Z'));
        assert!(!lock.is_stale(Timestamp::now()));
        assert_eq!(lock.pid, i64::from(std::process::id()));
    }
}
