//! Lock files in restic's format.
//!
//! rustic itself is lock-free. When restic and rustic share a repository, rustic reads
//! restic's locks so that it does not run an operation that restic would refuse, and it can
//! (opt-in) write restic-compatible locks itself, so that restic sees rustic too.

use std::{
    str::FromStr,
    sync::{
        Arc, Mutex, Weak,
        mpsc::{self, RecvTimeoutError},
    },
    thread::JoinHandle,
    time::Duration,
};

use jiff::{SignedDuration, Timestamp};
use log::{debug, error, warn};
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
    /// User ID which holds the lock (omitted when 0, as restic does)
    #[serde(default, skip_serializing_if = "is_zero")]
    pub uid: u32,
    /// Group ID which holds the lock (omitted when 0, as restic does)
    #[serde(default, skip_serializing_if = "is_zero")]
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

    /// Returns true if this lock is older than 30 minutes at time `now`. A lock with an
    /// unreadable time is never considered stale. See also [`LockFile::is_stale_here`].
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


fn is_zero(v: &u32) -> bool {
    *v == 0
}

impl LockFile {
    /// Returns true if `restic unlock` would remove this lock at time `now`: older than 30
    /// minutes, or created on this host by a process which no longer exists. The process
    /// check is done on Unix only; on Windows only the age counts, which is more cautious.
    #[must_use]
    pub fn is_stale_here(&self, now: Timestamp) -> bool {
        if self.is_stale(now) {
            return true;
        }
        let here = gethostname::gethostname().to_string_lossy().to_string();
        self.hostname == here && !process_exists(self.pid)
    }
}

#[cfg(unix)]
fn process_exists(pid: i64) -> bool {
    use nix::{errno::Errno, sys::signal::kill, unistd::Pid};
    let Ok(pid) = i32::try_from(pid) else {
        return true;
    };
    // like restic: signal 0 checks for the process; EPERM means it exists
    !matches!(kill(Pid::from_raw(pid), None), Err(Errno::ESRCH))
}
#[cfg(not(unix))]
const fn process_exists(_pid: i64) -> bool {
    true
}

/// Why a lock check failed.
enum CheckError {
    /// Another lock conflicts: permanent.
    Conflict(Box<RusticError>),
    /// Listing or reading failed: retried, like restic.
    Read(Box<RusticError>),
}

fn read_lock(be: &DecryptBackend<Key>, id: &Id) -> RusticResult<LockFile> {
    let data = be.read_encrypted_full(FileType::Lock, id)?;
    serde_json::from_slice(&data).map_err(|err| {
        RusticError::with_source(ErrorKind::Repository, "Invalid lock file `{id}`.", err)
            .attach_context("id", id.to_string())
    })
}

fn conflict(id: &Id, lock: LockFile, now: Timestamp) -> Box<RusticError> {
    let stale = if lock.is_stale_here(now) {
        " It looks stale; if no restic or rustic process is running, remove it with `rustic unlock` or `restic unlock`."
    } else {
        ""
    };
    RusticError::new(
        ErrorKind::Repository,
        "The repository is locked ({kind} lock {id}, created at {time} by {user}@{host}, PID {pid}). Wait for the other process to finish, or use --ignore-restic-locks if you know what you are doing.{stale}",
    )
    .attach_context("kind", if lock.exclusive { "exclusive" } else { "non-exclusive" })
    .attach_context("id", id.to_string())
    .attach_context("time", lock.time)
    .attach_context("user", lock.username)
    .attach_context("host", lock.hostname)
    .attach_context("pid", lock.pid.to_string())
    .attach_context("stale", stale)
}

/// One pass over the lock files; ids found valid and compatible are added to `checked`.
fn check_once(
    be: &DecryptBackend<Key>,
    exclusive: bool,
    checked: &mut Vec<Id>,
) -> Result<(), CheckError> {
    let now = Timestamp::now();
    let list = be
        .list_with_size(FileType::Lock)
        .map_err(CheckError::Read)?;
    for (id, size) in list {
        // like restic, skip empty files left by an interrupted upload
        if size == 0 || checked.contains(&id) {
            continue;
        }
        let lock = read_lock(be, &id).map_err(CheckError::Read)?;
        if exclusive || lock.exclusive {
            return Err(CheckError::Conflict(conflict(&id, lock, now)));
        }
        checked.push(id);
    }
    Ok(())
}

/// Check the lock files in the repository, ignoring the lock files in `own`.
///
/// An `exclusive` operation is refused if any other lock exists; a non-exclusive operation
/// is refused if an exclusive lock exists. Like restic: stale locks also refuse until they
/// are removed, empty lock files are ignored, and a listing or reading error is retried 3
/// times (after 5, 10 and 20 seconds; a lock may be replaced by its owner's refresh in the
/// meantime) before it refuses.
///
/// # Errors
///
/// * If a conflicting lock exists, or the lock files cannot be listed or read.
pub(crate) fn check_locks(
    be: &DecryptBackend<Key>,
    exclusive: bool,
    own: &[Id],
) -> RusticResult<()> {
    check_locks_with_delay(be, exclusive, own, INITIAL_RETRY_DELAY)
}

fn check_locks_with_delay(
    be: &DecryptBackend<Key>,
    exclusive: bool,
    own: &[Id],
    mut delay: Duration,
) -> RusticResult<()> {
    let mut checked = own.to_vec();
    let mut last = None;
    for attempt in 0..4 {
        if attempt > 0 {
            std::thread::sleep(delay);
            delay *= 2;
        }
        match check_once(be, exclusive, &mut checked) {
            Ok(()) => return Ok(()),
            Err(CheckError::Conflict(err)) => return Err(err),
            Err(CheckError::Read(err)) => {
                debug!("lock check failed, retrying: {err}");
                last = Some(err);
            }
        }
    }
    let err = last.expect("set by the loop");
    Err(RusticError::with_source(
        ErrorKind::Repository,
        "Could not read the lock files. `rustic unlock --remove-all` (or `restic unlock --remove-all`) removes invalid locks; make sure no other process uses the repository before running it.",
        err,
    ))
}

/// Remove lock files like `restic unlock`: those which are stale (see
/// [`LockFile::is_stale_here`]), or all of them if `all` is set. Unreadable lock files are
/// only removed with `all`. Lock files in `own` are never removed. With `dry_run`, nothing is
/// removed. Returns the ids which were (or would be) removed.
///
/// # Errors
///
/// * If the lock files cannot be listed or removed.
pub(crate) fn remove_locks(
    be: &DecryptBackend<Key>,
    all: bool,
    dry_run: bool,
    own: &[Id],
) -> RusticResult<Vec<Id>> {
    let now = Timestamp::now();
    let mut removed = Vec::new();
    for (id, _) in be.list_with_size(FileType::Lock)? {
        if own.contains(&id) {
            continue;
        }
        let remove = all
            || match read_lock(be, &id) {
                Err(err) => {
                    debug!("ignore lock {id}: {err}");
                    false
                }
                Ok(lock) => lock.is_stale_here(now),
            };
        if remove {
            if !dry_run {
                be.remove(FileType::Lock, &id, false)?;
            }
            debug!("removed lock {id}");
            removed.push(id);
        }
    }
    Ok(removed)
}

/// restic gives up refreshing (and cancels the operation) a bit before its lock becomes stale,
/// to allow for clock differences between clients (restic `refreshabilityTimeout`).
const REFRESHABILITY_TIMEOUT: Duration = Duration::from_secs(30 * 60 - 3 * 5 * 60 / 2);

/// restic starts retrying a failed lock check after this delay, doubling each time.
const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(5);

/// How often the refresher checks the wall clock (timers stop while a machine sleeps).
const POLL: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct State {
    /// Lock files held, with their content
    locks: Vec<(Id, LockFile)>,
    /// Old lock files whose removal failed; retried on every refresh and at the end
    to_remove: Vec<Id>,
    /// Wall-clock time of the last successful refresh of all locks
    refreshed: Timestamp,
}

/// Locks held by this process. The state mutex serializes creating, checking, refreshing
/// and removing, so that a refresh never changes an id while a check excludes our own ids.
#[derive(Debug)]
struct Held {
    be: DecryptBackend<Key>,
    state: Mutex<State>,
}

/// Every [`Held`] of this process, so that [`remove_held_locks`] can remove them on Ctrl-C.
static ALL_HELD: Mutex<Vec<Weak<Held>>> = Mutex::new(Vec::new());

/// Remove the lock files held by every open repository of this process. Call it before the
/// process exits without running destructors (e.g. from a Ctrl-C handler).
pub fn remove_held_locks() {
    let held: Vec<_> = ALL_HELD
        .lock()
        .map(|all| all.iter().filter_map(Weak::upgrade).collect())
        .unwrap_or_default();
    for h in held {
        h.remove_all();
    }
}

impl Held {
    fn write(&self, lock: &LockFile) -> RusticResult<Id> {
        let data = serde_json::to_vec(lock).map_err(|err| {
            RusticError::with_source(ErrorKind::Internal, "Failed to serialize lock.", err)
        })?;
        self.be.hash_write_full(FileType::Lock, &data)
    }

    fn try_remove(&self, state: &mut State) {
        state.to_remove.retain(|id| match self.be.remove(FileType::Lock, id, false) {
            Ok(()) => false,
            Err(err) => {
                warn!("could not remove old lock {id}: {err}");
                true
            }
        });
    }

    /// Create a lock and check for conflicting locks, like restic: check, create, wait,
    /// check again. On conflict, the new lock is removed again.
    fn add(&self, exclusive: bool) -> RusticResult<()> {
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        let mut own: Vec<Id> = state.locks.iter().map(|(id, _)| *id).collect();
        own.extend(state.to_remove.iter().copied());
        check_locks(&self.be, exclusive, &own)?;
        let lock = LockFile::new_for_this_process(exclusive);
        let id = self.write(&lock)?;
        std::thread::sleep(WAIT_BEFORE_LOCK_CHECK);
        own.push(id);
        if let Err(err) = check_locks(&self.be, exclusive, &own) {
            if let Err(err) = self.be.remove(FileType::Lock, &id, false) {
                warn!("could not remove lock {id}: {err}");
                state.to_remove.push(id);
            }
            return Err(err);
        }
        debug!("created {} lock {id}", if exclusive { "exclusive" } else { "non-exclusive" });
        state.locks.push((id, lock));
        Ok(())
    }

    fn exists(&self, ids: &[Id]) -> RusticResult<bool> {
        let present: Vec<Id> = self
            .be
            .list_with_size(FileType::Lock)?
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        Ok(ids.iter().all(|id| present.contains(id)))
    }

    /// Write every held lock again with the current time, then remove the old files, like
    /// restic's refresh. With `stale`, first make sure that all our lock files still exist,
    /// and again after writing the new ones (restic `RefreshStaleLock`): if one was removed
    /// in the meantime (`unlock` by another client), our locks are lost.
    fn refresh(&self, stale: bool) -> RusticResult<()> {
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        let old: Vec<Id> = state.locks.iter().map(|(id, _)| *id).collect();
        if stale && !self.exists(&old)? {
            return Err(lost());
        }
        let mut new = Vec::new();
        for (_, lock) in &state.locks {
            let mut lock = lock.clone();
            lock.time = Timestamp::now().to_string();
            match self.write(&lock) {
                Ok(id) => new.push((id, lock)),
                Err(err) => {
                    state.to_remove.extend(new.into_iter().map(|(id, _)| id));
                    self.try_remove(&mut state);
                    return Err(err);
                }
            }
        }
        if stale {
            std::thread::sleep(WAIT_BEFORE_LOCK_CHECK);
            if !self.exists(&old)? {
                state.to_remove.extend(new.into_iter().map(|(id, _)| id));
                self.try_remove(&mut state);
                return Err(lost());
            }
        }
        state.to_remove.extend(old);
        state.locks = new;
        state.refreshed = Timestamp::now();
        self.try_remove(&mut state);
        debug!("refreshed locks");
        Ok(())
    }

    fn remove_all(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let ids: Vec<Id> = state.locks.drain(..).map(|(id, _)| id).collect();
        state.to_remove.extend(ids);
        self.try_remove(&mut state);
        for id in &state.to_remove {
            warn!("lock {id} is left in the repository; remove it with `rustic unlock`");
        }
    }

    fn since_refresh(&self) -> Duration {
        self.state
            .lock()
            .map(|s| {
                Timestamp::now()
                    .duration_since(s.refreshed)
                    .unsigned_abs()
            })
            .unwrap_or(Duration::MAX)
    }
}

fn poisoned() -> Box<RusticError> {
    RusticError::new(ErrorKind::Internal, "Lock state is poisoned.")
}

fn lost() -> Box<RusticError> {
    RusticError::new(
        ErrorKind::Repository,
        "Our lock file was removed by another process.",
    )
}

/// The background refresher: refresh every 5 minutes; if no refresh succeeded for too long
/// (e.g. after the machine slept), try a stale refresh, and if that fails, stop the process,
/// like restic which cancels the running operation ("failed to refresh lock in time").
fn refresher(held: &Held, stop: &mpsc::Receiver<()>) {
    let mut next = LOCK_REFRESH_INTERVAL;
    loop {
        match stop.recv_timeout(POLL) {
            Err(RecvTimeoutError::Timeout) => {}
            _ => return,
        }
        let since = held.since_refresh();
        if since >= REFRESHABILITY_TIMEOUT {
            match held.refresh(true) {
                Ok(()) => next = LOCK_REFRESH_INTERVAL,
                Err(err) => {
                    error!("failed to refresh lock in time: {err}");
                    held.remove_all();
                    std::process::exit(1);
                }
            }
        } else if since >= next {
            match held.refresh(false) {
                Ok(()) => next = LOCK_REFRESH_INTERVAL,
                Err(err) => {
                    warn!("unable to refresh lock: {err}");
                    next = since + LOCK_REFRESH_INTERVAL;
                }
            }
        }
    }
}

/// restic-compatible locks held by this process for one open repository.
///
/// Created with a non-exclusive or exclusive lock; [`ResticLocks::exclusive`] adds an
/// exclusive one. Locks are refreshed every 5 minutes and removed when this value is dropped.
pub struct ResticLocks {
    held: Arc<Held>,
    stop: Option<mpsc::Sender<()>>,
    refresher: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ResticLocks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResticLocks")
            .field("locks", &self.ids())
            .finish_non_exhaustive()
    }
}

impl ResticLocks {
    /// Lock the repository like restic: check, create a lock, wait, check again.
    ///
    /// # Errors
    ///
    /// * If a conflicting lock exists, or the lock cannot be written.
    pub(crate) fn acquire(be: DecryptBackend<Key>, exclusive: bool) -> RusticResult<Self> {
        let held = Arc::new(Held {
            be,
            state: Mutex::new(State {
                locks: Vec::new(),
                to_remove: Vec::new(),
                refreshed: Timestamp::now(),
            }),
        });
        held.add(exclusive)?;
        if let Ok(mut all) = ALL_HELD.lock() {
            all.retain(|w| w.strong_count() > 0);
            all.push(Arc::downgrade(&held));
        }
        let (stop, rx) = mpsc::channel::<()>();
        let refresh = Arc::clone(&held);
        let refresher = std::thread::spawn(move || refresher(&refresh, &rx));
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
            .state
            .lock()
            .is_ok_and(|s| s.locks.iter().any(|(_, lock)| lock.exclusive));
        if has_exclusive {
            return Ok(());
        }
        self.held.add(true)
    }

    /// Ids of the lock files held by this process (including old ones not yet removed).
    #[must_use]
    pub fn ids(&self) -> Vec<Id> {
        self.held
            .state
            .lock()
            .map(|s| {
                s.locks
                    .iter()
                    .map(|(id, _)| *id)
                    .chain(s.to_remove.iter().copied())
                    .collect()
            })
            .unwrap_or_default()
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
        let json = r#"{"time":"2026-11-12T19:31:11.1234567+02:00","exclusive":false,"hostname":"h","username":"u","pid":42}"#;
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
    fn own_lock_is_restic_shaped() {
        let mut lock = LockFile::new_for_this_process(false);
        lock.uid = 0;
        lock.gid = 0;
        let json = serde_json::to_string(&lock).unwrap();
        assert!(json.contains(r#""time":""#));
        // like restic (`omitempty`), zero uid/gid are not written
        assert!(!json.contains("uid") && !json.contains("gid"));
        assert!(lock.time.ends_with('Z'));
        assert!(!lock.is_stale(Timestamp::now()));
        assert!(!lock.is_stale_here(Timestamp::now()), "our own process exists");
        assert_eq!(lock.pid, i64::from(std::process::id()));
    }

    #[test]
    fn refreshability_timeout_is_restics() {
        assert_eq!(REFRESHABILITY_TIMEOUT, Duration::from_secs(22 * 60 + 30));
    }
}
