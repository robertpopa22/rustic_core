//! Lock files as written by restic.
//!
//! rustic is lock-free and never writes lock files. When restic and rustic share a
//! repository, rustic reads restic's locks so that it does not run an exclusive operation
//! (like `prune`) while restic is using the repository.

use std::str::FromStr;

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

/// After this time without refresh, restic considers a lock stale (restic `staleTimeout`).
pub const LOCK_STALE_TIMEOUT: SignedDuration = SignedDuration::from_mins(30);

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
}

impl LockFile {
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
        let lock = LockFile {
            time: "garbage".into(),
            exclusive: true,
            hostname: String::new(),
            username: String::new(),
            pid: 0,
        };
        assert!(!lock.is_stale(Timestamp::now()));
    }
}
