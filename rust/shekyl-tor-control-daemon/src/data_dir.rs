// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-boot tor `DataDirectory` for the daemon overlay (PWD-E7).
//!
//! The wallet supervisor keeps a durable data directory — vanguards and a
//! stable onion need one. The daemon posture is ephemeral for identity: a new
//! onion every boot, and nothing identity-bearing (guards, keys, the onion)
//! joins this boot to the next. Tor's public directory cache is the exception
//! (`TSR-Q8`): it lives in [`CACHE_DIR_NAME`], a sibling this sweep does not
//! touch. The per-boot directory is a unique 0700 subdirectory, never reused.
//!
//! A directory ends by being retired (`TOR_SUPERVISOR.md` §4.7, §4.10): Tor's
//! log moves out to `ephemeral-tor-<id>.log` beside it, then the directory is
//! renamed to `ephemeral-tor-<id>.tomb`. Both names carry the sweep's prefix,
//! so the next start's sweep removes them. Deleting the tombstone is the
//! caller's, off the stop path and under a bound
//! ([`crate::ephemeral::TOMBSTONE_DELETE_BOUND`]).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use shekyl_tor_control_client::control::LOG_FILE_NAME;
use shekyl_tor_control_client::directory_cache::DirectoryCache;

/// Name prefix of every per-boot directory, kept log and tombstone. The
/// sweep removes whatever carries it.
const DIR_PREFIX: &str = "ephemeral-tor-";
/// Exact name used by an earlier durable-path revision of this crate.
const LEGACY_DIR_NAME: &str = "ephemeral-tor";
/// Appended to a retired directory's name: the tombstone.
const TOMBSTONE_SUFFIX: &str = ".tomb";
/// Appended to a retired directory's name: Tor's log, kept beside it.
const KEPT_LOG_SUFFIX: &str = ".log";

/// The public directory cache. Not a sweep target: it does not start with
/// [`DIR_PREFIX`] and it is not [`LEGACY_DIR_NAME`].
pub(crate) const CACHE_DIR_NAME: &str = "tor-directory-cache";

/// Space Tor writes into a running `DataDirectory` beyond the cache it was
/// given. It rebuilds its microdescriptor store at startup and every 30
/// minutes, so `cached-microdescs.new` holds at most about one full set
/// (29 MB measured, `TOR_SUPERVISOR.md` §10); `state`, the keys and the log
/// are small beside it.
pub const TOR_WRITE_HEADROOM: u64 = 32 * 1024 * 1024;

/// Bytes a spawn needs free under `parent`, the daemon's data directory
/// (`TOR_SUPERVISOR.md` §5, "Data directory unusable"). A fresh
/// `DataDirectory` is seeded from the public directory cache, so it also
/// needs the bytes [`DirectoryCache::copy_bytes`] would write; a kept one
/// (a respawn) already holds that copy.
#[must_use]
pub fn space_needed(parent: &Path, fresh: bool) -> u64 {
    let cache = if fresh {
        DirectoryCache::at(parent.join(CACHE_DIR_NAME)).copy_bytes()
    } else {
        0
    };
    TOR_WRITE_HEADROOM.saturating_add(cache)
}

/// Remove what earlier incarnations left under `parent`: their directories,
/// tombstones and kept logs, every entry named under the sweep's prefix
/// (`TSR-F14`). `spare` is a directory still held for a respawn; it wears the
/// same prefix and is not removed.
///
/// The directory cache is not a target. A symlink under the prefix is removed
/// as a link; what it points to is not followed (`TOR_SUPERVISOR.md` §8). A
/// fresh spawn sweeps before it measures free space: otherwise a crashed
/// boot's directories hold the disk and every retry refuses.
pub fn sweep_stale_data_dirs(parent: &Path, spare: Option<&Path>) {
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_sweep_target(name) || spare == Some(entry.path().as_path()) {
            continue;
        }
        // `DirEntry::file_type` does not follow a symlink.
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let removed = if kind.is_dir() {
            fs::remove_dir_all(entry.path())
        } else {
            fs::remove_file(entry.path())
        };
        // Best effort: what stays is swept at the next start.
        drop(removed);
    }
}

fn is_sweep_target(name: &str) -> bool {
    name == LEGACY_DIR_NAME || name.starts_with(DIR_PREFIX)
}

/// Where a retired directory's Tor log went.
#[derive(Debug)]
pub enum KeptLog {
    /// Moved out beside the directory, under the sweep's prefix.
    Kept(PathBuf),
    /// The directory held no log: Tor never opened one.
    Absent,
    /// The move failed. The log goes with the directory.
    NotMoved(io::Error),
}

/// A unique tor `DataDirectory`. It ends by [`Self::retire`]; a drop retires
/// it too.
pub(crate) struct EphemeralDataDir {
    path: PathBuf,
}

impl EphemeralDataDir {
    /// Create a unique 0700 subdirectory of `parent`. Leftovers of earlier
    /// incarnations are the caller's sweep ([`sweep_stale_data_dirs`]): a
    /// sweep here would remove the log a retired directory just kept.
    pub(crate) fn create_under(parent: &Path) -> io::Result<Self> {
        fs::create_dir_all(parent)?;
        let path = unique_child(parent);
        fs::create_dir(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { path })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Move Tor's log out beside the directory, then rename the directory to
    /// its tombstone. Both are metadata operations in the same parent; the
    /// caller is past the reap, so on Windows no Tor handle holds a file
    /// inside. A log that does not move goes with the directory, and the
    /// rename is still tried. A failed rename leaves the directory under its
    /// live name, which the next start's sweep removes.
    pub(crate) fn retire(mut self) -> (KeptLog, io::Result<PathBuf>) {
        let path = std::mem::take(&mut self.path);
        retire_at(&path)
    }
}

impl Drop for EphemeralDataDir {
    /// A directory dropped without [`Self::retire`] is retired here, and the
    /// tombstone is left to the next start's sweep: a drop cannot wait for
    /// the bounded delete.
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let path = std::mem::take(&mut self.path);
            drop(retire_at(&path));
        }
    }
}

fn retire_at(path: &Path) -> (KeptLog, io::Result<PathBuf>) {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
    else {
        let unnamed = io::Error::new(io::ErrorKind::InvalidInput, "no directory name");
        return (KeptLog::Absent, Err(unnamed));
    };
    let kept = parent.join(format!("{name}{KEPT_LOG_SUFFIX}"));
    let log = match fs::rename(path.join(LOG_FILE_NAME), &kept) {
        Ok(()) => KeptLog::Kept(kept),
        Err(error) if error.kind() == io::ErrorKind::NotFound => KeptLog::Absent,
        Err(error) => KeptLog::NotMoved(error),
    };
    let tombstone = parent.join(format!("{name}{TOMBSTONE_SUFFIX}"));
    let renamed = fs::rename(path, &tombstone).map(|()| tombstone);
    (log, renamed)
}

fn unique_child(parent: &Path) -> PathBuf {
    let mut suffix = [0u8; 8];
    let name = if getrandom::getrandom(&mut suffix).is_ok() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = String::with_capacity(DIR_PREFIX.len() + suffix.len() * 2);
        name.push_str(DIR_PREFIX);
        for byte in suffix {
            name.push(HEX[usize::from(byte >> 4)] as char);
            name.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        name
    } else {
        format!(
            "{DIR_PREFIX}{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
    };
    parent.join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names under `parent`, sorted.
    fn names(parent: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    /// Retiring moves Tor's log out and renames the directory: the live name
    /// is gone, the log and the tombstone carry the sweep's prefix. Red edit:
    /// delete the directory instead of renaming it, and the log is gone with
    /// it.
    #[test]
    fn retire_keeps_the_log_and_leaves_a_tombstone() {
        let parent = tempfile::tempdir().unwrap();
        let dir = EphemeralDataDir::create_under(parent.path()).unwrap();
        let live = dir.path().to_path_buf();
        let name = live.file_name().unwrap().to_str().unwrap().to_owned();
        fs::write(live.join(LOG_FILE_NAME), b"Tor's last words").unwrap();
        fs::write(live.join("state"), b"guards").unwrap();

        let (log, tombstone) = dir.retire();
        let tombstone = tombstone.unwrap();
        assert!(!live.exists(), "the live name is gone");
        let KeptLog::Kept(kept) = log else {
            panic!("the log was kept: {log:?}");
        };
        assert_eq!(fs::read(&kept).unwrap(), b"Tor's last words");
        assert!(
            tombstone.join("state").is_file(),
            "the tombstone holds the rest"
        );
        assert!(!tombstone.join(LOG_FILE_NAME).exists());
        assert_eq!(
            names(parent.path()),
            vec![
                format!("{name}{KEPT_LOG_SUFFIX}"),
                format!("{name}{TOMBSTONE_SUFFIX}")
            ]
        );
        assert!(names(parent.path()).iter().all(|n| is_sweep_target(n)));
    }

    /// A directory whose Tor never opened a log still retires.
    #[test]
    fn retire_without_a_log_reports_it_absent() {
        let parent = tempfile::tempdir().unwrap();
        let dir = EphemeralDataDir::create_under(parent.path()).unwrap();
        let (log, tombstone) = dir.retire();
        assert!(matches!(log, KeptLog::Absent), "{log:?}");
        assert!(tombstone.unwrap().is_dir());
    }

    /// A log that cannot move goes with the directory, and the directory is
    /// still renamed: a lost log never becomes a stuck directory. Red edit:
    /// return before the rename when the log move fails.
    #[test]
    fn a_log_that_does_not_move_still_lets_the_directory_retire() {
        let parent = tempfile::tempdir().unwrap();
        let dir = EphemeralDataDir::create_under(parent.path()).unwrap();
        let live = dir.path().to_path_buf();
        let name = live.file_name().unwrap().to_str().unwrap().to_owned();
        fs::write(live.join(LOG_FILE_NAME), b"log").unwrap();
        // A non-empty directory where the kept log would go: a file cannot
        // be renamed over it.
        let blocker = parent.path().join(format!("{name}{KEPT_LOG_SUFFIX}"));
        fs::create_dir(&blocker).unwrap();
        fs::write(blocker.join("x"), b"x").unwrap();

        let (log, tombstone) = dir.retire();
        assert!(matches!(log, KeptLog::NotMoved(_)), "{log:?}");
        let tombstone = tombstone.unwrap();
        assert!(
            tombstone.join(LOG_FILE_NAME).is_file(),
            "the log went with it"
        );
        assert!(!live.exists());
    }

    /// A drop retires the directory and deletes nothing: the tombstone waits
    /// for the next start's sweep. Red edit: wipe on drop, and the log is
    /// gone.
    #[test]
    fn a_drop_retires_the_directory() {
        let parent = tempfile::tempdir().unwrap();
        let (live, name) = {
            let dir = EphemeralDataDir::create_under(parent.path()).unwrap();
            fs::write(dir.path().join(LOG_FILE_NAME), b"log").unwrap();
            let live = dir.path().to_path_buf();
            let name = live.file_name().unwrap().to_str().unwrap().to_owned();
            (live, name)
        };
        assert!(!live.exists());
        assert_eq!(
            names(parent.path()),
            vec![
                format!("{name}{KEPT_LOG_SUFFIX}"),
                format!("{name}{TOMBSTONE_SUFFIX}")
            ]
        );
    }

    /// The sweep removes every entry under its prefix, files included: a
    /// crashed boot's directory, a tombstone, a kept log, the legacy path
    /// (`TSR-F14`). Red edit: remove directories only, and the kept log and
    /// the stray file stay.
    #[test]
    fn the_sweep_removes_directories_tombstones_and_kept_logs() {
        let parent = tempfile::tempdir().unwrap();
        let legacy = parent.path().join(LEGACY_DIR_NAME);
        fs::create_dir(&legacy).unwrap();
        fs::write(legacy.join("state"), b"guards").unwrap();
        let stale = parent.path().join(format!("{DIR_PREFIX}deadbeef"));
        fs::create_dir(&stale).unwrap();
        fs::write(stale.join("state"), b"guards").unwrap();
        let tomb = parent
            .path()
            .join(format!("{DIR_PREFIX}feedface{TOMBSTONE_SUFFIX}"));
        fs::create_dir(&tomb).unwrap();
        fs::write(tomb.join("cached-microdescs"), b"md").unwrap();
        let log = parent
            .path()
            .join(format!("{DIR_PREFIX}feedface{KEPT_LOG_SUFFIX}"));
        fs::write(&log, b"log").unwrap();
        let stray = parent.path().join(format!("{DIR_PREFIX}stray"));
        fs::write(&stray, b"file").unwrap();
        let unrelated = parent.path().join("lmdb");
        fs::create_dir(&unrelated).unwrap();

        sweep_stale_data_dirs(parent.path(), None);
        assert_eq!(names(parent.path()), vec!["lmdb".to_owned()]);
    }

    /// A directory held for a respawn wears the prefix and is spared. Red
    /// edit: ignore `spare`, and the held directory is deleted under a
    /// running respawn.
    #[test]
    fn the_sweep_spares_the_directory_held_for_a_respawn() {
        let parent = tempfile::tempdir().unwrap();
        let held = EphemeralDataDir::create_under(parent.path()).unwrap();
        fs::write(held.path().join("state"), b"guards").unwrap();
        let stale = parent.path().join(format!("{DIR_PREFIX}deadbeef"));
        fs::create_dir(&stale).unwrap();
        sweep_stale_data_dirs(parent.path(), Some(held.path()));
        assert!(held.path().join("state").is_file());
        assert!(!stale.exists());
    }

    /// A symlink planted under the prefix is removed as a link; the
    /// directory it names keeps its files (`TOR_SUPERVISOR.md` §8). Red
    /// edit: resolve the entry (`fs::canonicalize`) before removing it, and
    /// the outside directory is deleted.
    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_is_removed_and_its_target_survives() {
        let parent = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("precious"), b"keep").unwrap();
        let plant = parent.path().join(format!("{DIR_PREFIX}plant"));
        std::os::unix::fs::symlink(outside.path(), &plant).unwrap();
        sweep_stale_data_dirs(parent.path(), None);
        assert!(fs::symlink_metadata(&plant).is_err(), "the link is removed");
        assert_eq!(fs::read(outside.path().join("precious")).unwrap(), b"keep");
    }

    #[test]
    fn sweep_leaves_the_directory_cache() {
        // Fails if the cache name matches the sweep: a fresh spawn would
        // delete the cache.
        assert!(
            !is_sweep_target(CACHE_DIR_NAME),
            "{CACHE_DIR_NAME} must not match the ephemeral-tor sweep"
        );
        let parent = tempfile::tempdir().unwrap();
        let cache = parent.path().join(CACHE_DIR_NAME);
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("cached-certs"), b"certs").unwrap();
        let stale = parent.path().join(format!("{DIR_PREFIX}deadbeef"));
        fs::create_dir(&stale).unwrap();
        sweep_stale_data_dirs(parent.path(), None);
        assert!(cache.join("cached-certs").is_file());
        assert!(!stale.exists());
    }

    /// Creating a directory sweeps nothing: the sweep is the caller's, so a
    /// log kept a moment ago survives the spawn that follows. Red edit: sweep
    /// in `create_under`, and the kept log is gone.
    #[test]
    fn creating_a_directory_leaves_a_kept_log() {
        let parent = tempfile::tempdir().unwrap();
        let kept = parent
            .path()
            .join(format!("{DIR_PREFIX}feedface{KEPT_LOG_SUFFIX}"));
        fs::write(&kept, b"log").unwrap();
        let dir = EphemeralDataDir::create_under(parent.path()).unwrap();
        assert!(kept.is_file());
        assert!(dir.path().is_dir());
    }

    /// A fresh directory needs the cache's size on top of Tor's own write
    /// headroom; a kept one needs only the headroom. A missing cache adds
    /// nothing. Dropping the `fresh` branch fails the first assertion.
    #[test]
    fn space_needed_counts_the_cache_only_for_a_fresh_directory() {
        let parent = tempfile::tempdir().unwrap();
        assert_eq!(space_needed(parent.path(), true), TOR_WRITE_HEADROOM);
        let cache = parent.path().join(CACHE_DIR_NAME);
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("cached-certs"), vec![0u8; 1000]).unwrap();
        fs::write(cache.join("cached-microdesc-consensus"), vec![0u8; 2500]).unwrap();
        fs::create_dir(cache.join("not-a-file")).unwrap();
        fs::write(cache.join(".cached-certs.partial"), vec![0u8; 9000]).unwrap();
        fs::write(cache.join("notes"), vec![0u8; 800]).unwrap();
        assert_eq!(space_needed(parent.path(), true), TOR_WRITE_HEADROOM + 3500);
        assert_eq!(space_needed(parent.path(), false), TOR_WRITE_HEADROOM);
    }

    #[cfg(unix)]
    #[test]
    fn directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let dir = EphemeralDataDir::create_under(parent.path()).unwrap();
        let mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
