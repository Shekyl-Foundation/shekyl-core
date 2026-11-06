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
//! touch. The per-boot directory is a unique 0700 subdirectory, removed on
//! drop, never reused.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use shekyl_tor_control_client::directory_cache::DirectoryCache;

/// Directory-name prefix for this boot's DataDirectory and for leftover
/// sweeps of previous crashed boots.
const DIR_PREFIX: &str = "ephemeral-tor-";
/// Exact name used by an earlier durable-path revision of this crate.
const LEGACY_DIR_NAME: &str = "ephemeral-tor";

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

/// Remove leftover per-boot directories under `parent`.
///
/// The directory cache is not one of them. A directory kept for an in-boot
/// respawn wears one of these names too, so a caller sweeps only after that
/// directory has been dropped. A fresh spawn does this before it measures
/// free space: otherwise a crashed boot's directories hold the disk and
/// every retry refuses without reaching [`EphemeralDataDir::create_under`].
pub fn sweep_stale_data_dirs(parent: &Path) {
    sweep_stale(parent);
}

fn is_sweep_target(name: &str) -> bool {
    name == LEGACY_DIR_NAME || name.starts_with(DIR_PREFIX)
}

/// A unique tor `DataDirectory` that is wiped when dropped.
pub(crate) struct EphemeralDataDir {
    path: PathBuf,
}

impl EphemeralDataDir {
    /// Create a unique 0700 subdirectory of `parent`, after best-effort
    /// removal of leftover `ephemeral-tor*` siblings from a previous boot
    /// that did not tear down.
    pub(crate) fn create_under(parent: &Path) -> io::Result<Self> {
        sweep_stale(parent);
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

    /// Remove the directory now rather than waiting for drop. Idempotent on
    /// a second call: the path is taken.
    pub(crate) fn wipe(mut self) {
        best_effort_rm(&self.path);
        self.path = PathBuf::new();
    }
}

impl Drop for EphemeralDataDir {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            best_effort_rm(&self.path);
        }
    }
}

fn best_effort_rm(path: &Path) {
    drop(fs::remove_dir_all(path));
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

fn sweep_stale(parent: &Path) {
    let legacy = parent.join(LEGACY_DIR_NAME);
    if legacy.is_dir() {
        best_effort_rm(&legacy);
    }
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if is_sweep_target(name) {
            best_effort_rm(&entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_removes_the_directory() {
        let parent = tempfile::tempdir().unwrap();
        let dir = EphemeralDataDir::create_under(parent.path()).unwrap();
        let path = dir.path().to_path_buf();
        assert!(path.is_dir());
        dir.wipe();
        assert!(!path.exists());
    }

    #[test]
    fn drop_removes_the_directory() {
        let parent = tempfile::tempdir().unwrap();
        let path = {
            let dir = EphemeralDataDir::create_under(parent.path()).unwrap();
            let path = dir.path().to_path_buf();
            assert!(path.is_dir());
            path
        };
        assert!(!path.exists());
    }

    #[test]
    fn create_sweeps_legacy_and_stale_siblings() {
        let parent = tempfile::tempdir().unwrap();
        let legacy = parent.path().join(LEGACY_DIR_NAME);
        fs::create_dir(&legacy).unwrap();
        fs::write(legacy.join("state"), b"guards").unwrap();
        let stale = parent.path().join(format!("{DIR_PREFIX}deadbeef"));
        fs::create_dir(&stale).unwrap();
        fs::write(stale.join("state"), b"guards").unwrap();

        let dir = EphemeralDataDir::create_under(parent.path()).unwrap();
        assert!(!legacy.exists(), "legacy durable path must be wiped");
        assert!(!stale.exists(), "stale unique sibling must be wiped");
        assert!(dir.path().is_dir());
        assert_ne!(dir.path(), stale);
    }

    #[test]
    fn sweep_leaves_the_directory_cache() {
        // Fails if the cache name matches the sweep: creating a per-boot
        // directory would delete the cache.
        assert!(
            !is_sweep_target(CACHE_DIR_NAME),
            "{CACHE_DIR_NAME} must not match the ephemeral-tor sweep"
        );
        let parent = tempfile::tempdir().unwrap();
        let cache = parent.path().join(CACHE_DIR_NAME);
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("cached-certs"), b"certs").unwrap();
        let dir = EphemeralDataDir::create_under(parent.path()).unwrap();
        assert!(cache.join("cached-certs").is_file());
        assert_ne!(dir.path(), cache);
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

    /// A crashed boot's directory is a sweep target. The cache beside it is not.
    #[test]
    fn sweep_stale_data_dirs_removes_leftovers_and_keeps_the_cache() {
        let parent = tempfile::tempdir().unwrap();
        let stale = parent.path().join(format!("{DIR_PREFIX}deadbeef"));
        fs::create_dir(&stale).unwrap();
        fs::write(stale.join("state"), b"guards").unwrap();
        let cache = parent.path().join(CACHE_DIR_NAME);
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("cached-certs"), b"certs").unwrap();
        sweep_stale_data_dirs(parent.path());
        assert!(!stale.exists());
        assert!(cache.join("cached-certs").is_file());
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
