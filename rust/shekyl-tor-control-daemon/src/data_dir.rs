// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-boot tor `DataDirectory` for the daemon overlay (PWD-E7).
//!
//! The wallet supervisor keeps a durable data directory — vanguards and a
//! stable onion need one. The daemon posture is ephemeral: a new onion every
//! boot, and **nothing on disk that could join this boot to the next** (tor
//! otherwise persists entry guards in `state`). The type makes that
//! structural: a unique 0700 subdirectory, removed on drop, never reused.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Directory-name prefix for this boot's DataDirectory and for leftover
/// sweeps of previous crashed boots.
const DIR_PREFIX: &str = "ephemeral-tor-";
/// Exact name used by an earlier durable-path revision of this crate.
const LEGACY_DIR_NAME: &str = "ephemeral-tor";

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
        if name.starts_with(DIR_PREFIX) {
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
