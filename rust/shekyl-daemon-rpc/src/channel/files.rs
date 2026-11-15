// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The channel's files in the network's data directory, the one the
//! exclusive lock covers (RT-O34; Rick, 2026-11-14): the daemon's key, its
//! public bundle, a service's console key, and the enrolled set's store.
//!
//! Each is readable by the daemon's account alone: created `0600` with
//! `O_EXCL` on Unix, and on Windows with an owner-only descriptor and the
//! no-read-up label set in the creating call (`CreateFileW`, RT-P8's
//! finding), never tightened afterwards. A key file anyone else can read is
//! refused at start, never repaired: whoever can read it is the daemon.

use std::path::{Path, PathBuf};

use shekyl_rpc_channel::handshake::{KeyFileError, StaticKeypair};
use zeroize::Zeroizing;

use super::stage::{self, Access};

/// The daemon's static key (`StaticKeypair::to_key_file`).
pub const KEY_FILE: &str = "rpc-channel.key";

/// The daemon's public bundle: the X25519 key then the ML-KEM-768
/// encapsulation key, what `rpc_bundle_show` replies and a client is given.
pub const BUNDLE_FILE: &str = "rpc-channel.bundle";

/// A service's console key: the host administrator's credential (§5).
pub const CONSOLE_KEY_FILE: &str = "rpc-console.key";

/// Why a channel file cannot be used.
#[derive(Debug)]
pub enum FileRefused {
    /// It could not be read or written.
    Io(PathBuf, std::io::Error),
    /// Someone other than the daemon's account can read it, or it is not
    /// the account's.
    Exposed(PathBuf, String),
    /// It is not a key file this build reads.
    Key(PathBuf, KeyFileError),
}

impl std::fmt::Display for FileRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, e) => write!(f, "{}: {e}", path.display()),
            Self::Exposed(path, why) => write!(
                f,
                "{} {why}; only the daemon's account may read it, so it is refused, not repaired",
                path.display()
            ),
            Self::Key(path, e) => write!(f, "{}: {e}", path.display()),
        }
    }
}

impl std::error::Error for FileRefused {}

/// The key at `path`, read and checked; `None` when there is none yet.
///
/// # Errors
///
/// [`FileRefused`]: unreadable, readable by another account, or not a key.
pub fn read_key(path: &Path) -> Result<Option<StaticKeypair>, FileRefused> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(FileRefused::Io(path.to_path_buf(), e)),
    };
    private(path)?;
    StaticKeypair::from_key_file(&bytes)
        .map(Some)
        .map_err(|e| FileRefused::Key(path.to_path_buf(), e))
}

/// Write `bytes` to a new file at `path`, readable by this account alone,
/// created that way in one call. Refuses a path that already exists.
///
/// # Errors
///
/// [`FileRefused::Io`] when the create or the write fails.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), FileRefused> {
    stage::write_new(path, bytes, Access::OwnerOnly)
        .map_err(|error| FileRefused::Io(path.to_path_buf(), error))
}

/// Replace the file at `path` with `bytes`, readable by this account alone.
/// The bytes are the file's journal until the rename, so a reader sees the
/// old key or the new one.
///
/// # Errors
///
/// [`FileRefused::Io`] when a step fails.
pub fn replace_private(path: &Path, bytes: &[u8]) -> Result<(), FileRefused> {
    let journal = stage::StagedWrite::create(path, bytes, Access::OwnerOnly)
        .map_err(|error| FileRefused::Io(stage::staged_path(path), error))?;
    journal
        .commit()
        .map_err(|error| FileRefused::Io(path.to_path_buf(), error))
}

/// The enrolled set's store at `path`, made ready for redb: created empty
/// and owner-only on a first start, in the creating call as a key file is,
/// and checked before it is opened. The ceilings and the console cell are
/// what admission trusts, so a store anyone else can read or write is
/// refused, not repaired.
///
/// # Errors
///
/// [`FileRefused::Io`] when it cannot be created or read;
/// [`FileRefused::Exposed`] when another account can read it, it is not
/// this account's, or it is a link.
pub fn private_store(path: &Path) -> Result<(), FileRefused> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => write_private(path, &[])?,
        Err(e) => return Err(FileRefused::Io(path.to_path_buf(), e)),
    }
    private(path)
}

/// Whether only this account can read `path`.
#[cfg(unix)]
fn private(path: &Path) -> Result<(), FileRefused> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta =
        std::fs::symlink_metadata(path).map_err(|e| FileRefused::Io(path.to_path_buf(), e))?;
    let exposed = |why: String| Err(FileRefused::Exposed(path.to_path_buf(), why));
    if meta.file_type().is_symlink() {
        return exposed("is a symbolic link".to_owned());
    }
    let me = rustix::process::geteuid().as_raw();
    if meta.uid() != me {
        return exposed(format!(
            "is owned by uid {}, not this account (uid {me})",
            meta.uid()
        ));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return exposed(format!("has mode {mode:04o}"));
    }
    Ok(())
}

#[cfg(windows)]
fn private(path: &Path) -> Result<(), FileRefused> {
    shekyl_win_sec::rendezvous::check_owner_only_labelled(path)
        .map_err(|e| FileRefused::Exposed(path.to_path_buf(), e.to_string()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A key is written owner-only and reads back to the same identity; a
    /// key file another account can read is refused. Red edit: drop the
    /// mode test in `private`, and the 0640 key is read.
    #[test]
    fn a_key_file_is_the_accounts_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEY_FILE);
        assert!(read_key(&path).unwrap().is_none());
        let key = StaticKeypair::generate().unwrap();
        write_private(&path, &key.to_key_file()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let read = read_key(&path).unwrap().expect("the key");
        assert_eq!(read.public().fingerprint(), key.public().fingerprint());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(read_key(&path), Err(FileRefused::Exposed(..))));
    }

    /// A replacement lands whole, private, over the old key.
    #[test]
    fn a_replacement_is_private_and_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONSOLE_KEY_FILE);
        write_private(&path, &StaticKeypair::generate().unwrap().to_key_file()).unwrap();
        let new = StaticKeypair::generate().unwrap();
        replace_private(&path, &new.to_key_file()).unwrap();
        let read = read_key(&path).unwrap().expect("the new key");
        assert_eq!(read.public().fingerprint(), new.public().fingerprint());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
