// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The channel's files in the network's data directory, the one the
//! exclusive lock covers (RT-O34; Rick, 2026-11-14): the daemon's key, its
//! public bundle, a service's console key, and the enrolled set's store.
//!
//! Each is readable by the daemon's account alone, written and checked by
//! `shekyl-os-account`'s [`private_file`], the rule the tunnel's and a
//! remote CLI's keys follow too. A key file anyone else can read is refused
//! at start, never repaired: whoever can read it is the daemon.

use std::path::{Path, PathBuf};

use shekyl_os_account::private_file::{self, PrivateFileError};
use shekyl_rpc_channel::handshake::{KeyFileError, StaticKeypair};

/// The files' names: `shekyl-rpc-rendezvous`'s, which the clients that read
/// them use too.
pub use shekyl_rpc_rendezvous::{
    CHANNEL_BUNDLE_FILE as BUNDLE_FILE, CHANNEL_KEY_FILE as KEY_FILE, CONSOLE_KEY_FILE,
};

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

impl From<PrivateFileError> for FileRefused {
    fn from(error: PrivateFileError) -> Self {
        match error {
            PrivateFileError::Io(path, e) => Self::Io(path, e),
            PrivateFileError::Exposed(path, why) => Self::Exposed(path, why),
        }
    }
}

/// The key at `path`, read and checked; `None` when there is none yet.
///
/// # Errors
///
/// [`FileRefused`]: unreadable, readable by another account, or not a key.
pub fn read_key(path: &Path) -> Result<Option<StaticKeypair>, FileRefused> {
    read_key_with(path, private_file::read_private)
}

/// The console key at `path`. An administrator of this machine may read
/// it, as well as the account that wrote it ([`private_file::read_console`]).
///
/// # Errors
///
/// [`FileRefused`], as [`read_key`].
pub fn read_console_key(path: &Path) -> Result<Option<StaticKeypair>, FileRefused> {
    read_key_with(path, private_file::read_console)
}

fn read_key_with<B>(
    path: &Path,
    read: fn(&Path) -> Result<Option<B>, PrivateFileError>,
) -> Result<Option<StaticKeypair>, FileRefused>
where
    B: std::ops::Deref,
    B::Target: AsRef<[u8]>,
{
    let Some(bytes) = read(path)? else {
        return Ok(None);
    };
    StaticKeypair::from_key_file(bytes.deref().as_ref())
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
    Ok(private_file::write_private(path, bytes)?)
}

/// Replace the file at `path` with `bytes`, readable by this account alone.
/// The bytes are the file's journal until the rename, so a reader sees the
/// old key or the new one.
///
/// # Errors
///
/// [`FileRefused::Io`] when a step fails.
pub fn replace_private(path: &Path, bytes: &[u8]) -> Result<(), FileRefused> {
    Ok(private_file::replace_private(path, bytes)?)
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
    Ok(private_file::check_private(path)?)
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
