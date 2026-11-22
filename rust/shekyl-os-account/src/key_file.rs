// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A key file handed to this process: this account's own, or one the
//! superuser hands it (a systemd credential).
//!
//! The read is one order on every platform: open the name, judge who can
//! reach it, then copy at most the caller's limit and one more byte. What
//! is refused is never repaired.
//!
//! On Unix the judgment is the open handle. The open does not follow a link
//! at the name and does not block, so a symbolic link and a fifo are refused
//! before a byte is copied. Only this account and the superuser may reach
//! the file: one of them owns it, no other account can write it, every
//! account cannot read it, and its group can read it only when that group is
//! the superuser's. Mode `0440` owned by the superuser is a systemd
//! credential. An access-list entry is not read: it is how systemd grants
//! the service's account, and the mode's group bits are its mask.
//!
//! On Windows the judgment is the path's owner-only label
//! ([`crate::private_file::check_private`]), made before any byte is copied.
//! It is not a judgment of the open handle. A swap of the name between the
//! judgment and the read is the known gap, and a handle judgment is the next
//! increment.

use std::fs::File;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// The permission bits of a mode.
#[cfg(unix)]
const PERMISSION_BITS: u32 = 0o777;

/// Group and other write: another account can change the key.
#[cfg(unix)]
const OTHERS_MAY_WRITE: u32 = 0o022;

/// Other read: every account can read the key.
#[cfg(unix)]
const OTHERS_MAY_READ: u32 = 0o004;

/// Group read. Allowed only when the group is the superuser's, which is how
/// a systemd credential (`0440`) names the service's account.
#[cfg(unix)]
const GROUP_MAY_READ: u32 = 0o040;

/// The superuser's user and group id.
#[cfg(unix)]
const SUPERUSER: u32 = 0;

/// Why a key file was refused.
#[derive(Debug)]
pub enum KeyFileError {
    /// It could not be opened or read.
    Io(PathBuf, std::io::Error),
    /// A link, not a regular file, or another account can reach it.
    Exposed(PathBuf, String),
}

impl std::fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, error) => write!(f, "{}: {error}", path.display()),
            Self::Exposed(path, why) => write!(
                f,
                "{} {why}; only this account and the superuser may reach it, so it is refused, not repaired",
                path.display()
            ),
        }
    }
}

impl std::error::Error for KeyFileError {}

/// The bytes of the key file at `path`, at most `limit` and one more. `None`
/// when there is none.
///
/// A file longer than `limit` returns `limit + 1` bytes, so its reader
/// refuses it by length without the rest being read.
///
/// # Errors
///
/// [`KeyFileError::Io`] when it cannot be opened or read;
/// [`KeyFileError::Exposed`] when it is a link, not a regular file, or
/// another account can reach it.
pub fn read_key_file(
    path: &Path,
    limit: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, KeyFileError> {
    let Some(mut file) = open_key_file(path)? else {
        return Ok(None);
    };
    judge_key_file(&file, path)?;
    read_bounded(&mut file, path, limit).map(Some)
}

/// Open `path` for the judgment. `Ok(None)` when the name is absent.
#[cfg(unix)]
fn open_key_file(path: &Path) -> Result<Option<File>, KeyFileError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    match opts.open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        // `O_NOFOLLOW` refuses a link at the name with `ELOOP` on Linux and
        // macOS and `EMLINK` on FreeBSD; the name itself says which it was.
        Err(error) => {
            let link =
                std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink());
            Err(if link {
                KeyFileError::Exposed(path.to_path_buf(), "is a symbolic link".to_owned())
            } else {
                KeyFileError::Io(path.to_path_buf(), error)
            })
        }
    }
}

/// Judge the handle `open_key_file` returned: what is judged is what is read.
#[cfg(unix)]
fn judge_key_file(file: &File, path: &Path) -> Result<(), KeyFileError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let meta = file
        .metadata()
        .map_err(|error| KeyFileError::Io(path.to_path_buf(), error))?;
    if let Some(why) = key_file_exposure(&KeyFileFacts {
        is_file: meta.is_file(),
        owner: meta.uid(),
        group: meta.gid(),
        mode: meta.permissions().mode() & PERMISSION_BITS,
        me: crate::effective_uid(),
    }) {
        return Err(KeyFileError::Exposed(path.to_path_buf(), why));
    }
    Ok(())
}

/// Open `path`. `Ok(None)` when the name is absent.
#[cfg(windows)]
fn open_key_file(path: &Path) -> Result<Option<File>, KeyFileError> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(KeyFileError::Io(path.to_path_buf(), error)),
    }
}

/// Judge the path's owner-only label before any byte is copied.
///
/// `file` is the handle the read will use. The label is still the path's:
/// this is not a judgment of that handle.
#[cfg(windows)]
fn judge_key_file(_file: &File, path: &Path) -> Result<(), KeyFileError> {
    match crate::private_file::check_private(path) {
        Ok(()) => Ok(()),
        Err(error) => Err(from_private(path, error)),
    }
}

#[cfg(windows)]
fn from_private(path: &Path, error: crate::private_file::PrivateFileError) -> KeyFileError {
    use crate::private_file::PrivateFileError;
    match error {
        PrivateFileError::Exposed(path, why) => KeyFileError::Exposed(path, why),
        PrivateFileError::Io(path, error) => KeyFileError::Io(path, error),
        other => KeyFileError::Io(path.to_path_buf(), std::io::Error::other(other.to_string())),
    }
}

/// What a key file's handle says about who can reach it.
#[cfg(unix)]
#[derive(Clone, Copy)]
struct KeyFileFacts {
    is_file: bool,
    owner: u32,
    group: u32,
    mode: u32,
    /// This process's effective user id.
    me: u32,
}

/// Why another account can reach a key file, or `None` when only this
/// account and the superuser can.
#[cfg(unix)]
fn key_file_exposure(facts: &KeyFileFacts) -> Option<String> {
    let KeyFileFacts {
        is_file,
        owner,
        group,
        mode,
        me,
    } = *facts;
    if !is_file {
        return Some("is not a regular file".to_owned());
    }
    if owner != me && owner != SUPERUSER {
        return Some(format!(
            "is owned by uid {owner}, neither this account (uid {me}) nor the superuser"
        ));
    }
    if mode & OTHERS_MAY_WRITE != 0 {
        return Some(format!(
            "has mode {mode:04o}, so another account can write it"
        ));
    }
    if mode & OTHERS_MAY_READ != 0 {
        return Some(format!("has mode {mode:04o}, so every account can read it"));
    }
    if mode & GROUP_MAY_READ != 0 && group != SUPERUSER {
        return Some(format!("has mode {mode:04o}, so group {group} can read it"));
    }
    None
}

/// At most `limit` bytes and one more from `file`, into a buffer wiped on
/// drop and sized once, so no reallocation leaves a copy behind. The rest of
/// a longer file is never read.
fn read_bounded(
    file: &mut File,
    path: &Path,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    use std::io::Read;
    let mut bytes = Zeroizing::new(vec![0u8; limit + 1]);
    let mut filled = 0;
    while filled < bytes.len() {
        match file.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(KeyFileError::Io(path.to_path_buf(), error)),
        }
    }
    bytes.truncate(filled);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A key file is read at most one byte past its limit, and a missing
    /// one is `None`**, on every platform. Red edit: read the whole file and
    /// truncate (a longer file comes back whole), or treat a missing file as
    /// an error.
    #[test]
    fn a_key_file_is_read_at_most_one_byte_past_its_limit() {
        let dir = tempfile::tempdir().expect("directory");
        let key = dir.path().join("key");
        crate::private_file::write_private(&key, &[7; 96]).expect("key");
        let read = read_key_file(&key, 96).expect("read").expect("present");
        assert_eq!(read.as_slice(), &[7; 96]);
        let short = read_key_file(&key, 10).expect("read").expect("present");
        assert_eq!(
            short.as_slice(),
            &[7; 11],
            "one byte past the limit, no more"
        );
        assert!(read_key_file(&dir.path().join("absent"), 96)
            .expect("absent")
            .is_none());
    }

    /// **On Windows a plain file is refused before it is read.** A file made
    /// by a plain create, with the directory's inherited access and no
    /// owner-only label, is `Exposed`. Red edit: judge after the read, or
    /// skip the judgment.
    #[cfg(windows)]
    #[test]
    fn a_plain_file_is_not_a_key_file_on_windows() {
        let dir = tempfile::tempdir().expect("directory");
        let key = dir.path().join("key");
        std::fs::write(&key, [7u8; 96]).expect("plain file");
        assert!(
            matches!(read_key_file(&key, 96), Err(KeyFileError::Exposed(..))),
            "a plain file was read as a key"
        );
    }
}

#[cfg(all(test, unix))]
mod unix {
    use super::*;

    /// A key file's facts, as this account (uid 1000) sees them.
    fn key_facts(owner: u32, group: u32, mode: u32) -> KeyFileFacts {
        KeyFileFacts {
            is_file: true,
            owner,
            group,
            mode,
            me: 1000,
        }
    }

    /// **A systemd credential is a key file this account may read.** The
    /// service manager hands it owned by the superuser, group superuser,
    /// mode `0440` (seen on systemd 257: `LoadCredential=` under `User=`).
    /// So is this account's own `0600` or `0400` file. Red edit: refuse a
    /// superuser owner, or any group read bit.
    #[test]
    fn a_systemd_credential_and_an_owner_only_file_are_key_files() {
        assert_eq!(
            key_file_exposure(&key_facts(SUPERUSER, SUPERUSER, 0o440)),
            None
        );
        assert_eq!(key_file_exposure(&key_facts(1000, 1000, 0o600)), None);
        assert_eq!(key_file_exposure(&key_facts(1000, 1000, 0o400)), None);
        assert_eq!(
            key_file_exposure(&key_facts(SUPERUSER, SUPERUSER, 0o400)),
            None
        );
    }

    /// **A key file another account can reach is refused, by what reaches
    /// it.** A third account's file, a file its group or every account can
    /// write, one every account can read, one a group other than the
    /// superuser's can read, and anything not a regular file. Red edit: drop
    /// any one clause of [`key_file_exposure`].
    #[test]
    fn a_key_file_another_account_can_reach_is_refused() {
        let refused = [
            (key_facts(1001, 1000, 0o600), "neither this account"),
            (key_facts(1000, 1000, 0o620), "another account can write it"),
            (key_facts(1000, 1000, 0o602), "another account can write it"),
            (
                key_facts(SUPERUSER, SUPERUSER, 0o460),
                "another account can write it",
            ),
            (key_facts(1000, 1000, 0o604), "every account can read it"),
            (key_facts(1000, 1000, 0o640), "group 1000 can read it"),
            (key_facts(SUPERUSER, 1000, 0o440), "group 1000 can read it"),
        ];
        for (facts, why) in refused {
            let exposure = key_file_exposure(&facts)
                .unwrap_or_else(|| panic!("mode {:04o} was accepted", facts.mode));
            assert!(exposure.contains(why), "{exposure}");
        }
        let not_a_file = KeyFileFacts {
            is_file: false,
            ..key_facts(1000, 1000, 0o600)
        };
        assert_eq!(
            key_file_exposure(&not_a_file).as_deref(),
            Some("is not a regular file")
        );
    }

    /// **A link and a fifo are refused before a byte is copied.** A link at
    /// the name is not followed. A fifo with no writer is refused at once,
    /// not waited on. Red edit: drop `O_NOFOLLOW` (the link is read), or
    /// `O_NONBLOCK` (the fifo hangs the test).
    #[test]
    fn a_link_and_a_fifo_are_refused_before_a_byte_is_copied() {
        let dir = tempfile::tempdir().expect("directory");
        let key = dir.path().join("key");
        crate::private_file::write_private(&key, &[7; 96]).expect("key");

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&key, &link).expect("link");
        match read_key_file(&link, 96) {
            Err(ref error @ KeyFileError::Exposed(_, ref why)) => {
                assert_eq!(why, "is a symbolic link");
                let said = error.to_string();
                assert!(
                    said.contains(
                        "only this account and the superuser may reach it, so it is refused, not repaired"
                    ),
                    "{said}"
                );
            }
            other => panic!("a link was not refused: {other:?}"),
        }

        let fifo = dir.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("path");
        // SAFETY: `mkfifo` on a NUL-terminated path this test owns. The mode
        // is narrowed by the process umask; the judgment refuses the fifo
        // for not being a regular file before any mode is consulted.
        #[allow(unsafe_code, reason = "mkfifo has no safe wrapper in std")]
        let made = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
        assert_eq!(made, 0, "mkfifo");
        match read_key_file(&fifo, 96) {
            Err(KeyFileError::Exposed(_, why)) => assert_eq!(why, "is not a regular file"),
            other => panic!("a fifo was not refused: {other:?}"),
        }
    }
}
