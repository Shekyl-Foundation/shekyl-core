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
//! On Windows the judgment is the open handle too. The open shares reading
//! only, so while it is held no other open can write, rename, replace or
//! delete the file: a swap of the name between the judgment and the read
//! cannot happen. A reader that shares reading, such as a backup agent or a
//! scanner, does not stop it; a holder with write access does, and the open
//! fails. The open does not follow a reparse point at the name. A reparse
//! point, such as a symbolic link, is refused, and so is a directory: backup
//! semantics let a directory open so the judgment can see it. The rule is
//! the one [`crate::private_file::check_private`] applies to a path, read
//! from the handle by [`crate::private_file::check_private_file`] (owned by
//! this account, a protected access list that admits no other principal, a
//! no-read-up label). That read is one snapshot of the handle's descriptor.

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

/// Open the name itself. A reparse point is not followed, and a directory
/// opens so the judgment can refuse it.
#[cfg(windows)]
const OPEN_THE_NAME: u32 = windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT
    | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

/// Open `path` for the judgment, sharing reading only and not following a
/// reparse point at the name. `Ok(None)` when the name is absent.
///
/// Sharing reading only is the point: while this handle is held, no open
/// with write or delete access succeeds, so the name cannot be renamed,
/// replaced or written between the judgment and the read. Denying readers
/// too would add nothing (who may read is the access list's to say) and
/// would refuse the start whenever a backup agent or a scanner held the file.
///
/// [`OPEN_THE_NAME`] includes backup semantics. Without them a directory
/// fails in the open and is reported unreadable, and the judgment never
/// sees that it is not a file.
#[cfg(windows)]
fn open_key_file(path: &Path) -> Result<Option<File>, KeyFileError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(OPEN_THE_NAME);
    match opts.open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(KeyFileError::Io(path.to_path_buf(), error)),
    }
}

/// Judge the handle `open_key_file` returned: what is judged is what is read.
/// A reparse point (opened as itself, not followed) and anything not a
/// regular file are refused; then the handle's own descriptor must be
/// owner-only and labelled.
#[cfg(windows)]
fn judge_key_file(file: &File, path: &Path) -> Result<(), KeyFileError> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let meta = file
        .metadata()
        .map_err(|error| KeyFileError::Io(path.to_path_buf(), error))?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(KeyFileError::Exposed(
            path.to_path_buf(),
            REPARSE_POINT.to_owned(),
        ));
    }
    if !meta.is_file() {
        return Err(KeyFileError::Exposed(
            path.to_path_buf(),
            "is not a regular file".to_owned(),
        ));
    }
    crate::private_file::check_private_file(path, file).map_err(|error| key_error(path, error))
}

/// [`crate::private_file::check_private_file`]'s refusal, in this module's
/// error. `Exposed` and `Io` keep the path they already name. Any other
/// refusal names `opened`, the name this read opened.
#[cfg(windows)]
fn key_error(opened: &Path, error: crate::private_file::PrivateFileError) -> KeyFileError {
    use crate::private_file::PrivateFileError;
    match error {
        PrivateFileError::Exposed(path, why) => KeyFileError::Exposed(path, why),
        PrivateFileError::Io(path, error) => KeyFileError::Io(path, error),
        other => KeyFileError::Io(opened.to_path_buf(), std::io::Error::other(other)),
    }
}

/// Why a reparse point at the name is refused.
#[cfg(windows)]
const REPARSE_POINT: &str = "is a reparse point, such as a symbolic link";

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

#[cfg(all(test, windows))]
mod windows {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    /// Windows' "the process cannot access the file because it is being
    /// used by another process".
    const SHARING_VIOLATION: i32 = 32;

    /// A private key file of 96 bytes in a fresh directory.
    fn private_key() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("directory");
        let key = dir.path().join("key");
        crate::private_file::write_private(&key, &[7; 96]).expect("key");
        (dir, key)
    }

    /// Open `path` as another process would, sharing everything.
    fn hold(path: &Path, write: bool) -> File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(write)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(path)
            .expect("the other holder")
    }

    /// **While the judged handle is held, the name cannot be renamed or the
    /// file written.** The swap the judgment would otherwise miss cannot
    /// happen. Once the handle is closed both succeed, so the refusal is the
    /// handle's. Red edit: share writing or deleting in `open_key_file`.
    #[test]
    // CLIPPY: disallowed_methods — the rename is the swap under test, not a replace.
    #[allow(
        clippy::disallowed_methods,
        reason = "test support: a rename of the held name is the swap the share mode must refuse"
    )]
    fn a_judged_key_file_cannot_be_renamed_or_written_while_held() {
        let (dir, key) = private_key();
        let held = open_key_file(&key).expect("open").expect("present");
        judge_key_file(&held, &key).expect("a private key file is a key file");
        let moved = dir.path().join("moved");
        let renamed = std::fs::rename(&key, &moved).expect_err("the name was renamed while held");
        assert_eq!(renamed.raw_os_error(), Some(SHARING_VIOLATION), "{renamed}");
        let written = std::fs::OpenOptions::new()
            .write(true)
            .open(&key)
            .expect_err("the file was opened for writing while held");
        assert_eq!(written.raw_os_error(), Some(SHARING_VIOLATION), "{written}");
        drop(held);
        std::fs::rename(&key, &moved).expect("the rename once the handle is closed");
    }

    /// **A key file another process holds for reading is still read; one it
    /// holds for writing is refused.** A backup agent or a scanner shares
    /// reading, so the start goes on. A writer could change the key under
    /// the judgment, so the open fails with a sharing violation. Red edit:
    /// open sharing nothing (the reader's hold refuses the start), or share
    /// writing (the writer's hold is read).
    #[test]
    fn a_reader_s_hold_is_read_and_a_writer_s_is_refused() {
        let (_dir, key) = private_key();
        let reader = hold(&key, false);
        let read = read_key_file(&key, 96)
            .expect("read beside a reader")
            .expect("present");
        assert_eq!(read.as_slice(), &[7; 96]);
        drop(reader);
        let writer = hold(&key, true);
        match read_key_file(&key, 96) {
            Err(KeyFileError::Io(_, error)) => {
                assert_eq!(error.raw_os_error(), Some(SHARING_VIOLATION), "{error}");
            }
            other => panic!("a key file a writer holds was not refused: {other:?}"),
        }
        drop(writer);
    }

    /// **A directory at the name is refused as not a regular file.** The open
    /// uses backup semantics, so the directory opens and the judgment sees
    /// it. Red edit: drop `FILE_FLAG_BACKUP_SEMANTICS` from [`OPEN_THE_NAME`]
    /// (the open fails, and the name is reported unreadable).
    #[test]
    fn a_directory_at_the_name_is_refused() {
        let dir = tempfile::tempdir().expect("directory");
        let nested = dir.path().join("not-a-key");
        std::fs::create_dir(&nested).expect("directory");
        match read_key_file(&nested, 96) {
            Err(KeyFileError::Exposed(_, why)) => assert_eq!(why, "is not a regular file"),
            other => panic!("a directory was not refused: {other:?}"),
        }
    }

    /// **A symbolic link at the name is refused, not followed.** The link
    /// points at a private key file this account could read; it is refused
    /// as a reparse point before any byte is copied. Creating the link needs
    /// the symbolic-link privilege or developer mode, which this test
    /// requires. Red edit: drop `FILE_FLAG_OPEN_REPARSE_POINT` (the target
    /// is read through the link), or the reparse-point check (the link is
    /// refused for another reason, and the reason is asserted).
    #[test]
    fn a_symbolic_link_at_the_name_is_refused() {
        let (dir, key) = private_key();
        let link = dir.path().join("link");
        std::os::windows::fs::symlink_file(&key, &link)
            .expect("this test needs the symbolic-link privilege or developer mode");
        match read_key_file(&link, 96) {
            Err(KeyFileError::Exposed(_, why)) => assert_eq!(why, REPARSE_POINT),
            other => panic!("a link was not refused as a reparse point: {other:?}"),
        }
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
