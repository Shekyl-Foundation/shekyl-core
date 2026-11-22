// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The in-process server's private socket directory (Unix).
//!
//! The directory is published under its final name only after this process
//! holds its lock. A sweep removes a matching directory when this account
//! owns it and no server holds it. Holding is two facts, because `flock` is
//! not the same shape on every Unix: on Linux a second open in this process
//! blocks, and on FreeBSD and macOS a lock is per process, so a second
//! server here would be granted the lock it already holds. The file lock is
//! what another process sees. The set below is what this process sees.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing::{info, warn};

/// `shekyl-rpc-`, the prefix of a private directory's name.
pub const DIR_PREFIX: &str = "shekyl-rpc-";

/// `wallet-rpc.sock`, the socket's name inside the private directory.
pub const SOCKET_FILE: &str = "wallet-rpc.sock";

/// `wallet-rpc.lock`, held exclusively for the life of the server.
pub const LOCK_FILE: &str = "wallet-rpc.lock";

/// The private directory is traversable by its owner alone.
const DIR_MODE: u32 = 0o700;

/// The lock file is readable and writable by its owner alone. The socket is
/// given the same mode by the listener after it binds.
const LOCK_MODE: u32 = 0o600;

/// Appended while the directory is built. The final name appears at rename,
/// after the lock is held, so a sweep cannot observe a published directory
/// that nobody holds yet.
const CREATING_SUFFIX: &str = ".creating";

/// Directories this process has published and not yet dropped. A sweep skips
/// these before it tries the lock.
static HELD: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// The private directory and the lock that keeps a sweep from removing it.
pub(super) struct PrivateDir {
    path: PathBuf,
    lock: Option<File>,
}

/// Whether the socket file was present when the directory was removed.
pub(super) enum SocketFile {
    /// The serve task had already unlinked it.
    Absent,
    /// It was still there, and it has been removed.
    Removed,
}

impl PrivateDir {
    /// The directory's path.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the directory while this server still holds it.
    ///
    /// # Errors
    ///
    /// The socket, the lock file, or the directory could not be removed. The
    /// error names the path.
    pub(super) fn remove(self) -> io::Result<SocketFile> {
        let outcome = delete(&self.path);
        if let Ok(SocketFile::Removed) = &outcome {
            warn!(
                path = %self.path.join(SOCKET_FILE).display(),
                "the wallet RPC socket was still there at shutdown; removed"
            );
        }
        outcome
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        forget(&self.path);
        // Releasing the lock is what lets a later process's sweep remove a
        // directory this one did not. Shutdown removes the directory first;
        // this drop then releases the lock on a directory that is already gone.
        self.lock.take();
    }
}

/// Create the private directory for spawn `spawn` under the runtime base,
/// sweeping directories no server holds.
///
/// # Errors
///
/// The directory could not be created, or the name is already held.
pub(super) fn create(spawn: u64) -> io::Result<PrivateDir> {
    let base = runtime_base();
    sweep(&base);
    create_at(&base, std::process::id(), spawn)
}

fn runtime_base() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

/// Remove private directories in `base` that no server holds.
fn sweep(base: &Path) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if parse_dir_name(name).is_none() {
            continue;
        }
        let dir = entry.path();
        match occupant(&dir) {
            Ok(Occupant::Absent | Occupant::Kept) => {}
            Ok(Occupant::Stale { lock }) => {
                let removed = delete(&dir);
                drop(lock);
                match removed {
                    Ok(_) => {
                        info!(path = %dir.display(), "removed a stale wallet RPC socket directory")
                    }
                    Err(error) => warn!(
                        error = %error,
                        "a stale wallet RPC socket directory could not be removed"
                    ),
                }
            }
            // A lock that is not an ordinary file is refused before it is
            // opened, so the warning is the refusal, not a failed removal.
            Err(error) => warn!(
                error = %error,
                "a wallet RPC socket directory was left in place"
            ),
        }
    }
}

/// A parsed `shekyl-rpc-<pid>-<spawn>` name, optionally still `.creating`.
///
/// The fields are the grammar. Production asks only whether the parse
/// succeeded; the tests read the parts.
#[cfg_attr(not(test), allow(dead_code))]
struct DirName {
    pid: u32,
    spawn: u64,
    creating: bool,
}

fn parse_dir_name(name: &str) -> Option<DirName> {
    let (body, creating) = match name.strip_suffix(CREATING_SUFFIX) {
        Some(body) => (body, true),
        None => (name, false),
    };
    let rest = body.strip_prefix(DIR_PREFIX)?;
    let (pid, spawn) = rest.split_once('-')?;
    let decimal = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if !decimal(pid) || !decimal(spawn) {
        return None;
    }
    Some(DirName {
        pid: pid.parse().ok()?,
        spawn: spawn.parse().ok()?,
        creating,
    })
}

/// What a sweep may do with one private-directory path.
enum Occupant {
    /// Nothing is at the path.
    Absent,
    /// Leave it. This process published it, another server holds the lock,
    /// another account owns it, or it is not a directory. A directory that is
    /// a link is this too: it is not followed.
    Kept,
    /// This account owns it and no server holds it. When the lock file
    /// existed, `lock` is the file this call holds, through the removal.
    Stale { lock: Option<File> },
}

fn occupant(dir: &Path) -> io::Result<Occupant> {
    // Before the lock. On FreeBSD and macOS `flock` is per process, so a
    // second open here would be granted the lock this process already holds.
    if held_by_this_process(dir) {
        return Ok(Occupant::Kept);
    }
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Occupant::Absent),
        Err(error) => return Err(at(dir, &error)),
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Ok(Occupant::Kept);
    }
    use std::os::unix::fs::MetadataExt as _;
    if meta.uid() != shekyl_os_account::effective_uid() {
        return Ok(Occupant::Kept);
    }
    let lock_path = dir.join(LOCK_FILE);
    match std::fs::symlink_metadata(&lock_path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Occupant::Stale { lock: None }),
        Err(error) => Err(at(&lock_path, &error)),
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("{} is not a lock file", lock_path.display()),
        )),
        Ok(_) => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .map_err(|error| at(&lock_path, &error))?;
            match file.try_lock() {
                Ok(()) => Ok(Occupant::Stale { lock: Some(file) }),
                Err(std::fs::TryLockError::WouldBlock) => Ok(Occupant::Kept),
                Err(std::fs::TryLockError::Error(error)) => Err(at(&lock_path, &error)),
            }
        }
    }
}

fn create_at(base: &Path, pid: u32, spawn: u64) -> io::Result<PrivateDir> {
    let final_dir = base.join(format!("{DIR_PREFIX}{pid}-{spawn}"));
    let creating = base.join(format!("{DIR_PREFIX}{pid}-{spawn}{CREATING_SUFFIX}"));
    clear_stale(&final_dir)?;
    clear_stale(&creating)?;
    // The creating name joins the set before the directory exists. Between
    // the mkdir and the lock, a sweep in this process (another server
    // starting on another thread) would otherwise find a directory with no
    // lock held, and on FreeBSD and macOS its `try_lock` would be granted
    // anyway (per-process `flock`): it would remove the directory under this
    // start, and this start's lock would fail.
    remember(&creating);
    if let Err(error) = std::fs::DirBuilder::new().mode(DIR_MODE).create(&creating) {
        forget(&creating);
        return Err(at(&creating, &error));
    }
    let lock_path = creating.join(LOCK_FILE);
    let lock = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(LOCK_MODE)
        .open(&lock_path)
    {
        Ok(file) => file,
        Err(error) => {
            abandon(&creating);
            forget(&creating);
            return Err(at(&lock_path, &error));
        }
    };
    if let Err(error) = lock.lock() {
        abandon(&creating);
        forget(&creating);
        return Err(at(&lock_path, &error));
    }
    // The final name too, before it is visible: what a same-process sweep
    // sees after the rename. `flock` would not stop that sweep on FreeBSD or
    // macOS.
    remember(&final_dir);
    // CLIPPY: disallowed_methods — the unpublished directory is renamed onto
    // its final name. That is not a file replace.
    #[allow(
        clippy::disallowed_methods,
        reason = "renames the unpublished directory onto its final name; not a file replace"
    )]
    if let Err(error) = std::fs::rename(&creating, &final_dir) {
        forget(&creating);
        forget(&final_dir);
        abandon(&creating);
        return Err(at(&final_dir, &error));
    }
    forget(&creating);
    Ok(PrivateDir {
        path: final_dir,
        lock: Some(lock),
    })
}

fn clear_stale(dir: &Path) -> io::Result<()> {
    match occupant(dir)? {
        Occupant::Absent => Ok(()),
        Occupant::Kept => match std::fs::symlink_metadata(dir) {
            Ok(_) => Err(io::Error::new(
                ErrorKind::AlreadyExists,
                format!("{} is in use", dir.display()),
            )),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(at(dir, &error)),
        },
        Occupant::Stale { lock } => {
            let removed = delete(dir);
            drop(lock);
            removed.map(|_| ())
        }
    }
}

/// Remove a directory this start did not publish. A failure is left for the
/// next sweep: this path is already returning the error that caused it.
fn abandon(dir: &Path) {
    drop(delete(dir));
}

fn delete(dir: &Path) -> io::Result<SocketFile> {
    let socket = remove_if_present(&dir.join(SOCKET_FILE))?;
    remove_if_present(&dir.join(LOCK_FILE))?;
    std::fs::remove_dir(dir).map_err(|error| at(dir, &error))?;
    Ok(socket)
}

fn remove_if_present(path: &Path) -> io::Result<SocketFile> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(SocketFile::Removed),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(SocketFile::Absent),
        Err(error) => Err(at(path, &error)),
    }
}

fn at(path: &Path, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{}: {error}", path.display()))
}

fn with_held<T>(body: impl FnOnce(&mut Vec<PathBuf>) -> T) -> T {
    let mut held = HELD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    body(&mut held)
}

fn remember(path: &Path) {
    with_held(|held| {
        if !held.iter().any(|have| have == path) {
            held.push(path.to_path_buf());
        }
    });
}

fn forget(path: &Path) {
    with_held(|held| held.retain(|have| have != path));
}

fn held_by_this_process(path: &Path) -> bool {
    with_held(|held| held.iter().any(|have| have == path))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    /// The sweep's whole idea of a name. Anything else is left alone, including
    /// a name that merely contains a pid. Red edit: accept `shekyl-rpc-1`.
    #[test]
    fn only_a_private_directory_name_parses() {
        let parsed = parse_dir_name("shekyl-rpc-4242-0").expect("a final name");
        assert_eq!(parsed.pid, 4242);
        assert_eq!(parsed.spawn, 0);
        assert!(!parsed.creating);
        let creating = parse_dir_name("shekyl-rpc-4242-17.creating").expect("a creating name");
        assert_eq!(creating.pid, 4242);
        assert_eq!(creating.spawn, 17);
        assert!(creating.creating);
        for other in [
            "shekyl-rpc-4242",
            "shekyl-rpc--0",
            "shekyl-rpc-4242-",
            "shekyl-rpc-42a-0",
            "shekyl-rpc-4242-0x",
            "shekyl-rpc-+42-0",
            "shekyl-rpc-99999999999-0",
            "shekyl-rpc-dispatch-x-1",
            "other-4242-0",
            "shekyl-rpc-4242-0.creating.creating",
        ] {
            assert!(parse_dir_name(other).is_none(), "{other}");
        }
    }

    /// A directory this process holds is left in place, including a second
    /// directory held beside it. A directory whose lock has been released is
    /// removed, and so is one that never had a lock, including a half-built
    /// `.creating` directory. A name that is not `shekyl-rpc-<pid>-<spawn>`
    /// stays. A link is not followed, whether it is the directory or the lock
    /// file. Red edit: sweep by pid, remove a directory this process still
    /// holds, follow a link, or keep a half-built directory.
    #[test]
    fn a_held_directory_stays_and_an_unheld_one_is_removed() {
        let base = tempfile::tempdir().expect("tempdir");
        let root = base.path();
        let held = create_at(root, 10, 0).expect("first directory");
        let also = create_at(root, 10, 1).expect("second directory");
        assert_eq!(mode(held.path()), 0o700);
        assert_eq!(mode(&held.path().join(LOCK_FILE)), 0o600);

        let released = root.join(format!("{DIR_PREFIX}20-0"));
        std::fs::create_dir(&released).expect("released dir");
        std::fs::write(released.join(SOCKET_FILE), b"").expect("its socket");
        drop(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(released.join(LOCK_FILE))
                .expect("a lock that is not held"),
        );
        let unlocked = root.join(format!("{DIR_PREFIX}30-0"));
        std::fs::create_dir(&unlocked).expect("unlocked dir");
        std::fs::write(unlocked.join(SOCKET_FILE), b"").expect("its socket");
        let target = root.join("real");
        std::fs::create_dir(&target).expect("link target");
        std::fs::write(target.join("keep"), b"x").expect("target file");
        std::os::unix::fs::symlink(&target, root.join(format!("{DIR_PREFIX}40-0"))).expect("link");
        let creating = root.join(format!("{DIR_PREFIX}50-0{CREATING_SUFFIX}"));
        std::fs::create_dir(&creating).expect("creating dir");
        std::fs::write(creating.join(SOCKET_FILE), b"").expect("its socket");
        let decoy = root.join(format!("{DIR_PREFIX}4242"));
        std::fs::create_dir(&decoy).expect("a name that only begins with the prefix");
        let secret = root.join("secret");
        std::fs::write(&secret, b"keep").expect("secret");
        let linked_lock = root.join(format!("{DIR_PREFIX}60-0"));
        std::fs::create_dir(&linked_lock).expect("dir whose lock is a link");
        std::os::unix::fs::symlink(&secret, linked_lock.join(LOCK_FILE)).expect("lock link");

        sweep(root);
        assert!(
            held.path().join(LOCK_FILE).exists(),
            "a held directory was removed"
        );
        assert!(
            also.path().join(LOCK_FILE).exists(),
            "the other held directory was removed"
        );
        assert!(!released.exists(), "a released lock was left behind");
        assert!(
            !unlocked.exists(),
            "a directory with no lock was left behind"
        );
        assert!(
            target.join("keep").exists(),
            "a directory link was followed"
        );
        assert!(root
            .join(format!("{DIR_PREFIX}40-0"))
            .symlink_metadata()
            .expect("the link")
            .file_type()
            .is_symlink());
        assert!(!creating.exists(), "a half-built directory was left behind");
        assert!(
            decoy.exists(),
            "a name that is not a private directory was removed"
        );
        assert!(secret.exists(), "a lock file that is a link was followed");
        assert!(
            linked_lock.exists(),
            "a directory whose lock is a link was removed"
        );

        drop(held);
        sweep(root);
        assert!(
            !root.join(format!("{DIR_PREFIX}10-0")).exists(),
            "a dropped directory stayed"
        );
        assert!(
            also.path().exists(),
            "dropping one directory removed the other"
        );
    }

    /// Keeps `path` in the in-process set until dropped.
    struct Published(PathBuf);

    impl Published {
        fn new(path: &Path) -> Self {
            remember(path);
            Self(path.to_path_buf())
        }
    }

    impl Drop for Published {
        fn drop(&mut self) {
            forget(&self.0);
        }
    }

    /// The in-process set is the whole reason this directory stays: it has
    /// no lock, so a sweep that trusts `try_lock` alone removes it. That is
    /// what FreeBSD and macOS need, where `flock` is per process and a
    /// second open in this process is granted. Red edit: delete the set and
    /// decide only by the lock.
    /// Servers starting at once in one process, each sweeping the base its
    /// siblings are creating in: every start succeeds and keeps its own
    /// directory. Seen red on macOS (a sibling's sweep removed a directory
    /// between its mkdir and its lock: `wallet-rpc.lock: Invalid argument`).
    /// Red edit: record the creating name only after the lock.
    #[test]
    fn starts_in_one_process_never_sweep_each_other() {
        const STARTS: u64 = 8;
        const ROUNDS: usize = 50;
        for round in 0..ROUNDS {
            let base = tempfile::tempdir().expect("tempdir");
            let gate = std::sync::Barrier::new(usize::try_from(STARTS).expect("small"));
            let made: Vec<PrivateDir> = std::thread::scope(|scope| {
                let starts: Vec<_> = (0..STARTS)
                    .map(|spawn| {
                        let (base, gate) = (base.path(), &gate);
                        scope.spawn(move || {
                            gate.wait();
                            sweep(base);
                            create_at(base, 7, 1000 * round as u64 + spawn)
                        })
                    })
                    .collect();
                starts
                    .into_iter()
                    .map(|start| {
                        start
                            .join()
                            .expect("a start thread")
                            .unwrap_or_else(|e| panic!("round {round}: a start failed: {e}"))
                    })
                    .collect()
            });
            for dir in &made {
                assert!(
                    dir.path().join(LOCK_FILE).exists(),
                    "round {round}: {} lost its lock file to a sibling's sweep",
                    dir.path().display()
                );
            }
            for dir in made {
                dir.remove().expect("remove");
            }
        }
    }

    #[test]
    fn a_directory_this_process_published_stays_even_with_no_lock() {
        let base = tempfile::tempdir().expect("tempdir");
        let dir = base.path().join(format!("{DIR_PREFIX}7-0"));
        std::fs::create_dir(&dir).expect("dir");
        std::fs::write(dir.join(SOCKET_FILE), b"").expect("socket");
        let published = Published::new(&dir);
        sweep(base.path());
        assert!(
            dir.join(SOCKET_FILE).exists(),
            "a directory this process published was removed"
        );
        drop(published);
        sweep(base.path());
        assert!(
            !dir.exists(),
            "forgetting the directory left it for the next start"
        );
    }
}
