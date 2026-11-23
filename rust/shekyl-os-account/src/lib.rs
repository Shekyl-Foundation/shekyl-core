// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The operating-system account this process runs as, read from the
//! platform's own interface and never from the environment (IG-Q14).
//!
//! **The contract: who this account is, where its home and its session keep
//! things, which files it alone may read, and which account is at the other
//! end of a local socket; nothing that dials, listens or speaks a
//! protocol.** It is a leaf with no network stack (libc
//! on Unix, `shekyl-win-sec` on Windows), so the daemon's process-hardening
//! crate and the client transport both read the account here without either
//! pulling in the other (`docs/design/RPC_CHANNEL.md` RT-15, §7.1).
//!
//! - [`effective_uid`] (Unix): this process's effective user id.
//! - [`session_dir`]: the account's per-user session directory, where a
//!   run-as-me daemon's owner's socket lives on Unix.
//! - [`account_root`]: the account's root for a rendezvous: the session
//!   directory on Unix, the local application data folder on Windows.
//! - [`account_home`], [`per_account_root_in`], [`per_account_root`]: the
//!   account's home and the per-account root under it
//!   ([`PER_ACCOUNT_ROOT_NAME`]), where every per-account default path sits
//!   (rule 83 IG-13). The one owner of that name: the daemon's
//!   configuration, the rendezvous and the wallets read it here.
//!   [`ensure_per_account_root`] makes it as the daemon does, which a
//!   wallet binary does at its start, before it makes anything in it.
//! - [`create_account_dir_all`]: a directory and the missing ones above it,
//!   made as the daemon makes its data directory: owner-only on Unix
//!   ([`OWNER_ONLY_DIR_MODE`]), whatever the umask.
//!   The wallet directory in it is the wallet file crate's
//!   (`shekyl_engine_file::paths::wallet_dir_in`), which knows networks.
//! - `directory` (Unix): what a path is, as a directory, for this account.
//!   The one walk every caller reads; the mode rule stays with the caller.
//! - [`peer_uid`] (Unix): the account of the process at the other end of a
//!   connected Unix socket (`SO_PEERCRED` on Linux, `getpeereid`
//!   elsewhere). On Windows the pipe's peer check is
//!   `shekyl_win_sec::open_verified`, which opens and checks in one call.
//! - [`private_file`]: files this account alone may read (a key), written
//!   that way in the creating call and refused when read if they are not,
//!   and files it publishes for every account to read; each written
//!   durably, or staged beside its destination and renamed over it.
//! - [`key_file`]: a key file this account or the superuser may read. It is
//!   opened, judged, and then read; a systemd credential qualifies.

#![deny(unsafe_code)]

use std::path::{Path, PathBuf};

#[cfg(unix)]
pub mod directory;
pub mod key_file;
pub mod private_file;

/// This process's effective user id.
#[cfg(unix)]
#[must_use]
#[allow(unsafe_code, reason = "geteuid has no safe wrapper in std")]
pub fn effective_uid() -> u32 {
    // SAFETY: no preconditions; returns the effective user id.
    unsafe { libc::geteuid() }
}

/// The account's per-user session directory, from the platform's own
/// interface, never `XDG_RUNTIME_DIR` (IG-Q14): `/run/user/<euid>` on Linux
/// when it is a directory (the session, or linger, keeps it), and
/// `confstr(_CS_DARWIN_USER_TEMP_DIR)` on macOS. `None` elsewhere and when
/// absent. What is found is only a candidate: the owner's socket asserts
/// its owner and mode before binding (`RPC_CHANNEL.md` §7.1).
#[must_use]
pub fn session_dir() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let dir = PathBuf::from(format!("/run/user/{}", effective_uid()));
        std::fs::symlink_metadata(&dir)
            .is_ok_and(|meta| meta.is_dir())
            .then_some(dir)
    }
    #[cfg(target_os = "macos")]
    {
        darwin_user_temp_dir()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// The account's root for a rendezvous: the session directory on Unix, the
/// local application data folder on Windows. `None` where there is none.
#[must_use]
pub fn account_root() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        session_dir()
    }
    #[cfg(windows)]
    {
        shekyl_win_sec::known_folder::local_app_data()
    }
}

/// The per-account root's name inside the account's home (rule 83 IG-13):
/// `.shekyl` on Linux, FreeBSD and macOS, `Shekyl` on Windows, where the
/// home is the local application data folder.
pub const PER_ACCOUNT_ROOT_NAME: &str = if cfg!(windows) { "Shekyl" } else { ".shekyl" };

/// The per-account root inside `home`, the account's home as
/// [`account_home`] reads it. Every per-account default path sits under it:
/// a run-as-user daemon's data and logs, the wallet directory and the wallet
/// binaries' configuration (rule 83 IG-13). Taking the home as a value lets
/// a caller resolve against a home it was handed.
#[must_use]
pub fn per_account_root_in(home: &Path) -> PathBuf {
    home.join(PER_ACCOUNT_ROOT_NAME)
}

/// This account's per-account root ([`per_account_root_in`] its
/// [`account_home`]), or `None` when the account has no home.
#[must_use]
pub fn per_account_root() -> Option<PathBuf> {
    account_home().map(|home| per_account_root_in(&home))
}

/// Creates the per-account root `root` where it does not exist, as the
/// daemon creates it, so whichever of the daemon and a wallet binary runs
/// first makes the same directory. A wallet binary calls it at its start,
/// before it makes anything in the root: a directory made later, under any
/// spelling of the root's path (Windows matches names without regard to
/// case), then finds the root already made with its protections. On Windows it is owner-only with the
/// no-read-up label, made in the creating call
/// (`shekyl_win_sec::rendezvous::ensure_data_home`); on Unix it is
/// [`OWNER_ONLY_DIR_MODE`], made by [`create_account_dir_all`] as the
/// daemon's data directory is. An existing root is the operator's and is
/// left as it is.
///
/// # Errors
/// The create failed, or on Windows the owner or the descriptor could not
/// be had.
pub fn ensure_per_account_root(root: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        shekyl_win_sec::rendezvous::ensure_data_home(root)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
    #[cfg(not(windows))]
    {
        create_account_dir_all(root)
    }
}

/// The mode of a directory this account alone may enter: what the daemon
/// gives every directory it creates on Unix, whatever the umask.
pub const OWNER_ONLY_DIR_MODE: u32 = 0o700;

/// Brings a directory this process just made to [`OWNER_ONLY_DIR_MODE`],
/// through a handle that refuses a symbolic link. Under a writable parent
/// another account can swap the new name for a link before this runs, and a
/// `chmod` by path would follow it and change a directory this account owns
/// elsewhere. Under an ordinary umask `mkdir` already gave the mode and nothing
/// is changed. A umask that removes the owner's own read bit makes the open
/// fail, and the create reports it.
#[cfg(unix)]
fn settle_new_dir_mode(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let made = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)?;
    if made.metadata()?.permissions().mode() & directory::PERMISSION_BITS != OWNER_ONLY_DIR_MODE {
        made.set_permissions(std::fs::Permissions::from_mode(OWNER_ONLY_DIR_MODE))?;
    }
    Ok(())
}

/// Creates `path` and every directory above it that is missing, the way
/// the daemon creates its data directory (Rick, 2026-11-22).
///
/// On Unix each directory this call creates is [`OWNER_ONLY_DIR_MODE`],
/// whatever the umask: it is created with that mode, which a umask can only
/// narrow, and then set to it. A directory that already exists, or that
/// another process creates first, is not this call's and keeps its mode.
/// The data directory holds the service's console key, the host
/// administrator's credential, and its console socket, so it is the
/// account's alone on its own account, not only through a directory above
/// it.
///
/// On Windows it is `create_dir_all`: each directory inherits its parent's
/// access list. The files and the pipe the daemon keeps there carry their
/// own owner-only descriptors from their creating calls, which Windows
/// enforces on every open, so the directory is not their containment.
///
/// # Errors
/// A directory could not be created or its mode set.
pub fn create_account_dir_all(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // The missing directories, innermost first.
        let mut missing = Vec::new();
        let mut at = Some(path);
        while let Some(dir) = at.filter(|dir| !dir.as_os_str().is_empty()) {
            match std::fs::symlink_metadata(dir) {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(dir);
                    at = dir.parent();
                }
                Err(error) => return Err(error),
            }
        }
        for dir in missing.into_iter().rev() {
            match std::fs::DirBuilder::new()
                .mode(OWNER_ONLY_DIR_MODE)
                .create(dir)
            {
                Ok(()) => settle_new_dir_mode(dir)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        // What is at the path now, whoever made it, must be a directory: a
        // file, or a link to nothing, is not one.
        if !path.as_os_str().is_empty() && !path.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                format!("{} is not a directory", path.display()),
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// The calling account's home from the operating system's account interface
/// (rule 83 IG-13), never `HOME`, `XDG_*` or `%APPDATA%`: the passwd entry's
/// home on Unix, or `None` when the account has none (unset or
/// `/nonexistent`) or it cannot be read.
#[cfg(unix)]
#[must_use]
#[allow(unsafe_code, reason = "getpwuid_r has no safe wrapper in std")]
pub fn account_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    let uid = effective_uid();
    // SAFETY: `passwd` is plain data; a zeroed value is a valid out-struct
    // for `getpwuid_r` to fill.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `entry`, `buffer` and `found` are live locals of the sizes
    // passed; the call writes the entry's strings into `buffer`, which
    // outlives every read of `entry` below.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &raw mut entry,
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            buffer.len(),
            &raw mut found,
        )
    };
    if rc != 0 || found.is_null() || entry.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` points at a NUL-terminated string inside `buffer`.
    let dir = unsafe { CStr::from_ptr(entry.pw_dir) };
    home_of_passwd_dir(dir.to_bytes()).map(|home| PathBuf::from(OsStr::from_bytes(home)))
}

/// The passwd home that names no home: a service account's (rule 83 IG-13).
#[cfg(unix)]
const NO_HOME_SENTINEL: &[u8] = b"/nonexistent";

/// The home a passwd entry's `pw_dir` names: `None` when it is unset (empty)
/// or the no-home sentinel `/nonexistent`, so such an account has no
/// default paths (rule 83 IG-13).
#[cfg(unix)]
fn home_of_passwd_dir(dir: &[u8]) -> Option<&[u8]> {
    (!dir.is_empty() && dir != NO_HOME_SENTINEL).then_some(dir)
}

/// The calling account's home on Windows: the local application data folder
/// (`FOLDERID_LocalAppData`), never Roaming AppData, which copies what is in
/// it to domain servers (rule 83 IG-13).
#[cfg(windows)]
#[must_use]
pub fn account_home() -> Option<PathBuf> {
    shekyl_win_sec::known_folder::local_app_data()
}

/// `confstr(_CS_DARWIN_USER_TEMP_DIR)`: the per-user, per-boot temporary
/// directory macOS keeps for the account, with no environment read.
#[cfg(target_os = "macos")]
#[allow(unsafe_code, reason = "confstr has no safe wrapper")]
fn darwin_user_temp_dir() -> Option<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let mut buffer = vec![0u8; 1024];
    // SAFETY: `buffer` is a live allocation of the length passed; `confstr`
    // writes at most that many bytes, NUL included, and returns the length
    // it needs.
    let needed = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            buffer.len(),
        )
    };
    if needed == 0 || needed > buffer.len() {
        return None;
    }
    // `needed` counts the terminating NUL.
    buffer.truncate(needed - 1);
    let dir = PathBuf::from(OsStr::from_bytes(&buffer));
    // The interface's spelling ends in a separator; the directory is the
    // same without it.
    Some(dir.components().collect())
}

/// The account of the process at the other end of `socket`, a connected
/// Unix socket.
///
/// # Errors
///
/// The operating system's, when the peer's credentials cannot be read.
#[cfg(target_os = "linux")]
#[allow(unsafe_code, reason = "SO_PEERCRED has no safe wrapper in std")]
pub fn peer_uid(socket: &impl std::os::fd::AsFd) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;

    // SAFETY: `ucred` is plain data; a zeroed value is a valid out-struct.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .expect("ucred's size fits socklen_t");
    // SAFETY: `cred` and `length` are locals of the sizes passed, and the
    // descriptor is `socket`'s, borrowed open for the call.
    let failed = unsafe {
        libc::getsockopt(
            socket.as_fd().as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &raw mut length,
        )
    } != 0;
    if failed {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// The account of the process at the other end of `socket`, a connected
/// Unix socket.
///
/// # Errors
///
/// The operating system's, when the peer's credentials cannot be read.
#[cfg(all(unix, not(target_os = "linux")))]
#[allow(unsafe_code, reason = "getpeereid has no safe wrapper in std")]
pub fn peer_uid(socket: &impl std::os::fd::AsFd) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `uid` and `gid` are locals; the descriptor is `socket`'s,
    // borrowed open for the call.
    if unsafe { libc::getpeereid(socket.as_fd().as_raw_fd(), &raw mut uid, &raw mut gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A passwd entry whose home is unset or `/nonexistent` names no home,
    /// so the account has no default paths (rule 83 IG-13); any other path
    /// is the home. Red edit: drop the sentinel, and a service account's
    /// root is `/nonexistent/.shekyl`.
    #[test]
    fn an_unset_or_nonexistent_passwd_home_is_no_home() {
        assert_eq!(home_of_passwd_dir(b""), None);
        assert_eq!(home_of_passwd_dir(b"/nonexistent"), None);
        assert_eq!(
            home_of_passwd_dir(b"/var/lib/shekyl"),
            Some(&b"/var/lib/shekyl"[..])
        );
        assert_eq!(
            home_of_passwd_dir(b"/nonexistent/a"),
            Some(&b"/nonexistent/a"[..])
        );
    }

    /// The passwd home is absolute and exists for the account the tests
    /// run under; it is read without consulting `HOME`.
    #[test]
    fn the_passwd_home_is_an_absolute_existing_directory() {
        let home = account_home().expect("the test account has a passwd entry");
        assert!(home.is_absolute(), "{}", home.display());
        assert!(home.is_dir(), "{}", home.display());
    }

    /// The process at the other end of a pair this process made is this
    /// account.
    #[test]
    fn the_peer_of_this_process_s_own_pair_is_this_account() {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().expect("a pair");
        assert_eq!(
            peer_uid(&ours).expect("the peer's account"),
            effective_uid()
        );
        assert_eq!(
            peer_uid(&theirs).expect("the peer's account"),
            effective_uid()
        );
    }

    /// A descriptor that is not a socket has no peer: the call fails, it
    /// does not answer with an account.
    #[test]
    fn a_descriptor_that_is_not_a_socket_has_no_peer() {
        let file = tempfile::tempfile().expect("a file");
        assert!(peer_uid(&file).is_err());
    }

    /// On Linux the session directory is `/run/user/<euid>`, or none; it is
    /// never what `XDG_RUNTIME_DIR` says. The test sets that variable to a
    /// directory that exists and is not the session directory.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_linux_session_directory_is_the_uids_and_not_the_environments() {
        let elsewhere = tempfile::tempdir().expect("a directory");
        // No other test in this crate reads the variable.
        std::env::set_var("XDG_RUNTIME_DIR", elsewhere.path());
        let expected = PathBuf::from(format!("/run/user/{}", effective_uid()));
        match session_dir() {
            Some(found) => assert_eq!(found, expected),
            None => assert!(!expected.is_dir(), "{} exists", expected.display()),
        }
    }

    /// On Unix the account's root is its session directory.
    #[test]
    fn the_unix_account_root_is_the_session_directory() {
        assert_eq!(account_root(), session_dir());
    }
}

/// The per-account root on every platform, pinned as rule 83 IG-13 states
/// it rather than recomputed from the constant.
#[cfg(test)]
mod per_account_root_tests {
    use super::*;

    #[test]
    fn the_per_account_root_is_the_rules() {
        let home = Path::new("home");
        let expected = if cfg!(windows) { "Shekyl" } else { ".shekyl" };
        assert_eq!(per_account_root_in(home), home.join(expected));
    }

    /// The root is made where it is missing, and an existing one is left as
    /// it is, so the daemon and a wallet binary may each run first.
    #[test]
    fn the_root_is_made_once_and_then_left_as_it_is() {
        let base = tempfile::tempdir().expect("a scratch directory");
        let root = per_account_root_in(base.path());
        ensure_per_account_root(&root).expect("the root is made");
        assert!(root.is_dir(), "{}", root.display());
        ensure_per_account_root(&root).expect("an existing root is left as it is");
    }

    /// On Windows the root is made owner-only with the no-read-up label,
    /// as the daemon makes it, and a directory made in it afterwards under
    /// another spelling of its name lands in that same root. Windows only:
    /// the estate's Windows hosts run it.
    #[cfg(windows)]
    #[test]
    fn the_root_is_owner_only_and_a_respelled_path_finds_it() {
        let base = tempfile::tempdir().expect("a scratch directory");
        let root = per_account_root_in(base.path());
        ensure_per_account_root(&root).expect("the root is made");
        shekyl_win_sec::rendezvous::check_owner_only_labelled(&root)
            .expect("the root is owner-only and refuses read-up");
        let respelled = base.path().join("SHEKYL").join("wallets");
        std::fs::create_dir_all(&respelled).expect("made");
        assert!(root.join("wallets").is_dir(), "the same root");
        shekyl_win_sec::rendezvous::check_owner_only_labelled(&root)
            .expect("the root keeps its protections");
    }

    /// On Unix every directory the creator makes is owner-only, the data
    /// home and the network directory alike, and a directory that was
    /// already there keeps its mode. Red edit: `create_dir_all`, whose
    /// directories take the umask's mode (`0755` under the common `022`).
    #[cfg(unix)]
    #[test]
    fn every_directory_made_is_owner_only_and_an_existing_one_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |dir: &Path| {
            std::fs::metadata(dir)
                .expect("the directory's metadata")
                .permissions()
                .mode()
                & 0o777
        };
        let base = tempfile::tempdir().expect("a scratch directory");
        let shared = base.path().join("shared");
        std::fs::create_dir(&shared).expect("made");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).expect("set");
        let home = shared.join("home");
        let data = home.join("testnet");
        create_account_dir_all(&data).expect("made");
        assert_eq!(mode(&home), OWNER_ONLY_DIR_MODE, "the data home");
        assert_eq!(mode(&data), OWNER_ONLY_DIR_MODE, "the network directory");
        assert_eq!(
            mode(&shared),
            0o755,
            "an existing directory is not this call's"
        );
        create_account_dir_all(&data).expect("an existing directory is left as it is");
    }

    /// The new directory's mode is settled through a handle that refuses a
    /// link, so a name swapped for a link in the moment after `mkdir` cannot
    /// redirect the change to a directory elsewhere. Red edit: `chmod` by path,
    /// and the link's target becomes 0700.
    #[cfg(unix)]
    #[test]
    fn a_new_directory_swapped_for_a_link_does_not_redirect_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |dir: &Path| {
            std::fs::metadata(dir)
                .expect("the directory's metadata")
                .permissions()
                .mode()
                & directory::PERMISSION_BITS
        };
        let base = tempfile::tempdir().expect("a scratch directory");
        let elsewhere = base.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("made");
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o750)).expect("set");
        let swapped = base.path().join("swapped");
        std::os::unix::fs::symlink(&elsewhere, &swapped).expect("a link");
        settle_new_dir_mode(&swapped).expect_err("a link is refused");
        assert_eq!(mode(&elsewhere), 0o750, "the link's target is untouched");

        // A umask that narrowed the owner's bits is brought back to the mode.
        let narrowed = base.path().join("narrowed");
        std::fs::create_dir(&narrowed).expect("made");
        std::fs::set_permissions(&narrowed, std::fs::Permissions::from_mode(0o600)).expect("set");
        settle_new_dir_mode(&narrowed).expect("a directory of its own");
        assert_eq!(mode(&narrowed), OWNER_ONLY_DIR_MODE);
    }

    /// A path that is a file, or a link to nothing, is not a directory, and
    /// the creator says so rather than succeeding. Red edit: drop the final
    /// check, and both return `Ok`.
    #[cfg(unix)]
    #[test]
    fn a_file_or_a_dangling_link_at_the_path_is_refused() {
        let base = tempfile::tempdir().expect("a scratch directory");
        let file = base.path().join("file");
        std::fs::write(&file, b"").expect("a file");
        let dangling = base.path().join("dangling");
        std::os::unix::fs::symlink(base.path().join("nowhere"), &dangling).expect("a link");
        for path in [&file, &dangling] {
            let error = create_account_dir_all(path).expect_err("not a directory");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotADirectory,
                "{}",
                path.display()
            );
        }
    }

    /// The root this account resolves is its home's, on every platform the
    /// tests run on; every test account has a home.
    #[test]
    fn this_account_s_root_is_under_its_home() {
        let home = account_home().expect("the test account has a home");
        assert_eq!(per_account_root(), Some(per_account_root_in(&home)));
        assert!(home.is_absolute(), "{}", home.display());
    }
}
