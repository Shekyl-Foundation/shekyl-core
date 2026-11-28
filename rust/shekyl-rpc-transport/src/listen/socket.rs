// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Unix socket every Shekyl listener binds (Rick, 2026-11-22).
//!
//! One order, so the wallet RPC, the daemon's owner socket, the daemon's
//! console leg and the tunnel cannot disagree: the directory is this
//! account's alone, what is at the path is replaceable and is removed, the
//! socket is created and close-on-exec before its bind, bound in the
//! directory being held, narrowed to [`OWNER_ONLY_SOCKET_MODE`] on that
//! directory's name, and only then listens. The removal and the mode use
//! the directory descriptor. Each listener keeps only its own wording of a
//! refusal, said
//! through [`OwnerSocketRefusal::line`]. The directory's fact is
//! [`shekyl_os_account::directory::account_alone`], said once.

use std::ffi::{c_int, OsStr};
use std::fs::File;
use std::io::{self, ErrorKind};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::fs::{chmodat, fstat, lstat, statat, unlinkat, AtFlags, FileType, Mode};
use shekyl_os_account::directory::{account_alone, AccountAloneFault};

use super::SOCKET_PROBE_BOUND;

/// The mode of every listener's socket from the first moment anything can
/// connect to it: this account's alone ([`bind_owner_only_socket`]).
pub const OWNER_ONLY_SOCKET_MODE: u32 = 0o600;

/// The listen backlog: the system's maximum, what tokio's own Unix bind
/// asks for (through mio) on Linux, FreeBSD and macOS, so a listener queues
/// as it did before it bound through [`bind_owner_only_socket`].
const SOCKET_BACKLOG: c_int = -1;

/// How often a start polls for another start's hold on the directory.
const START_POLL: Duration = Duration::from_millis(10);

/// Whether a listener may replace what is at its socket path. The one
/// decision every socket listener shares, and only through
/// [`bind_owner_only_socket`]: that bind holds the directory, and a caller
/// of the decision alone would see a socket that is bound and not yet
/// listening as a stopped server's.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SocketPath {
    /// Nothing is there, or a socket whose server is proven gone: remove
    /// it, if it is there, and bind.
    Replace,
    /// Leave the path as it is and refuse the start, for this reason.
    Refuse(SocketRefusal),
}

/// Why a listener may not bind at a socket path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketRefusal {
    /// A server accepted the probe: it is live.
    Answers,
    /// Something other than a socket is at the path, a symbolic link
    /// included: it is not the listener's to remove.
    NotASocket,
    /// A socket another account owns (its uid): not the listener's to
    /// remove, whatever its server's state.
    NotThisAccounts(u32),
    /// The probe proved nothing: another account's socket (permission
    /// denied), a server whose accept queue is full, no answer within
    /// [`super::SOCKET_PROBE_BOUND`], or the path could not be read.
    Unknown(String),
    /// The path may be replaced, and removing the file failed. The path is
    /// left as it is.
    NotRemoved(String),
}

/// May the listener replace the name `name` in `dir`?
///
/// The name is read from `dir`'s descriptor, without following a symbolic
/// link, and only a socket this account owns is ever probed. The type check
/// is part of the decision, not a courtesy: on Linux a connect to a path
/// that is not a socket also reports connection refused, the same answer a
/// dead server's socket gives, so a probe alone would replace a regular
/// file, or a link to a dead socket elsewhere. A socket is replaced only
/// when its connection is refused, the one answer that proves its server
/// gone. The probe is bounded by [`super::SOCKET_PROBE_BOUND`]; it is
/// synchronous, so a start that binds before its runtime serves (the
/// daemon's owner socket) takes the same decision as one that binds inside
/// it. On Linux the probe dials the name through `dir`'s descriptor. Where
/// that path does not exist, the probe dials `path` only while `path`'s
/// directory is still `dir`.
fn may_replace_socket(dir: &File, name: &OsStr, path: &Path) -> SocketPath {
    let found = match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(found) => found,
        Err(error) if error.kind() == ErrorKind::NotFound => return SocketPath::Replace,
        Err(error) => return SocketPath::Refuse(SocketRefusal::Unknown(error.to_string())),
    };
    if FileType::from_raw_mode(found.st_mode) != FileType::Socket {
        return SocketPath::Refuse(SocketRefusal::NotASocket);
    }
    let uid = owner_uid(&found);
    if uid != shekyl_os_account::effective_uid() {
        return SocketPath::Refuse(SocketRefusal::NotThisAccounts(uid));
    }
    match probe_socket(dir, name, path) {
        Ok(()) => SocketPath::Refuse(SocketRefusal::Answers),
        Err(error) if error.kind() == ErrorKind::ConnectionRefused => SocketPath::Replace,
        Err(error) if error.kind() == ErrorKind::TimedOut => {
            SocketPath::Refuse(SocketRefusal::Unknown(format!(
                "no answer within {} s",
                SOCKET_PROBE_BOUND.as_secs()
            )))
        }
        Err(error) => SocketPath::Refuse(SocketRefusal::Unknown(error.to_string())),
    }
}

/// Dial the socket at `name` in `dir`. Linux dials it through the directory
/// descriptor, so a parent swapped for a link is not what is probed.
fn probe_socket(dir: &File, name: &OsStr, path: &Path) -> io::Result<()> {
    let pinned = Path::new("/proc/self/fd")
        .join(dir.as_raw_fd().to_string())
        .join(name);
    let at = if std::fs::symlink_metadata(&pinned).is_ok() {
        pinned
    } else {
        if !directory_is(dir, path) {
            return Err(io::Error::other(
                "the socket directory changed before the probe",
            ));
        }
        path.to_path_buf()
    };
    let probed = socket2::SockAddr::unix(&at).and_then(|address| {
        socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?
            .connect_timeout(&address, SOCKET_PROBE_BOUND)
    });
    if at == path && !directory_is(dir, path) {
        return Err(io::Error::other(
            "the socket directory changed during the probe",
        ));
    }
    probed
}

/// Whether `path`'s directory is the inode `dir` holds.
fn directory_is(dir: &File, path: &Path) -> bool {
    let Ok(held) = fstat(dir) else {
        return false;
    };
    let parent = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let Ok(found) = lstat(parent) else {
        return false;
    };
    same_file(&held, &found)
}

fn same_file(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

/// `st_uid` as the account id [`shekyl_os_account::effective_uid`] returns.
fn owner_uid(stat: &rustix::fs::Stat) -> u32 {
    #[allow(
        clippy::unnecessary_cast,
        reason = "uid_t on the libc backend, already u32 on linux_raw"
    )]
    {
        stat.st_uid as u32
    }
}

/// What the bind found at a path it may replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cleared {
    /// Nothing was there.
    Empty,
    /// A socket whose server was gone was there, and was removed.
    ReplacedStale,
}

/// Remove `name` in `dir` when [`may_replace_socket`] would replace it, so a
/// listener can bind. The removal is `unlinkat` on `dir`, so it removes the
/// name in the directory this start is holding. A refusal leaves the name
/// as it is, and so does a removal that fails ([`SocketRefusal::NotRemoved`]).
fn clear_replaceable_socket(
    dir: &File,
    name: &OsStr,
    path: &Path,
) -> Result<Cleared, SocketRefusal> {
    match may_replace_socket(dir, name, path) {
        SocketPath::Replace => match unlinkat(dir, name, AtFlags::empty()) {
            Ok(()) => Ok(Cleared::ReplacedStale),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Cleared::Empty),
            Err(error) => Err(SocketRefusal::NotRemoved(format!(
                "the socket could not be removed: {error}"
            ))),
        },
        SocketPath::Refuse(refusal) => Err(refusal),
    }
}

/// Is `dir` a directory only this account can enter? [`account_alone`].
fn owner_only_socket_dir(dir: &Path) -> Result<(), AccountAloneFault> {
    account_alone(dir, shekyl_os_account::effective_uid()).map(|_| ())
}

/// Why [`bind_owner_only_socket`] bound nothing. Each listener words it.
#[derive(Debug)]
pub enum OwnerSocketRefusal {
    /// The path has no directory to check (`/`). A bare name's is the
    /// current directory.
    NoDirectory,
    /// The socket's directory is not this account's alone.
    Directory(AccountAloneFault),
    /// What is at the path may not be replaced.
    Path(SocketRefusal),
    /// Making, binding, narrowing or listening on the socket failed. A path
    /// the bind made has been removed; if that failed too, the error says
    /// so. The kind is the failing step's: `AddrInUse` is another server
    /// that bound between the decision and this bind.
    Socket(io::Error),
}

/// A listening socket at its path, this account's alone from before it
/// listened, not yet handed to a runtime.
#[derive(Debug)]
pub struct OwnerOnlyListener {
    listener: UnixListener,
    cleared: Cleared,
}

impl OwnerOnlyListener {
    /// What was at the path before the bind.
    #[must_use]
    pub fn cleared(&self) -> Cleared {
        self.cleared
    }

    /// The listener, non-blocking, for a start that hands it to its
    /// runtime later (the daemon's owner socket, served once its node is
    /// open).
    #[must_use]
    pub fn into_std(self) -> UnixListener {
        self.listener
    }

    /// The listener in the current tokio runtime.
    ///
    /// # Errors
    /// The runtime would not take it.
    ///
    /// # Panics
    /// Outside a tokio runtime with I/O enabled, as `from_std` does.
    pub fn into_tokio(self) -> io::Result<tokio::net::UnixListener> {
        tokio::net::UnixListener::from_std(self.listener)
    }
}

/// Bind the socket every Shekyl socket listener serves on (Rick,
/// 2026-11-22): the wallet server, the daemon's owner socket, the daemon's
/// console leg and the tunnel.
///
/// In order: `path`'s directory must be this account's alone (not a link,
/// owned by this account, and not enterable by its group or by others);
/// what is at `path` must be replaceable, and is removed; then the socket
/// is created (close-on-exec before its bind: atomically on Linux and
/// FreeBSD, and just after creation on macOS, whose `socket` has no such
/// flag; every production spawn also marks descriptors from 3 up
/// close-on-exec in the child, `shekyl_spawn::inherit`), bound, narrowed to
/// [`OWNER_ONLY_SOCKET_MODE`] with `chmodat` on the held directory's name,
/// and only then listens. Until it listens a connect is refused, so no
/// account but this one ever connects to it at a wider mode, whatever the
/// umask. The directory stays mandatory: it is the containment, since
/// BSD-derived systems may not enforce a socket's mode on connect. On Linux
/// the bind names the socket through the held directory's descriptor, so a
/// parent swapped for a link is not where the socket is created. The mode
/// is set on that directory's name: `fchmod` on the socket descriptor
/// changes the socket object, which on Linux is not the directory entry a
/// connect checks. A failure after the bind removes the socket it made.
///
/// The directory is held from the decision through the listen, so a second
/// start cannot see a socket that refuses connects (not yet listening) and
/// replace it. The decision and the bind are synchronous, so a start that
/// binds before its runtime serves takes the same steps; the listener
/// reaches tokio through [`OwnerOnlyListener::into_tokio`], or
/// [`OwnerOnlyListener::into_std`] for a start that hands it over later.
///
/// # Errors
/// Why nothing was bound.
pub fn bind_owner_only_socket(path: &Path) -> Result<OwnerOnlyListener, OwnerSocketRefusal> {
    bind_owner_only_socket_observed(path, |_| {})
}

/// [`bind_owner_only_socket`], calling `bound` with the path between the
/// narrowing and the listen: the one point the order test observes. The
/// public function is this with nothing observed, so the test reads the
/// path every listener binds through.
fn bind_owner_only_socket_observed(
    path: &Path,
    bound: impl FnOnce(&Path),
) -> Result<OwnerOnlyListener, OwnerSocketRefusal> {
    // A bare name is in the current directory, which is checked like any.
    let dir = match path.parent() {
        Some(dir) if dir.as_os_str().is_empty() => Path::new("."),
        Some(dir) => dir,
        None => return Err(OwnerSocketRefusal::NoDirectory),
    };
    let Some(name) = path.file_name() else {
        return Err(OwnerSocketRefusal::NoDirectory);
    };
    owner_only_socket_dir(dir).map_err(OwnerSocketRefusal::Directory)?;
    // Held from the decision through the listen: between its bind and its
    // listen a socket refuses a connect as a stopped server's does, so a
    // second start probing it then would take it for stale and replace it.
    let held = hold_the_directory(dir)?;
    let cleared = clear_replaceable_socket(&held, name, path).map_err(OwnerSocketRefusal::Path)?;
    let address = bind_in_held(&held, name, path).map_err(OwnerSocketRefusal::Socket)?;
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
        .map_err(OwnerSocketRefusal::Socket)?;
    if let Err(error) = socket.bind(&address) {
        return Err(OwnerSocketRefusal::Socket(error));
    }
    // The name in the held directory must be a socket of this account. A
    // path bind that followed a swapped parent leaves no such name.
    if let Err(error) = held_socket(&held, name) {
        remove_stray(&held, path);
        drop(remove_held_socket(&held, name));
        return Err(OwnerSocketRefusal::Socket(error));
    }
    let listening = narrow_name(&held, name)
        .and_then(|()| {
            bound(path);
            socket.listen(SOCKET_BACKLOG)
        })
        .and_then(|()| socket.set_nonblocking(true));
    match listening {
        Ok(()) => Ok(OwnerOnlyListener {
            listener: socket.into(),
            cleared,
        }),
        Err(error) => Err(OwnerSocketRefusal::Socket(
            match remove_held_socket(&held, name) {
                Ok(()) => error,
                Err(left) => io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; the socket it bound at {} could not be removed: {left}",
                        path.display()
                    ),
                ),
            },
        )),
    }
}

/// The words a listener puts around [`OwnerSocketRefusal`]. The shared arms
/// are one sentence; `answers` and `no_directory` are the listener's own,
/// because a live console socket and a missing wallet directory are not said
/// the same way.
pub struct ListenerLine<'a> {
    /// The leg, as the directory sentence names it: "the wallet RPC's socket".
    pub listener: &'a str,
    /// What an inconclusive probe might still be: "a server", "a tunnel",
    /// "anything".
    pub holder: &'a str,
    /// The whole sentence when a live socket is left in place.
    pub answers: &'a str,
    /// The whole sentence when the path names no directory.
    pub no_directory: &'a str,
}

impl OwnerSocketRefusal {
    /// This refusal as `words` says it, for the socket at `path` whose
    /// directory is `directory`.
    #[must_use]
    pub fn line(&self, path: &Path, directory: &Path, words: &ListenerLine<'_>) -> String {
        match self {
            Self::NoDirectory => words.no_directory.to_owned(),
            Self::Directory(why) => format!(
                "{}; {} is not bound there",
                why.clause(Some(&directory.display().to_string())),
                words.listener
            ),
            Self::Path(SocketRefusal::Answers) => words.answers.to_owned(),
            Self::Path(SocketRefusal::NotASocket) => {
                format!("{} is not a socket; it is not replaced", path.display())
            }
            Self::Path(SocketRefusal::NotThisAccounts(uid)) => format!(
                "{} is a socket another account owns (uid {uid}); it is not replaced",
                path.display()
            ),
            Self::Path(SocketRefusal::Unknown(why)) => format!(
                "{}: whether {} still holds this socket is not known ({why}); it is not replaced",
                path.display(),
                words.holder
            ),
            Self::Path(SocketRefusal::NotRemoved(why)) => format!("{}: {why}", path.display()),
            Self::Socket(error) => format!("{}: {error}", path.display()),
        }
    }
}

/// The address to bind. On Linux the name is under the held directory's
/// descriptor, so the socket is created in that directory. Elsewhere the
/// path is used, and [`held_socket`] refuses a bind that did not land there.
fn bind_in_held(dir: &File, name: &OsStr, path: &Path) -> io::Result<socket2::SockAddr> {
    let proc_dir = Path::new("/proc/self/fd").join(dir.as_raw_fd().to_string());
    let at = if std::fs::symlink_metadata(&proc_dir).is_ok() {
        proc_dir.join(name)
    } else {
        path.to_path_buf()
    };
    socket2::SockAddr::unix(at)
}

/// The name in `dir` is a socket this account owns.
fn held_socket(dir: &File, name: &OsStr) -> io::Result<()> {
    let found = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if our_socket(&found) {
        Ok(())
    } else {
        Err(io::Error::other(
            "the socket bound outside the directory this start is holding",
        ))
    }
}

fn our_socket(stat: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Socket
        && owner_uid(stat) == shekyl_os_account::effective_uid()
}

/// Narrow the directory entry `name` to [`OWNER_ONLY_SOCKET_MODE`]. The flag
/// that does not follow a link is not implemented on every kernel; where it
/// is refused, the name was just read as a socket in a directory only this
/// account can write.
fn narrow_name(dir: &File, name: &OsStr) -> io::Result<()> {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the mode is 0o600, and `mode_t` is 16 bits on the BSDs and macOS"
    )]
    let mode = Mode::from_raw_mode(OWNER_ONLY_SOCKET_MODE as rustix::fs::RawMode);
    match chmodat(dir, name, mode, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::NOSYS) => {
            chmodat(dir, name, mode, AtFlags::empty())?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Remove `name` in `dir` when it is a socket this account owns.
fn remove_held_socket(dir: &File, name: &OsStr) -> io::Result<()> {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(found) if our_socket(&found) => {
            unlinkat(dir, name, AtFlags::empty())?;
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Remove `path` when it is a socket this account owns outside `dir`.
fn remove_stray(dir: &File, path: &Path) {
    if directory_is(dir, path) {
        return;
    }
    let Ok(found) = lstat(path) else {
        return;
    };
    if our_socket(&found) {
        drop(std::fs::remove_file(path));
    }
}

/// Take the socket directory's exclusive lock (`flock` on the directory
/// itself, so nothing is added to a directory its owner may remove), waiting
/// up to [`super::SOCKET_PROBE_BOUND`] for another start, which holds it only from
/// its decision to its listen. Starts on one directory therefore never
/// interleave, and every socket a start observes is live or a stopped
/// server's. Released when the returned file drops.
///
/// The race this closes is another process. `flock` on Linux is per open
/// file, so a second open in this process waits; on FreeBSD and macOS a
/// lock is per process, so a second start in this process is granted the
/// lock this one already holds. Another process waits on every one of them.
fn hold_the_directory(dir: &Path) -> Result<std::fs::File, OwnerSocketRefusal> {
    let held = std::fs::File::open(dir).map_err(OwnerSocketRefusal::Socket)?;
    let deadline = Instant::now() + SOCKET_PROBE_BOUND;
    loop {
        match held.try_lock() {
            Ok(()) => return Ok(held),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(START_POLL);
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(OwnerSocketRefusal::Socket(io::Error::new(
                    ErrorKind::WouldBlock,
                    format!(
                        "another start held {} for longer than {SOCKET_PROBE_BOUND:?}",
                        dir.display()
                    ),
                )));
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(OwnerSocketRefusal::Socket(error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    use shekyl_os_account::directory::{AccountAloneFault, DirectoryFault};

    use super::{
        bind_owner_only_socket, bind_owner_only_socket_observed, clear_replaceable_socket,
        may_replace_socket, owner_only_socket_dir, Cleared, OwnerSocketRefusal, SocketPath,
        SocketRefusal, OWNER_ONLY_SOCKET_MODE,
    };

    /// The replace decision for `path`, from its directory's descriptor.
    fn decision(path: &Path) -> SocketPath {
        let held = open_parent(path);
        may_replace_socket(&held, path.file_name().expect("a name"), path)
    }

    /// [`clear_replaceable_socket`] for `path`, from its directory's descriptor.
    fn cleared(path: &Path) -> Result<Cleared, SocketRefusal> {
        let held = open_parent(path);
        clear_replaceable_socket(&held, path.file_name().expect("a name"), path)
    }

    fn open_parent(path: &Path) -> std::fs::File {
        let dir = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::File::open(dir).expect("the directory")
    }

    /// **Only a socket whose connection is refused may be replaced**: a
    /// socket a closed listener left is `Replace`, and so is an empty path;
    /// a listening one is refused as live; one this account may not
    /// connect to is refused as unknown, never replaced, so a listener
    /// does not take another account's live socket (Copilot's review of
    /// #1490). Red edit: replace on any connect error. The permission arm
    /// is skipped under root, which connects to a mode-000 socket.
    #[test]
    fn only_a_socket_whose_connection_is_refused_may_be_replaced() {
        let dir = tempfile::tempdir().expect("a directory");
        assert_eq!(decision(&dir.path().join("none")), SocketPath::Replace);

        let left = dir.path().join("left");
        drop(UnixListener::bind(&left).expect("bind"));
        assert!(
            left.exists(),
            "the control: a closed listener leaves its file"
        );
        assert_eq!(decision(&left), SocketPath::Replace);

        let live = dir.path().join("live");
        let _listener = UnixListener::bind(&live).expect("bind");
        assert_eq!(decision(&live), SocketPath::Refuse(SocketRefusal::Answers));

        if shekyl_os_account::effective_uid() == 0 {
            eprintln!("skipped the permission arm: root connects to a mode-000 socket");
            return;
        }
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
        let unknown = decision(&live);
        assert!(
            matches!(unknown, SocketPath::Refuse(SocketRefusal::Unknown(_))),
            "a socket this account may not open is not proven gone: {unknown:?}"
        );
    }

    /// **Removing a socket is the same decision as the probe**: a path that
    /// is not there, and a socket whose server is gone, become absent; a
    /// live socket, a regular file and a socket this account cannot probe
    /// stay, so a start cannot take them over by unlinking. The permission
    /// arm is skipped under root, which connects to a mode-000 socket.
    /// Red edit: unlink on any probe error.
    #[test]
    fn a_replaceable_socket_is_removed_and_every_other_path_is_left() {
        let dir = tempfile::tempdir().expect("a directory");
        let missing = dir.path().join("none");
        assert_eq!(cleared(&missing), Ok(Cleared::Empty));
        assert!(!missing.exists(), "nothing was created");

        let left = dir.path().join("left");
        drop(UnixListener::bind(&left).expect("bind"));
        assert_eq!(cleared(&left), Ok(Cleared::ReplacedStale));
        assert!(!left.exists(), "a socket whose server is gone is removed");

        let live = dir.path().join("live");
        let _listener = UnixListener::bind(&live).expect("bind");
        assert_eq!(cleared(&live), Err(SocketRefusal::Answers));
        assert!(live.exists(), "a live socket is left in place");

        let file = dir.path().join("file");
        std::fs::write(&file, b"not a socket").expect("a regular file");
        assert_eq!(cleared(&file), Err(SocketRefusal::NotASocket));
        assert_eq!(std::fs::read(&file).expect("kept"), b"not a socket");

        if shekyl_os_account::effective_uid() == 0 {
            eprintln!("skipped the permission arm: root connects to a mode-000 socket");
            return;
        }
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
        assert!(
            matches!(cleared(&live), Err(SocketRefusal::Unknown(_))),
            "a socket this account may not open is not removed"
        );
        assert!(live.exists(), "the unprobed socket is left in place");
    }

    /// **A regular file and a symbolic link at a socket path are refused
    /// and left in place** (Rick, 2026-11-21). On Linux a connect to a path
    /// that is not a socket reports connection refused, as a dead socket
    /// does: the control shows it, so the type check, not the probe, is
    /// what keeps them. The link points at a socket a closed listener left,
    /// the case a decision that followed links would replace. Red edits:
    /// read the path with `metadata` (the link is followed and replaced),
    /// or drop the type check (the file is replaced).
    #[test]
    fn a_regular_file_and_a_symlink_at_a_socket_path_are_refused_and_kept() {
        let dir = tempfile::tempdir().expect("a directory");
        let file = dir.path().join("file");
        std::fs::write(&file, b"not a socket").expect("a regular file");
        #[cfg(target_os = "linux")]
        {
            let probed = std::os::unix::net::UnixStream::connect(&file).expect_err("not a socket");
            assert_eq!(
                probed.kind(),
                ErrorKind::ConnectionRefused,
                "the control: Linux answers a connect to a regular file as refused"
            );
        }
        assert_eq!(
            decision(&file),
            SocketPath::Refuse(SocketRefusal::NotASocket)
        );
        assert_eq!(std::fs::read(&file).expect("kept"), b"not a socket");

        let dead = dir.path().join("dead");
        drop(UnixListener::bind(&dead).expect("bind"));
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&dead, &link).expect("a symbolic link");
        assert_eq!(
            decision(&link),
            SocketPath::Refuse(SocketRefusal::NotASocket)
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("kept")
                .file_type()
                .is_symlink(),
            "the link is left in place"
        );
    }

    /// **A socket directory is this account's alone**: owned by it, with no
    /// group or other access, and not a link. A group-writable directory, a
    /// group-readable one and a link to an owner-only one are refused; a
    /// missing one is named missing. The refusal is the walk's clause, so a
    /// link is a link and a wider mode names its mode. Red edit: accept
    /// group access, or follow the link.
    #[test]
    fn a_socket_directory_is_this_accounts_alone() {
        let base = tempfile::tempdir().expect("a directory");
        let dir = base.path().join("d");
        let missing = owner_only_socket_dir(&dir).expect_err("missing");
        assert!(matches!(
            missing,
            AccountAloneFault::Walk(DirectoryFault::Missing)
        ));
        assert_eq!(
            missing.clause(Some(&dir.display().to_string())),
            format!("{} does not exist", dir.display())
        );
        std::fs::create_dir(&dir).expect("a directory");
        for (mode, ok) in [
            (0o700, true),
            (0o770, false),
            (0o750, false),
            (0o701, false),
        ] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).expect("chmod");
            let found = owner_only_socket_dir(&dir);
            assert_eq!(found.is_ok(), ok, "mode {mode:o}");
            if !ok {
                let refused = found.expect_err("wider");
                assert_eq!(
                    refused.clause(None),
                    format!("its mode is {mode:04o}, so other accounts can enter it")
                );
            }
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let link = base.path().join("l");
        std::os::unix::fs::symlink(&dir, &link).expect("a symbolic link");
        let linked = owner_only_socket_dir(&link).expect_err("a link");
        assert!(matches!(
            linked,
            AccountAloneFault::Walk(DirectoryFault::SymbolicLink)
        ));
        assert_eq!(
            linked.clause(Some(&link.display().to_string())),
            format!("{} is a symbolic link", link.display())
        );
    }

    /// An owner-only directory under a fresh temporary one.
    fn owner_only_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("a directory");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod 700");
        dir
    }

    /// **A socket is the owner's before it listens** (Rick, 2026-11-22):
    /// at the point between the narrowing and the listen, on the path every
    /// listener binds through, the socket is already 0600 and a connect is
    /// refused; once bound, a connect succeeds. The test's umask leaves a
    /// freshly bound socket wider than 0600, so the mode is the narrowing's.
    /// Red edits: listen before the narrowing (the connect in `bound`
    /// succeeds and the mode is the umask's), or narrow after the listen
    /// (the mode is the umask's).
    #[test]
    fn a_socket_is_the_owners_before_it_listens() {
        let dir = owner_only_dir();
        let path = dir.path().join("s");
        let mut observed = false;
        let listener = bind_owner_only_socket_observed(&path, |at| {
            observed = true;
            let mode = std::fs::metadata(at)
                .expect("the bound socket")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                OWNER_ONLY_SOCKET_MODE,
                "the socket is the owner's before it listens"
            );
            let early = std::os::unix::net::UnixStream::connect(at)
                .expect_err("nothing connects before the listen");
            assert_eq!(
                early.kind(),
                ErrorKind::ConnectionRefused,
                "a connect before the listen is refused: {early}"
            );
        })
        .expect("bound");
        assert!(observed, "the order was observed");
        assert_eq!(listener.cleared(), Cleared::Empty);
        std::os::unix::net::UnixStream::connect(&path).expect("it listens once bound");
    }

    /// **A directory that is not this account's alone is refused and
    /// nothing is bound in it**, and a path with no directory is refused by
    /// name. Red edit: skip the directory check.
    #[test]
    fn a_socket_is_never_bound_in_a_directory_others_can_enter() {
        let dir = owner_only_dir();
        for mode in [0o750, 0o770, 0o701] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode))
                .expect("chmod");
            let path = dir.path().join("s");
            let refused = bind_owner_only_socket(&path).expect_err("wider");
            match refused {
                OwnerSocketRefusal::Directory(why) => {
                    assert_eq!(
                        why.clause(None),
                        format!("its mode is {mode:04o}, so other accounts can enter it"),
                        "mode {mode:o}"
                    );
                }
                other => panic!("mode {mode:o}: {other:?}"),
            }
            assert!(!path.exists(), "nothing was bound under mode {mode:o}");
        }
        assert!(matches!(
            bind_owner_only_socket(Path::new("/")),
            Err(OwnerSocketRefusal::NoDirectory)
        ));
    }

    /// **The bind replaces a socket whose server is gone and refuses a live
    /// one**, through the shared decision. Red edit: bind without clearing
    /// (the stale socket's path is in use).
    #[test]
    fn the_bind_replaces_a_stale_socket_and_refuses_a_live_one() {
        let dir = owner_only_dir();
        let path = dir.path().join("s");
        drop(UnixListener::bind(&path).expect("bind"));
        let replacing = bind_owner_only_socket(&path).expect("the stale socket is replaced");
        assert_eq!(replacing.cleared(), Cleared::ReplacedStale);
        assert!(matches!(
            bind_owner_only_socket(&path),
            Err(OwnerSocketRefusal::Path(SocketRefusal::Answers))
        ));
        drop(replacing);
    }

    /// **Another account's socket is never replaced** (the daemon's owner
    /// socket refused one by uid before the decision was shared). Only root
    /// can give a socket to another account, so the arm runs as root and is
    /// skipped otherwise. Red edit: drop the owner check (the dead socket
    /// is replaced).
    #[test]
    fn another_accounts_socket_is_never_replaced() {
        if shekyl_os_account::effective_uid() != 0 {
            eprintln!("skipped: only root can give a socket to another account");
            return;
        }
        let dir = owner_only_dir();
        let path = dir.path().join("s");
        drop(UnixListener::bind(&path).expect("bind"));
        /// An account other than root that exists on Linux, FreeBSD and
        /// macOS (`daemon`).
        const ANOTHER_ACCOUNT: u32 = 1;
        std::os::unix::fs::chown(&path, Some(ANOTHER_ACCOUNT), None).expect("chown");
        assert_eq!(
            decision(&path),
            SocketPath::Refuse(SocketRefusal::NotThisAccounts(ANOTHER_ACCOUNT))
        );
        assert!(path.exists(), "the other account's socket is left");
    }
}
