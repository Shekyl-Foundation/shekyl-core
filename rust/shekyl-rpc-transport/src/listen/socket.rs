// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Unix socket every Shekyl listener binds (Rick, 2026-11-22).
//!
//! One order, so the wallet RPC, the daemon's owner socket, the daemon's
//! console leg and the tunnel cannot disagree: the directory is this
//! account's alone, what is at the path is replaceable and is removed, the
//! socket is created and close-on-exec before its bind, bound, narrowed to
//! [`OWNER_ONLY_SOCKET_MODE`], and only then listens. The directory check
//! and the replace decision are this module's; a caller reaches them
//! through [`bind_owner_only_socket`], which holds the directory from the
//! decision through the listen. Each listener keeps only its own wording
//! of a refusal. [`SocketDirRefusal::clause`] is the directory's fact, said
//! once.

use std::ffi::c_int;
use std::fmt;
use std::io::{self, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::{Duration, Instant};

use shekyl_os_account::directory::{DirectoryFacts, DirectoryFault};

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

/// May the listener replace what is at `path`?
///
/// The path is read without following a symbolic link, and only a socket
/// this account owns is ever probed. The type check is part of the
/// decision, not a courtesy: on Linux a connect to a path that is not a
/// socket also reports connection refused, the same answer a dead server's
/// socket gives, so a probe alone would replace a regular file, or a link
/// to a dead socket elsewhere. A socket is replaced only when its
/// connection is refused, the one answer that proves its server gone. The
/// probe is bounded by [`super::SOCKET_PROBE_BOUND`]; it is synchronous, so a
/// start that binds before its runtime serves (the daemon's owner socket)
/// takes the same decision as one that binds inside it.
fn may_replace_socket(path: &Path) -> SocketPath {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let found = match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return SocketPath::Replace,
        Err(e) => return SocketPath::Refuse(SocketRefusal::Unknown(e.to_string())),
        Ok(found) => found,
    };
    if !found.file_type().is_socket() {
        return SocketPath::Refuse(SocketRefusal::NotASocket);
    }
    if found.uid() != shekyl_os_account::effective_uid() {
        return SocketPath::Refuse(SocketRefusal::NotThisAccounts(found.uid()));
    }
    let probe = socket2::SockAddr::unix(path).and_then(|address| {
        socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?
            .connect_timeout(&address, SOCKET_PROBE_BOUND)
    });
    match probe {
        Ok(()) => SocketPath::Refuse(SocketRefusal::Answers),
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => SocketPath::Replace,
        Err(e) if e.kind() == ErrorKind::TimedOut => SocketPath::Refuse(SocketRefusal::Unknown(
            format!("no answer within {} s", SOCKET_PROBE_BOUND.as_secs()),
        )),
        Err(e) => SocketPath::Refuse(SocketRefusal::Unknown(e.to_string())),
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

/// Remove `path` when [`may_replace_socket`] would replace it, so a listener
/// can bind. A refusal leaves the path as it is, and so does a removal that
/// fails ([`SocketRefusal::NotRemoved`]).
fn clear_replaceable_socket(path: &Path) -> Result<Cleared, SocketRefusal> {
    match may_replace_socket(path) {
        SocketPath::Replace => match std::fs::remove_file(path) {
            Ok(()) => Ok(Cleared::ReplacedStale),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Cleared::Empty),
            Err(error) => Err(SocketRefusal::NotRemoved(format!(
                "the socket could not be removed: {error}"
            ))),
        },
        SocketPath::Refuse(refusal) => Err(refusal),
    }
}

/// Why a directory may not hold a listener's socket. The fact is
/// [`Self::clause`]; each listener adds only its own frame.
#[derive(Debug)]
pub enum SocketDirRefusal {
    /// The shared directory walk refused the path: it is missing, unreadable,
    /// a symbolic link, not a directory, or another account's.
    Facts(DirectoryFault),
    /// Group or other has a permission bit, so another account can enter.
    GroupOrOtherCanEnter {
        /// The directory's mode, permission bits only.
        mode: u32,
    },
}

impl SocketDirRefusal {
    /// The directory's fact. `shown` is the path, when the sentence names
    /// it; without it the sentence is the form a diagnostic already names
    /// the path around ("its mode is …").
    #[must_use]
    pub fn clause(&self, shown: Option<&str>) -> String {
        match self {
            Self::Facts(fault) => fault.clause(shown),
            Self::GroupOrOtherCanEnter { mode } => match shown {
                Some(path) => {
                    format!("{path} has mode {mode:04o}, so other accounts can enter it")
                }
                None => format!("its mode is {mode:04o}, so other accounts can enter it"),
            },
        }
    }
}

impl fmt::Display for SocketDirRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.clause(None))
    }
}

/// Is `dir` a directory only this account can enter: owned by the effective
/// user, no group or other access, not a symbolic link? The check both
/// socket listeners hold their directory to. The mode rule is this check's;
/// the facts are [`DirectoryFacts`].
fn owner_only_socket_dir(dir: &Path) -> Result<(), SocketDirRefusal> {
    let facts = match DirectoryFacts::inspect(dir) {
        Ok(facts) => facts,
        Err(fault) => return Err(SocketDirRefusal::Facts(fault)),
    };
    let facts = match facts.require_owner(shekyl_os_account::effective_uid()) {
        Ok(facts) => facts,
        Err(fault) => return Err(SocketDirRefusal::Facts(fault)),
    };
    if facts.group_or_other_can_enter() {
        Err(SocketDirRefusal::GroupOrOtherCanEnter { mode: facts.mode() })
    } else {
        Ok(())
    }
}

/// Why [`bind_owner_only_socket`] bound nothing. Each listener words it.
#[derive(Debug)]
pub enum OwnerSocketRefusal {
    /// The path has no directory to check (`/`). A bare name's is the
    /// current directory.
    NoDirectory,
    /// The socket's directory is not this account's alone.
    Directory(SocketDirRefusal),
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
/// [`OWNER_ONLY_SOCKET_MODE`], and only then listens. Until it listens a
/// connect is refused, so no account but this one ever connects to it at a
/// wider mode, whatever the umask. The directory stays mandatory: it is the
/// containment, since BSD-derived systems may not enforce a socket's mode
/// on connect. A failure after the bind removes the path it made.
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
    owner_only_socket_dir(dir).map_err(OwnerSocketRefusal::Directory)?;
    // Held from the decision through the listen: between its bind and its
    // listen a socket refuses a connect as a stopped server's does, so a
    // second start probing it then would take it for stale and replace it.
    let _start = hold_the_directory(dir)?;
    let cleared = clear_replaceable_socket(path).map_err(OwnerSocketRefusal::Path)?;
    let address = socket2::SockAddr::unix(path).map_err(OwnerSocketRefusal::Socket)?;
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
        .map_err(OwnerSocketRefusal::Socket)?;
    socket.bind(&address).map_err(OwnerSocketRefusal::Socket)?;
    // From here the path is this bind's: a failure removes it.
    let listening = std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(OWNER_ONLY_SOCKET_MODE),
    )
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
            match std::fs::remove_file(path) {
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
    use std::time::{Duration, Instant};

    use shekyl_os_account::directory::DirectoryFault;

    use super::{
        bind_owner_only_socket, bind_owner_only_socket_observed, clear_replaceable_socket,
        may_replace_socket, owner_only_socket_dir, Cleared, OwnerSocketRefusal, SocketDirRefusal,
        SocketPath, SocketRefusal, OWNER_ONLY_SOCKET_MODE, START_POLL,
    };
    use crate::listen::SOCKET_PROBE_BOUND;

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
        assert_eq!(
            may_replace_socket(&dir.path().join("none")),
            SocketPath::Replace
        );

        let left = dir.path().join("left");
        drop(UnixListener::bind(&left).expect("bind"));
        assert!(
            left.exists(),
            "the control: a closed listener leaves its file"
        );
        assert_eq!(may_replace_socket(&left), SocketPath::Replace);

        let live = dir.path().join("live");
        let _listener = UnixListener::bind(&live).expect("bind");
        assert_eq!(
            may_replace_socket(&live),
            SocketPath::Refuse(SocketRefusal::Answers)
        );

        if shekyl_os_account::effective_uid() == 0 {
            eprintln!("skipped the permission arm: root connects to a mode-000 socket");
            return;
        }
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
        let unknown = may_replace_socket(&live);
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
        assert_eq!(clear_replaceable_socket(&missing), Ok(Cleared::Empty));
        assert!(!missing.exists(), "nothing was created");

        let left = dir.path().join("left");
        drop(UnixListener::bind(&left).expect("bind"));
        assert_eq!(clear_replaceable_socket(&left), Ok(Cleared::ReplacedStale));
        assert!(!left.exists(), "a socket whose server is gone is removed");

        let live = dir.path().join("live");
        let _listener = UnixListener::bind(&live).expect("bind");
        assert_eq!(clear_replaceable_socket(&live), Err(SocketRefusal::Answers));
        assert!(live.exists(), "a live socket is left in place");

        let file = dir.path().join("file");
        std::fs::write(&file, b"not a socket").expect("a regular file");
        assert_eq!(
            clear_replaceable_socket(&file),
            Err(SocketRefusal::NotASocket)
        );
        assert_eq!(std::fs::read(&file).expect("kept"), b"not a socket");

        if shekyl_os_account::effective_uid() == 0 {
            eprintln!("skipped the permission arm: root connects to a mode-000 socket");
            return;
        }
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
        assert!(
            matches!(
                clear_replaceable_socket(&live),
                Err(SocketRefusal::Unknown(_))
            ),
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
            may_replace_socket(&file),
            SocketPath::Refuse(SocketRefusal::NotASocket)
        );
        assert_eq!(std::fs::read(&file).expect("kept"), b"not a socket");

        let dead = dir.path().join("dead");
        drop(UnixListener::bind(&dead).expect("bind"));
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&dead, &link).expect("a symbolic link");
        assert_eq!(
            may_replace_socket(&link),
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
            SocketDirRefusal::Facts(DirectoryFault::Missing)
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
            SocketDirRefusal::Facts(DirectoryFault::SymbolicLink)
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

    /// The other process reads this and holds that directory. A test reads
    /// it; the listeners do not.
    const OTHER_START_DIR: &str = "SHEKYL_TEST_HOLD_SOCKET_DIRECTORY";

    /// How long the other process holds the directory: well past the probe,
    /// so the parent observes the wait rather than a release.
    const OTHER_START_HOLD: Duration = Duration::from_secs(30);

    /// How long the parent waits for that process to take the lock.
    const OTHER_START_READY: Duration = Duration::from_secs(5);

    /// The file the other process writes once it holds the directory.
    const HELD: &str = "held";

    /// Stops the other start when this test ends, however it ends.
    struct StopTheOtherStart(Option<std::process::Child>);

    impl Drop for StopTheOtherStart {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                if child.kill().is_ok() {
                    let _status = child.wait();
                }
            }
        }
    }

    /// This test's libtest filter: the harness names a test without the
    /// crate.
    fn this_test(name: &str) -> String {
        let within = module_path!().split_once("::").expect("a crate path").1;
        format!("{within}::{name}")
    }

    /// Hold `dir` and say so, then wait. The parent is another process: on
    /// FreeBSD and macOS a second lock in this process would be granted.
    fn hold_for_the_parent(dir: &str) {
        let held = std::fs::File::open(dir).expect("the directory");
        held.lock().expect("the other start's hold");
        std::fs::write(Path::new(dir).join(HELD), b"1").expect("ready");
        std::thread::sleep(OTHER_START_HOLD);
    }

    /// A start waits while another process holds the socket's directory, and
    /// past [`crate::listen::SOCKET_PROBE_BOUND`] refuses with nothing bound, so a socket
    /// bound and not yet listening is never probed as a stopped server's.
    /// Once that process is gone, the bind goes ahead. Red edit: drop the
    /// hold, or take it in this process (FreeBSD and macOS grant it).
    #[test]
    fn a_start_waits_for_another_start_on_the_same_directory() {
        if let Ok(dir) = std::env::var(OTHER_START_DIR) {
            hold_for_the_parent(&dir);
            return;
        }
        let dir = owner_only_dir();
        let path = dir.path().join("s.sock");
        let child = std::process::Command::new(std::env::current_exe().expect("this test"))
            .arg("--exact")
            .arg(this_test(
                "a_start_waits_for_another_start_on_the_same_directory",
            ))
            .arg("--test-threads")
            .arg("1")
            .env(OTHER_START_DIR, dir.path())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the other start");
        let mut other = StopTheOtherStart(Some(child));
        let ready = dir.path().join(HELD);
        let deadline = Instant::now() + OTHER_START_READY;
        while !ready.exists() {
            let child = other.0.as_mut().expect("the other start");
            match child.try_wait() {
                Ok(Some(_)) => {
                    let output = other
                        .0
                        .take()
                        .expect("the other start")
                        .wait_with_output()
                        .expect("the other start's output");
                    panic!(
                        "the other start exited before holding the directory\n{}{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                Ok(None) if Instant::now() < deadline => std::thread::sleep(START_POLL),
                Ok(None) => panic!("the other start never took the directory"),
                Err(error) => panic!("the other start: {error}"),
            }
        }
        let started = Instant::now();
        let refused = bind_owner_only_socket(&path).expect_err("another start holds it");
        assert!(
            started.elapsed() >= SOCKET_PROBE_BOUND,
            "it waited out the bound"
        );
        assert!(
            matches!(&refused, OwnerSocketRefusal::Socket(e) if e.kind() == ErrorKind::WouldBlock),
            "{refused:?}"
        );
        assert!(!path.exists(), "nothing was bound");
        let child = other.0.as_mut().expect("the other start");
        child.kill().expect("stop the other start");
        child.wait().expect("the other start ended");
        bind_owner_only_socket(&path).expect("bound once the other start is done");
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
            may_replace_socket(&path),
            SocketPath::Refuse(SocketRefusal::NotThisAccounts(ANOTHER_ACCOUNT))
        );
        assert!(path.exists(), "the other account's socket is left");
    }
}
