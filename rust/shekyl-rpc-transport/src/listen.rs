// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Listen-address posture shared by every Shekyl RPC listener
//! (`docs/design/RPC_TRANSPORT_POSTURE.md` RT-1, RT-2).
//!
//! One classifier and one parser, so the wallet RPC and the daemon RPC cannot
//! disagree on what "wildcard" or "loopback" means — the IPv4-mapped
//! spellings included (`[::ffff:0.0.0.0]` *is* the wildcard;
//! `[::ffff:127.0.0.1]` *is* loopback) — nor on what a listen string may say.
//! The refusals themselves stay with each listener, because each names a
//! different remedy: the wallet can take `--rpc-login`; the daemon has no
//! authentication at all and points at the onion service or the pinned-TLS
//! leg instead. The *reason* a wildcard is refused is the same everywhere and
//! lives here once ([`WILDCARD_REASON`]).
//!
//! Parsing is strict: a listen address names an interface, and resolving a
//! hostname at bind time would make the bind depend on a resolver's answer,
//! so `localhost:29500` is refused with the spelling to use rather than left
//! to a syntax error. One pair of brackets around an IPv6 literal is
//! notation (`[::1]` and `::1` name the same interface); anything else is not
//! a literal.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// How long a start waits for the server at a socket file to accept its
/// probe ([`may_replace_socket`]).
#[cfg(unix)]
pub const SOCKET_PROBE_BOUND: std::time::Duration = std::time::Duration::from_secs(2);

/// The mode of every listener's socket from the first moment anything can
/// connect to it: this account's alone ([`bind_owner_only_socket`]).
#[cfg(unix)]
pub const OWNER_ONLY_SOCKET_MODE: u32 = 0o600;

/// The listen backlog: the system's maximum, what tokio's own Unix bind
/// asks for (through mio) on Linux, FreeBSD and macOS, so a listener queues
/// as it did before it bound through [`bind_owner_only_socket`].
#[cfg(unix)]
const SOCKET_BACKLOG: std::ffi::c_int = -1;

/// Whether a listener may replace what is at its socket path: the one
/// decision every socket listener shares, through
/// [`bind_owner_only_socket`]. Each keeps only its own wording of a refusal.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketPath {
    /// Nothing is there, or a socket whose server is proven gone: remove
    /// it, if it is there, and bind.
    Replace,
    /// Leave the path as it is and refuse the start, for this reason.
    Refuse(SocketRefusal),
}

/// Why a listener may not bind at a socket path.
#[cfg(unix)]
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
    /// [`SOCKET_PROBE_BOUND`], or the path could not be read.
    Unknown(String),
    /// The path may be replaced, and removing the file failed
    /// ([`clear_replaceable_socket`]). The path is left as it is.
    NotRemoved(String),
}

/// May the listener replace what is at `path`?
///
/// [`clear_replaceable_socket`] is the bind step: it removes the path when
/// this returns [`SocketPath::Replace`], and leaves it when this refuses.
///
/// The path is read without following a symbolic link, and only a socket
/// this account owns is ever probed. The type check is part of the
/// decision, not a courtesy: on Linux a connect to a path that is not a
/// socket also reports connection refused, the same answer a dead server's
/// socket gives, so a probe alone would replace a regular file, or a link
/// to a dead socket elsewhere. A socket is replaced only when its
/// connection is refused, the one answer that proves its server gone. The
/// probe is bounded by [`SOCKET_PROBE_BOUND`]; it is synchronous, so a
/// start that binds before its runtime serves (the daemon's owner socket)
/// takes the same decision as one that binds inside it.
#[cfg(unix)]
pub fn may_replace_socket(path: &std::path::Path) -> SocketPath {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let found = match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return SocketPath::Replace,
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
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => SocketPath::Replace,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            SocketPath::Refuse(SocketRefusal::Unknown(format!(
                "no answer within {} s",
                SOCKET_PROBE_BOUND.as_secs()
            )))
        }
        Err(e) => SocketPath::Refuse(SocketRefusal::Unknown(e.to_string())),
    }
}

/// What [`clear_replaceable_socket`] found at a path it may bind.
#[cfg(unix)]
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
///
/// # Errors
/// Why the path may not be bound.
#[cfg(unix)]
pub fn clear_replaceable_socket(path: &std::path::Path) -> Result<Cleared, SocketRefusal> {
    match may_replace_socket(path) {
        SocketPath::Replace => match std::fs::remove_file(path) {
            Ok(()) => Ok(Cleared::ReplacedStale),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Cleared::Empty),
            Err(error) => Err(SocketRefusal::NotRemoved(format!(
                "the socket could not be removed: {error}"
            ))),
        },
        SocketPath::Refuse(refusal) => Err(refusal),
    }
}

/// Why a directory may not hold a listener's socket.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketDirRefusal {
    /// Nothing is at the path.
    Missing,
    /// It is not a directory (a symbolic link to one included), it is not
    /// this account's, or its group or others have any access. The
    /// directory is the containment: a socket is 0600 from before it
    /// listens ([`bind_owner_only_socket`]), but BSD-derived systems may not
    /// enforce a socket's mode on connect.
    NotOwnerOnly,
    /// It could not be read.
    Unreadable(String),
}

/// Is `dir` a directory only this account can enter: owned by the
/// effective user, no group or other access, not a symbolic link? The
/// check both socket listeners hold their directory to (the tunnel's R0
/// §1.1 construction).
///
/// # Errors
/// Why it is not.
#[cfg(unix)]
pub fn owner_only_socket_dir(dir: &std::path::Path) -> Result<(), SocketDirRefusal> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SocketDirRefusal::Missing);
        }
        Err(e) => return Err(SocketDirRefusal::Unreadable(e.to_string())),
    };
    if meta.is_dir()
        && meta.uid() == shekyl_os_account::effective_uid()
        && meta.permissions().mode() & 0o077 == 0
    {
        Ok(())
    } else {
        Err(SocketDirRefusal::NotOwnerOnly)
    }
}

/// Why [`bind_owner_only_socket`] bound nothing. Each listener words it.
#[cfg(unix)]
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
    Socket(std::io::Error),
}

/// A listening socket at its path, this account's alone from before it
/// listened, not yet handed to a runtime.
#[cfg(unix)]
#[derive(Debug)]
pub struct OwnerOnlyListener {
    listener: std::os::unix::net::UnixListener,
    cleared: Cleared,
}

#[cfg(unix)]
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
    pub fn into_std(self) -> std::os::unix::net::UnixListener {
        self.listener
    }

    /// The listener in the current tokio runtime.
    ///
    /// # Errors
    /// The runtime would not take it.
    ///
    /// # Panics
    /// Outside a tokio runtime with I/O enabled, as `from_std` does.
    pub fn into_tokio(self) -> std::io::Result<tokio::net::UnixListener> {
        tokio::net::UnixListener::from_std(self.listener)
    }
}

/// Bind the socket every Shekyl socket listener serves on (Rick,
/// 2026-11-22): the wallet server, the daemon's owner socket, the daemon's
/// console leg and the tunnel.
///
/// In order: `path`'s directory must be this account's alone
/// ([`owner_only_socket_dir`]); what is at `path` must be replaceable, and
/// is removed ([`clear_replaceable_socket`]); then the socket is created
/// (close-on-exec from creation), bound, narrowed to
/// [`OWNER_ONLY_SOCKET_MODE`], and only then listens. Until it listens a
/// connect is refused, so no account but this one ever connects to it at a
/// wider mode, whatever the umask. The directory stays mandatory: it is the
/// containment, since BSD-derived systems may not enforce a socket's mode
/// on connect. A failure after the bind removes the path it made.
///
/// The decision and the bind are synchronous, so a start that binds before
/// its runtime serves takes the same steps; the listener reaches tokio
/// through [`OwnerOnlyListener::into_tokio`], or [`OwnerOnlyListener::into_std`]
/// for a start that hands it over later.
///
/// # Errors
/// Why nothing was bound.
#[cfg(unix)]
pub fn bind_owner_only_socket(
    path: &std::path::Path,
) -> Result<OwnerOnlyListener, OwnerSocketRefusal> {
    bind_owner_only_socket_observed(path, |_| {})
}

/// [`bind_owner_only_socket`], calling `bound` with the path between the
/// narrowing and the listen: the one point the order test observes. The
/// public function is this with nothing observed, so the test reads the
/// path every listener binds through.
#[cfg(unix)]
fn bind_owner_only_socket_observed(
    path: &std::path::Path,
    bound: impl FnOnce(&std::path::Path),
) -> Result<OwnerOnlyListener, OwnerSocketRefusal> {
    use std::os::unix::fs::PermissionsExt;
    // A bare name is in the current directory, which is checked like any.
    let dir = match path.parent() {
        Some(dir) if dir.as_os_str().is_empty() => std::path::Path::new("."),
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
                Err(left) => std::io::Error::new(
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

/// How often a start polls for another start's hold on the directory.
#[cfg(unix)]
const START_POLL: std::time::Duration = std::time::Duration::from_millis(10);

/// Take the socket directory's exclusive lock (`flock` on the directory
/// itself, so nothing is added to a directory its owner may remove), waiting
/// up to [`SOCKET_PROBE_BOUND`] for another start, which holds it only from
/// its decision to its listen. Starts on one directory therefore never
/// interleave, and every socket a start observes is live or a stopped
/// server's. Released when the returned file drops.
#[cfg(unix)]
fn hold_the_directory(dir: &std::path::Path) -> Result<std::fs::File, OwnerSocketRefusal> {
    let held = std::fs::File::open(dir).map_err(OwnerSocketRefusal::Socket)?;
    let deadline = std::time::Instant::now() + SOCKET_PROBE_BOUND;
    loop {
        match held.try_lock() {
            Ok(()) => return Ok(held),
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(START_POLL);
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(OwnerSocketRefusal::Socket(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
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

/// What a TCP listen address is, under RT-1/RT-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenClass {
    /// `127.0.0.1`, `::1`, or the IPv4-mapped loopback: this machine only.
    Loopback,
    /// `0.0.0.0`, `::`, or the IPv4-mapped wildcard: every interface,
    /// including ones that do not exist yet — refused by every listener.
    Wildcard,
    /// A specific non-loopback address: reachable from the network, so it
    /// needs an authentication story the listener must supply or refuse.
    Addressed,
}

/// `true` for a loopback address after folding IPv4-mapped IPv6 to IPv4
/// (`::ffff:127.0.0.1` is `127.0.0.1`), so every spelling of the same
/// address answers the same way. The one loopback predicate, for listen
/// addresses here and for outbound endpoints in
/// [`crate::network_posture`] — the two sides cannot disagree about what
/// loopback is.
#[must_use]
pub fn is_loopback_ip(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

/// Classify `addr` after folding IPv4-mapped IPv6 to IPv4, so every
/// spelling of the same address classifies the same way.
#[must_use]
pub fn classify_listen(addr: SocketAddr) -> ListenClass {
    let ip = addr.ip().to_canonical();
    if ip.is_unspecified() {
        ListenClass::Wildcard
    } else if is_loopback_ip(ip) {
        ListenClass::Loopback
    } else {
        ListenClass::Addressed
    }
}

/// Why a wildcard bind is refused — one sentence, the same in every
/// listener's refusal; the remedy that follows it is the listener's own.
pub const WILDCARD_REASON: &str = "0.0.0.0 and :: bind every interface, including ones that do \
                                   not exist yet (a VPN that comes up later, a hotspot, a \
                                   container bridge)";

/// A listen string that does not name a numeric interface and port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenParseError {
    /// Nothing was given.
    Empty,
    /// The host part is not an IP literal — a hostname, or broken brackets.
    NotAnIp(String),
    /// An address form without a port (a bare IPv6 literal is this too: its
    /// port would be ambiguous without brackets).
    NoPort(String),
    /// The port is not a number in `0..=65535` (0 asks the OS for a free
    /// port; a listener that cannot report what it got refuses it itself).
    BadPort(String),
}

impl fmt::Display for ListenParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(
                f,
                "listen address is empty: give a numeric IP (127.0.0.1 or ::1)"
            ),
            Self::NotAnIp(given) => write!(
                f,
                "'{given}' is not a numeric IP address (hostnames are not resolved): use \
                 127.0.0.1 or ::1 — with a port, 127.0.0.1:29500 or [::1]:29500"
            ),
            Self::NoPort(given) => write!(
                f,
                "'{given}' has no port: use IP:PORT such as 127.0.0.1:29500 or [::1]:29500"
            ),
            Self::BadPort(given) => write!(f, "'{given}' is not a port in 0..=65535"),
        }
    }
}

impl std::error::Error for ListenParseError {}

/// Parse a host as a numeric IP literal: IPv4, IPv6, or IPv6 in one pair of
/// brackets. Surrounding whitespace is ignored; a hostname is refused by
/// name, never resolved.
pub fn parse_listen_host(host: &str) -> Result<IpAddr, ListenParseError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(ListenParseError::Empty);
    }
    let literal = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    literal
        .parse::<IpAddr>()
        .map_err(|_| ListenParseError::NotAnIp(host.to_owned()))
}

/// Parse a port: a number in `0..=65535`. Port 0 means "any free port" —
/// legitimate for an in-process listener that reads back what it got; a
/// listener fed from a flag refuses it itself.
pub fn parse_listen_port(port: &str) -> Result<u16, ListenParseError> {
    let port = port.trim();
    port.parse::<u16>()
        .map_err(|_| ListenParseError::BadPort(port.to_owned()))
}

/// Parse a listen string as a numeric `IP:PORT` — `127.0.0.1:29500`,
/// `[::1]:29500` — and nothing else.
pub fn parse_listen_addr(s: &str) -> Result<SocketAddr, ListenParseError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ListenParseError::Empty);
    }
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let Some((inner, after)) = rest.split_once(']') else {
            return Err(ListenParseError::NotAnIp(s.to_owned()));
        };
        let Some(port) = after.strip_prefix(':') else {
            return Err(ListenParseError::NoPort(s.to_owned()));
        };
        (format!("[{inner}]"), port)
    } else if s.matches(':').count() > 1 {
        // A bare IPv6 literal: which colon starts the port is ambiguous.
        return Err(ListenParseError::NoPort(s.to_owned()));
    } else {
        let Some((host, port)) = s.rsplit_once(':') else {
            return Err(ListenParseError::NoPort(s.to_owned()));
        };
        (host.to_owned(), port)
    };
    Ok(SocketAddr::new(
        parse_listen_host(&host)?,
        parse_listen_port(port)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Only a socket whose connection is refused may be replaced**: a
    /// socket a closed listener left is `Replace`, and so is an empty path;
    /// a listening one is refused as live; one this account may not
    /// connect to is refused as unknown, never replaced, so a listener
    /// does not take another account's live socket (Copilot's review of
    /// #1490). Red edit: replace on any connect error. The permission arm
    /// is skipped under root, which connects to a mode-000 socket.
    #[cfg(unix)]
    #[test]
    fn only_a_socket_whose_connection_is_refused_may_be_replaced() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("a directory");
        assert_eq!(
            may_replace_socket(&dir.path().join("none")),
            SocketPath::Replace
        );

        let left = dir.path().join("left");
        drop(std::os::unix::net::UnixListener::bind(&left).expect("bind"));
        assert!(
            left.exists(),
            "the control: a closed listener leaves its file"
        );
        assert_eq!(may_replace_socket(&left), SocketPath::Replace);

        let live = dir.path().join("live");
        let _listener = std::os::unix::net::UnixListener::bind(&live).expect("bind");
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
    #[cfg(unix)]
    #[test]
    fn a_replaceable_socket_is_removed_and_every_other_path_is_left() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("a directory");
        let missing = dir.path().join("none");
        assert_eq!(clear_replaceable_socket(&missing), Ok(Cleared::Empty));
        assert!(!missing.exists(), "nothing was created");

        let left = dir.path().join("left");
        drop(std::os::unix::net::UnixListener::bind(&left).expect("bind"));
        assert_eq!(clear_replaceable_socket(&left), Ok(Cleared::ReplacedStale));
        assert!(!left.exists(), "a socket whose server is gone is removed");

        let live = dir.path().join("live");
        let _listener = std::os::unix::net::UnixListener::bind(&live).expect("bind");
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
    #[cfg(unix)]
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
                std::io::ErrorKind::ConnectionRefused,
                "the control: Linux answers a connect to a regular file as refused"
            );
        }
        assert_eq!(
            may_replace_socket(&file),
            SocketPath::Refuse(SocketRefusal::NotASocket)
        );
        assert_eq!(std::fs::read(&file).expect("kept"), b"not a socket");

        let dead = dir.path().join("dead");
        drop(std::os::unix::net::UnixListener::bind(&dead).expect("bind"));
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
    /// missing one is named missing. Red edit: accept group access.
    #[cfg(unix)]
    #[test]
    fn a_socket_directory_is_this_accounts_alone() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().expect("a directory");
        let dir = base.path().join("d");
        assert_eq!(owner_only_socket_dir(&dir), Err(SocketDirRefusal::Missing));
        std::fs::create_dir(&dir).expect("a directory");
        for (mode, ok) in [
            (0o700, true),
            (0o770, false),
            (0o750, false),
            (0o701, false),
        ] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).expect("chmod");
            assert_eq!(owner_only_socket_dir(&dir).is_ok(), ok, "mode {mode:o}");
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let link = base.path().join("l");
        std::os::unix::fs::symlink(&dir, &link).expect("a symbolic link");
        assert_eq!(
            owner_only_socket_dir(&link),
            Err(SocketDirRefusal::NotOwnerOnly)
        );
    }

    /// An owner-only directory under a fresh temporary one.
    #[cfg(unix)]
    fn owner_only_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
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
    #[cfg(unix)]
    #[test]
    fn a_socket_is_the_owners_before_it_listens() {
        use std::os::unix::fs::PermissionsExt;
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
                std::io::ErrorKind::ConnectionRefused,
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
    #[cfg(unix)]
    #[test]
    fn a_socket_is_never_bound_in_a_directory_others_can_enter() {
        use std::os::unix::fs::PermissionsExt;
        let dir = owner_only_dir();
        for mode in [0o750, 0o770, 0o701] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode))
                .expect("chmod");
            let path = dir.path().join("s");
            assert!(
                matches!(
                    bind_owner_only_socket(&path),
                    Err(OwnerSocketRefusal::Directory(
                        SocketDirRefusal::NotOwnerOnly
                    ))
                ),
                "mode {mode:o}"
            );
            assert!(!path.exists(), "nothing was bound under mode {mode:o}");
        }
        assert!(matches!(
            bind_owner_only_socket(std::path::Path::new("/")),
            Err(OwnerSocketRefusal::NoDirectory)
        ));
    }

    /// A start waits while another start holds the socket's directory, and
    /// past [`SOCKET_PROBE_BOUND`] refuses with nothing bound, so a socket
    /// bound and not yet listening is never probed as a stopped server's
    /// (review finding). Once the other start is done, the bind goes ahead.
    /// Red edit: drop the hold, and the bind succeeds at once.
    #[test]
    fn a_start_waits_for_another_start_on_the_same_directory() {
        let dir = owner_only_dir();
        let path = dir.path().join("s.sock");
        let other = std::fs::File::open(dir.path()).expect("the directory");
        other.lock().expect("the other start's hold");
        let started = std::time::Instant::now();
        let refused = bind_owner_only_socket(&path).expect_err("another start holds it");
        assert!(
            started.elapsed() >= SOCKET_PROBE_BOUND,
            "it waited out the bound"
        );
        assert!(
            matches!(&refused, OwnerSocketRefusal::Socket(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "{refused:?}"
        );
        assert!(!path.exists(), "nothing was bound");
        other.unlock().expect("released");
        bind_owner_only_socket(&path).expect("bound once the other start is done");
    }

    /// **The bind replaces a socket whose server is gone and refuses a live
    /// one**, through the shared decision. Red edit: bind without clearing
    /// (the stale socket's path is in use).
    #[cfg(unix)]
    #[test]
    fn the_bind_replaces_a_stale_socket_and_refuses_a_live_one() {
        let dir = owner_only_dir();
        let path = dir.path().join("s");
        drop(std::os::unix::net::UnixListener::bind(&path).expect("bind"));
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
    #[cfg(unix)]
    #[test]
    fn another_accounts_socket_is_never_replaced() {
        if shekyl_os_account::effective_uid() != 0 {
            eprintln!("skipped: only root can give a socket to another account");
            return;
        }
        let dir = owner_only_dir();
        let path = dir.path().join("s");
        drop(std::os::unix::net::UnixListener::bind(&path).expect("bind"));
        /// An account other than root that exists on Linux, FreeBSD and
        /// macOS (`daemon`).
        const ANOTHER_ACCOUNT: u32 = 1;
        let other = ANOTHER_ACCOUNT;
        std::os::unix::fs::chown(&path, Some(other), None).expect("chown");
        assert_eq!(
            may_replace_socket(&path),
            SocketPath::Refuse(SocketRefusal::NotThisAccounts(other))
        );
        assert!(path.exists(), "the other account's socket is left");
    }

    /// Every spelling of the wildcard and of loopback classifies the same
    /// way, IPv4-mapped forms included; an addressed bind is neither.
    #[test]
    fn spellings_classify_by_what_they_name() {
        for wildcard in ["0.0.0.0:1", "[::]:1", "[::ffff:0.0.0.0]:1"] {
            assert_eq!(
                classify_listen(parse_listen_addr(wildcard).unwrap()),
                ListenClass::Wildcard,
                "{wildcard}"
            );
        }
        for loopback in [
            "127.0.0.1:1",
            "127.0.0.2:1",
            "[::1]:1",
            "[::ffff:127.0.0.1]:1",
        ] {
            assert_eq!(
                classify_listen(parse_listen_addr(loopback).unwrap()),
                ListenClass::Loopback,
                "{loopback}"
            );
        }
        for addressed in ["192.0.2.1:1", "[2001:db8::1]:1", "[::ffff:192.0.2.1]:1"] {
            assert_eq!(
                classify_listen(parse_listen_addr(addressed).unwrap()),
                ListenClass::Addressed,
                "{addressed}"
            );
        }
    }

    /// A hostname is refused by name, with the spelling to use — never
    /// resolved, never a bare syntax error; a bare IPv6 literal has no
    /// unambiguous port; a missing or bad port is named as such.
    #[test]
    fn listen_strings_are_refused_with_the_remedy() {
        for bad in ["localhost:29500", "wallet.lan:29500"] {
            let err = parse_listen_addr(bad).expect_err(bad).to_string();
            assert!(err.contains("hostnames are not resolved"), "{bad}: {err}");
            assert!(err.contains("127.0.0.1:29500"), "{bad}: {err}");
        }
        assert_eq!(parse_listen_addr(""), Err(ListenParseError::Empty));
        assert_eq!(
            parse_listen_addr("::1"),
            Err(ListenParseError::NoPort("::1".into())),
            "a bare IPv6 literal has no unambiguous port"
        );
        assert_eq!(
            parse_listen_addr("127.0.0.1"),
            Err(ListenParseError::NoPort("127.0.0.1".into()))
        );
        assert_eq!(
            parse_listen_addr("[::1]evil"),
            Err(ListenParseError::NoPort("[::1]evil".into()))
        );
        assert_eq!(
            parse_listen_addr("127.0.0.1:0").map(|a| a.port()),
            Ok(0),
            "port 0 is any free port; refusing it is a listener's own call"
        );
        assert_eq!(
            parse_listen_addr("[::1]:http"),
            Err(ListenParseError::BadPort("http".into()))
        );
    }

    /// The host parser alone: one bracket pair is notation; broken or
    /// doubled brackets are not a literal; whitespace is ignored.
    #[test]
    fn hosts_parse_strictly() {
        let v6: IpAddr = "::1".parse().unwrap();
        assert_eq!(parse_listen_host("[::1]"), Ok(v6));
        assert_eq!(parse_listen_host(" ::1 "), Ok(v6));
        assert_eq!(
            parse_listen_host("127.0.0.1"),
            Ok("127.0.0.1".parse().unwrap())
        );
        for bad in ["[::1", "::1]", "[[::1]]", "localhost"] {
            assert!(
                matches!(parse_listen_host(bad), Err(ListenParseError::NotAnIp(_))),
                "{bad}"
            );
        }
        assert_eq!(parse_listen_host("  "), Err(ListenParseError::Empty));
        assert_eq!(parse_listen_port("65535"), Ok(65535));
        assert_eq!(parse_listen_port("0"), Ok(0));
        for bad in ["65536", "http", "", "-1"] {
            assert!(
                matches!(parse_listen_port(bad), Err(ListenParseError::BadPort(_))),
                "{bad}"
            );
        }
    }
}
