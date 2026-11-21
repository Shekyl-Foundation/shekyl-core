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

/// Whether a listener may replace what is at its socket path: the one
/// decision the wallet RPC's and the tunnel's socket listeners share. Each
/// keeps only its own wording of a refusal.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketPath {
    /// Nothing is there, or a socket whose server is proven gone: remove
    /// it, if it is there, and bind.
    Replace,
    /// Leave the path as it is and refuse the start, for this reason.
    Refuse(SocketRefusal),
}

/// Why a socket path may not be replaced.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketRefusal {
    /// A server accepted the probe: it is live.
    Answers,
    /// Something other than a socket is at the path, a symbolic link
    /// included: it is not the listener's to remove.
    NotASocket,
    /// The probe proved nothing: another account's socket (permission
    /// denied), a server whose accept queue is full, no answer within
    /// [`SOCKET_PROBE_BOUND`], or the path could not be read.
    Unknown(String),
}

/// May the listener replace what is at `path`?
///
/// The path is read without following a symbolic link, and only a socket
/// is ever probed. The type check is part of the decision, not a
/// courtesy: on Linux a connect to a path that is not a socket also
/// reports connection refused, the same answer a dead server's socket
/// gives, so a probe alone would replace a regular file, or a link to a
/// dead socket elsewhere. A socket is replaced only when its connection is
/// refused, the one answer that proves its server gone. The probe does not
/// block: tokio's connect, bounded by [`SOCKET_PROBE_BOUND`].
#[cfg(unix)]
pub async fn may_replace_socket(path: &std::path::Path) -> SocketPath {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SocketPath::Replace,
        Err(e) => SocketPath::Refuse(SocketRefusal::Unknown(e.to_string())),
        Ok(found) if !found.file_type().is_socket() => {
            SocketPath::Refuse(SocketRefusal::NotASocket)
        }
        Ok(_) => {
            match tokio::time::timeout(SOCKET_PROBE_BOUND, tokio::net::UnixStream::connect(path))
                .await
            {
                Ok(Ok(_)) => SocketPath::Refuse(SocketRefusal::Answers),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    SocketPath::Replace
                }
                Ok(Err(e)) => SocketPath::Refuse(SocketRefusal::Unknown(e.to_string())),
                Err(_) => SocketPath::Refuse(SocketRefusal::Unknown(format!(
                    "no answer within {} s",
                    SOCKET_PROBE_BOUND.as_secs()
                ))),
            }
        }
    }
}

/// Why a directory may not hold a listener's socket.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketDirRefusal {
    /// Nothing is at the path.
    Missing,
    /// It is not a directory (a symbolic link to one included), it is not
    /// this account's, or its group or others have any access. A socket's
    /// own mode is set only after its bind, so until then the directory is
    /// all that keeps another account from connecting.
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
    #[tokio::test]
    async fn only_a_socket_whose_connection_is_refused_may_be_replaced() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("a directory");
        assert_eq!(
            may_replace_socket(&dir.path().join("none")).await,
            SocketPath::Replace
        );

        let left = dir.path().join("left");
        drop(std::os::unix::net::UnixListener::bind(&left).expect("bind"));
        assert!(
            left.exists(),
            "the control: a closed listener leaves its file"
        );
        assert_eq!(may_replace_socket(&left).await, SocketPath::Replace);

        let live = dir.path().join("live");
        let _listener = std::os::unix::net::UnixListener::bind(&live).expect("bind");
        assert_eq!(
            may_replace_socket(&live).await,
            SocketPath::Refuse(SocketRefusal::Answers)
        );

        if shekyl_os_account::effective_uid() == 0 {
            eprintln!("skipped the permission arm: root connects to a mode-000 socket");
            return;
        }
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
        let unknown = may_replace_socket(&live).await;
        assert!(
            matches!(unknown, SocketPath::Refuse(SocketRefusal::Unknown(_))),
            "a socket this account may not open is not proven gone: {unknown:?}"
        );
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
    #[tokio::test]
    async fn a_regular_file_and_a_symlink_at_a_socket_path_are_refused_and_kept() {
        let dir = tempfile::tempdir().expect("a directory");
        let file = dir.path().join("file");
        std::fs::write(&file, b"not a socket").expect("a regular file");
        #[cfg(target_os = "linux")]
        {
            let probed = tokio::net::UnixStream::connect(&file)
                .await
                .expect_err("not a socket");
            assert_eq!(
                probed.kind(),
                std::io::ErrorKind::ConnectionRefused,
                "the control: Linux answers a connect to a regular file as refused"
            );
        }
        assert_eq!(
            may_replace_socket(&file).await,
            SocketPath::Refuse(SocketRefusal::NotASocket)
        );
        assert_eq!(std::fs::read(&file).expect("kept"), b"not a socket");

        let dead = dir.path().join("dead");
        drop(std::os::unix::net::UnixListener::bind(&dead).expect("bind"));
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&dead, &link).expect("a symbolic link");
        assert_eq!(
            may_replace_socket(&link).await,
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
