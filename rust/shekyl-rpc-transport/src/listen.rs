// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Listen-address posture shared by every Shekyl RPC listener
//! (`docs/design/RPC_TRANSPORT_POSTURE.md` RT-1, RT-2).
//!
//! One classifier, so the wallet RPC and the daemon RPC cannot disagree on
//! what "wildcard" or "loopback" means — the IPv4-mapped spellings included
//! (`[::ffff:0.0.0.0]` *is* the wildcard; `[::ffff:127.0.0.1]` *is*
//! loopback). The refusals themselves stay with each listener, because each
//! names a different remedy: the wallet can take `--rpc-login`; the daemon
//! has no authentication at all and points at the onion service or the
//! pinned-TLS leg instead.
//!
//! Parsing is strict: a listen address names an interface, and resolving a
//! hostname at bind time would make the bind depend on a resolver's answer,
//! so `localhost:29500` is refused with the spelling to use rather than left
//! to a syntax error.

use std::fmt;
use std::net::SocketAddr;

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

/// Classify `addr` after folding IPv4-mapped IPv6 to IPv4, so every
/// spelling of the same address classifies the same way.
#[must_use]
pub fn classify_listen(addr: SocketAddr) -> ListenClass {
    let ip = addr.ip().to_canonical();
    if ip.is_unspecified() {
        ListenClass::Wildcard
    } else if ip.is_loopback() {
        ListenClass::Loopback
    } else {
        ListenClass::Addressed
    }
}

/// A listen string that is not a numeric `IP:PORT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenParseError {
    given: String,
    detail: String,
}

impl fmt::Display for ListenParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid listen address '{}': {}. Use a numeric IP:PORT such as 127.0.0.1:29500 \
             or [::1]:29500 — hostnames are not resolved",
            self.given, self.detail
        )
    }
}

impl std::error::Error for ListenParseError {}

/// Parse a listen string as a numeric `IP:PORT` — `127.0.0.1:29500`,
/// `[::1]:29500` — and nothing else. Hostnames are not resolved.
pub fn parse_listen_addr(s: &str) -> Result<SocketAddr, ListenParseError> {
    s.parse::<SocketAddr>().map_err(|e| ListenParseError {
        given: s.to_owned(),
        detail: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    /// resolved, never a bare syntax error.
    #[test]
    fn hostnames_are_refused_with_the_remedy() {
        for bad in ["localhost:29500", "wallet.lan:29500", "127.0.0.1", ""] {
            let err = parse_listen_addr(bad).expect_err(bad).to_string();
            assert!(err.contains("hostnames are not resolved"), "{bad}: {err}");
            assert!(err.contains("127.0.0.1:29500"), "{bad}: {err}");
        }
    }
}
