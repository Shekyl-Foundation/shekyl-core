// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Daemon RPC bind seam (`RPC_TRANSPORT_POSTURE.md` RT-1, RT-2; slice RT-W2).
//!
//! Every daemon listener — main, restricted, IPv4, IPv6 — passes through
//! [`bind_listener`]. Policy is pure ([`refuse_non_loopback`]); I/O is the
//! bind. IPv6 is a first-class family: `::1` is loopback the same way
//! `127.0.0.1` is. Network IPv6 is refused for the same reason as network
//! IPv4 — the daemon RPC has no authentication.

use std::net::{IpAddr, SocketAddr};

use shekyl_rpc_transport::listen::{classify_listen, ListenClass};

/// One pair of IPv6 brackets, if present. `[::1]` and `::1` name the same
/// interface; `[[::1]]` and unbalanced brackets are not a literal.
fn strip_one_bracket_pair(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host)
}

/// The operator's bind-host / bind-port strings, as given, to the address
/// [`bind_listener`] decides on. C++ composes nothing. A hostname is refused
/// by name, never resolved; an empty host or a port outside `1..=65535` is
/// refused. IPv4 and IPv6 are the same parser (`IpAddr`).
pub fn parse_bind(host: &str, port: &str) -> Result<SocketAddr, String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("RPC bind address is empty: give a numeric IP (127.0.0.1 or ::1)".into());
    }
    let ip = strip_one_bracket_pair(host)
        .parse::<IpAddr>()
        .map_err(|_| {
            format!(
                "RPC bind address '{host}' is not a numeric IP address (hostnames are not \
                 resolved): use 127.0.0.1 or ::1"
            )
        })?;
    let port = port
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("RPC bind port '{port}' is not a port in 1..=65535"))?;
    Ok(SocketAddr::new(ip, port))
}

/// Addresses one FFI start will bind: the primary host, and — when `host_v6`
/// is present and parses to a *different* address — that family too.
/// `::1` and `[::1]` are one socket. C++ does not compose, classify, or
/// decide to skip; it passes the operator's strings through.
pub fn listen_addrs(
    host: &str,
    port: &str,
    host_v6: Option<&str>,
) -> Result<Vec<SocketAddr>, String> {
    let primary = parse_bind(host, port)?;
    let mut addrs = vec![primary];
    if let Some(v6) = host_v6.map(str::trim).filter(|s| !s.is_empty()) {
        let second = parse_bind(v6, port)?;
        if second != primary {
            addrs.push(second);
        }
    }
    Ok(addrs)
}

/// RT-1 / RT-2 for the daemon RPC. Loopback (v4 or v6, mapped forms
/// included) is the only accepted class: the daemon has no authentication,
/// so a wildcard or a network address would be an unauthenticated control
/// surface. The remote legs are the onion service (RT-8) and pinned mutual
/// TLS (RT-4) — not a cleartext bind.
pub fn refuse_non_loopback(addr: SocketAddr) -> Result<(), String> {
    match classify_listen(addr) {
        ListenClass::Loopback => Ok(()),
        ListenClass::Wildcard => Err(format!(
            "refusing to bind the daemon RPC to the wildcard address {addr}: 0.0.0.0 and :: \
             bind every interface, including ones that do not exist yet (a VPN that comes up \
             later, a hotspot, a container bridge). Bind 127.0.0.1 or [::1]."
        )),
        ListenClass::Addressed => Err(format!(
            "refusing to serve the daemon RPC on {addr}: the address is reachable from the \
             network and the daemon RPC has no authentication, so every request would be \
             honoured. Bind 127.0.0.1 or [::1]; for another machine of yours, reach this \
             node through its onion service (docs/DAEMON_RPC_RUST.md) — the authenticated \
             network leg is RPC_TRANSPORT_POSTURE.md RT-4."
        )),
    }
}

/// Bind the daemon RPC TCP listener — **the** seam every daemon listener
/// passes through (the restricted one included, IPv6 included).
///
/// Separated from serving so a caller (the FFI start path) can validate the
/// bind synchronously and fail loudly — the refusal or EADDRINUSE logged
/// with its reason before any handle is handed back — rather than discovering
/// the failure asynchronously inside a spawned serve task.
pub async fn bind_listener(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    match refuse_non_loopback(addr) {
        Ok(()) => tokio::net::TcpListener::bind(addr).await,
        Err(refusal) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            refusal,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{bind_listener, listen_addrs, parse_bind, refuse_non_loopback};

    fn addr(s: &str) -> std::net::SocketAddr {
        s.parse().expect("test address")
    }

    /// The operator's two strings become one typed address here and nowhere
    /// else: one bracket pair tolerated, hostnames refused by name, an empty
    /// host and a bad port refused, IPv4 and IPv6 the same parser.
    #[test]
    fn host_and_port_parse_strictly() {
        assert_eq!(
            parse_bind("127.0.0.1", "21029"),
            Ok(addr("127.0.0.1:21029"))
        );
        assert_eq!(parse_bind("[::1]", "21029"), Ok(addr("[::1]:21029")));
        assert_eq!(parse_bind("::1", "21029"), Ok(addr("[::1]:21029")));
        assert_eq!(parse_bind(" 0.0.0.0 ", "1"), Ok(addr("0.0.0.0:1")));
        assert_eq!(
            parse_bind("::1", "21029"),
            parse_bind("[::1]", "21029"),
            "brackets are notation, not a different address"
        );
        for (host, port, names) in [
            ("localhost", "21029", "hostnames are not resolved"),
            ("", "21029", "RPC bind address is empty"),
            ("127.0.0.1", "0", "RPC bind port"),
            ("127.0.0.1", "70000", "RPC bind port"),
            ("127.0.0.1", "http", "RPC bind port"),
            ("[::1", "21029", "not a numeric IP"),
            ("::1]", "21029", "not a numeric IP"),
            ("[[::1]]", "21029", "not a numeric IP"),
        ] {
            let err = parse_bind(host, port).expect_err(host);
            assert!(err.contains(names), "{host:?}:{port:?}: {err}");
        }
    }

    /// The second family is a second address, not a C++ second start: same
    /// address after parse is one socket; IPv4 + ::1 is two.
    #[test]
    fn second_family_is_deduped_after_parse() {
        assert_eq!(listen_addrs("127.0.0.1", "21029", None).unwrap().len(), 1);
        assert_eq!(
            listen_addrs("127.0.0.1", "21029", Some("::1"))
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            listen_addrs("::1", "21029", Some("[::1]")).unwrap().len(),
            1,
            "brackets are notation"
        );
        assert_eq!(
            listen_addrs("127.0.0.1", "21029", Some("")).unwrap().len(),
            1
        );
        assert_eq!(
            listen_addrs("127.0.0.1", "21029", Some("  "))
                .unwrap()
                .len(),
            1
        );
    }

    /// RT-1: every wildcard spelling is refused before any socket exists.
    /// The edit that turns this red is classifying as loopback, or binding
    /// without classifying.
    #[test]
    fn wildcard_binds_are_refused() {
        for addr in ["0.0.0.0:0", "[::]:0", "[::ffff:0.0.0.0]:0"] {
            let err =
                refuse_non_loopback(self::addr(addr)).expect_err("a wildcard bind must be refused");
            assert!(err.contains("wildcard"), "{addr}: {err}");
            assert!(
                err.contains("127.0.0.1"),
                "{addr}: must say what to do: {err}"
            );
        }
    }

    /// RT-2: a specific network address is refused, v4 and v6 the same
    /// reason (no authentication) and the same remedy (loopback; the onion).
    /// TEST-NET addresses, so nothing is bound even if the refusal failed.
    #[test]
    fn network_binds_are_refused() {
        for addr in ["192.0.2.1:0", "[2001:db8::1]:0", "[::ffff:192.0.2.1]:0"] {
            let err =
                refuse_non_loopback(self::addr(addr)).expect_err("a network bind must be refused");
            assert!(err.contains("no authentication"), "{addr}: {err}");
            assert!(
                err.contains("onion"),
                "{addr}: must name the remote leg: {err}"
            );
        }
    }

    /// IPv6 loopback is loopback. The compelling reason to refuse a *network*
    /// IPv6 bind is RT-2 (no authentication), not the address family.
    #[test]
    fn ipv6_loopback_is_loopback() {
        refuse_non_loopback(addr("[::1]:0")).expect("::1 is loopback");
        refuse_non_loopback(addr("[::ffff:127.0.0.1]:0")).expect("mapped loopback");
    }

    /// The complement: loopback in every spelling binds.
    #[tokio::test]
    async fn loopback_binds() {
        for addr in ["127.0.0.1:0", "[::1]:0", "[::ffff:127.0.0.1]:0"] {
            let listener = bind_listener(self::addr(addr))
                .await
                .unwrap_or_else(|e| panic!("{addr} must bind: {e}"));
            assert!(listener
                .local_addr()
                .unwrap()
                .ip()
                .to_canonical()
                .is_loopback());
        }
    }
}
