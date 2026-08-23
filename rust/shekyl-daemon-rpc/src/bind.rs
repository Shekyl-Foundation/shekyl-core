// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Daemon RPC bind seam (`RPC_TRANSPORT_POSTURE.md` RT-1, RT-2; slice RT-W2).
//!
//! Every daemon listener — main, restricted, IPv4, IPv6 — passes through
//! [`bind_listener`]. Policy is pure ([`refuse_non_loopback`]); I/O is the
//! bind; and what comes out is a [`BoundListener`], the only thing the server
//! will serve — so a socket that skipped the refusal is a type error, not a
//! review finding. IPv6 is a first-class family: `::1` is loopback the same
//! way `127.0.0.1` is. Network IPv6 is refused for the same reason as network
//! IPv4 — the daemon RPC has no authentication.

use std::fmt;
use std::net::SocketAddr;

use shekyl_rpc_transport::listen::{
    classify_listen, parse_listen_host, parse_listen_port, ListenClass, WILDCARD_REASON,
};

/// The operator's bind-host / bind-port strings, as given, to the address
/// [`bind_listener`] decides on. C++ composes nothing. One parser for every
/// Shekyl listener (`shekyl_rpc_transport::listen`): a hostname is refused by
/// name, never resolved; one bracket pair around an IPv6 literal is
/// notation; an empty host or a port outside `1..=65535` is refused.
pub fn parse_bind(host: &str, port: &str) -> Result<SocketAddr, String> {
    let ip = parse_listen_host(host).map_err(|e| format!("RPC bind address: {e}"))?;
    let port = parse_listen_port(port).map_err(|e| format!("RPC bind port: {e}"))?;
    if port == 0 {
        // "Any free port" is for a listener that reads back what it got; the
        // daemon's port comes from a flag the operator and the wallet must
        // agree on.
        return Err("RPC bind port: '0' is not a port in 1..=65535".into());
    }
    Ok(SocketAddr::new(ip, port))
}

/// Addresses one FFI start will bind: the primary host, and — when `host_v6`
/// is present (the family is enabled) and names a *different* interface —
/// that family too. `Some("")` is an enabled family with an empty address
/// and is refused like any empty host, not skipped: C++ does not compose,
/// classify, or decide to skip; it passes the operator's strings through.
/// Deduped on what is bound, not on how it was spelled: `::1` and `[::1]`
/// are one socket, and so are `127.0.0.1` and `::ffff:127.0.0.1` (the kernel
/// answers the second with EADDRINUSE).
pub fn listen_addrs(
    host: &str,
    port: &str,
    host_v6: Option<&str>,
) -> Result<Vec<SocketAddr>, String> {
    let primary = parse_bind(host, port)?;
    let mut addrs = vec![primary];
    if let Some(v6) = host_v6 {
        let second = parse_bind(v6, port)?;
        if second.ip().to_canonical() != primary.ip().to_canonical() {
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
            "refusing to bind the daemon RPC to the wildcard address {addr}: {WILDCARD_REASON}. \
             Bind 127.0.0.1 or [::1]."
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

/// A TCP listener that passed the daemon's listen posture. Constructible only
/// through [`bind_listener`], and the only thing `serve_listeners` accepts,
/// so there is no way to serve a socket that was not refused first.
pub struct BoundListener {
    addr: SocketAddr,
    listener: tokio::net::TcpListener,
}

impl BoundListener {
    /// The address actually bound (a port of 0 has been resolved by the OS).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn into_parts(self) -> (SocketAddr, tokio::net::TcpListener) {
        (self.addr, self.listener)
    }
}

impl fmt::Debug for BoundListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundListener")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

/// Bind the daemon RPC TCP listener — **the** seam every daemon listener
/// passes through (the restricted one included, IPv6 included).
///
/// Separated from serving so a caller (the FFI start path) can validate the
/// bind synchronously and fail loudly — the refusal or EADDRINUSE logged
/// with its reason before any handle is handed back — rather than discovering
/// the failure asynchronously inside a spawned serve task.
pub async fn bind_listener(addr: SocketAddr) -> std::io::Result<BoundListener> {
    if let Err(refusal) = refuse_non_loopback(addr) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            refusal,
        ));
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let addr = listener.local_addr()?;
    Ok(BoundListener { addr, listener })
}

#[cfg(test)]
mod tests {
    use super::{bind_listener, listen_addrs, parse_bind, refuse_non_loopback};

    fn addr(s: &str) -> std::net::SocketAddr {
        s.parse().expect("test address")
    }

    /// The operator's two strings become one typed address here and nowhere
    /// else: one bracket pair tolerated, hostnames refused by name, an empty
    /// host and a bad port refused with the flag named, IPv4 and IPv6 the
    /// same parser.
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
            ("", "21029", "RPC bind address: listen address is empty"),
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

    /// The second family is a second address, not a C++ second start: the
    /// same interface after parse is one socket (brackets, and the
    /// IPv4-mapped spelling of the same loopback); IPv4 + `::1` is two.
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
            listen_addrs("127.0.0.1", "21029", Some("::ffff:127.0.0.1"))
                .unwrap()
                .len(),
            1,
            "the mapped spelling of the same loopback is the same socket"
        );
        for empty in [Some(""), Some("  ")] {
            let err = listen_addrs("127.0.0.1", "21029", empty)
                .expect_err("an enabled family with an empty address is refused, not skipped");
            assert!(err.contains("is empty"), "{err}");
        }
    }

    /// RT-1 as policy: every wildcard spelling is refused. (The seam that
    /// applies the policy is tested below.)
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

    /// RT-2 as policy: a specific network address is refused, v4 and v6 the
    /// same reason (no authentication) and the same remedy (loopback; the
    /// onion).
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

    /// The seam, not the policy: `bind_listener` applies the refusal before
    /// any socket exists. The edit that turns this red is binding without
    /// refusing. Wildcard and TEST-NET addresses with port 0, so even a
    /// failed refusal binds nothing anyone could reach by accident.
    #[tokio::test]
    async fn the_seam_refuses_before_binding() {
        for (addr, names) in [
            ("0.0.0.0:0", "wildcard"),
            ("[::]:0", "wildcard"),
            ("192.0.2.1:0", "no authentication"),
            ("[2001:db8::1]:0", "no authentication"),
        ] {
            let err = bind_listener(self::addr(addr))
                .await
                .expect_err("the seam must refuse")
                .to_string();
            assert!(err.contains(names), "{addr}: {err}");
        }
    }

    /// The complement: loopback in every spelling binds, and what comes back
    /// knows its own (resolved) address.
    #[tokio::test]
    async fn loopback_binds() {
        for addr in ["127.0.0.1:0", "[::1]:0", "[::ffff:127.0.0.1]:0"] {
            let bound = bind_listener(self::addr(addr))
                .await
                .unwrap_or_else(|e| panic!("{addr} must bind: {e}"));
            assert!(bound.local_addr().ip().to_canonical().is_loopback());
            assert_ne!(bound.local_addr().port(), 0, "port 0 resolved by the OS");
        }
    }
}
