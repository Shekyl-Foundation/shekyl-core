// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `GETINFO net/listeners/*` reply parsing — the `SocksPort auto` discovery
//! step every supervisor performs after bootstrap.
//!
//! Lifted out of the wallet supervisor (PWD-E7 piece 2 pre-step): the parse is
//! pure control-protocol reply shape, with nothing wallet- or daemon-postured
//! about it, and both supervisors need it. What a `None` *means* — tear down,
//! degrade, retry — is the caller's classification, not this module's.

use std::net::SocketAddr;

use super::framing::ControlReply;

/// Extract the first TCP listener from a `GETINFO net/listeners/socks` reply —
/// the `SocksPort auto` discovery. Tor normally returns a space-separated list of
/// **quoted** listener specs (`"127.0.0.1:9050"`, possibly `"unix:/…"`), but each
/// entry is escaped independently and the `getsockname()`-fallback path (exactly
/// the auto-port case discovery relies on) emits an **unquoted** `addr:port` — so
/// a *mixed* list is possible. One uniform pass handles every shape: whitespace
/// tokens, surrounding quotes stripped per token, first token that parses as a
/// socket address wins (unix and other non-TCP entries never parse and are
/// skipped; a quoted unix path containing spaces splits into tokens that also
/// never parse — harmless). `None` = no TCP SOCKS listener at all — a tor no
/// caller can dial through; how to classify that (failure vs. degrade) is the
/// consuming supervisor's decision.
pub fn parse_socks_listeners(reply: &ControlReply) -> Option<SocketAddr> {
    let line = reply
        .lines()
        .iter()
        .find_map(|l| l.strip_prefix("net/listeners/socks="))?;
    line.split_ascii_whitespace()
        .map(|tok| tok.trim_matches('"'))
        .find_map(|tok| tok.parse::<SocketAddr>().ok())
}

#[cfg(test)]
mod tests {
    use super::super::framing::ReplyFramer;
    use super::*;

    // --- SOCKS-listener parse KATs (drive a reply through the real framer so
    // the KAT covers the actual ingress shape, mirroring the bootstrap KATs) ---

    fn reply_from(payload: &str) -> ControlReply {
        let mut framer = ReplyFramer::new();
        framer.push_bytes(format!("250-{payload}\r\n250 OK\r\n").as_bytes());
        framer
            .next_reply()
            .expect("well-formed")
            .expect("one reply")
    }

    #[test]
    fn socks_listener_single_quoted_addr_parses() {
        let reply = reply_from(r#"net/listeners/socks="127.0.0.1:38581""#);
        assert_eq!(
            parse_socks_listeners(&reply),
            Some("127.0.0.1:38581".parse().unwrap())
        );
    }

    #[test]
    fn socks_listener_skips_unix_and_takes_first_tcp() {
        let reply = reply_from(
            r#"net/listeners/socks="unix:/run/tor/socks" "127.0.0.1:9050" "127.0.0.1:9051""#,
        );
        assert_eq!(
            parse_socks_listeners(&reply),
            Some("127.0.0.1:9050".parse().unwrap())
        );
    }

    /// Tor's getsockname()-fallback (exactly the auto-port path) can emit a
    /// single UNQUOTED address; discovery must still parse it rather than tear
    /// down a healthy tor.
    #[test]
    fn socks_listener_unquoted_addr_parses() {
        let reply = reply_from("net/listeners/socks=127.0.0.1:9050");
        assert_eq!(
            parse_socks_listeners(&reply),
            Some("127.0.0.1:9050".parse().unwrap())
        );
    }

    /// Each listener entry is escaped independently, so a MIXED list (a quoted
    /// unix entry + an unquoted TCP fallback entry) is possible — the uniform
    /// token pass must still find the TCP listener.
    #[test]
    fn socks_listener_mixed_quoted_and_unquoted_parses() {
        let reply = reply_from(r#"net/listeners/socks="unix:/run/tor/socks" 127.0.0.1:9050"#);
        assert_eq!(
            parse_socks_listeners(&reply),
            Some("127.0.0.1:9050".parse().unwrap())
        );
        // Quoted-unix-only genuinely has no TCP listener — still None.
        let none = reply_from(r#"net/listeners/socks="unix:/run/tor/socks""#);
        assert_eq!(parse_socks_listeners(&none), None);
    }

    #[test]
    fn socks_listener_empty_or_absent_is_none() {
        assert_eq!(
            parse_socks_listeners(&reply_from(r#"net/listeners/socks="#)),
            None
        );
        assert_eq!(parse_socks_listeners(&reply_from("version=0.4.9.11")), None);
    }
}
