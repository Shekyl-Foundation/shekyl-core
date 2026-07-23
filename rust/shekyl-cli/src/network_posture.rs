// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Network-exposure disclosure for the wallet's outbound endpoints — the
//! **asymmetric warn-only rule** ratified in `ARCHIVAL_BOND_WI4_MEASUREMENT.md`
//! §15 (2026-07-23), replacing the rejected structural-refusal proposal.
//!
//! # The rule, and why it is asymmetric
//!
//! - **Non-loopback with no proxy → warn.** True regardless of who controls the
//!   far end: the traffic crosses a network path in the clear, so a passive
//!   observer on that path learns the operator runs a Shekyl wallet and when it
//!   is active.
//! - **Loopback, unix socket, or any configured proxy → silence.**
//! - **No configuration ever draws an assurance.** This is the load-bearing
//!   half. A positive "your connection is private" claim derived from an
//!   endpoint check asserts a property the check cannot measure: the check sees
//!   a *socket address*, never *who controls the far end* or *whether a proxy is
//!   trustworthy*. Deriving a security claim from a proxy for the property is
//!   the Monero HTTPS-autodetect failure, and §15 rejected a refusal built on
//!   the same signal for the same reason. A negative-only claim cannot fail that
//!   way: "this is weaker" holds no matter who owns the daemon.
//!
//! # What this deliberately does not do
//!
//! It does not refuse, and it does not grade the user's proxy. A user routing
//! through their own hardened Tor, a VPN, or an SSH tunnel may be better
//! protected than any default we ship; refusing or nagging them would repeat
//! §15's rejected error (a check with false positives on the safe case). We
//! report the one fact we can actually establish and leave the judgment to the
//! operator.
//!
//! # Relationship to the engine's loopback pin
//!
//! `shekyl-engine-core`'s `prpc.rs` classifies the same *fact* (is this host
//! loopback?) but applies the opposite *policy*: it **refuses** non-loopback for
//! the persona-transport local posture, where the shared-network-identity
//! argument genuinely does not hold. Same predicate, different consequence —
//! this crate does not depend on engine-core, and the duplicated logic is a thin
//! wrapper over `std::net::IpAddr::is_loopback` rather than a rule that can
//! drift.

/// What an outbound endpoint exposes to a passive network observer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exposure {
    /// Loopback host or a unix-domain socket: no network path to observe.
    Local,
    /// A proxy is configured, so the connection does not leave in the clear.
    /// This says **nothing** about whether the proxy is trustworthy — only that
    /// one is in use. We cannot assess it and do not try.
    Proxied,
    /// A non-loopback endpoint with no proxy: the connection crosses a network
    /// path in the clear.
    ClearNetwork {
        /// The host as parsed, for the warning text.
        host: String,
    },
}

/// Extract the host from an endpoint in any of the forms the CLI accepts:
/// a bare `host:port`, a `scheme://host:port[/path]`, or a bracketed IPv6
/// literal (`[::1]:11028`, `http://[::1]:11028`).
///
/// The bracket handling is the part worth getting right: a naive
/// `rsplit_once(':')` on `[::1]:11028` yields `[::1]` (fine) but on a bare
/// `::1` yields `::` — silently misclassifying a loopback address as remote.
fn host_of(endpoint: &str) -> &str {
    // Strip any scheme.
    let after_scheme = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    // The authority ends at the first path/query/fragment delimiter — stop at
    // whichever comes first so a `?query` or `#fragment` with no path cannot
    // pull a stray `@`/`:` into the userinfo/port split below.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Strip userinfo if present (`user@host:port`).
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);

    if let Some(bracketed) = authority.strip_prefix('[') {
        // `[::1]:port` / `[::1]` — the host is inside the brackets.
        return bracketed.split_once(']').map_or(bracketed, |(h, _)| h);
    }
    // An unbracketed authority containing more than one ':' is a bare IPv6
    // literal (`::1`, `fe80::1`), not host:port — do not strip a "port".
    if authority.matches(':').count() > 1 {
        return authority;
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

/// `true` for the loopback forms: the `localhost` name and any address
/// literal `std` classifies as loopback (`127.0.0.0/8`, `::1`).
///
/// This is deliberately a **syntactic** check — it does not resolve names. A
/// custom hostname alias that maps to loopback (e.g. an `/etc/hosts` entry for
/// `127.0.0.1`) is therefore not recognized and draws the clear-network
/// warning; use `localhost` or `127.0.0.1` to silence it. Resolving would be
/// worse than the nag: `is_loopback_host` runs *before* the proxy check, so a
/// lookup here would hand the daemon hostname to the local resolver even for a
/// proxied endpoint — a DNS leak that defeats the very privacy a proxy buys
/// (Tor proxies DNS through the SOCKS layer precisely to avoid this).
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Classify one endpoint under the §15 rule. `proxy` is the operator's
/// configured SOCKS proxy, if any.
#[must_use]
pub fn classify(endpoint: &str, proxy: Option<&str>) -> Exposure {
    // An empty address opens no connection at all (`DaemonClient::new` returns
    // `NotConfigured`), so there is nothing to disclose.
    if endpoint.is_empty() {
        return Exposure::Local;
    }
    // A unix-domain socket never touches the network.
    if endpoint.starts_with("uds://") || endpoint.starts_with("unix://") {
        return Exposure::Local;
    }
    let host = host_of(endpoint);
    // Loopback first: a local endpoint has no network path to protect, so a
    // proxy setting is irrelevant to the disclosure either way.
    if is_loopback_host(host) {
        return Exposure::Local;
    }
    if proxy.is_some() {
        return Exposure::Proxied;
    }
    Exposure::ClearNetwork {
        host: host.to_owned(),
    }
}

/// The warning text for a clear-network endpoint whose connection **can** be
/// proxied (the `--rpc-url` client and the REPL's direct daemon client); it
/// therefore fires only when no proxy is configured. `label` names which
/// endpoint (so an operator with several configured knows which one to fix).
///
/// Phrased as a statement of exposure, never as a grade: it frames the leak as
/// *metadata* (that a Shekyl wallet is running, and when) rather than claiming
/// the payload is unencrypted — the exposure holds even over TLS — and it never
/// implies any other configuration is "safe".
#[must_use]
pub fn warning_for(label: &str, host: &str) -> String {
    format!(
        "Warning: {label} '{host}' is not loopback and no proxy is configured. \
         An observer on the network path can see that you connect to a remote \
         node — that you run a Shekyl wallet, and when it is active — which \
         holds regardless of who operates the far end and even if the link is \
         encrypted. Route it through a proxy (--proxy), or point it at a node \
         on this machine."
    )
}

/// The warning text for the self-hosted wallet server's connection to a remote
/// daemon. That connection **cannot** be proxied (its transport has no proxy
/// support), so — unlike [`warning_for`] — it fires regardless of `--proxy`,
/// and its only remedy is a node on this machine.
#[must_use]
pub fn warning_for_direct(label: &str, host: &str) -> String {
    format!(
        "Warning: {label} '{host}' is not loopback. The self-hosted wallet \
         server scans the chain over this connection, which does not use \
         --proxy, so an observer on the network path can see that you run a \
         Shekyl wallet and when it is active — regardless of who operates the \
         node and even if the link is encrypted. Point --daemon-address at a \
         node on this machine to avoid this."
    )
}

/// Emit the disclosure for one endpoint. Returns the warning that was printed,
/// if any — `None` means silence, which is the correct output for every
/// non-clear-network case (there is deliberately no "looks good" message).
pub fn disclose(label: &str, endpoint: &str, proxy: Option<&str>) -> Option<String> {
    match classify(endpoint, proxy) {
        Exposure::Local | Exposure::Proxied => None,
        Exposure::ClearNetwork { host } => {
            let msg = warning_for(label, &host);
            eprintln!("{msg}");
            Some(msg)
        }
    }
}

/// Disclose an endpoint whose connection **cannot** honor `--proxy` — the
/// self-hosted wallet server's block-scanning link to the daemon, whose
/// transport has no proxy support. Warns on a non-loopback daemon *regardless*
/// of `--proxy` (it genuinely does not protect this connection), and is silent
/// for a loopback / unix-socket / unconfigured daemon. Returns the warning
/// printed, if any.
pub fn disclose_unproxyable(label: &str, endpoint: &str) -> Option<String> {
    // Passing `None` makes `classify` do the loopback/uds/empty determination
    // without ever reporting `Proxied` — which is exactly right here, since the
    // proxy does not reach this connection.
    match classify(endpoint, None) {
        Exposure::Local | Exposure::Proxied => None,
        Exposure::ClearNetwork { host } => {
            let msg = warning_for_direct(label, &host);
            eprintln!("{msg}");
            Some(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_forms_are_local() {
        for ep in [
            "localhost:11028",
            "LocalHost:11028",
            "127.0.0.1:11028",
            "127.0.0.2:11028",
            "http://localhost:11028",
            "http://127.0.0.1:11028",
            "[::1]:11028",
            "http://[::1]:11028",
            "::1",
            "uds:///run/shekyl/wallet.sock",
            "unix:///run/shekyl/wallet.sock",
            // No address configured: no connection is opened, nothing to say.
            "",
        ] {
            assert_eq!(classify(ep, None), Exposure::Local, "endpoint {ep}");
        }
    }

    #[test]
    fn bare_ipv6_loopback_is_not_mangled_into_a_remote_host() {
        // The regression this guards: `rsplit_once(':')` on `::1` yields `::`,
        // which fails to parse as loopback and would warn on a local endpoint.
        assert_eq!(host_of("::1"), "::1");
        assert_eq!(host_of("[::1]:11028"), "::1");
        assert_eq!(host_of("fe80::1"), "fe80::1");
        assert_eq!(classify("::1", None), Exposure::Local);
    }

    #[test]
    fn non_loopback_without_proxy_is_clear_network() {
        for (ep, host) in [
            ("node.example.com:11028", "node.example.com"),
            ("http://node.example.com:11028", "node.example.com"),
            ("203.0.113.7:11028", "203.0.113.7"),
            ("[2001:db8::1]:11028", "2001:db8::1"),
            ("https://node.example.com/json_rpc", "node.example.com"),
        ] {
            assert_eq!(
                classify(ep, None),
                Exposure::ClearNetwork {
                    host: host.to_owned()
                },
                "endpoint {ep}"
            );
        }
    }

    #[test]
    fn any_proxy_silences_a_remote_endpoint() {
        // We do not grade the proxy — only that one is configured.
        assert_eq!(
            classify("node.example.com:11028", Some("socks5://127.0.0.1:9050")),
            Exposure::Proxied
        );
        assert_eq!(
            classify("node.example.com:11028", Some("socks5://vpn.invalid:1080")),
            Exposure::Proxied
        );
    }

    #[test]
    fn loopback_is_local_even_with_a_proxy_configured() {
        assert_eq!(
            classify("127.0.0.1:11028", Some("socks5://127.0.0.1:9050")),
            Exposure::Local
        );
    }

    #[test]
    fn only_clear_network_speaks() {
        assert!(disclose("daemon", "127.0.0.1:11028", None).is_none());
        assert!(disclose("daemon", "node.example.com:11028", Some("socks5://x")).is_none());
        assert!(disclose("daemon", "node.example.com:11028", None).is_some());
    }

    /// The load-bearing property: no configuration produces an assurance. The
    /// only output this module can emit is a warning; every other path is
    /// silent. A future edit that adds a "connection is private" message for the
    /// loopback or proxied case fails here.
    #[test]
    fn no_configuration_ever_draws_an_assurance() {
        let outputs = [
            disclose("daemon", "127.0.0.1:11028", None),
            disclose("daemon", "uds:///run/w.sock", None),
            disclose("daemon", "node.example.com:11028", Some("socks5://x")),
            disclose("daemon", "node.example.com:11028", None),
        ];
        for out in outputs.into_iter().flatten() {
            assert!(
                out.starts_with("Warning:"),
                "the only emitted message may be a warning, got: {out}"
            );
        }
    }

    #[test]
    fn warning_names_the_endpoint_and_asserts_nothing_about_the_operator() {
        let w = warning_for("daemon address", "node.example.com");
        assert!(w.contains("daemon address"));
        assert!(w.contains("node.example.com"));
        // Exposure statement, not an accusation and not a grade.
        assert!(w.contains("regardless of who operates the far end"));
        assert!(!w.to_lowercase().contains("secure"));
        assert!(!w.to_lowercase().contains("safe"));
    }

    #[test]
    fn host_of_stops_at_query_and_fragment() {
        // A query or fragment with no path must not pull an `@`/`:` into the
        // userinfo/port split (regression: `rsplit_once('@')` inside a query).
        assert_eq!(host_of("http://node:11028?u=a@b"), "node");
        assert_eq!(host_of("http://node:11028#frag"), "node");
        assert_eq!(host_of("node.example.com:11028?x=1"), "node.example.com");
        assert_eq!(
            classify("http://node:11028?u=a@b", None),
            Exposure::ClearNetwork {
                host: "node".to_owned()
            }
        );
    }

    #[test]
    fn unproxyable_disclosure_warns_regardless_of_proxy() {
        // The self-hosted scan connection cannot use --proxy: a non-loopback
        // daemon warns; loopback / unix-socket / unconfigured stay silent.
        assert!(disclose_unproxyable("daemon address", "127.0.0.1:11028").is_none());
        assert!(disclose_unproxyable("daemon address", "uds:///run/w.sock").is_none());
        assert!(disclose_unproxyable("daemon address", "").is_none());
        let w = disclose_unproxyable("daemon address", "node.example.com:11028")
            .expect("a non-loopback self-hosted daemon warns");
        assert!(w.starts_with("Warning:"));
        assert!(w.contains("does not use --proxy"));
        assert!(w.contains("node.example.com"));
    }

    #[test]
    fn warnings_do_not_claim_the_payload_is_cleartext() {
        // #5: neither warning says "in the clear" — the exposure is metadata,
        // which holds even over an encrypted (TLS) link.
        for w in [
            warning_for("daemon", "node"),
            warning_for_direct("daemon", "node"),
        ] {
            assert!(!w.to_lowercase().contains("in the clear"), "{w}");
            assert!(w.contains("even if the link is encrypted"), "{w}");
        }
    }
}
