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
//!   far end: an observer on that network path learns the operator runs a Shekyl
//!   wallet and when it is active. This is *metadata* exposure — it holds even
//!   if the link is encrypted (TLS) — not a claim that the payload is cleartext.
//! - **A local-resolving SOCKS scheme (`socks5://`, `socks4://`) with a
//!   *hostname* endpoint, dialed by a transport that honors the scheme →
//!   warn.** Those schemes resolve the target locally and connect the proxy to
//!   the resulting IP, so the hostname reaches the system resolver in
//!   cleartext *before* the proxy is involved. This is a documented property
//!   of the scheme, not a guess about the far end — and it is why
//!   `socks5h://` / `socks4a://` exist. An IP-literal endpoint has no name to
//!   leak and is silent — and so is an endpoint whose dialing transport
//!   always resolves at the proxy regardless of scheme
//!   ([`ProxyResolution::AlwaysRemote`]): warning there would claim a lookup
//!   no opened connection performs, the mirror error of an unearned
//!   assurance.
//! - **Loopback, unix socket, or a remote-resolving proxy → silence.**
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

/// How the transport that will dial an endpoint resolves its hostname when a
/// proxy is configured — the fact the DNS-leak disclosure hinges on. The
/// *caller* knows which transport opens; this module only knows schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyResolution {
    /// The transport honors the proxy URL's scheme: `socks5://` / `socks4://`
    /// resolve the endpoint hostname at the local resolver (the leak),
    /// `socks5h://` / `socks4a://` at the proxy. The ureq clients — the
    /// `--rpc-url` session and the REPL's direct daemon client — are this.
    HonorsScheme,
    /// The transport hands the hostname to the proxy regardless of scheme
    /// (SOCKS5h semantics always), so there is no local lookup to disclose.
    /// The self-hosted scan transport (`shekyl-rpc-transport`) is this.
    AlwaysRemote,
}

/// What an outbound endpoint exposes to a passive network observer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exposure {
    /// Loopback host or a unix-domain socket: no network path to observe.
    Local,
    /// A proxy is configured, so the connection is routed through it rather than
    /// dialed directly. This says **nothing** about whether the proxy is
    /// trustworthy — only that one is in use. We cannot assess it and do not try.
    Proxied,
    /// A non-loopback endpoint with no proxy: the connection is dialed directly
    /// across a network path a passive observer can see (metadata exposure —
    /// this holds even if the link is TLS-encrypted, not a claim about payload).
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
///
/// Public because `rpc_client`'s `--rpc-url` acceptance check uses the *same*
/// extractor: a hostless `http://` must be rejected there rather than reaching
/// this module and producing a warning about an empty host. Two parsers could
/// disagree about what a host is; one cannot.
#[must_use]
pub fn host_of(endpoint: &str) -> &str {
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
/// warning; use `localhost` or `127.0.0.1` to silence it.
///
/// Resolving is avoided for two reasons, the first fundamental:
///
/// 1. **DNS is not a locality measurement.** Asking a resolver "does this name
///    map to loopback?" trusts a manipulable oracle to report the network fact
///    rather than establishing it — a poisoned resolver, a hostile
///    `/etc/hosts`, an on-path answer, or plain resolve-then-connect TOCTOU can
///    all make the answer lie. That is the exact §15 category error the
///    warn-only rule exists to reject (deriving a claim a check cannot
///    measure): a host is not on-machine because DNS *says* so. An IP literal,
///    by contrast, *is* loopback by definition — the syntactic check measures
///    the very thing it asserts.
/// 2. **It would also leak.** `is_loopback_host` runs *before* the proxy
///    branch, so a lookup here hands the daemon hostname to the local resolver
///    even for a proxied endpoint — a DNS leak that defeats the privacy a proxy
///    buys (Tor proxies DNS through the SOCKS layer precisely to avoid this).
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
    // Endpoint-neutral wording: this text serves both the wallet-RPC endpoint
    // (`--rpc-url`) and the REPL's direct daemon client, so it must not say
    // "node" — `label` already names which endpoint is being reported.
    format!(
        "Warning: {label} '{host}' is not loopback and no proxy is configured. \
         An observer on the network path can see that you connect to a remote \
         endpoint — that you run a Shekyl wallet, and when it is active — which \
         holds regardless of who operates the far end and even if the link is \
         encrypted. Route it through a proxy (--proxy), or point it at an \
         endpoint on this machine."
    )
}

/// `true` for SOCKS schemes that resolve the target hostname **locally** and
/// then connect the proxy to the resulting IP — leaking the hostname to the
/// system resolver in cleartext before the proxy is ever involved.
///
/// `socks5` / `socks4` resolve locally; `socks5h` / `socks4a` hand the hostname
/// to the proxy (the `h`/`a` variants exist precisely for this). HTTP proxies
/// pass the host in the request line / `CONNECT`, so they also resolve remotely.
/// An absent or unrecognized scheme is **not** reported: silence is this
/// module's answer for anything it cannot establish, and claiming a leak we
/// have not established is the mirror of claiming a safety we cannot measure.
fn proxy_resolves_locally(proxy: &str) -> bool {
    let scheme = proxy.split("://").next().unwrap_or_default();
    scheme.eq_ignore_ascii_case("socks5") || scheme.eq_ignore_ascii_case("socks4")
}

/// The warning text for a proxy that will resolve the target hostname locally.
///
/// Fires only when there is actually a name to leak — an IP-literal endpoint
/// involves no lookup, so warning on it would be a false positive of exactly the
/// kind §15 rejected.
#[must_use]
pub fn warning_for_dns_leak(label: &str, host: &str, proxy: &str) -> String {
    let scheme = proxy.split("://").next().unwrap_or_default();
    format!(
        "Warning: --proxy uses '{scheme}://', which resolves target hostnames \
         locally, so connecting to {label} '{host}' leaks that hostname to your \
         system resolver in cleartext before the proxy is involved — defeating \
         much of what the proxy is for. (A .onion address cannot be resolved \
         this way at all.) Use 'socks5h://' (or 'socks4a://') so the proxy \
         resolves the hostname instead."
    )
}

/// Emit the disclosure for one endpoint. Returns the warning that was printed,
/// if any — `None` means silence, which is the correct output for every case
/// this module cannot establish a weakness for (there is deliberately no
/// "looks good" message).
///
/// `resolution` names how the dialing transport resolves hostnames under a
/// proxy: the DNS-leak warning is only *true* for a transport that honors a
/// local-resolving scheme, so a [`ProxyResolution::AlwaysRemote`] transport
/// never draws it (the clear-network warning is unaffected — it is about
/// having no proxy at all).
///
/// The two warnings are mutually exclusive by construction: `ClearNetwork` means
/// no proxy is configured, `Proxied` means one is.
pub fn disclose(
    label: &str,
    endpoint: &str,
    proxy: Option<&str>,
    resolution: ProxyResolution,
) -> Option<String> {
    match classify(endpoint, proxy) {
        Exposure::Local => None,
        // A proxy is in use — we still say nothing about whether it is
        // trustworthy. But a local-resolving SOCKS scheme hands the hostname to
        // the system resolver *before* the proxy sees anything, and that is a
        // property of the scheme itself, not a guess about the far end.
        Exposure::Proxied => {
            let proxy = proxy?;
            let host = host_of(endpoint);
            if resolution == ProxyResolution::HonorsScheme
                && proxy_resolves_locally(proxy)
                && host.parse::<std::net::IpAddr>().is_err()
            {
                let msg = warning_for_dns_leak(label, host, proxy);
                eprintln!("{msg}");
                return Some(msg);
            }
            None
        }
        Exposure::ClearNetwork { host } => {
            let msg = warning_for(label, &host);
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
    fn any_proxy_classifies_a_remote_endpoint_as_proxied() {
        // `classify` reports only *that* a proxy is configured — it does not
        // grade it, and it is deliberately blind to the scheme. The scheme's
        // resolution behavior is a separate, reportable fact handled in
        // `disclose` (see `local_resolving_proxy_warns_only_when_there_is_a_
        // name_to_leak`), so `Proxied` here does not imply silence there.
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
    fn only_establishable_weaknesses_speak() {
        // Local: nothing to disclose.
        assert!(disclose(
            "daemon",
            "127.0.0.1:11028",
            None,
            ProxyResolution::HonorsScheme
        )
        .is_none());
        // Remote, no proxy: clear-network warning.
        assert!(disclose(
            "daemon",
            "node.example.com:11028",
            None,
            ProxyResolution::HonorsScheme
        )
        .is_some());
        // Remote behind a remote-resolving proxy: silence — we do not grade it.
        assert!(disclose(
            "daemon",
            "node.example.com:11028",
            Some("socks5h://x"),
            ProxyResolution::HonorsScheme
        )
        .is_none());
    }

    /// A local-resolving SOCKS scheme leaks the hostname to the system resolver
    /// before the proxy is involved. That is a property of the scheme, not a
    /// guess about the far end, so it is reportable.
    #[test]
    fn local_resolving_proxy_warns_only_when_there_is_a_name_to_leak() {
        // socks5:// + hostname → the leak exists.
        let leaked = disclose(
            "daemon address",
            "node.example.com:11028",
            Some("socks5://x"),
            ProxyResolution::HonorsScheme,
        );
        let msg = leaked.expect("socks5:// with a hostname must warn");
        assert!(
            msg.contains("socks5://"),
            "names the offending scheme: {msg}"
        );
        assert!(msg.contains("socks5h://"), "names the remedy: {msg}");
        assert!(msg.contains("node.example.com"));

        // socks4:// resolves locally too.
        assert!(disclose(
            "daemon",
            "node.example.com:11028",
            Some("socks4://x"),
            ProxyResolution::HonorsScheme
        )
        .is_some());

        // The remote-resolving variants are the fix, not the problem.
        assert!(disclose(
            "daemon",
            "node.example.com:11028",
            Some("socks5h://x"),
            ProxyResolution::HonorsScheme
        )
        .is_none());
        assert!(disclose(
            "daemon",
            "node.example.com:11028",
            Some("socks4a://x"),
            ProxyResolution::HonorsScheme
        )
        .is_none());

        // An IP-literal endpoint involves no lookup — warning would be a false
        // positive of exactly the kind §15 rejected.
        assert!(disclose(
            "daemon",
            "203.0.113.7:11028",
            Some("socks5://x"),
            ProxyResolution::HonorsScheme
        )
        .is_none());
        assert!(disclose(
            "daemon",
            "[2001:db8::1]:11028",
            Some("socks5://x"),
            ProxyResolution::HonorsScheme
        )
        .is_none());

        // An HTTP proxy passes the host in the request; it does not resolve
        // locally. An unrecognized/absent scheme is not an established leak.
        assert!(disclose(
            "daemon",
            "node.example.com:11028",
            Some("http://x"),
            ProxyResolution::HonorsScheme
        )
        .is_none());
        assert!(disclose(
            "daemon",
            "node.example.com:11028",
            Some("127.0.0.1:9050"),
            ProxyResolution::HonorsScheme
        )
        .is_none());
    }

    /// An always-remote transport (the self-hosted scan) performs no local
    /// lookup for any proxy scheme, so the DNS-leak warning would assert a
    /// leak no opened connection produces — it stays silent. The
    /// clear-network warning (no proxy at all) is about the dial itself and
    /// is unaffected.
    #[test]
    fn always_remote_transport_never_draws_the_dns_leak_warning() {
        assert!(disclose(
            "daemon address",
            "node.example.com:11028",
            Some("socks5://x"),
            ProxyResolution::AlwaysRemote
        )
        .is_none());
        assert!(disclose(
            "daemon address",
            "node.example.com:11028",
            Some("socks4://x"),
            ProxyResolution::AlwaysRemote
        )
        .is_none());
        assert!(disclose(
            "daemon address",
            "node.example.com:11028",
            None,
            ProxyResolution::AlwaysRemote
        )
        .is_some());
    }

    /// The load-bearing property: no configuration produces an assurance. The
    /// only output this module can emit is a warning; every other path is
    /// silent. A future edit that adds a "connection is private" message for the
    /// loopback or proxied case fails here.
    #[test]
    fn no_configuration_ever_draws_an_assurance() {
        let outputs = [
            disclose(
                "daemon",
                "127.0.0.1:11028",
                None,
                ProxyResolution::HonorsScheme,
            ),
            disclose(
                "daemon",
                "uds:///run/w.sock",
                None,
                ProxyResolution::HonorsScheme,
            ),
            disclose(
                "daemon",
                "node.example.com:11028",
                Some("socks5://x"),
                ProxyResolution::HonorsScheme,
            ),
            disclose(
                "daemon",
                "node.example.com:11028",
                Some("socks5h://x"),
                ProxyResolution::HonorsScheme,
            ),
            disclose(
                "daemon",
                "node.example.com:11028",
                None,
                ProxyResolution::HonorsScheme,
            ),
        ];
        for out in outputs.into_iter().flatten() {
            assert!(
                out.starts_with("Warning:"),
                "the only emitted message may be a warning, got: {out}"
            );
        }
    }

    /// `warning_for` serves both the wallet-RPC endpoint and the daemon client,
    /// so it must not name one of them. `label` carries that.
    #[test]
    fn shared_warning_text_is_endpoint_neutral() {
        let w = warning_for("wallet-RPC endpoint", "rpc.example.com");
        assert!(w.contains("wallet-RPC endpoint"));
        assert!(
            !w.contains("node"),
            "shared text must not say 'node' — it also serves the wallet-RPC \
             endpoint, where that is wrong: {w}"
        );
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

    /// The self-hosted daemon scan now honors --proxy (SOCKS5h), so it is
    /// disclosed via `disclose` like every other daemon connection — there is
    /// no longer an "unproxyable" path. A non-loopback daemon with no proxy
    /// warns; a remote-resolving proxy silences it.
    #[test]
    fn self_hosted_daemon_is_disclosed_proxy_aware() {
        assert!(disclose(
            "daemon address",
            "127.0.0.1:11028",
            None,
            ProxyResolution::HonorsScheme
        )
        .is_none());
        assert!(disclose(
            "daemon address",
            "node.example.com:11028",
            Some("socks5h://x"),
            ProxyResolution::HonorsScheme
        )
        .is_none());
        let w = disclose(
            "daemon address",
            "node.example.com:11028",
            None,
            ProxyResolution::HonorsScheme,
        )
        .expect("a non-loopback daemon with no proxy warns");
        assert!(w.starts_with("Warning:"));
        assert!(w.contains("node.example.com"));
    }

    #[test]
    fn warnings_do_not_claim_the_payload_is_cleartext() {
        // #5: the warning does not say "in the clear" — the exposure is
        // metadata, which holds even over an encrypted (TLS) link.
        let w = warning_for("daemon", "node");
        assert!(!w.to_lowercase().contains("in the clear"), "{w}");
        assert!(w.contains("even if the link is encrypted"), "{w}");
    }
}
