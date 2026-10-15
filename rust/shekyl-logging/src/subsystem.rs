// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The closed set of log subsystems an operator can set a level for
//! (`INPUT_GRAMMAR.md` §5, `log-category`; ruled 2026-10-15: subsystem
//! names, never implementation names).
//!
//! A subsystem is an operator-meaningful part of the daemon. Each maps to
//! the `tracing` targets that implement it: the C++ categories as the legacy
//! translator spells them (`.` becomes `::`) and the Rust crates by module
//! path. A crate rename changes a list here, never a configuration file.
//! The list is the owner the grammar's `log-category` row validates its
//! keys against, by reference.

use tracing::Level;

use crate::filter::level_directive;

/// One subsystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Subsystem {
    /// The process: start, stop, configuration, the runtime.
    Daemon,
    /// Peer connections: dialling, admission, the peer lists, the transport.
    P2p,
    /// Chain synchronisation with peers.
    Sync,
    /// Block and transaction validation.
    Chain,
    /// The chain store.
    Store,
    /// The transaction pool.
    Txpool,
    /// Transaction relay and its privacy mechanisms.
    Relay,
    /// The RPC service.
    Rpc,
    /// The managed Tor and the Tor connector.
    Tor,
    /// Mining.
    Miner,
    /// The notify runner.
    Notify,
    /// Archival serving and fetching.
    Archival,
}

impl Subsystem {
    /// Every subsystem, in the order `log-category` lists them.
    pub const ALL: [Self; 12] = [
        Self::Daemon,
        Self::P2p,
        Self::Sync,
        Self::Chain,
        Self::Store,
        Self::Txpool,
        Self::Relay,
        Self::Rpc,
        Self::Tor,
        Self::Miner,
        Self::Notify,
        Self::Archival,
    ];

    /// The key an operator writes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::P2p => "p2p",
            Self::Sync => "sync",
            Self::Chain => "chain",
            Self::Store => "store",
            Self::Txpool => "txpool",
            Self::Relay => "relay",
            Self::Rpc => "rpc",
            Self::Tor => "tor",
            Self::Miner => "miner",
            Self::Notify => "notify",
            Self::Archival => "archival",
        }
    }

    /// The subsystem a key names, if any.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }

    /// The `tracing` targets the subsystem covers. A target is a prefix at
    /// the `::` boundary, as `EnvFilter` reads it, so `net` covers
    /// `net::p2p`; a longer target in another subsystem takes precedence
    /// there, as `EnvFilter` ranks the more specific directive first.
    #[must_use]
    pub const fn targets(self) -> &'static [&'static str] {
        match self {
            Self::Daemon => &[
                "daemon",
                "global",
                "default",
                "stacktrace",
                "util",
                "shekyl_ffi",
                "shekyl_daemon_config",
                "shekyl_runtime",
                "shekyl_timing_engine",
            ],
            Self::P2p => &[
                "net",
                "shekyl_dialer",
                "shekyl_peerlist",
                "shekyl_seam",
                "shekyl_transport_layer",
                "shekyl_clearnet",
                "shekyl_levin",
                "shekyl_p2p_transport",
                "shekyl_peer_policy",
                "shekyl_noise",
                "shekyl_socks",
            ],
            Self::Sync => &["net::cn", "cn::block_queue", "shekyl_chain_ingest"],
            Self::Chain => &[
                "blockchain",
                "cn",
                "verify",
                "checkpoints",
                "difficulty",
                "bcutil",
                "shekyl_chain_rules",
                "shekyl_consensus",
                "shekyl_difficulty",
            ],
            Self::Store => &["blockchain::db", "shekyl_chain_store"],
            Self::Txpool => &["txpool"],
            Self::Relay => &["net::p2p::tx", "shekyl_relay", "shekyl_relay_privacy"],
            Self::Rpc => &[
                "daemon::rpc",
                "net::http",
                "shekyl_daemon_rpc",
                "shekyl_rpc_channel",
                "shekyl_rpc_transport",
            ],
            Self::Tor => &[
                "shekyl_tor",
                "shekyl_tor_control_client",
                "shekyl_tor_control_daemon",
            ],
            Self::Miner => &["miner", "shekyl_block_template", "shekyl_pow_randomx"],
            Self::Notify => &["notify", "spawn"],
            Self::Archival => &[
                "shekyl_p_serve",
                "shekyl_p_fetch",
                "shekyl_p_store",
                "shekyl_p_host",
                "shekyl_archival_fetch_sched",
                "shekyl_archival_retention",
                "shekyl_archival_bond_builder",
            ],
        }
    }
}

/// Whether `name` is a subsystem. Shaped as a plain function so a table's
/// key rule can point at it.
#[must_use]
pub fn is_subsystem(name: &str) -> bool {
    Subsystem::from_name(name).is_some()
}

/// The `EnvFilter` directive for a base level and per-subsystem overrides:
/// the base first, then every covered target at its subsystem's level.
/// Returns something `EnvFilter::try_new` accepts for every input.
#[must_use]
pub fn directive(base: Level, overrides: &[(Subsystem, Level)]) -> String {
    let mut parts = vec![level_directive(base)];
    for (subsystem, level) in overrides {
        let level = level_directive(*level);
        for target in subsystem.targets() {
            parts.push(format!("{target}={level}"));
        }
    }
    parts.join(",")
}

/// The five level words the grammar spells (`log-level`, `log-category`).
#[must_use]
pub fn level_from_word(word: &str) -> Option<Level> {
    match word {
        "error" => Some(Level::ERROR),
        "warn" => Some(Level::WARN),
        "info" => Some(Level::INFO),
        "debug" => Some(Level::DEBUG),
        "trace" => Some(Level::TRACE),
        _ => None,
    }
}

/// [`directive`] from the grammar's words: a base level and
/// `(subsystem, level)` pairs. `None` when a word is not a level or a
/// subsystem, which the table refuses before this is reached.
#[must_use]
pub fn directive_from_words(base: &str, overrides: &[(&str, &str)]) -> Option<String> {
    let base = level_from_word(base)?;
    let mut pairs = Vec::with_capacity(overrides.len());
    for (subsystem, level) in overrides {
        pairs.push((Subsystem::from_name(subsystem)?, level_from_word(level)?));
    }
    Some(directive(base, &pairs))
}

/// Applies a base level and per-subsystem overrides to the live filter: the
/// runtime owner of `log-level` and `log-category` (IG-12,
/// `DAEMON_CONFIG_CUTOVER.md` §2.7). The directive is [`directive`]'s, so
/// it is always one the filter accepts, and the swap goes through the
/// handle the one `init` registered for the life of the process. The apply
/// therefore cannot fail on its input; the only failure is a process with no
/// subscriber, which is reported to standard error and leaves the filter as
/// it was, so a caller that built its values first stays all or nothing.
pub fn apply(base: Level, overrides: &[(Subsystem, Level)]) {
    let directive = directive(base, overrides);
    if let Err(reason) = crate::ffi::reload_directive(directive) {
        eprintln!("shekyl-logging: the runtime log change was not applied: {reason}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use tracing_subscriber::EnvFilter;

    #[test]
    fn names_are_distinct_lowercase_words_and_round_trip() {
        let mut seen = BTreeSet::new();
        for s in Subsystem::ALL {
            let n = s.name();
            assert!(
                n.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "{n}"
            );
            assert!(seen.insert(n), "{n} twice");
            assert_eq!(Subsystem::from_name(n), Some(s));
        }
        assert!(!is_subsystem("Net"));
        assert!(!is_subsystem("shekyl_dialer"));
    }

    #[test]
    fn no_target_belongs_to_two_subsystems_and_none_is_reserved() {
        let mut seen = BTreeSet::new();
        for s in Subsystem::ALL {
            for t in s.targets() {
                assert!(seen.insert(*t), "{t} is listed twice");
                assert!(*t != "logging" && *t != "msgwriter", "{t} is reserved");
            }
        }
    }

    /// Every Rust target names a crate of this workspace: a renamed or
    /// deleted crate fails here, not silently in an operator's filter.
    #[test]
    fn every_rust_target_is_a_workspace_member() {
        let manifest =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml"))
                .expect("workspace manifest");
        for s in Subsystem::ALL {
            for t in s.targets() {
                if let Some(rest) = t.strip_prefix("shekyl_") {
                    let dir = format!("\"shekyl-{}\"", rest.replace('_', "-"));
                    assert!(
                        manifest.contains(&dir),
                        "{t} names no workspace member {dir}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_words_build_the_same_directive_and_an_unknown_word_is_none() {
        assert_eq!(
            directive_from_words("warn", &[("p2p", "debug")]),
            Some(directive(Level::WARN, &[(Subsystem::P2p, Level::DEBUG)]))
        );
        assert_eq!(directive_from_words("loud", &[]), None);
        assert_eq!(directive_from_words("warn", &[("net", "debug")]), None);
        assert_eq!(directive_from_words("warn", &[("p2p", "verbose")]), None);
    }

    #[test]
    fn the_directive_is_accepted_by_env_filter_for_every_subsystem() {
        let all: Vec<(Subsystem, Level)> =
            Subsystem::ALL.iter().map(|s| (*s, Level::TRACE)).collect();
        let d = directive(Level::WARN, &all);
        assert!(d.starts_with("warn,"), "{d}");
        EnvFilter::try_new(&d).expect("every target parses");
        assert_eq!(directive(Level::INFO, &[]), "info");
    }
}
