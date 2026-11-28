// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The closed set of log subsystems an operator can set a level for
//! (`INPUT_GRAMMAR.md` §5, `log-category`; ruled 2026-10-15: subsystem
//! names, never implementation names).
//!
//! A subsystem is an operator-meaningful part of a Shekyl binary. Each maps
//! to the `tracing` targets that implement it: the Rust crates by module
//! path, and the few explicit targets the code names (`global`, `daemon`,
//! `txpool`, `tor`, `notify`). A crate rename changes a list here, never a
//! configuration file.
//!
//! Every crate that logs, and every explicit target, belongs to exactly one
//! subsystem ([`Subsystem::of_target`]); the audit of the workspace's source
//! holds the map to the code. Each binary's `log-category` row names its own
//! list of subsystems, the ones its code and its dependencies log under, and
//! the same audit holds each list to what that binary logs.

use std::io::Write;

use tracing::Level;

use crate::filter::{level_directive, Directive};

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
    /// The wallet: its engine, files, scanner, transaction building and RPC.
    Wallet,
}

impl Subsystem {
    /// Every subsystem, in the order `log-category` lists them.
    pub const ALL: [Self; 13] = [
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
        Self::Wallet,
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
            Self::Wallet => "wallet",
        }
    }

    /// The subsystem a key names, if any.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }

    /// The `tracing` targets the subsystem covers. A target is a prefix at
    /// the `::` boundary, as `EnvFilter` reads it, so `shekyl_relay` covers
    /// `shekyl_relay::graph`.
    #[must_use]
    pub const fn targets(self) -> &'static [&'static str] {
        match self {
            Self::Daemon => &[
                "daemon",
                "global",
                "shekyl_daemon_config",
                "shekyl_node",
                "shekyl_runtime",
                "shekyl_timing_engine",
            ],
            Self::P2p => &[
                "shekyl_dialer",
                "shekyl_peerlist",
                "shekyl_p2p_session",
                "shekyl_p2p",
                "shekyl_transport_layer",
                "shekyl_clearnet",
                "shekyl_levin",
                "shekyl_p2p_transport",
                "shekyl_peer_policy",
                "shekyl_noise",
                "shekyl_socks",
            ],
            Self::Sync => &[
                "shekyl_chain_sync",
                "shekyl_chain_sync_runtime",
                "shekyl_chain_ingest",
            ],
            // `shekyl_fcmp`'s lines are a membership proof that failed to
            // verify: validation's.
            Self::Chain => &[
                "shekyl_chain_rules",
                "shekyl_consensus",
                "shekyl_difficulty",
                "shekyl_fcmp",
            ],
            Self::Store => &["shekyl_chain_store"],
            // The node's pool lines (`shekyl-node`'s pool door and the pool
            // file's opening) name this target.
            Self::Txpool => &["txpool"],
            Self::Relay => &["shekyl_relay", "shekyl_relay_privacy"],
            Self::Rpc => &[
                "shekyl_daemon_rpc",
                "shekyl_rpc_channel",
                "shekyl_rpc_transport",
                "shekyl_rpc_tunnel",
            ],
            // `tor` is the daemon's Tor driver's own target
            // (`shekyl-daemon/src/tor/`): its lines, a stuck round and each
            // descriptor event among them, are this subsystem's.
            Self::Tor => &[
                "shekyl_tor",
                "shekyl_tor_control_client",
                "shekyl_tor_control_daemon",
                "tor",
            ],
            Self::Miner => &[
                "shekyl_block_template",
                "shekyl_miner",
                "shekyl_pow_randomx",
            ],
            Self::Notify => &["notify"],
            Self::Archival => &[
                "shekyl_p_serve",
                "shekyl_p_fetch",
                "shekyl_p_store",
                "shekyl_p_host",
                "shekyl_archival_fetch_sched",
                "shekyl_archival_retention",
                "shekyl_archival_bond_builder",
            ],
            Self::Wallet => &[
                "shekyl_engine_core",
                "shekyl_engine_file",
                "shekyl_engine_state",
                "shekyl_scanner",
                "shekyl_tx_builder",
                "shekyl_wallet_contract",
                "shekyl_wallet_rpc",
            ],
        }
    }
}

impl Subsystem {
    /// The subsystem whose targets cover `target`: one equal to it, or a
    /// crate or module above it at the `::` boundary. No two subsystems
    /// cover one target (the map's own tests), so this is the one.
    #[must_use]
    pub fn of_target(target: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|s| s.targets().iter().any(|t| covers(t, target)))
    }
}

/// Whether the target `listed` covers `target`, as `EnvFilter` reads a
/// directive: equal, or `target` is a module path below it.
fn covers(listed: &str, target: &str) -> bool {
    target == listed
        || target
            .strip_prefix(listed)
            .is_some_and(|rest| rest.starts_with("::"))
}

/// The keys of a list of subsystems, in its order. A binary's table builds
/// its `log-category` keys with this from its own list of [`Subsystem`]s.
#[must_use]
pub const fn names<const N: usize>(list: [Subsystem; N]) -> [&'static str; N] {
    let mut names = [""; N];
    let mut i = 0;
    while i < N {
        names[i] = list[i].name();
        i += 1;
    }
    names
}

/// Every subsystem's key, in [`Subsystem::ALL`] order: the keys a
/// `log-category` row knows. A binary takes its own list of them; a known
/// key outside that list has its own refusal, naming the binary.
pub const NAMES: [&str; Subsystem::ALL.len()] = names(Subsystem::ALL);

/// [`NAMES`], comma separated. The retired-target error names them from
/// here, so the list cannot drift from the subsystem set.
#[must_use]
pub(crate) fn joined_names() -> &'static str {
    use std::sync::OnceLock;
    static JOINED: OnceLock<String> = OnceLock::new();
    JOINED.get_or_init(|| NAMES.join(", "))
}

/// Targets no Rust code logs under. A free-form directive naming one, or
/// a module path below one, is the C++ daemon's category. `daemon`,
/// `global`, `txpool`, `tor` and `notify` are live targets and are not
/// here. `miner` is a subsystem key whose targets are
/// `shekyl_block_template` and `shekyl_pow_randomx`; the bare name was a
/// C++ category and is retired.
const RETIRED_TARGETS: &[&str] = &[
    "net",
    "cn",
    "blockchain",
    "bcutil",
    "checkpoints",
    "difficulty",
    "verify",
    "miner",
    "spawn",
    "stacktrace",
    "util",
    "default",
    "wallet",
    "perf",
    "shekyl_ffi",
];

/// Retired even though the root is a live target. `daemon` is the process
/// target; `daemon::rpc` was the C++ RPC category.
const RETIRED_EXACT: &[&str] = &["daemon::rpc"];

/// Whether `target` is retired: equal to a retired root, or a module path
/// below one (`net` covers `net::p2p` and does not cover `notify`).
#[must_use]
pub(crate) fn is_retired_target(target: &str) -> bool {
    if RETIRED_EXACT.contains(&target) {
        return true;
    }
    RETIRED_TARGETS.iter().any(|retired| {
        target == *retired
            || target
                .strip_prefix(retired)
                .is_some_and(|rest| rest.starts_with("::"))
    })
}

/// The `EnvFilter` directive for a base level and per-subsystem overrides:
/// the base first, then every covered target at its subsystem's level.
/// The result has been through [`Directive::parse`].
#[must_use]
pub fn directive(base: Level, overrides: &[(Subsystem, Level)]) -> Directive {
    let mut parts = vec![level_directive(base)];
    for (subsystem, level) in overrides {
        let level = level_directive(*level);
        for target in subsystem.targets() {
            parts.push(format!("{target}={level}"));
        }
    }
    Directive::parse(&parts.join(","), "a subsystem directive")
        .expect("subsystem targets are live and parse")
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
pub fn directive_from_words(base: &str, overrides: &[(&str, &str)]) -> Option<Directive> {
    let base = level_from_word(base)?;
    let mut pairs = Vec::with_capacity(overrides.len());
    for (subsystem, level) in overrides {
        pairs.push((Subsystem::from_name(subsystem)?, level_from_word(level)?));
    }
    Some(directive(base, &pairs))
}

/// Applies a base level and per-subsystem overrides to the live filter.
/// The directive is [`directive`]'s. See [`apply_directive`].
pub fn apply(base: Level, overrides: &[(Subsystem, Level)]) {
    apply_directive(&directive(base, overrides));
}

/// Installs one directive on the live filter: the runtime owner of
/// `log-level` and `log-category` (IG-12, `DAEMON_CONFIG_CUTOVER.md` §2.7).
///
/// The directive is what [`directive`] and [`directive_from_words`] build,
/// so a caller that already holds it does not convert the words a second
/// time. The swap goes through the handle the one `init` registered for
/// the life of the process. The apply cannot fail on a directive those
/// functions built; the only failure is a process with no subscriber,
/// which is reported to standard error and leaves the filter as it was,
/// so a caller that built its values first stays all or nothing.
pub fn apply_directive(directive: &Directive) {
    if let Err(reason) = crate::reload::reload_directive(directive) {
        // No subscriber is the failure, so this cannot go through tracing.
        // The line is the operator's, on standard error.
        drop(writeln!(
            std::io::stderr(),
            "shekyl-logging: the runtime log change was not applied: {reason}"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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
        assert_eq!(Subsystem::from_name("Net"), None);
        assert_eq!(Subsystem::from_name("shekyl_dialer"), None);
    }

    #[test]
    fn the_key_list_is_every_subsystem_in_order() {
        assert_eq!(NAMES, Subsystem::ALL.map(Subsystem::name));
    }

    /// No listed target covers another, so no target the code logs under
    /// can belong to two subsystems. Red edit: list `shekyl_p2p::dial`
    /// under `sync`.
    #[test]
    fn no_target_belongs_to_two_subsystems() {
        let all: Vec<(&str, Subsystem)> = Subsystem::ALL
            .into_iter()
            .flat_map(|s| s.targets().iter().map(move |t| (*t, s)))
            .collect();
        for (i, (a, sa)) in all.iter().enumerate() {
            for (b, sb) in &all[i + 1..] {
                assert!(
                    !covers(a, b) && !covers(b, a),
                    "`{a}` ({}) and `{b}` ({}) overlap",
                    sa.name(),
                    sb.name()
                );
            }
        }
    }

    #[test]
    fn a_target_resolves_to_the_subsystem_listing_it_or_the_crate_above_it() {
        assert_eq!(Subsystem::of_target("txpool"), Some(Subsystem::Txpool));
        assert_eq!(
            Subsystem::of_target("shekyl_engine_core::pscan"),
            Some(Subsystem::Wallet)
        );
        assert_eq!(
            Subsystem::of_target("shekyl_p2p_session"),
            Some(Subsystem::P2p)
        );
        assert_eq!(Subsystem::of_target("shekyl_relayx"), None);
        assert_eq!(Subsystem::of_target("hyper"), None);
    }

    /// The converse of the map's other checks: every crate that logs, under
    /// its own name, and every explicit target the code names belongs to a
    /// subsystem (exactly one, by `no_target_belongs_to_two_subsystems`).
    /// Without it a crate's lines fall under no key, and no `log-category`
    /// setting can raise or lower them. Red edit: drop `shekyl_miner`.
    #[test]
    fn every_target_the_code_logs_under_belongs_to_a_subsystem() {
        let logging = crate::audit::workspace_logging().expect("the audit reads the workspace");
        let mut unmapped = Vec::new();
        for (package, logged) in &logging {
            for target in &logged.targets {
                if Subsystem::of_target(target).is_none() {
                    unmapped.push(format!("{package}: `{target}`"));
                }
            }
        }
        assert!(
            unmapped.is_empty(),
            "targets no subsystem covers: {unmapped:?}"
        );
        assert!(logging.contains_key("shekyl-node"), "{:?}", logging.keys());
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

    /// `log-category tor=debug` reaches the daemon's Tor driver, whose lines
    /// use the target `tor`. Without it the driver's debug lines (a stuck
    /// upload round, each descriptor event) could not be turned on.
    #[test]
    fn the_tor_category_reaches_the_daemons_tor_driver() {
        assert!(Subsystem::Tor.targets().contains(&"tor"));
        let directive = directive_from_words("info", &[("tor", "debug")]).expect("known words");
        assert!(
            directive
                .as_str()
                .split(',')
                .any(|part| part == "tor=debug"),
            "{directive}"
        );
    }

    /// `log-category wallet=debug` raises the wallet's crates and leaves
    /// everything else, third-party libraries included, at the base level.
    /// The key is live while the bare target `wallet`, the C++ category,
    /// stays retired. Red edit: drop `shekyl_engine_core` from the list.
    #[test]
    fn the_wallet_category_reaches_the_wallets_crates_alone() {
        let directive = directive_from_words("info", &[("wallet", "debug")]).expect("known words");
        let parts: Vec<&str> = directive.as_str().split(',').collect();
        assert_eq!(parts[0], "info");
        for crate_target in ["shekyl_engine_core", "shekyl_scanner", "shekyl_wallet_rpc"] {
            assert!(
                parts.contains(&format!("{crate_target}=debug").as_str()),
                "{directive}"
            );
        }
        assert!(!parts.iter().any(|p| p.starts_with("hyper")), "{directive}");
        assert!(is_retired_target("wallet"));
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
        assert!(d.as_str().starts_with("warn,"), "{d}");
        assert_eq!(directive(Level::INFO, &[]).as_str(), "info");
    }

    #[test]
    fn no_live_target_is_retired() {
        for subsystem in Subsystem::ALL {
            for target in subsystem.targets() {
                assert!(
                    !is_retired_target(target),
                    "{target} ({}) is both live and retired",
                    subsystem.name()
                );
            }
        }
        assert!(is_retired_target("miner"));
        assert!(is_retired_target("net::p2p"));
        assert!(!is_retired_target("daemon"));
        assert!(is_retired_target("daemon::rpc"));
        assert!(!is_retired_target("notify"));
    }
}
