// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `EnvFilter` resolution at startup.
//!
//! [`resolve_env_filter`] picks the source for the process-wide filter
//! directive string: `SHEKYL_LOG` (and, under the `dev-env-fallback`
//! feature flag, `RUST_LOG`), otherwise a directive synthesized from the
//! caller's `fallback_default`.
//!
//! A directive from the environment is checked for C++ log categories
//! (`net.p2p:DEBUG`, `blockchain`, `*:WARNING`) before it is parsed.
//! `EnvFilter` would take each as a target that nothing logs under and
//! filter in silence, so a category is refused by name
//! ([`FilterError::CxxCategory`]): an operator who sets one is told what
//! to write instead.

use tracing::Level;
use tracing_subscriber::filter::{EnvFilter, ParseError};

/// Why a directive from the environment was refused.
#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    /// The directive names a log category of the C++ daemon. Its logs
    /// were `easylogging++` categories; the daemon is Rust, and its
    /// targets are the crates' module paths and the subsystems'
    /// explicit targets ([`crate::subsystem`]).
    #[error(
        "`{target}` in {source_var} is a log category of the C++ daemon, which is gone; \
         set a level per subsystem with `log-category` (daemon, p2p, sync, chain, store, \
         txpool, relay, rpc, tor, miner, notify, archival) or name a Rust target \
         (`shekyl_chain_sync=debug`)"
    )]
    CxxCategory {
        /// The refused target, as written.
        target: String,
        /// The variable it came from.
        source_var: &'static str,
    },
    /// `EnvFilter` refused the directive's syntax.
    #[error("{source_var} is not a filter directive: {source}")]
    Parse {
        /// The variable it came from.
        source_var: &'static str,
        /// `EnvFilter`'s reason.
        source: ParseError,
    },
}

/// The C++ daemon's category roots that no Rust code logs under. A
/// target equal to one, or below one at a `::` boundary, is a C++
/// category. `daemon`, `global`, `txpool`, `tor` and `notify` are not
/// here: Rust code logs under those names.
const CXX_CATEGORIES: &[&str] = &[
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

/// The first C++ category `spec` names, if any. A directive is
/// `target[span]=level`, comma separated; a bare level has no target.
/// The C++ spelling is caught by shape as well as by name: a `.` in a
/// target, a `:` that is not part of `::`, or a `*` never names a Rust
/// target.
fn cxx_category(spec: &str) -> Option<String> {
    spec.split(',').find_map(|directive| {
        let target = directive
            .split(['[', '='])
            .next()
            .unwrap_or_default()
            .trim();
        if target.is_empty()
            || target
                .parse::<tracing_subscriber::filter::LevelFilter>()
                .is_ok()
        {
            return None;
        }
        let root = target.split("::").next().unwrap_or(target);
        let cxx_shape =
            target.contains('.') || target.contains('*') || target.replace("::", "").contains(':');
        (cxx_shape || CXX_CATEGORIES.contains(&root) || target == "daemon::rpc")
            .then(|| target.to_owned())
    })
}

fn checked(spec: &str, source_var: &'static str) -> Result<EnvFilter, FilterError> {
    if let Some(target) = cxx_category(spec) {
        return Err(FilterError::CxxCategory { target, source_var });
    }
    EnvFilter::try_new(spec).map_err(|source| FilterError::Parse { source_var, source })
}

/// Env var name consulted by [`resolve_env_filter`].
///
/// Deliberately named `SHEKYL_LOG` rather than `RUST_LOG`: Shekyl binaries
/// handle wallet-adjacent data, and silently honoring a long-lived shell
/// export of `RUST_LOG=debug` would be a privacy foot-cannon. See the
/// crate README.
pub const SHEKYL_LOG_ENV: &str = "SHEKYL_LOG";

/// Env var name consulted only under the `dev-env-fallback` feature flag.
pub const DEV_FALLBACK_ENV: &str = "RUST_LOG";

/// Resolve the process-wide `EnvFilter` at startup.
///
/// Precedence, top wins:
///
/// 1. `SHEKYL_LOG` env var (if set and non-empty).
/// 2. `RUST_LOG` env var (only when the `dev-env-fallback` feature is
///    enabled — off by default).
/// 3. A single-level directive derived from `fallback_default`.
///
/// # Errors
///
/// [`FilterError::CxxCategory`] when the variable names a C++ log
/// category; [`FilterError::Parse`] when `EnvFilter` refuses its syntax.
pub fn resolve_env_filter(fallback_default: Level) -> Result<EnvFilter, FilterError> {
    if let Some(spec) = env_var_non_empty(SHEKYL_LOG_ENV) {
        return checked(&spec, SHEKYL_LOG_ENV);
    }

    #[cfg(feature = "dev-env-fallback")]
    {
        if let Some(spec) = env_var_non_empty(DEV_FALLBACK_ENV) {
            return checked(&spec, DEV_FALLBACK_ENV);
        }
    }

    EnvFilter::try_new(level_directive(fallback_default)).map_err(|source| FilterError::Parse {
        source_var: "the fallback level",
        source,
    })
}

fn env_var_non_empty(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(s) if !s.trim().is_empty() => Some(s),
        _ => None,
    }
}

pub(crate) fn level_directive(level: Level) -> String {
    match level {
        Level::ERROR => "error".to_owned(),
        Level::WARN => "warn".to_owned(),
        Level::INFO => "info".to_owned(),
        Level::DEBUG => "debug".to_owned(),
        Level::TRACE => "trace".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::cxx_category;

    #[test]
    fn a_cxx_category_is_named_by_shape_or_by_name() {
        for (spec, target) in [
            ("net.p2p:DEBUG", "net.p2p:DEBUG"),
            ("info,wallet.wallet2:INFO", "wallet.wallet2:INFO"),
            ("*:WARNING", "*:WARNING"),
            ("blockchain=debug", "blockchain"),
            ("warn,net::p2p=trace", "net::p2p"),
            ("cn", "cn"),
            ("daemon::rpc=debug", "daemon::rpc"),
            ("shekyl_ffi=debug", "shekyl_ffi"),
        ] {
            assert_eq!(cxx_category(spec).as_deref(), Some(target), "{spec}");
        }
    }

    #[test]
    fn rust_targets_levels_and_dependencies_pass() {
        for spec in [
            "warn",
            "info,shekyl_wallet_rpc=debug",
            "shekyl_wallet_rpc::scanner=trace",
            "daemon=debug,global=info,txpool=trace,tor=warn,notify=info",
            "warn,hyper=error,tokio=off",
            "shekyl_chain_sync[connect]=debug",
            "3",
            "",
        ] {
            assert_eq!(cxx_category(spec), None, "{spec}");
        }
    }
}
