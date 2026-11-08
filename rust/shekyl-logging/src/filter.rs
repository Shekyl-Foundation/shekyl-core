// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Filter directives.
//!
//! A directive is text `EnvFilter` can parse. Free-form text — `SHEKYL_LOG`,
//! `RUST_LOG` under the `dev-env-fallback` feature, or any other string an
//! operator wrote — enters through [`Directive::parse`] and nowhere else.
//! The subsystem builder ([`crate::subsystem::directive`]) produces the same
//! type, by parsing the string it assembled from live targets.
//! [`crate::config::Config`] stores a [`Directive`], so a raw string cannot
//! be installed.

use tracing::Level;
use tracing_subscriber::filter::{EnvFilter, LevelFilter, ParseError};

use crate::subsystem;

/// A directive that names no retired target and that `EnvFilter` accepts.
///
/// Construct it with [`Directive::parse`]. There is no conversion from
/// [`String`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directive(String);

impl Directive {
    /// Refuse a retired target, then a directive `EnvFilter` itself refuses.
    ///
    /// `source_var` is the operator-facing name of where `spec` came from
    /// (`SHEKYL_LOG`, "the configured log directive").
    ///
    /// # Errors
    ///
    /// [`FilterError::RetiredTarget`] when `spec` names a retired target or
    /// uses the retired spelling (a `.`, a `*`, or a `:` outside `::`).
    /// [`FilterError::Parse`] when the spelling is current but `EnvFilter`
    /// refuses it.
    pub fn parse(spec: &str, source_var: &'static str) -> Result<Self, FilterError> {
        if let Some(target) = retired_in(spec) {
            return Err(FilterError::RetiredTarget {
                target,
                source_var,
                subsystems: subsystem::names(),
            });
        }
        EnvFilter::try_new(spec).map_err(|source| FilterError::Parse { source_var, source })?;
        Ok(Self(spec.to_owned()))
    }

    /// The directive text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The filter this directive installs. [`parse`](Self::parse) already
    /// accepted the text, so a refusal here is the parser disagreeing with
    /// itself.
    pub(crate) fn to_env_filter(&self) -> Result<EnvFilter, ParseError> {
        EnvFilter::try_new(&self.0)
    }
}

impl std::fmt::Display for Directive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a directive was refused.
#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    /// The directive names a target nothing in this tree logs under, or
    /// spells a target the way the C++ logger did. `EnvFilter` would take
    /// it as a target and filter in silence.
    #[error(
        "`{target}` in {source_var} is a log category of the C++ daemon, which is gone; \
         set a level per subsystem with `log-category` ({subsystems}) or name a Rust target \
         (`shekyl_chain_sync=debug`)"
    )]
    RetiredTarget {
        /// The refused target, as written.
        target: String,
        /// Where the directive came from.
        source_var: &'static str,
        /// The subsystem keys, from [`subsystem::Subsystem::ALL`].
        subsystems: &'static str,
    },
    /// `EnvFilter` refused the directive's syntax.
    #[error("{source_var} is not a filter directive: {source}")]
    Parse {
        /// Where the directive came from.
        source_var: &'static str,
        /// `EnvFilter`'s reason.
        source: ParseError,
    },
}

/// The first retired target `spec` names, if any.
///
/// A directive is `target[span]=level`, comma separated. A bare level has
/// no target. The retired spelling is a `.` in a target (`net.p2p`), a
/// `*` (`*:WARNING`), or a `:` that is not part of `::` (`net.p2p:DEBUG`).
fn retired_in(spec: &str) -> Option<String> {
    spec.split(',').find_map(|directive| {
        let target = directive
            .split(['[', '='])
            .next()
            .unwrap_or_default()
            .trim();
        if target.is_empty() || target.parse::<LevelFilter>().is_ok() {
            return None;
        }
        (retired_shape(target) || subsystem::is_retired_target(target)).then(|| target.to_owned())
    })
}

/// A target spelling the C++ logger used. `::` is a Rust path and stays.
fn retired_shape(target: &str) -> bool {
    target.contains('.') || target.contains('*') || target.replace("::", "").contains(':')
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

/// Where a fallback level's directive says it came from.
const FALLBACK_SOURCE: &str = "the fallback level";

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
/// [`FilterError::RetiredTarget`] when the variable names a retired target;
/// [`FilterError::Parse`] when `EnvFilter` refuses its syntax.
pub fn resolve_env_filter(fallback_default: Level) -> Result<EnvFilter, FilterError> {
    let (directive, source_var) = parsed_directive(fallback_default)?;
    directive
        .to_env_filter()
        .map_err(|source| FilterError::Parse { source_var, source })
}

fn parsed_directive(fallback_default: Level) -> Result<(Directive, &'static str), FilterError> {
    if let Some(spec) = env_var_non_empty(SHEKYL_LOG_ENV) {
        return Ok((Directive::parse(&spec, SHEKYL_LOG_ENV)?, SHEKYL_LOG_ENV));
    }

    #[cfg(feature = "dev-env-fallback")]
    {
        if let Some(spec) = env_var_non_empty(DEV_FALLBACK_ENV) {
            return Ok((Directive::parse(&spec, DEV_FALLBACK_ENV)?, DEV_FALLBACK_ENV));
        }
    }

    Ok((
        Directive::parse(&level_directive(fallback_default), FALLBACK_SOURCE)
            .expect("a level word is a filter directive"),
        FALLBACK_SOURCE,
    ))
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
    use super::{Directive, FilterError};

    const SOURCE: &str = "the configured log directive";

    fn refused(spec: &str) -> String {
        match Directive::parse(spec, SOURCE) {
            Err(FilterError::RetiredTarget {
                target, source_var, ..
            }) => {
                assert_eq!(source_var, SOURCE, "{spec}");
                target
            }
            other => panic!("{spec} must be a retired target, got {other:?}"),
        }
    }

    #[test]
    fn a_retired_target_is_refused_by_shape_or_by_name() {
        for (spec, target) in [
            ("net.p2p:DEBUG", "net.p2p:DEBUG"),
            ("info,wallet.wallet2:INFO", "wallet.wallet2:INFO"),
            ("*:WARNING", "*:WARNING"),
            ("blockchain=debug", "blockchain"),
            ("warn,net::p2p=trace", "net::p2p"),
            ("cn", "cn"),
            ("daemon::rpc=debug", "daemon::rpc"),
            ("shekyl_ffi=debug", "shekyl_ffi"),
            ("miner=debug", "miner"),
        ] {
            assert_eq!(refused(spec), target, "{spec}");
        }
    }

    #[test]
    fn live_targets_levels_and_dependencies_parse() {
        for spec in [
            "warn",
            "info,shekyl_wallet_rpc=debug",
            "shekyl_wallet_rpc::scanner=trace",
            "info,shekyl_chain_rules=debug,daemon=debug,tor=debug",
            "daemon=debug,global=info,txpool=trace,tor=warn,notify=info",
            "warn,hyper=error,tokio=off",
            "shekyl_chain_sync[connect]=debug",
            "3",
        ] {
            Directive::parse(spec, SOURCE).unwrap_or_else(|e| panic!("{spec}: {e}"));
        }
        assert!(
            !matches!(
                Directive::parse("", SOURCE),
                Err(FilterError::RetiredTarget { .. })
            ),
            "an empty directive is not a retired target"
        );
    }
}
