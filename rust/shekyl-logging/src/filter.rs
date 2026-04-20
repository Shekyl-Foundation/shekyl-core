// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `EnvFilter` resolution and the legacy-category translator.
//!
//! Two entry points matter to external callers:
//!
//! - [`resolve_env_filter`] picks the right source for the process-wide
//!   filter directive string at startup. It reads `SHEKYL_LOG` (and,
//!   under the `dev-env-fallback` feature flag, `RUST_LOG`), otherwise
//!   synthesizes a directive from the caller's `fallback_default`.
//! - [`directives_from_legacy_categories`] translates a spec expressed in
//!   the legacy C++ `easylogging++` `log-levels=` grammar to the EnvFilter
//!   directive string used by `tracing_subscriber`.
//!
//! See the crate README and the plan document for design rationale.

use thiserror::Error;
use tracing::Level;
use tracing_subscriber::filter::{EnvFilter, ParseError};

use crate::legacy;

/// Env var name consulted by [`resolve_env_filter`].
///
/// Deliberately named `SHEKYL_LOG` rather than `RUST_LOG`: Shekyl binaries
/// handle wallet-adjacent data, and silently honoring a long-lived shell
/// export of `RUST_LOG=debug` would be a privacy foot-cannon. See the
/// crate README.
pub const SHEKYL_LOG_ENV: &str = "SHEKYL_LOG";

/// Env var name consulted only under the `dev-env-fallback` feature flag.
pub const DEV_FALLBACK_ENV: &str = "RUST_LOG";

/// Structured result of translating a legacy `log-levels=` spec.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TranslationReport {
    /// The EnvFilter-shaped directive string, ready to hand to
    /// [`EnvFilter::try_new`]. May be empty; see the "empty spec" edge
    /// cases in the crate's plan document.
    pub directive: String,

    /// Category names that appeared in the input but are not recognized.
    ///
    /// Reported (not rejected) so callers can choose to surface a warning
    /// without failing startup. Unknown categories still appear in
    /// `directive` verbatim.
    pub unknown: Vec<String>,

    /// Soft-compat messages.
    ///
    /// Populated, for example, when a lowercase level name was accepted
    /// and normalized. Callers (especially the eventual wallet-rpc
    /// startup path in Chore #2) can render these as a single deprecation
    /// line.
    pub warnings: Vec<String>,
}

/// Errors returned from [`directives_from_legacy_categories`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FilterError {
    /// A level token was neither a recognized name (`FATAL`, `ERROR`,
    /// `WARNING`, `INFO`, `DEBUG`, `TRACE` — uppercase or lowercase) nor
    /// a numeric preset.
    #[error("unknown log level token: {token:?}")]
    UnknownLevel {
        /// The unrecognized token, captured verbatim from the input.
        token: String,
    },

    /// A bare-numeric spec fell outside the supported `0..=4` range.
    #[error("numeric log level {value} is out of range 0..=4")]
    NumericLevelOutOfRange {
        /// The out-of-range numeric value.
        value: i64,
    },

    /// A suffix-glob spec of the form `*y.z:LEVEL` was rejected.
    ///
    /// `tracing_subscriber::EnvFilter` has no native suffix-glob support,
    /// and expanding against a hardcoded target list would silently rot
    /// as new Rust modules are added. Callers should enumerate the
    /// intended targets explicitly or reach for `*:LEVEL` if a wildcard
    /// was the actual intent.
    #[error("suffix-glob {original:?} is not supported by the EnvFilter backend")]
    UnsupportedGlob {
        /// The glob pattern as it appeared in the input (without the
        /// trailing `:LEVEL`).
        original: String,
        /// If the spec looks like a common prefix-typo (e.g.
        /// `*.dump:DEBUG`, which is really `dump.*:DEBUG`), this carries
        /// the suggested rewrite.
        suggested_rewrite: Option<String>,
    },

    /// The spec was syntactically malformed (missing level, stray
    /// separator, etc.).
    #[error("malformed legacy spec: {reason}")]
    MalformedSpec {
        /// Human-readable description of what's wrong.
        reason: String,
    },
}

/// Resolve the process-wide `EnvFilter` at startup.
///
/// Precedence, top wins:
///
/// 1. `SHEKYL_LOG` env var (if set and non-empty).
/// 2. `RUST_LOG` env var (only when the `dev-env-fallback` feature is
///    enabled — off by default).
/// 3. A single-level directive derived from `fallback_default`.
///
/// The legacy translator is *not* invoked here. Those inputs arrive via
/// the runtime `mlog_set_log` / `mlog_set_categories` path wired up in
/// Chore #2.
pub fn resolve_env_filter(fallback_default: Level) -> Result<EnvFilter, ParseError> {
    if let Some(spec) = env_var_non_empty(SHEKYL_LOG_ENV) {
        return EnvFilter::try_new(&spec);
    }

    #[cfg(feature = "dev-env-fallback")]
    {
        if let Some(spec) = env_var_non_empty(DEV_FALLBACK_ENV) {
            return EnvFilter::try_new(&spec);
        }
    }

    EnvFilter::try_new(level_directive(fallback_default))
}

fn env_var_non_empty(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(s) if !s.trim().is_empty() => Some(s),
        _ => None,
    }
}

/// Translate a spec expressed in the legacy easylogging++ `log-levels=`
/// grammar to an EnvFilter directive.
///
/// Stateful: callers pass the currently-active spec (the one last
/// accepted) so that `+cat:LEVEL` / `-cat` modifiers can be applied as a
/// grammar-level textual merge before translation. Process startup
/// passes `current_spec = None`.
///
/// `fallback_default` is consulted only when both `current_spec` is
/// `None` and the translation would otherwise produce an empty directive
/// (empty env var, whitespace-only `new_spec`). This prevents the
/// "empty directive, everything logs at subscriber baseline" landmine at
/// startup while preserving the C++ "empty input == no change" semantics
/// on the RPC-runtime path.
///
/// # Reserved target names
///
/// The legacy preset strings reference two easylogging++ self-
/// instrumentation categories, `logging` and `msgwriter`. They survive
/// translation verbatim because removing them would silently drop the
/// preset's self-instrumentation overrides, but they are **reserved**:
/// no new Rust `tracing::*` call site should use `target: "logging"` or
/// `target: "msgwriter"`. `tests/reserved_names.rs` enforces this at CI
/// time.
pub fn directives_from_legacy_categories(
    current_spec: Option<&str>,
    new_spec: &str,
    fallback_default: Level,
) -> Result<TranslationReport, FilterError> {
    legacy::translate(current_spec, new_spec, fallback_default)
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
