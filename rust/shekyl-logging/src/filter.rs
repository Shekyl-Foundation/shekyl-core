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

use tracing::Level;
use tracing_subscriber::filter::{EnvFilter, ParseError};

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

pub(crate) fn level_directive(level: Level) -> String {
    match level {
        Level::ERROR => "error".to_owned(),
        Level::WARN => "warn".to_owned(),
        Level::INFO => "info".to_owned(),
        Level::DEBUG => "debug".to_owned(),
        Level::TRACE => "trace".to_owned(),
    }
}
