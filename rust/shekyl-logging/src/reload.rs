// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The live filter's reload handle.
//!
//! [`crate::init`] wraps the resolved `EnvFilter` in a
//! [`tracing_subscriber::reload::Layer`] and registers its handle here, once
//! per process. [`crate::subsystem::apply_directive`] swaps the live filter
//! through it, so a runtime `log-level` / `log-category` change does not
//! tear the subscriber down.

use std::sync::OnceLock;

use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::reload;
use tracing_subscriber::Registry;

use crate::filter::Directive;

/// The handle for the process-global reload layer wrapping the `EnvFilter`.
pub(crate) type FilterReloadHandle = reload::Handle<EnvFilter, Registry>;

/// Set by the one successful install. A subscriber installs once per
/// process, so the handle does too.
static HANDLE: OnceLock<FilterReloadHandle> = OnceLock::new();

/// Records the handle of the subscriber [`crate::init`] just installed.
/// The reservation in `install_reserved` lets one install succeed per
/// process, so a second registration cannot happen; if one did, the first
/// handle stays.
pub(crate) fn register(handle: FilterReloadHandle) {
    drop(HANDLE.set(handle));
}

/// Swaps the live filter for `directive`. The directive was parsed when
/// it was built ([`Directive::parse`]), so the only `Err`s a caller
/// reaches are a subscriber that was never installed and a reload layer
/// that is gone, neither of which a daemon reaches after start.
pub(crate) fn reload_directive(directive: &Directive) -> Result<(), String> {
    let Some(handle) = HANDLE.get() else {
        return Err("no subscriber is installed".to_owned());
    };
    let filter = directive
        .to_env_filter()
        .map_err(|e| format!("the directive {directive} is not a filter: {e}"))?;
    handle
        .reload(filter)
        .map_err(|e| format!("the reload layer is gone: {e}"))
}
