// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Product flag for cooperative payment-request labels (default off at V3.0).
//!
//! Enable via `prefs.toml` `operational.cooperative_payment_requests = true`
//! or environment variable `SHEKYL_COOPERATIVE_PAYMENT_REQUESTS=1`.

use shekyl_engine_prefs::WalletPrefs;

/// True when cooperative REQUEST tag handling is enabled.
#[must_use]
pub fn cooperative_payment_requests_enabled(prefs: &WalletPrefs) -> bool {
    if env_flag_set() {
        return true;
    }
    prefs.operational.cooperative_payment_requests
}

fn env_flag_set() -> bool {
    match std::env::var("SHEKYL_COOPERATIVE_PAYMENT_REQUESTS") {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => false,
    }
}
