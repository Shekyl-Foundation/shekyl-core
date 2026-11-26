// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! No environment variable sets the filter (`INPUT_GRAMMAR.md` IG-13). This
//! file is its own process and holds one test, because it sets variables and
//! installs the process's one subscriber.

use shekyl_logging::{init, Config};
use tracing::Level;

/// A shell export cannot raise a wallet's log level. Red edit: read
/// `SHEKYL_LOG` in `install_subscriber_with_stderr`, and `INFO` is enabled.
#[test]
fn no_environment_variable_sets_the_filter() {
    // SAFETY: this file is its own process, and this test runs before any
    // thread of ours exists.
    unsafe {
        std::env::set_var("SHEKYL_LOG", "trace");
        std::env::set_var("RUST_LOG", "trace");
    }
    let _guard = init(Config::stderr_only(Level::WARN)).expect("init");
    assert!(tracing::enabled!(Level::WARN), "the configured level is on");
    assert!(
        !tracing::enabled!(Level::INFO),
        "an environment variable raised the filter"
    );
}
