// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The runtime owner of `log-level` and `log-category`
//! (`DAEMON_CONFIG_CUTOVER.md` §2.7, `RPC_CHANNEL.md` RT-O25): a typed
//! apply swaps the live filter through the handle `init` registered. Its
//! own binary, because a subscriber installs once per process.

use shekyl_logging::subsystem::{apply, Subsystem};
use shekyl_logging::Config;
use tracing::Level;

#[test]
fn a_typed_apply_swaps_the_live_filter() {
    let _guard = shekyl_logging::init(Config::stderr_only(Level::WARN)).expect("first init");
    assert!(!tracing::enabled!(target: "shekyl_dialer", Level::DEBUG));
    assert!(!tracing::enabled!(target: "daemon", Level::INFO));

    apply(Level::INFO, &[(Subsystem::P2p, Level::DEBUG)]);

    // The base moved to info and the p2p targets to debug; a target outside
    // the override keeps the base.
    assert!(tracing::enabled!(target: "shekyl_dialer", Level::DEBUG));
    assert!(tracing::enabled!(target: "daemon", Level::INFO));
    assert!(!tracing::enabled!(target: "daemon", Level::DEBUG));
    assert!(!tracing::enabled!(target: "txpool", Level::DEBUG));

    // Back to the defaults: `none` overrides, the startup base.
    apply(Level::WARN, &[]);
    assert!(!tracing::enabled!(target: "shekyl_dialer", Level::DEBUG));
    assert!(!tracing::enabled!(target: "daemon", Level::INFO));
}
