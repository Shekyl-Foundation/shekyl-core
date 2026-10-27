// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The runtime owner of `log-level` and `log-category`
//! (`DAEMON_CONFIG_CUTOVER.md` §2.7, `RPC_CHANNEL.md` RT-O25): a typed
//! apply swaps the live filter through the handle `init` registered, and
//! the recorded directive follows it. Its own binary, because a subscriber
//! installs once per process.

use shekyl_logging::subsystem::{apply, directive, Subsystem};
use shekyl_logging::Config;
use tracing::Level;

#[test]
fn a_typed_apply_swaps_the_live_filter_and_records_its_directive() {
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

    // The recorded directive is the one applied, read back through the
    // C reader the C++ still calls.
    let mut buf = vec![0u8; 1024];
    let n = unsafe {
        shekyl_logging::ffi::shekyl_log_get_categories(buf.as_mut_ptr().cast(), buf.len())
    };
    assert!(n > 0 && n <= buf.len(), "{n}");
    let recorded = String::from_utf8(buf[..n].to_vec()).unwrap();
    assert_eq!(
        recorded,
        directive(Level::INFO, &[(Subsystem::P2p, Level::DEBUG)])
    );

    // Back to the defaults: `none` overrides, the startup base.
    apply(Level::WARN, &[]);
    assert!(!tracing::enabled!(target: "shekyl_dialer", Level::DEBUG));
    assert!(!tracing::enabled!(target: "daemon", Level::INFO));
}
