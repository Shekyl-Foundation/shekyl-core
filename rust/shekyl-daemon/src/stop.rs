// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one export the remnant calls: a stop request
//! (`DAEMON_CONFIG_CUTOVER.md` §2.2 step 9).
//!
//! The console's `exit` and the RPC's `stop_daemon` reach the one owner in
//! [`crate::signals`] through [`shekyl_daemon_request_stop`], so every
//! trigger runs the stop in step 9's order. The remnant never stops
//! itself. This file is a signature-gate surface; the `#[allow]` below is
//! this crate's one exception to its rule, on the one item the lint names.

/// Asks for a stop, from the remnant: the console's `exit` and the RPC's
/// `stop_daemon`. Returns at once; the stop runs in step 9's order from the
/// one owner. A request before the owner waits is kept for it; a second
/// request is a no-op.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn shekyl_daemon_request_stop() {
    crate::signals::request_stop();
}
