// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `daemon_status`, as the console reads it.
//!
//! `daemon status`, `chain stats`, `chain alt`, `chain difficulty`,
//! `version` and `txpool stats` read this method. A renamed or removed
//! member is a decode error naming it, never a confident zero, because the
//! shared type defaults nothing; a part the caller is not shown is absent,
//! never zero (RK-D23).

use shekyl_rpc_client::wire;
use shekyl_rpc_types::kinds::NoParams;
use shekyl_rpc_types::wire::daemon::DaemonStatus;

use crate::daemon::DaemonClient;

/// The daemon's state, after the handshake.
pub(super) fn fetch_status(daemon: &DaemonClient) -> Result<DaemonStatus, String> {
    super::call::<wire::DaemonStatus>(daemon, &NoParams)
}

/// The chain's block count: the tip's height plus one. The console words
/// that print a "height" have always printed this count.
pub(super) const fn chain_count(status: &DaemonStatus) -> u64 {
    status.height.0.saturating_add(1)
}

pub(super) const fn network_label(nettype: shekyl_rpc_types::Network) -> &'static str {
    nettype.name()
}
