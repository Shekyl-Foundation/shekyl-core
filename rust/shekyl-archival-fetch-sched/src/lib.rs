// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Operator-fetch scheduler of `shekyl-p-fetch::fetch` (`ARCHIVAL_SHARD_FETCH.md` SF-D1).
//!
//! Linked only from `shekyl-daemon-image`. Every node is a full node and
//! every node prunes: shard bodies below the window live with stakers, or
//! temporarily here after a view-fetch. Holder draw + SOCKS are not a
//! production path yet; this entry returns MISS so the JSON-RPC maps a
//! typed "could not retrieve this archive". When those schedulers land,
//! this is the same `fetch()` entry with no caller tag (`SF-D7`), and a
//! local staker-hold / view-cache is still this function, not a C++ chain
//! walk.

use shekyl_p_fetch::MAX_INFLIGHT;

/// Re-export so the daemon image cannot drop the in-flight pin by accident.
pub const OPERATOR_FETCH_MAX_INFLIGHT: usize = MAX_INFLIGHT;

pub const SHEKYL_DAEMON_SHARD_FETCH_OK: u8 = 0;
pub const SHEKYL_DAEMON_SHARD_FETCH_MISS: u8 = 1;

/// Packed ruling-A aggregate. Field order is the ABI; keep in lockstep with
/// `ShekylArchivalShardAggregateOut` in `shekyl_daemon_fetch.h`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylArchivalShardAggregateOut {
    pub shard_id: u64,
    pub shard_hash: [u8; 32],
    pub block_count: u64,
    pub tx_count: u64,
    pub output_count: u64,
    pub coinbase_output_count: u64,
    pub time_range_seconds: u64,
}

/// Admit an operator view-fetch for `shard_id`. Typed miss until holder
/// draw / SOCKS (or a local hold) is production-wired. `out` is written
/// only on OK.
#[no_mangle]
pub extern "C" fn shekyl_daemon_operator_shard_fetch(
    _shard_id: u64,
    _out: *mut ShekylArchivalShardAggregateOut,
) -> u8 {
    let _ = OPERATOR_FETCH_MAX_INFLIGHT;
    SHEKYL_DAEMON_SHARD_FETCH_MISS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_fetch_is_typed_miss() {
        assert_eq!(
            shekyl_daemon_operator_shard_fetch(0, std::ptr::null_mut()),
            SHEKYL_DAEMON_SHARD_FETCH_MISS
        );
        assert_eq!(OPERATOR_FETCH_MAX_INFLIGHT, MAX_INFLIGHT);
    }
}
