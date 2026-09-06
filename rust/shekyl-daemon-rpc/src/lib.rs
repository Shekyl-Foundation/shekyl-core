// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Rust daemon RPC server — Axum replacement for epee's HTTP server.
//!
//! Native methods live in [`methods`] over [`chain_facts`]. C++ still serves
//! the methods this crate has not taken (`core_rpc_server::on_*`); this crate
//! owns HTTP, dispatch, restricted-mode, and every method the KV cutover has
//! moved.

// This crate's `tracing::*` events reach the C++-installed subscriber
// because the daemon links exactly one Rust image
// (`rust/shekyl-daemon-image`, which combines this crate with
// `shekyl-ffi`'s logging surface into one archive with one
// `tracing-core` dispatcher). See V3_WALLET_DECISION_LOG.md
// (single-image contract, 2026-06-11 amendment).

pub mod bind;
pub mod chain_facts;

/// The consensus constants this crate reads, generated from the JSON
/// authority (`config/consensus_constants.json`) by `build.rs` — the same
/// source that emits the C++ `shekyl/consensus_constants_generated.h`
/// through `cmake/generate_consensus_constants.py`.
///
/// **At the crate root rather than under `submit`,** because the submit
/// engine is no longer the only reader: the daemon console renders block
/// statistics against `DAA_TARGET_SECONDS`, and a constant with a single
/// authority should not be reached through the module that happened to need
/// it first.
///
/// Nothing here comes off the wire. `/get_info` does report `target`, and a
/// console that read it would give one genesis-frozen constant two sources —
/// one of them a remote daemon that could report anything. Comparing the two
/// is a real check and belongs to the client-side version-and-constants
/// validation round; taking the remote value as the answer is not.
pub mod consensus {
    include!(concat!(env!("OUT_DIR"), "/consensus_constants.rs"));

    // Decision-14 sentinels, mirroring the static_asserts in
    // src/cryptonote_config.h: a JSON bump must be a reviewed consensus
    // change, not a silent parameter drift.
    const _: () = assert!(
        FCMP_REFERENCE_BLOCK_MIN_AGE == 5,
        "FCMP_REFERENCE_BLOCK_MIN_AGE diverged from Decision 14 baseline (5); \
         review consensus implications before updating the sentinel"
    );
    const _: () = assert!(
        FCMP_REFERENCE_BLOCK_MAX_AGE == 100,
        "FCMP_REFERENCE_BLOCK_MAX_AGE diverged from baseline (100); \
         review consensus implications before updating the sentinel"
    );
    const _: () = assert!(
        DAA_TARGET_SECONDS == 120,
        "DAA_TARGET_SECONDS diverged from the LWMA-1 ratified T (120); \
         review consensus implications before updating the sentinel"
    );
}

pub mod conn_limit;
pub mod console;
pub mod core;
pub mod ctl_client;
pub mod ffi;
pub mod ffi_exports;
pub mod handlers;
pub mod methods;
pub mod middleware;
pub mod server;
pub mod submit;
pub mod types;
