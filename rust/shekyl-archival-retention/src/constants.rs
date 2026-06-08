// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Genesis-pinned timing and challenge counts from
//! [`ARCHIVAL_RETENTION_GATE2.md`](../../docs/design/ARCHIVAL_RETENTION_GATE2.md) §3.1
//! and [`ARCHIVAL_TIMING_CONSTANTS.md`](../../docs/design/ARCHIVAL_TIMING_CONSTANTS.md).

/// Guaranteed on-demand tests per `(P, shard, settlement_epoch)`.
pub const CHALLENGES_PER_EPOCH: u32 = 1;

/// Slash grace after `H_close` (settlement epoch end).
pub const CHALLENGE_RESOLUTION_BLOCKS: u64 = 10_000;

/// Blocks after `H_open` before the fire beacon input `block_hash(H_seal)` is fixed.
///
/// Genesis provisional pin: `1` (gate-2 §3.4 "TBD (≥ 1)"). Revisit at byte-pin pass.
pub const CHALLENGE_BEACON_SEAL_BLOCKS: u64 = 1;

/// Blocks after `H_fire` to accept serve-credit (must end before `H_close`).
///
/// Not yet byte-pinned in gate-2 §3.1; consensus wire lands with the vin serializer.
pub const CHALLENGE_RESPONSE_BLOCKS: Option<u64> = None;
