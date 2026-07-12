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

/// Global settlement-epoch boundary (`ARCHIVAL_TIMING_CONSTANTS.md` §1).
pub const SETTLEMENT_EPOCH_BLOCKS: u64 = 10_000;

/// Clamp a raw `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` override: absent,
/// unparsable, `< 2`, or `> SETTLEMENT_EPOCH_BLOCKS` → the genesis
/// default. Pure (no env read) so the clamp itself is testable env-free;
/// the env read happens exactly once, in
/// [`effective_settlement_epoch_blocks`].
///
/// Bounds rationale (rule 75): the lever exists only to *shorten* epochs
/// so a regtest chain reaches close boundaries in minutes — a value above
/// the genesis pin has no consumer and is rejected. The lower bound 2
/// keeps epochs non-degenerate: at 1, every height is a close boundary
/// and epoch 0 collapses to the genesis block, which no close/claim
/// timing pin was designed against. Invalid values fall back to the
/// default (never a partial application), mirroring the
/// `SEEDHASH_EPOCH_*` clamp discipline in `shekyl-pow-randomx`.
#[must_use]
pub fn clamp_settlement_epoch_blocks(raw: Option<&str>) -> u64 {
    match raw.map(str::trim).and_then(|s| s.parse::<u64>().ok()) {
        Some(v) if (2..=SETTLEMENT_EPOCH_BLOCKS).contains(&v) => v,
        _ => SETTLEMENT_EPOCH_BLOCKS,
    }
}

/// The effective settlement-epoch length: the genesis-pinned
/// [`SETTLEMENT_EPOCH_BLOCKS`], or the clamped
/// `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` env override — the fakechain-only
/// regtest lever that makes epoch-close e2e coverage affordable
/// (`EMISSION_CLAIM_BUILDER.md` §8 PR-4). Read once per process
/// (`OnceLock`), the same read-once semantics as the `SEEDHASH_EPOCH_*`
/// lever; consensus code must consume the schedule through this accessor
/// (or the schedule functions built on it), never the raw env.
///
/// The epoch schedule is consensus: the daemon refuses to start with the
/// override active on any non-FAKECHAIN network (`Blockchain::init`, next
/// to the seed-epoch gate), so a leaked environment cannot silently fork
/// a public node.
#[must_use]
pub fn effective_settlement_epoch_blocks() -> u64 {
    static EFFECTIVE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *EFFECTIVE.get_or_init(|| {
        clamp_settlement_epoch_blocks(
            std::env::var("SHEKYL_SETTLEMENT_EPOCH_BLOCKS")
                .ok()
                .as_deref(),
        )
    })
}

/// True iff the effective schedule differs from the genesis default
/// (i.e. a `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` override is active). Drives
/// the daemon's fail-closed startup gate and its loud fakechain warning.
#[must_use]
pub fn settlement_epoch_blocks_overridden() -> bool {
    effective_settlement_epoch_blocks() != SETTLEMENT_EPOCH_BLOCKS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The clamp accepts exactly the in-range values and falls back to
    /// the genesis default everywhere else — never a partial application.
    #[test]
    fn settlement_epoch_clamp() {
        assert_eq!(clamp_settlement_epoch_blocks(None), 10_000);
        assert_eq!(clamp_settlement_epoch_blocks(Some("50")), 50);
        assert_eq!(clamp_settlement_epoch_blocks(Some(" 200 ")), 200);
        assert_eq!(clamp_settlement_epoch_blocks(Some("2")), 2);
        assert_eq!(clamp_settlement_epoch_blocks(Some("10000")), 10_000);
        assert_eq!(clamp_settlement_epoch_blocks(Some("1")), 10_000);
        assert_eq!(clamp_settlement_epoch_blocks(Some("0")), 10_000);
        assert_eq!(clamp_settlement_epoch_blocks(Some("10001")), 10_000);
        assert_eq!(clamp_settlement_epoch_blocks(Some("-5")), 10_000);
        assert_eq!(clamp_settlement_epoch_blocks(Some("junk")), 10_000);
        assert_eq!(clamp_settlement_epoch_blocks(Some("")), 10_000);
    }
}
