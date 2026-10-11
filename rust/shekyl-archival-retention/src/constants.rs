// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Genesis-pinned timing and challenge counts from
//! [`ARCHIVAL_RETENTION_GATE2.md`](../../docs/design/ARCHIVAL_RETENTION_GATE2.md) §3.1
//! and [`ARCHIVAL_TIMING_CONSTANTS.md`](../../docs/design/ARCHIVAL_TIMING_CONSTANTS.md).

/// λ_target — derived challenges issued per `(P, shard)` pair per settlement
/// epoch. Ruled `3` by the 2-of-3 nesting
/// (`ARCHIVAL_CHALLENGE_MECHANISM.md` §3): the inner majority settles one
/// epoch's serve-credit bit, and §3 carries its derivation (liar containment
/// `3f²(1−f)+f³`, honest survival `a²(3−2a)`, the unanimity rejection, and the
/// free-rider deterrent `n·I − S`).
///
/// **Per *pair*, not per block.** The public urn that spread `λ·D` draws
/// across an epoch is deleted. This constant remains the number of draws
/// settlement counts for one pair. It is not a parameter a caller supplies.
///
/// Jointly pinned with settlement's
/// [`COUNTED_DRAWS`](shekyl_types::archival::COUNTED_DRAWS): the assert
/// below keeps them one number. The threshold's own two
/// properties — reachable, and a strict majority — are asserted beside it
/// in `shekyl_types::archival`. Re-pinning requires re-running §3's
/// derivation, the `(m, n)` window re-pin, and the economics-sim arithmetic
/// that scales with it.
pub const CHALLENGES_PER_PAIR_PER_EPOCH: u32 = 3;

const _: () = assert!(
    CHALLENGES_PER_PAIR_PER_EPOCH as usize == shekyl_types::archival::COUNTED_DRAWS,
    "the per-pair challenge count and the draws settlement counts are one decision"
);

/// `k` — the slash grace after `H_close`, **in settlement epochs**: the
/// slash fold for epoch `E` runs at the first block strictly above
/// `H_slash_deadline(E) = last_block(E) + k·SEB = last_block(E + k)`
/// ([`crate::SettlementSchedule::slash_deadline_height`]; `failure_window.rs`
/// carries the connect-order coupling and the `k ≥ 1` floor const-assert).
///
/// **Ratified `1` (DRS-E4, 2026-09-30): a persona gets one full settlement
/// epoch after close to land one transaction.** That is what makes the slash
/// tolerant by design — the Gate-6 round corrected a knife-edge assumption
/// against exactly this — and it was the meaning on record from the start:
/// Gate-6 read the grace as *"a full settlement epoch"*, and the free-rider
/// round read the deadline guard as *"a full epoch of settling after
/// close"*. Two independent readings, months apart, both describing it as
/// one epoch rather than as a number that happened to equal one.
///
/// What this replaces: `CHALLENGE_RESOLUTION_BLOCKS = 10_000`, a
/// block-denominated pin equal to `SETTLEMENT_EPOCH_BLOCKS` by coincidence
/// (two independent numbers, one of which a re-pin could move alone) and —
/// the live defect — **not** carried by the Fakechain schedule lever: under
/// `SEB = 100` the grace stayed ten thousand blocks, a hundred epochs, so
/// every slash the regtest regime reached was reached under a relationship
/// production never has. Written as the multiple, the relationship is
/// structural and only the factor is open; a Stage-2 sweep that wants the
/// ratio other than `1×` edits this constant and nothing else.
///
/// The binding constraint under derived assignment is against the response
/// window: a challenge issued at the epoch's **last** block must be
/// resolvable before the fold reads the epoch, so `grace ≥ W₂` wherever
/// the schedule has a window. Both are drawn from the same epoch on
/// [`crate::SettlementSchedule`]. A window is a positive count: an epoch
/// shorter than [`W2_EPOCH_DIVISOR`] has no W₂, and the inequality is not
/// asked of it. On the production pin the coupling is
/// `SLASH_GRACE_EPOCHS · SETTLEMENT_EPOCH_BLOCKS ≥ CHALLENGE_RESPONSE_BLOCKS`.
pub const SLASH_GRACE_EPOCHS: u64 = 1;

/// Blocks after `H_open` before the fire beacon input `block_hash(H_seal)` is fixed.
///
/// **Retired-mechanism constant.** The fire-beacon challenge shape
/// (`H_seal`/`H_fire`, gate-2 §3.4) is superseded by derived assignment
/// (`ARCHIVAL_CHALLENGE_MECHANISM.md` §2: `assignment(h)` seeds from
/// `block_hash(h−1)`, no seal lag). This constant still feeds the **live
/// interim serve-credit gate** (`challenge.rs` → `shekyl-ffi` →
/// `blockchain.cpp`/`db_lmdb.cpp`), which keeps admitting the interim wire
/// until the format round freezes the replacement response wire — it
/// deletes with that round's deletion surface, not before, because today it
/// is the only admission path standing.
pub const CHALLENGE_BEACON_SEAL_BLOCKS: u64 = 1;

/// W₂ — blocks after a challenge's issuing block to accept its serve-credit
/// response. **Pinned at one twentieth of a settlement epoch
/// ([`W2_EPOCH_DIVISOR`]) — 500 blocks, ≈16.7 h.** This constant is that
/// fraction evaluated on the genesis schedule
/// ([`crate::SettlementSchedule::challenge_response_blocks`] on
/// `GENESIS`); the computation lives on the schedule so W₂ and the slash
/// grace are drawn from one epoch (see [`SLASH_GRACE_EPOCHS`]). The band
/// asserts below defend the ruling at this value.
///
/// # The ruling that makes a number pinnable: W₂ has no surviving upper bound
///
/// This was treated as a two-sided optimization for as long as it kept
/// circling, and it stopped being one without anyone noticing. Every argument
/// against a generous W₂ was **clock-burn** — a witness commits to a challenge,
/// sits on it, and burns the pair's slot for W₂ blocks. That attack needed two
/// things that no longer exist: a commitment record (superseded by derived
/// assignment) and an abandonment penalty (killed by the impossibility result;
/// §6 now keeps its sizing arithmetic "as the record of what a penalty would
/// have had to achieve, **not as pending work**"). Under derived assignment
/// **there is no occupancy to extend**: the witness is the producer of block
/// `h`, and if it does nothing, nothing is held. A witness that sits on its
/// assignment wastes exactly one of the pair's three draws whether W₂ is 500
/// blocks or 5,000 — clock-burn is a *draw-count* attack, not a *duration*
/// one, and it is contained by the 2-of-3 quadratic plus the outer `(m, n)`
/// window rather than by keeping this number small.
///
/// The remaining upper-bound candidates are all slack. Settlement bookkeeping:
/// the slash grace ([`SLASH_GRACE_EPOCHS`]) is already a full epoch, and
/// `E` stays explicit in the record precisely so a response window may cross
/// the boundary. Outstanding-challenge count: bookkeeping, no consensus cost.
/// `P`'s availability burden: unchanged — `P` is continuously obligated either
/// way. DDoS: longer is a **defense**, since the attacker must suppress the
/// whole window (§6 already lists long-W₂ as a mitigation, not a cost).
///
/// One further candidate, raised and rejected: **outsourcing resistance** — a
/// generous window lets a persona that does not store a shard fetch it on
/// demand and answer, making this prove retrievability rather than retention.
/// It fails three ways, and the third is decisive. The economics invert it
/// (λ·3 challenges across up to `MAX_HOLDINGS_SHARDS` is far more fetched
/// bandwidth per epoch than the bytes cost to store once). Half of it is not an
/// attack (a persona backed by a full node the same operator runs still means
/// the operator retains the corpus). And a short W₂ **does not prevent it**:
/// the cheapest outsourcing is a local or LAN fetch that completes in seconds,
/// so shortening this buys almost none of the property while charging honest
/// archivers real slash risk.
///
/// # Asymmetric with slack on one side means pick generous, not optimal
///
/// The lower bound is hard: too short and honest archivers miss on transfer
/// time they do not control, which slashes capital. The upper bound is absent.
/// So this is a fraction of [`SETTLEMENT_EPOCH_BLOCKS`] rather than a tight
/// quantile, written as a fraction so it tracks if the epoch is ever re-pinned.
/// `SEB/20` is a choice within a defensible band (roughly 200–500 on the same
/// reasoning); the **band is the ruled part, the integer is a consequence**. A
/// reader who disagrees with 500 should re-check the argument above, not
/// re-litigate the divisor.
///
/// # No measurement is owed, and that is a ruling about *this* parameter
///
/// Sanity, so the number is not blind: ~97 pairs per block at maturity means
/// the assigned producer fetches ~323 MB. That producer is a **miner** — this
/// is the fetch side, not the serving side, and the two do not share a floor —
/// so the reference machine is a mining box, at plausible Tor rendezvous
/// throughput minutes of work with a heavy tail to perhaps an hour. 500 blocks
/// is ≈16.7 h: two orders of margin, which is what you want when the tail is
/// unmeasured and the failure mode is someone's bond.
///
/// Sixteen hours against a transfer that takes minutes is not a value that
/// needs *finding*; it is a value that needs to be **large enough**, and the
/// asymmetry above already guarantees 500 is. Derive-don't-hardcode earns its
/// keep where a number sits between two competing pressures and being wrong in
/// either direction costs something. Here the pressure is one-sided, so a
/// derivation would confirm what the asymmetry settles and nothing more. This
/// parameter is **ruled, not provisional**; it is not awaiting a floor check,
/// and a comment claiming otherwise is what kept the question circling.
///
/// **Reopen (rule 21):** a *premise* of the ruling returns — clock-burn
/// regains both a commitment record and an abandonment penalty, restoring an
/// upper bound where none survives; or [`SETTLEMENT_EPOCH_BLOCKS`] is re-pinned
/// and carries this out of its band (the const-assert below arms on exactly
/// that). Raising W₂ then means **widening the band deliberately**, re-running
/// the ruling rather than editing past the assert.
///
/// **What is not a reopening trigger:** whether a rule-76 Pi-4 can serve ~97
/// concurrent rendezvous circuits. That reads like a W₂ question, is not one,
/// and on inspection is not a question at all: `λ·D/E` ≈ 97 is *draws per block
/// assigned to that block's producer*, a producer is a miner, and nobody mines
/// on a Pi 4. A serving persona sees a handful of concurrent readers once those
/// draws spread across the pair population — a load
/// `docs/design/SP_T3_SKELETON_MEASUREMENT.md` §18 already measured with margin
/// (4→32 readers, p50 10.9 s → 14.8 s). The `docs/FOLLOWUPS.md` entry that
/// briefly held it is closed. Attaching it here is what dragged W₂ back open
/// twice; re-attaching it under a new name would do it a third time.
///
/// **Not a reopening either (2026-09-30):** moving the *computation* onto
/// [`crate::SettlementSchedule`] so a levered epoch yields its own W₂. The
/// band stays `1/20`, ratified; what moved is which epoch the fraction is
/// taken of. **UPDATE 2026-10-01:** an epoch shorter than the divisor has
/// no window (`None`). The coupling `grace ≥ W₂` is asked only where a
/// window exists; zero is not a window.
pub const CHALLENGE_RESPONSE_BLOCKS: u64 =
    match crate::SettlementSchedule::GENESIS.challenge_response_blocks() {
        Some(window) => window.get(),
        None => {
            panic!("genesis settlement epoch does not cover a challenge-response window")
        }
    };

/// Fraction of a settlement epoch W₂ occupies: `SEB / 20`.
///
/// Named rather than inline so a re-pin is a visible edit to a documented
/// quantity instead of a digit change inside an expression.
pub const W2_EPOCH_DIVISOR: u64 = 20;

/// Lower and upper edge of the band the W₂ ruling defends.
///
/// The ruling is "asymmetric with slack on one side ⇒ pick generous, not
/// optimal", and it holds anywhere in roughly 200–500 blocks. **The band is
/// the ruled part; the divisor is a consequence** — so these are what the
/// const-asserts below defend, not the divisor.
pub const W2_MIN_DEFENSIBLE_BLOCKS: u64 = 200;
/// Upper edge of the W₂ band — see [`W2_MIN_DEFENSIBLE_BLOCKS`].
pub const W2_MAX_DEFENSIBLE_BLOCKS: u64 = 500;

// Keep the doc's "one twentieth of a settlement epoch" literally true. Integer
// division would silently truncate if `SETTLEMENT_EPOCH_BLOCKS` were ever
// re-pinned to a non-multiple, leaving the prose claiming a fraction the value
// is not. Compile-time, so a re-pin cannot land it quietly.
const _: () = assert!(
    SETTLEMENT_EPOCH_BLOCKS.is_multiple_of(W2_EPOCH_DIVISOR),
    "SETTLEMENT_EPOCH_BLOCKS is not a multiple of W2_EPOCH_DIVISOR: CHALLENGE_RESPONSE_BLOCKS \
     would truncate and no longer be the fraction of an epoch its doc claims; re-pin the \
     divisor deliberately rather than inheriting a rounded value"
);

// The one that defends the *ruling* rather than the arithmetic. Divisibility
// keeps the prose true; this keeps the value inside the band the ruling was
// made over. A re-pin of `SETTLEMENT_EPOCH_BLOCKS` alone would otherwise carry
// W₂ out of that band while every claim about it still read as current —
// `SEB = 100_000` divides evenly and yields 5_000, which no part of the ruling
// covers.
const _: () = assert!(
    CHALLENGE_RESPONSE_BLOCKS >= W2_MIN_DEFENSIBLE_BLOCKS
        && CHALLENGE_RESPONSE_BLOCKS <= W2_MAX_DEFENSIBLE_BLOCKS,
    "CHALLENGE_RESPONSE_BLOCKS is outside the band the W2 ruling was made over; a change \
     to SETTLEMENT_EPOCH_BLOCKS has carried W2 with it. Re-run the ruling (no surviving \
     upper bound; hard lower bound) before widening the band"
);

// The slash fold for epoch E must not run before the response window of E's
// last-issued challenge closes, or in-flight responses read as misses. The fold
// runs strictly above the deadline (`failure_window.rs`), so `>=` is exact.
// This is the production pin: grace `k · SEB` against the genesis window.
// A schedule whose epoch is shorter than `W2_EPOCH_DIVISOR` has no window
// (`challenge_response_blocks` is `None`); that case is the lever test.
// `k · divisor ≥ 1` stays true while the division yields 0, so it does not
// say the window exists.
const _: () = assert!(
    SLASH_GRACE_EPOCHS * SETTLEMENT_EPOCH_BLOCKS >= CHALLENGE_RESPONSE_BLOCKS,
    "the production slash grace (k * SEB) is shorter than the genesis \
     challenge-response window, so the fold for an epoch would run before \
     the response window of its last-issued challenge closes"
);

/// Global settlement-epoch boundary (`ARCHIVAL_TIMING_CONSTANTS.md` §1).
pub const SETTLEMENT_EPOCH_BLOCKS: u64 = 10_000;

use crate::bond_floor::ARCHIVAL_REORG_DEPTH_BLOCKS;

/// The reorg-cap floor a settlement-epoch override must clear: the epoch
/// is strictly above the cap (`SEB > D_max` — `shekyl_chain_rules::reorg`
/// const-asserts it on the production pair; this is the same inequality on
/// a regtest pair), and never below `2` (at `1` every height is a close
/// boundary and epoch 0 collapses to the genesis block, which no
/// close/claim timing pin was designed against).
#[must_use]
pub const fn settlement_epoch_override_floor(reorg_cap: u64) -> u64 {
    let above_cap = reorg_cap.saturating_add(1);
    if above_cap > 2 {
        above_cap
    } else {
        2
    }
}

/// Why a raw regtest schedule lever (`SHEKYL_SETTLEMENT_EPOCH_BLOCKS`,
/// `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS`) or an arming attempt was refused.
/// Every arm is a loud, operator-actionable startup state, never a silent
/// fall-back (rule 82).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettlementEpochOverrideError {
    /// `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` is set but is not an integer in
    /// `floor..=SETTLEMENT_EPOCH_BLOCKS`, `floor` being
    /// [`settlement_epoch_override_floor`] of the reorg cap in force. A
    /// typo'd lever must abort the regtest run it was meant to shorten —
    /// silently running the mainnet schedule instead would only surface as
    /// an unexplained harness timeout — and an epoch at or below the cap is
    /// a configuration mainnet cannot reach (every body inside a legal
    /// reorg reaped; `ARCHIVAL_PRUNED_DAEMON_MODE.md` Q2): refused, with
    /// the floor named so the operator lowers the cap lever with the epoch.
    #[error(
        "SHEKYL_SETTLEMENT_EPOCH_BLOCKS={raw:?} is not a valid override: expected an \
         integer in {floor}..={max} (strictly above the reorg cap of {reorg_cap}; lower \
         SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS with the epoch); fix the value or unset the variable",
        max = SETTLEMENT_EPOCH_BLOCKS
    )]
    Invalid {
        /// The rejected raw value, named so the refusal is diagnosable.
        raw: String,
        /// The lowest epoch the cap in force admits.
        floor: u64,
        /// The reorg cap in force when the epoch was parsed.
        reorg_cap: u64,
    },
    /// `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS` is set but is not an integer in
    /// `1..=ARCHIVAL_REORG_DEPTH_BLOCKS`. The lever exists only to *shorten*
    /// the cap so a shortened epoch stays above it; a cap above the genesis
    /// pin has no consumer, and a cap of `0` would follow no reorg at all.
    #[error(
        "SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS={raw:?} is not a valid override: expected an \
         integer in 1..={max}; fix the value or unset the variable",
        max = ARCHIVAL_REORG_DEPTH_BLOCKS
    )]
    InvalidReorgCap {
        /// The rejected raw value.
        raw: String,
    },
    /// Arming happened after some code path already read (and latched) the
    /// schedule in unarmed mode — an initialization-order bug in the arming
    /// process, surfaced loudly instead of running split-schedule arithmetic.
    #[error(
        "settlement-epoch override armed after the schedule already latched at {latched} \
         blocks; arm at process startup, before any epoch arithmetic"
    )]
    ArmedTooLate {
        /// The schedule value the process had already latched.
        latched: u64,
    },
}

/// Parse a raw `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` override against the reorg
/// cap in force: absent → `None`; a valid integer in
/// `settlement_epoch_override_floor(reorg_cap)..=SETTLEMENT_EPOCH_BLOCKS` →
/// `Some(v)`; anything else → a typed refusal. Pure (no env read) so the
/// validation is testable env-free; the env read happens exactly once,
/// behind [`effective_settlement_epoch_blocks`] /
/// [`arm_settlement_epoch_override_for_regtest`].
///
/// Bounds rationale (rule 75): the lever exists only to *shorten* epochs
/// so a regtest chain reaches close boundaries in minutes — a value above
/// the genesis pin has no consumer and is rejected. The lower bound is the
/// cap's: `SEB > D_max` is an invariant of every valid configuration on
/// every nettype (`ARCHIVAL_PRUNED_DAEMON_MODE.md` Q2, rule 71), so a
/// regtest that shortens the epoch below the production cap lowers the
/// cap lever with it — the Fakechain rule set the daemon runs names that
/// cap (`shekyl_chain_rules::RuleSet::fakechain`).
pub fn parse_settlement_epoch_override(
    raw: Option<&str>,
    reorg_cap: u64,
) -> Result<Option<u64>, SettlementEpochOverrideError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let floor = settlement_epoch_override_floor(reorg_cap);
    match raw.trim().parse::<u64>() {
        Ok(v) if (floor..=SETTLEMENT_EPOCH_BLOCKS).contains(&v) => Ok(Some(v)),
        _ => Err(SettlementEpochOverrideError::Invalid {
            raw: raw.to_string(),
            floor,
            reorg_cap,
        }),
    }
}

/// Parse a raw `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS` override: absent →
/// `None`; a valid integer in `1..=ARCHIVAL_REORG_DEPTH_BLOCKS` → `Some(v)`;
/// anything else → a typed refusal. Pure, like its sibling.
pub fn parse_reorg_cap_override(
    raw: Option<&str>,
) -> Result<Option<u64>, SettlementEpochOverrideError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    match raw.trim().parse::<u64>() {
        Ok(v) if (1..=ARCHIVAL_REORG_DEPTH_BLOCKS).contains(&v) => Ok(Some(v)),
        _ => Err(SettlementEpochOverrideError::InvalidReorgCap {
            raw: raw.to_string(),
        }),
    }
}

/// The process-latched effective schedule: the epoch and reorg-cap values
/// plus how they were established, so the wallet-side warning surface can
/// name an ignored override without re-reading the environment.
struct EffectiveSchedule {
    blocks: u64,
    reorg_cap: u64,
    /// A lever was set but this process never armed — the override was
    /// deliberately ignored (the leaked-environment posture).
    ignored_override: bool,
}

static EFFECTIVE: std::sync::OnceLock<EffectiveSchedule> = std::sync::OnceLock::new();

fn raw_override() -> Option<String> {
    std::env::var("SHEKYL_SETTLEMENT_EPOCH_BLOCKS").ok()
}

fn raw_reorg_cap_override() -> Option<String> {
    std::env::var("SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS").ok()
}

fn latch_unarmed() -> &'static EffectiveSchedule {
    EFFECTIVE.get_or_init(|| EffectiveSchedule {
        blocks: SETTLEMENT_EPOCH_BLOCKS,
        reorg_cap: ARCHIVAL_REORG_DEPTH_BLOCKS,
        ignored_override: raw_override().is_some() || raw_reorg_cap_override().is_some(),
    })
}

/// The effective settlement-epoch length: the genesis-pinned
/// [`SETTLEMENT_EPOCH_BLOCKS`], or — **only in a process that explicitly
/// armed via [`arm_settlement_epoch_override_for_regtest`]** — the validated
/// `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` env override, the fakechain-only regtest
/// lever that makes epoch-close e2e coverage affordable
/// (`EMISSION_CLAIM_BUILDER.md` §8 PR-4). Read once per process
/// (`OnceLock`), the same read-once semantics as the `SEEDHASH_EPOCH_*`
/// lever; consensus code must consume the schedule through this accessor
/// (or the schedule functions built on it), never the raw env.
///
/// The epoch schedule is consensus, and arming is the enforced invariant
/// (not caller discipline): an **unarmed** process — every wallet process
/// today, and any daemon on a public network — computes the genesis
/// schedule no matter what the environment says, so a leaked
/// `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` (shared systemd template, container
/// base layer) cannot silently mis-epoch wallet state or fork a public
/// node. The daemon arms only on FAKECHAIN, behind its own fail-closed
/// startup gate (`Blockchain::init`, next to the seed-epoch gate);
/// unarmed consumers surface the ignored lever via
/// [`settlement_epoch_override_ignored`].
#[must_use]
pub fn effective_settlement_epoch_blocks() -> u64 {
    latch_unarmed().blocks
}

/// The effective reorg cap: the genesis-pinned
/// [`ARCHIVAL_REORG_DEPTH_BLOCKS`] (`D_max`, `PDM-Q11`), or — only in a
/// process that armed — the validated `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS`
/// override. **This is the cap the daemon's Fakechain rule set names**
/// (`shekyl_chain_rules::RuleSet::fakechain(fixed, schedule)`, the
/// schedule a `FakechainSchedule` pair of this and
/// [`effective_settlement_epoch_blocks`], DRS-E4 `ARW-15`): the rule set
/// is the consensus home of the cap and the store's undo retention is
/// constrained by it (S-CHAIN-W SCW-7); this accessor is where a levered
/// daemon reads the value it hands that constructor. Same read-once,
/// armed-only semantics as [`effective_settlement_epoch_blocks`].
#[must_use]
pub fn effective_archival_reorg_depth_blocks() -> u64 {
    latch_unarmed().reorg_cap
}

/// Arm the regtest schedule levers — `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` and
/// `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS` — for a **regtest context**: the
/// daemon's FAKECHAIN startup path, or a wallet-side regtest harness whose
/// epoch arithmetic must match a short-epoch regtest daemon. Must run at
/// process startup, before any epoch arithmetic: arming after the schedule
/// latched is a typed refusal ([`SettlementEpochOverrideError::ArmedTooLate`]),
/// as is an invalid value ([`SettlementEpochOverrideError::Invalid`],
/// [`SettlementEpochOverrideError::InvalidReorgCap`]) — never a silent
/// fall-back to the genesis schedule. The cap is parsed first and the epoch
/// is parsed against it, so `SEB ≤ cap` is refused here at the ruled site
/// (`ARCHIVAL_PRUNED_DAEMON_MODE.md` Q2 item 5); the store's open-time
/// refusal beneath it is a belt. Idempotent when re-armed to the same
/// effective pair. Returns the effective epoch length.
pub fn arm_settlement_epoch_override_for_regtest() -> Result<u64, SettlementEpochOverrideError> {
    let reorg_cap = parse_reorg_cap_override(raw_reorg_cap_override().as_deref())?
        .unwrap_or(ARCHIVAL_REORG_DEPTH_BLOCKS);
    let target = parse_settlement_epoch_override(raw_override().as_deref(), reorg_cap)?
        .unwrap_or(SETTLEMENT_EPOCH_BLOCKS);
    let latched = EFFECTIVE.get_or_init(|| EffectiveSchedule {
        blocks: target,
        reorg_cap,
        ignored_override: false,
    });
    if latched.blocks != target || latched.reorg_cap != reorg_cap {
        return Err(SettlementEpochOverrideError::ArmedTooLate {
            latched: latched.blocks,
        });
    }
    Ok(latched.blocks)
}

/// True iff a regtest schedule lever is set but this process never armed —
/// the override is being deliberately ignored. Unarmed consumers (the
/// wallet's stake-engine spawn) surface this loudly once so the
/// leaked-environment case is diagnosable instead of silent.
#[must_use]
pub fn settlement_epoch_override_ignored() -> bool {
    latch_unarmed().ignored_override
}

/// True iff `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` or
/// `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS` is present in this process's
/// environment at all (no validation, no latching). Drives the daemon's
/// public-network refusal: on a non-FAKECHAIN net the *presence* of a
/// lever is the operator error to surface, before any question of validity.
#[must_use]
pub fn settlement_epoch_override_present() -> bool {
    raw_override().is_some() || raw_reorg_cap_override().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parse accepts exactly the in-range values, treats absence as
    /// "no override", and refuses everything else with the rejected raw
    /// value named — never a silent fall-back.
    #[test]
    fn settlement_epoch_override_parse() {
        // Under the production cap the floor is 721: the ruled site of the
        // `SEB ≤ D_max` refusal (Q2 item 5).
        let cap = ARCHIVAL_REORG_DEPTH_BLOCKS;
        assert_eq!(settlement_epoch_override_floor(cap), 721);
        assert_eq!(parse_settlement_epoch_override(None, cap), Ok(None));
        assert_eq!(
            parse_settlement_epoch_override(Some("721"), cap),
            Ok(Some(721))
        );
        assert_eq!(
            parse_settlement_epoch_override(Some(" 5000 "), cap),
            Ok(Some(5000))
        );
        assert_eq!(
            parse_settlement_epoch_override(Some("10000"), cap),
            Ok(Some(10_000))
        );
        for bad in ["720", "512", "2", "1", "0", "10001", "-5", "junk", ""] {
            assert_eq!(
                parse_settlement_epoch_override(Some(bad), cap),
                Err(SettlementEpochOverrideError::Invalid {
                    raw: bad.to_string(),
                    floor: 721,
                    reorg_cap: cap,
                }),
                "{bad:?} must refuse with the raw value and the floor named"
            );
        }
        // A lowered cap lowers the floor with it, never below 2.
        assert_eq!(settlement_epoch_override_floor(1), 2);
        assert_eq!(settlement_epoch_override_floor(0), 2);
        assert_eq!(settlement_epoch_override_floor(50), 51);
        assert_eq!(parse_settlement_epoch_override(Some("2"), 1), Ok(Some(2)));
        assert_eq!(
            parse_settlement_epoch_override(Some("512"), 64),
            Ok(Some(512))
        );
        assert_eq!(
            parse_settlement_epoch_override(Some("50"), 50),
            Err(SettlementEpochOverrideError::Invalid {
                raw: "50".to_string(),
                floor: 51,
                reorg_cap: 50,
            }),
            "the epoch is strictly above the cap"
        );
    }

    #[test]
    fn reorg_cap_override_parse() {
        assert_eq!(parse_reorg_cap_override(None), Ok(None));
        assert_eq!(parse_reorg_cap_override(Some("1")), Ok(Some(1)));
        assert_eq!(parse_reorg_cap_override(Some(" 64 ")), Ok(Some(64)));
        assert_eq!(parse_reorg_cap_override(Some("720")), Ok(Some(720)));
        for bad in ["0", "721", "-1", "junk", ""] {
            assert_eq!(
                parse_reorg_cap_override(Some(bad)),
                Err(SettlementEpochOverrideError::InvalidReorgCap {
                    raw: bad.to_string()
                }),
                "{bad:?} must refuse with the raw value named"
            );
        }
    }

    /// This test binary never arms and never sets the lever, so the latched
    /// schedule is the genesis pin, nothing reads as overridden or ignored,
    /// and post-latch arming to the same value stays idempotent. (The armed
    /// and armed-too-late paths are process-global one-shots — they are
    /// exercised by the regtest harness processes that actually arm.)
    #[test]
    fn unarmed_process_latches_the_genesis_schedule() {
        assert_eq!(effective_settlement_epoch_blocks(), SETTLEMENT_EPOCH_BLOCKS);
        assert_eq!(
            effective_archival_reorg_depth_blocks(),
            ARCHIVAL_REORG_DEPTH_BLOCKS
        );
        assert!(!settlement_epoch_override_ignored());
        assert_eq!(
            arm_settlement_epoch_override_for_regtest(),
            Ok(SETTLEMENT_EPOCH_BLOCKS),
            "re-arming to the already-latched value is idempotent"
        );
    }
}
