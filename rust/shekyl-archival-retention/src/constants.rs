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
/// **Per *pair*, not per block.** The urn issues `λ·D/E` draws in each block
/// (`D` = drawable pairs, `E` = `SETTLEMENT_EPOCH_BLOCKS`); that per-block
/// count is *derived* by [`crate::challenge_assignment`], never pinned. This
/// constant is the coverage target the urn is given.
///
/// Jointly pinned with [`crate::SERVE_THRESHOLD_PASSES`] — 2-of-3 is one
/// decision, and `attestation.rs` const-asserts the two properties that make
/// it one: the threshold must be reachable, and it must be a strict majority.
/// Re-pinning either requires re-running §3's derivation, the `(m, n)` window
/// re-pin, and the economics-sim arithmetic that scales with it.
pub const CHALLENGES_PER_PAIR_PER_EPOCH: u32 = 3;

/// Slash grace after `H_close` (settlement epoch end): the slash fold for
/// epoch `E` runs at the first block strictly above
/// `H_slash_deadline(E) = (E+1)·SEB − 1 + CHALLENGE_RESOLUTION_BLOCKS`
/// (`failure_window.rs` carries the connect-order coupling and the `≥ 1`
/// floor const-assert).
///
/// Pinned (one full epoch) under the retired fire-to-close challenge shape.
/// Under derived assignment the binding constraint is against the response
/// window: a challenge issued at the epoch's **last** block, `(E+1)·SEB − 1`,
/// must be resolvable before the slash fold reads the epoch, so the resolution
/// grace must satisfy `CHALLENGE_RESOLUTION_BLOCKS ≥ W₂` — enforced by the
/// const-assert below, which reads [`CHALLENGE_RESPONSE_BLOCKS`] directly now
/// that W₂ is a pinned `u64` rather than an unfilled `Option`. One epoch
/// dominates W₂'s ruled band by a factor of twenty, so the coupling has
/// slack; re-derive it alongside any W₂ re-pin, not on any other schedule.
pub const CHALLENGE_RESOLUTION_BLOCKS: u64 = 10_000;

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
/// ([`W2_EPOCH_DIVISOR`]) — 500 blocks, ≈16.7 h.**
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
/// [`CHALLENGE_RESOLUTION_BLOCKS`] already grants a full epoch of grace, and
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
/// the assigned producer fetches ~323 MB; at plausible Tor rendezvous
/// throughput on a floor device that is minutes, with a heavy tail to perhaps
/// an hour. 500 blocks is ≈16.7 h — two orders of margin, which is what you
/// want when the tail is unmeasured and the failure mode is someone's bond.
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
/// concurrent rendezvous circuits at all. That reads like a W₂ question and is
/// not one — it is a *device-requirement* question, and it has a different
/// answer if it fails (re-open the floor, or bound what a floor device is asked
/// to serve), none of which is a number for this window. It is filed on its own
/// in `docs/FOLLOWUPS.md`; attaching it here is what dragged W₂ back open twice.
pub const CHALLENGE_RESPONSE_BLOCKS: u64 = SETTLEMENT_EPOCH_BLOCKS / W2_EPOCH_DIVISOR;

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
const _: () = assert!(
    CHALLENGE_RESOLUTION_BLOCKS >= CHALLENGE_RESPONSE_BLOCKS,
    "CHALLENGE_RESOLUTION_BLOCKS < CHALLENGE_RESPONSE_BLOCKS (W2): the slash fold \
     for an epoch would run before the response window of its last-issued \
     challenge closes, reading in-flight responses as misses; re-derive the \
     resolution grace alongside any W2 re-pin"
);

/// Global settlement-epoch boundary (`ARCHIVAL_TIMING_CONSTANTS.md` §1).
pub const SETTLEMENT_EPOCH_BLOCKS: u64 = 10_000;

/// Why a raw `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` value or an arming attempt
/// was refused. Both arms are loud, operator-actionable startup states,
/// never silent fall-backs (rule 82).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettlementEpochOverrideError {
    /// The variable is set but is not an integer in
    /// `2..=SETTLEMENT_EPOCH_BLOCKS`. A typo'd lever must abort the regtest
    /// run it was meant to shorten — silently running the mainnet schedule
    /// instead would only surface as an unexplained harness timeout.
    #[error(
        "SHEKYL_SETTLEMENT_EPOCH_BLOCKS={raw:?} is not a valid override: expected an \
         integer in 2..={max}; fix the value or unset the variable",
        max = SETTLEMENT_EPOCH_BLOCKS
    )]
    Invalid {
        /// The rejected raw value, named so the refusal is diagnosable.
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

/// Parse a raw `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` override: absent → `None`;
/// a valid in-range integer → `Some(v)`; anything else → a typed refusal.
/// Pure (no env read) so the validation is testable env-free; the env read
/// happens exactly once, behind [`effective_settlement_epoch_blocks`] /
/// [`arm_settlement_epoch_override_for_regtest`].
///
/// Bounds rationale (rule 75): the lever exists only to *shorten* epochs
/// so a regtest chain reaches close boundaries in minutes — a value above
/// the genesis pin has no consumer and is rejected. The lower bound 2
/// keeps epochs non-degenerate: at 1, every height is a close boundary
/// and epoch 0 collapses to the genesis block, which no close/claim
/// timing pin was designed against.
pub fn parse_settlement_epoch_override(
    raw: Option<&str>,
) -> Result<Option<u64>, SettlementEpochOverrideError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    match raw.trim().parse::<u64>() {
        Ok(v) if (2..=SETTLEMENT_EPOCH_BLOCKS).contains(&v) => Ok(Some(v)),
        _ => Err(SettlementEpochOverrideError::Invalid {
            raw: raw.to_string(),
        }),
    }
}

/// The process-latched effective schedule: the blocks value plus how it was
/// established, so the wallet-side warning surface can name an ignored
/// override without re-reading the environment.
struct EffectiveSchedule {
    blocks: u64,
    /// The env var was set but this process never armed — the override was
    /// deliberately ignored (the leaked-environment posture).
    ignored_override: bool,
}

static EFFECTIVE: std::sync::OnceLock<EffectiveSchedule> = std::sync::OnceLock::new();

fn raw_override() -> Option<String> {
    std::env::var("SHEKYL_SETTLEMENT_EPOCH_BLOCKS").ok()
}

fn latch_unarmed() -> &'static EffectiveSchedule {
    EFFECTIVE.get_or_init(|| EffectiveSchedule {
        blocks: SETTLEMENT_EPOCH_BLOCKS,
        ignored_override: raw_override().is_some(),
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

/// Arm the `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` override for a **regtest
/// context** — the daemon's FAKECHAIN startup path, or a wallet-side
/// regtest harness whose epoch arithmetic must match a short-epoch regtest
/// daemon. Must run at process startup, before any epoch arithmetic:
/// arming after the schedule latched is a typed refusal
/// ([`SettlementEpochOverrideError::ArmedTooLate`]), as is an invalid
/// value ([`SettlementEpochOverrideError::Invalid`]) — never a silent
/// fall-back to the genesis schedule. Idempotent when re-armed to the
/// same effective value. Returns the effective blocks value.
pub fn arm_settlement_epoch_override_for_regtest() -> Result<u64, SettlementEpochOverrideError> {
    let target = parse_settlement_epoch_override(raw_override().as_deref())?
        .unwrap_or(SETTLEMENT_EPOCH_BLOCKS);
    let latched = EFFECTIVE.get_or_init(|| EffectiveSchedule {
        blocks: target,
        ignored_override: false,
    });
    if latched.blocks != target {
        return Err(SettlementEpochOverrideError::ArmedTooLate {
            latched: latched.blocks,
        });
    }
    Ok(latched.blocks)
}

/// True iff the effective schedule differs from the genesis default
/// (i.e. an **armed** `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` override is
/// active). Drives the daemon's loud fakechain warning.
#[must_use]
pub fn settlement_epoch_blocks_overridden() -> bool {
    effective_settlement_epoch_blocks() != SETTLEMENT_EPOCH_BLOCKS
}

/// True iff `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` is set but this process never
/// armed it — the override is being deliberately ignored. Unarmed consumers
/// (the wallet's stake-engine spawn) surface this loudly once so the
/// leaked-environment case is diagnosable instead of silent.
#[must_use]
pub fn settlement_epoch_override_ignored() -> bool {
    latch_unarmed().ignored_override
}

/// True iff `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` is present in this process's
/// environment at all (no validation, no latching). Drives the daemon's
/// public-network refusal: on a non-FAKECHAIN net the *presence* of the
/// lever is the operator error to surface, before any question of validity.
#[must_use]
pub fn settlement_epoch_override_present() -> bool {
    raw_override().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parse accepts exactly the in-range values, treats absence as
    /// "no override", and refuses everything else with the rejected raw
    /// value named — never a silent fall-back.
    #[test]
    fn settlement_epoch_override_parse() {
        assert_eq!(parse_settlement_epoch_override(None), Ok(None));
        assert_eq!(parse_settlement_epoch_override(Some("50")), Ok(Some(50)));
        assert_eq!(
            parse_settlement_epoch_override(Some(" 200 ")),
            Ok(Some(200))
        );
        assert_eq!(parse_settlement_epoch_override(Some("2")), Ok(Some(2)));
        assert_eq!(
            parse_settlement_epoch_override(Some("10000")),
            Ok(Some(10_000))
        );
        for bad in ["1", "0", "10001", "-5", "junk", ""] {
            assert_eq!(
                parse_settlement_epoch_override(Some(bad)),
                Err(SettlementEpochOverrideError::Invalid {
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
        assert!(!settlement_epoch_blocks_overridden());
        assert!(!settlement_epoch_override_ignored());
        assert_eq!(
            arm_settlement_epoch_override_for_regtest(),
            Ok(SETTLEMENT_EPOCH_BLOCKS),
            "re-arming to the already-latched value is idempotent"
        );
    }
}
