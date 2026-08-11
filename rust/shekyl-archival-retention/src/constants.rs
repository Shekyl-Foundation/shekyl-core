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
/// Under derived assignment the binding constraint is instead against the
/// response window: a challenge issued at the epoch's **last** block,
/// `(E+1)·SEB − 1`, must be resolvable before the slash fold reads the
/// epoch, so `CHALLENGE_RESOLUTION_BLOCKS ≥ CHALLENGE_RESPONSE_BLOCKS`
/// (the const-assert below arms itself the moment W₂ pins). One epoch
/// dominates any plausible W₂; re-confirm this value when the W₂
/// measurement program reports.
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
/// response.
///
/// Unpinned: the value comes from the W₂ **measurement program**
/// (`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.5 — provisioned at the Pi-4 floor
/// per rule 76, measured on the real Tor network), and its byte-pin lands
/// with the format round's frozen response wire (rule 42 version bump).
/// The gate-2 wording that its wire "lands with the vin serializer" is
/// obsolete — that serializer is on the format round's deletion surface.
pub const CHALLENGE_RESPONSE_BLOCKS: Option<u64> = None;

// Armed the moment W₂ pins: the slash fold for epoch E must not run before
// the response window of E's last-issued challenge has closed, or the fold
// reads a still-open epoch and mints misses out of in-flight responses.
// Derived from the same block-index convention failure_window.rs litigated
// (fold runs strictly above the deadline, so `>=` is exact).
const _: () = assert!(
    match CHALLENGE_RESPONSE_BLOCKS {
        Some(w2) => CHALLENGE_RESOLUTION_BLOCKS >= w2,
        None => true,
    },
    "CHALLENGE_RESOLUTION_BLOCKS < CHALLENGE_RESPONSE_BLOCKS: the slash fold \
     for an epoch would run before the response window of its last-issued \
     challenge closes, reading in-flight responses as misses; re-derive the \
     resolution grace alongside the W2 pin"
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
