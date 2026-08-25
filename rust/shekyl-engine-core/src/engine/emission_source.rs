// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Emission claim-source RPC client: request shape + response decode
//! (`EMISSION_CLAIM_BUILDER.md` §7, PR 1).
//!
//! The daemon-side handler (`src/rpc/archival_claim_source.cpp`) serializes
//! the single landed gather (`gather_archival_emission_epoch_snapshot`) for
//! every epoch in the claim window, unconditionally. This module is the
//! wallet-side twin: it decodes that response into **exactly** the structs
//! verify already consumes — [`EmissionEpochSource`] + [`ClaimantBondRecord`]
//! views over owned rows — via the same two-pass shape as the verify FFI shim
//! (`shekyl-ffi/src/archival_ffi.rs`). No builder-private mirror of either
//! struct exists here (§7.3 decode-locus pin: the §2 step-7 self-check must
//! consume the same decoded values the assembly consumed).
//!
//! Transport: [`fetch_emission_claim_source`] is generic over
//! [`Rpc`], but persona-side callers ride the persona's transport
//! (`PTorClient`/`PRpc`) — **never** the principal's daemon session (§7.4
//! transport pin; the claim orchestrator's caller supplies the transport
//! and enforces this). The request carries `p_id` **only**: no epoch selector,
//! no range, no claimable-subset encoding (§7.2 transport cause-blindness).
//!
//! Untrusted-daemon posture (`20-rust-vs-cpp-policy.mdc` §3): scalar and
//! bool fields are mandatory — a response missing one is a malformed reply,
//! loudly rejected, never silently defaulted. Array fields decode absent as
//! empty, matching epee KV serialization's omit-empty-container behavior on
//! the daemon side (the C++ wire-contract test pins that behavior). The
//! decode also enforces `status == "OK"` (a `BUSY`/error-shaped body must
//! never decode as a valid zeroed source) and the invariants the consumers
//! rely on: `claimed_settlement_epochs` strictly increasing (the
//! `claimed_epochs_contains` binary-search operand), `epochs` in strictly
//! ascending epoch order, and `current_settled_epoch` consistent with
//! `chain_height` under the frozen mapping (`settlement_epoch_at_height` —
//! the daemon derives both from one `db.height()` read, and the builder's
//! window boundaries and the step-7 self-check split the pair downstream).

use serde_json::{json, Value};
use shekyl_archival_retention::{
    settlement_epoch_at_height, BadInterval, ClaimantBondRecord, CreditPair, EmissionEpochSource,
    EpochCloseBond, EpochCloseInputs, EpochCloseShard, HoldingsDescriptor, HoldingsKind, ShardSet,
};
use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_types::ChainCount;

/// The daemon JSON-RPC method name (registered on both the epee and
/// Rust/Axum transports in PR 1's daemon half).
pub const EMISSION_CLAIM_SOURCE_METHOD: &str = "get_archival_emission_claim_source";

/// Claim-source fetch/decode failure.
#[derive(Debug, thiserror::Error)]
pub enum EmissionSourceError {
    /// Transport / JSON-RPC envelope failure.
    #[error(transparent)]
    Rpc(#[from] RpcError),
    /// The daemon's response is not the expected shape — an untrusted-input
    /// rejection (missing mandatory field, wrong type, odd-length interval
    /// flattening, unknown holdings kind, ordering-invariant violation),
    /// never silently defaulted.
    #[error("malformed emission claim-source response: {0}")]
    Malformed(String),
    /// The daemon answered with a non-`OK` `status` (e.g. `BUSY`) — a
    /// retryable daemon-side condition, never a payload: a zeroed
    /// error-shaped body must not decode as "no claimable epochs".
    #[error("daemon status not OK: {0}")]
    Status(String),
}

/// One gathered bond row, owned (mirrors the wire's `bonds[]` entry; the
/// flattened `(start_epoch, end_exclusive)` pairs are re-paired at decode).
#[derive(Debug, Clone)]
pub struct BondRow {
    pub join_settlement_epoch: u64,
    pub is_foundation_complete_tree: bool,
    pub bad_intervals: Vec<BadInterval>,
}

/// One epoch's as-of-`E` snapshot, owned — the wire twin of the daemon's
/// `ArchivalEmissionEpochSnapshot` (field-for-field; §7.3 part B).
#[derive(Debug, Clone)]
pub struct EpochSnapshot {
    pub settlement_epoch: u64,
    /// The close-**processing** height `(E+1)·SEB` (the shard-age operand),
    /// as the daemon sourced it — the wallet never re-derives it.
    pub close_block_height: u64,
    /// The **persisted** `Σwork(E)` — the stored denominator, never a
    /// recompute (the M1 gate's outcome reaches the wallet only through
    /// this value, same as verify).
    pub sigma_work_milli: u64,
    /// Frozen close-row `budget(E)`; meaningful only when `has_budget_row`.
    pub budget_atomic: u64,
    /// Absent close row ⇒ this epoch is unclaimable to the builder
    /// (mirrors the verify shim's reject).
    pub has_budget_row: bool,
    pub bonds: Vec<BondRow>,
    pub shards: Vec<EpochCloseShard>,
    pub credit_pairs: Vec<CreditPair>,
    /// `None` = the wire's `u64::MAX` sentinel (the landed `SIZE_MAX`),
    /// decoded exactly as the verify shim decodes it.
    pub claimant_bond_idx: Option<usize>,
}

/// The whole-record release-cooldown anchor, as the **daemon folded it**.
///
/// Deliberately not an `Option<u64>` at rest, and the reason is a safety
/// boundary rather than a style preference. Both consensus predicates that
/// consume this operand treat an absent anchor as *permissive*:
/// `release_cooldown_elapsed` returns `true` on `None`, and
/// `slashes_settled_through` returns `true` on `None`. That is correct at the
/// daemon, where absence can only mean "no shard has ever served" — nothing
/// served, nothing whose settlement an exit could outrun.
///
/// On this side of the wire a bare `None` could also mean "the field never
/// arrived", and that fact must be *fail-closed*: it would otherwise flow into
/// the same permissive branch and report an irreversible exit as ready on a
/// value the wallet never received. The daemon therefore reports the
/// distinction (`has_last_served_epoch`) instead of leaving it inferred, the
/// decoder requires the field (an absent one is
/// [`EmissionSourceError::Malformed`], never a default), and this type has no
/// variant for "unknown" — so the unsafe state cannot be constructed here at
/// all, rather than being constructible and merely discouraged.
///
/// Epoch 0 is a real settlement epoch, so a zero-means-absent encoding would
/// have collapsed the same two facts one layer lower.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeAnchor {
    /// The daemon reported that no shard on this record has served.
    NeverServed,
    /// The daemon's folded whole-record anchor.
    ServedAt(u64),
}

impl ServeAnchor {
    /// The consensus predicates' operand form.
    ///
    /// The single place this becomes an `Option`, so every `None` reaching
    /// `release_cooldown_elapsed` / `slashes_settled_through` provably came
    /// from a daemon that said "never served" — not from a missing field.
    #[must_use]
    #[allow(dead_code)] // PR-P4 slice 2: `AssembleUnbond` is the caller; it is the only conversion to the verifier's operand form.
    pub const fn as_verify_operand(self) -> Option<u64> {
        match self {
            Self::NeverServed => None,
            Self::ServedAt(epoch) => Some(epoch),
        }
    }
}

/// The slash scheduler's monotone watermark, as the daemon reported it.
///
/// The storage sentinel (`u64::MAX` = nothing settled yet) is resolved
/// daemon-side, so it never reaches this type.
///
/// Note the deliberate asymmetry with [`ServeAnchor`]: absence on *this*
/// operand is already fail-closed at consensus — `slashes_settled_through`
/// returns `false` when the watermark is absent but an anchor exists. The two
/// therefore cannot share one "absent" encoding without being wrong for one of
/// them, which is why they are separate types rather than two `Option<u64>`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashWatermark {
    /// No settlement epoch has been slash-processed yet.
    NothingSettled,
    /// Every epoch up to and including this one has been processed.
    SettledThrough(u64),
}

impl SlashWatermark {
    /// The consensus predicate's operand form.
    #[must_use]
    #[allow(dead_code)] // PR-P4 slice 2: `AssembleUnbond` is the caller; it is the only conversion to the verifier's operand form.
    pub const fn as_verify_operand(self) -> Option<u64> {
        match self {
            Self::NothingSettled => None,
            Self::SettledThrough(epoch) => Some(epoch),
        }
    }
}

/// Part-A claim context: the claimant's bond record as the daemon read it.
#[derive(Debug, Clone)]
pub struct BondContext {
    /// `E_join` — verify step 2's `E ≥ E_join + 1` operand (read via
    /// [`Self::record`] by the §2 step-7 self-check).
    pub join_settlement_epoch: u64,
    /// The record's holdings descriptor — the vin copies this **by value**
    /// (§5.3/§6.4.1: verify demands record equality; the builder never
    /// recomputes a descriptor).
    pub holdings: HoldingsDescriptor,
    /// Strictly increasing claimed-epoch set — the step-1 dedup operand
    /// (`claimed_epochs_contains` binary-searches it; the ordering is
    /// enforced at decode, not assumed).
    pub claimed_settlement_epochs: Vec<u64>,
    /// The record's current bonded balance — `verify_unbond_bond_post`'s first
    /// operand (`NothingToUnbond` at zero) and the exact value a full exit's
    /// `bond_debit` must equal.
    #[allow(dead_code)] // PR-P4 slice 2: read by `AssembleUnbond` as the exit's `bond_debit`.
    pub bonded_total_atomic: u64,
    /// The release-cooldown anchor. See [`ServeAnchor`] for why this is not an
    /// `Option<u64>`.
    #[allow(dead_code)] // PR-P4 slice 2: read by `AssembleUnbond` / `unbond_readiness`.
    pub last_served: ServeAnchor,
    /// The slash scheduler's watermark. See [`SlashWatermark`].
    #[allow(dead_code)]
    // PR-P4 slice 2: read by `AssembleUnbond`'s slash-settlement precondition.
    pub last_settled_slash: SlashWatermark,
}

impl BondContext {
    /// The verify-side view over this record — the §2 step-7 self-check's
    /// `EmissionVerifyContext::bond` operand.
    pub fn record(&self) -> ClaimantBondRecord<'_> {
        ClaimantBondRecord {
            join_settlement_epoch: self.join_settlement_epoch,
            holdings: &self.holdings,
            claimed_settlement_epochs: &self.claimed_settlement_epochs,
        }
    }
}

/// The decoded claim-source response: part-A claim context + the full
/// claim window's snapshots, exactly as the daemon serialized them.
#[derive(Debug, Clone)]
pub struct EmissionClaimSource {
    /// Chain block **count** at gather time ([`ChainCount`] — a count, not
    /// a height; the type's two bridges are the two facts consumers need).
    /// Its [`next_height`](ChainCount::next_height) is the §2 step-7
    /// self-check's verify-context height (the earliest inclusion height)
    /// and the derivation's strict-finalization operand (`emission_claim`
    /// step 2: verify admits `E` one count after the connect window does);
    /// its [`tip`](ChainCount::tip) is the designation/sweep spendability
    /// anchor and the §2 step-3 same-tip staleness operand (the
    /// `AssembleEmissionClaim` handler's same-tip check). The exact operand
    /// the daemon derived `current_settled_epoch` from —
    /// `archival_claim_source.cpp` gathers both from one `db.height()` read.
    pub chain_height: ChainCount,
    /// The daemon's settled-epoch operand (same helper consensus uses),
    /// **decode-enforced** equal to `settlement_epoch_at_height(chain_height)`
    /// — so the step-1 window boundaries (which consume this field) and the
    /// step-7 self-check / on-chain verify (which recompute settled from
    /// `chain_height`) provably share one boundary basis. Step 1's window
    /// bounds derive from this via the landed predicate functions — never
    /// inline boundary arithmetic (§2 step 1).
    pub current_settled_epoch: u64,
    /// `None` when the daemon has no bond record for `p_id` — the builder
    /// refuses idle (`NoClaimableEpochs`), not an error.
    pub bond: Option<BondContext>,
    /// One entry per window epoch, in strictly ascending epoch order
    /// (enforced at decode, not assumed).
    pub epochs: Vec<EpochSnapshot>,
}

impl EpochSnapshot {
    /// First pass of the two-pass view construction (the verify FFI shim's
    /// shape): the borrowing bond rows, anchored to `self`.
    pub fn bonds_view(&self) -> Vec<EpochCloseBond<'_>> {
        self.bonds
            .iter()
            .map(|b| EpochCloseBond {
                join_settlement_epoch: b.join_settlement_epoch,
                is_foundation_complete_tree: b.is_foundation_complete_tree,
                bad_intervals: &b.bad_intervals,
            })
            .collect()
    }

    /// Second pass: the verify-side source struct over `bonds` from
    /// [`Self::bonds_view`].
    ///
    /// Consensus constants and the close-only M1 operands come from the
    /// wallet's **own compiled constants pipeline** via the single-sourced
    /// [`EpochCloseInputs::verify_view`] constructor — the same construction
    /// the verify FFI shims use (`archival_ffi.rs`), so the wallet's §2
    /// step-7 self-check and consensus verify cannot drift. They are
    /// deliberately not on the wire (§7.3: a wire copy is a second source
    /// that can drift).
    pub fn source<'a>(&'a self, bonds: &'a [EpochCloseBond<'a>]) -> EmissionEpochSource<'a> {
        EmissionEpochSource {
            inputs: EpochCloseInputs::verify_view(
                self.settlement_epoch,
                self.close_block_height,
                bonds,
                &self.shards,
                &self.credit_pairs,
            ),
            persisted_sigma_work_milli: self.sigma_work_milli,
            claimant_bond_idx: self.claimant_bond_idx,
            budget: self.budget_atomic,
        }
    }
}

// ── Decode (untrusted input; loud on malformation) ──────────────────────

fn req_u64(v: &Value, field: &str) -> Result<u64, EmissionSourceError> {
    v.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| EmissionSourceError::Malformed(format!("missing/non-u64 `{field}`")))
}

fn req_bool(v: &Value, field: &str) -> Result<bool, EmissionSourceError> {
    v.get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| EmissionSourceError::Malformed(format!("missing/non-bool `{field}`")))
}

/// Array fields: absent decodes as empty (epee KV omits empty containers);
/// present-but-not-an-array is malformed.
fn opt_array<'v>(v: &'v Value, field: &str) -> Result<&'v [Value], EmissionSourceError> {
    match v.get(field) {
        None => Ok(&[]),
        Some(a) => a
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| EmissionSourceError::Malformed(format!("non-array `{field}`"))),
    }
}

fn u64_array(v: &Value, field: &str) -> Result<Vec<u64>, EmissionSourceError> {
    opt_array(v, field)?
        .iter()
        .map(|e| {
            e.as_u64()
                .ok_or_else(|| EmissionSourceError::Malformed(format!("non-u64 in `{field}`")))
        })
        .collect()
}

fn to_usize(value: u64, field: &str) -> Result<usize, EmissionSourceError> {
    usize::try_from(value)
        .map_err(|_| EmissionSourceError::Malformed(format!("`{field}` exceeds usize")))
}

/// Ordering invariants are load-bearing downstream (`claimed_epochs_contains`
/// binary-searches the claimed set; window iteration assumes ascending
/// epochs), so an out-of-order reply is rejected at decode — unspecified
/// binary-search results on unsorted data could silently skip a claimable
/// epoch (lost emission) or wedge the claim loop on a doomed vin.
fn require_strictly_increasing(values: &[u64], field: &str) -> Result<(), EmissionSourceError> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(EmissionSourceError::Malformed(format!(
            "`{field}` not strictly increasing"
        )))
    }
}

fn decode_bond_row(v: &Value) -> Result<BondRow, EmissionSourceError> {
    let flat = u64_array(v, "bad_intervals_flat")?;
    if flat.len() % 2 != 0 {
        return Err(EmissionSourceError::Malformed(
            "odd-length `bad_intervals_flat`".into(),
        ));
    }
    let bad_intervals = flat
        .chunks_exact(2)
        .map(|pair| BadInterval {
            start_epoch: pair[0],
            end_exclusive: pair[1],
        })
        .collect();
    Ok(BondRow {
        join_settlement_epoch: req_u64(v, "join_settlement_epoch")?,
        is_foundation_complete_tree: req_bool(v, "is_foundation_complete_tree")?,
        bad_intervals,
    })
}

fn decode_epoch(v: &Value) -> Result<EpochSnapshot, EmissionSourceError> {
    let bonds = opt_array(v, "bonds")?
        .iter()
        .map(decode_bond_row)
        .collect::<Result<Vec<_>, _>>()?;
    let shards = opt_array(v, "shards")?
        .iter()
        .map(|s| {
            Ok(EpochCloseShard {
                shard_id: req_u64(s, "shard_id")?,
                freeze_height: req_u64(s, "freeze_height")?,
                has_segment: req_bool(s, "has_segment")?,
            })
        })
        .collect::<Result<Vec<_>, EmissionSourceError>>()?;
    let credit_pairs = opt_array(v, "credit_pairs")?
        .iter()
        .map(|p| {
            Ok(CreditPair {
                bond_idx: to_usize(req_u64(p, "bond_idx")?, "bond_idx")?,
                shard_idx: to_usize(req_u64(p, "shard_idx")?, "shard_idx")?,
            })
        })
        .collect::<Result<Vec<_>, EmissionSourceError>>()?;
    // The landed SIZE_MAX sentinel rides the wire as u64::MAX → None,
    // exactly as the verify shim decodes it.
    let claimant_bond_idx = match req_u64(v, "claimant_bond_idx")? {
        u64::MAX => None,
        idx => Some(to_usize(idx, "claimant_bond_idx")?),
    };
    Ok(EpochSnapshot {
        settlement_epoch: req_u64(v, "settlement_epoch")?,
        close_block_height: req_u64(v, "close_block_height")?,
        sigma_work_milli: req_u64(v, "sigma_work_milli")?,
        budget_atomic: req_u64(v, "budget_atomic")?,
        has_budget_row: req_bool(v, "has_budget_row")?,
        bonds,
        shards,
        credit_pairs,
        claimant_bond_idx,
    })
}

impl EmissionClaimSource {
    /// Decode the `get_archival_emission_claim_source` JSON-RPC result.
    pub fn from_json(v: &Value) -> Result<Self, EmissionSourceError> {
        // Non-OK status first (the daemon.rs fee-estimate idiom): an
        // error-shaped body carries zeroed payload fields that would
        // otherwise decode as a valid "nothing claimable" source.
        let status = v
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| EmissionSourceError::Malformed("missing/non-string `status`".into()))?;
        if status != "OK" {
            return Err(EmissionSourceError::Status(status.to_owned()));
        }
        let bond = if req_bool(v, "has_bond_record")? {
            let kind_raw = req_u64(v, "holdings_kind")?;
            let kind_byte = u8::try_from(kind_raw).map_err(|_| {
                EmissionSourceError::Malformed(format!("holdings_kind {kind_raw} exceeds u8"))
            })?;
            let kind = HoldingsKind::from_u8(kind_byte).map_err(|_| {
                EmissionSourceError::Malformed(format!("unknown holdings_kind {kind_byte}"))
            })?;
            let claimed_settlement_epochs = u64_array(v, "claimed_settlement_epochs")?;
            require_strictly_increasing(&claimed_settlement_epochs, "claimed_settlement_epochs")?;
            Some(BondContext {
                join_settlement_epoch: req_u64(v, "join_settlement_epoch")?,
                holdings: HoldingsDescriptor {
                    kind,
                    // Daemon-response decoder boundary: the shard list is
                    // untrusted input, so it is validated at construction (bound
                    // + duplicate-free) like every other holdings decoder. The
                    // ShardSetError carries the specific fault (which id
                    // duplicated / the offending count) — surface it.
                    shard_ids: ShardSet::new(u64_array(v, "held_shard_ids")?).map_err(|e| {
                        EmissionSourceError::Malformed(format!("held_shard_ids: {e}"))
                    })?,
                },
                claimed_settlement_epochs,
                bonded_total_atomic: req_u64(v, "bonded_total_atomic")?,
                // `req_*`, not an `unwrap_or`: an absent field must be a decode
                // error, because the only other option — defaulting — produces
                // exactly the permissive `None` that would report an
                // irreversible exit as ready on a value that never arrived.
                // This is the line that makes "unknown" unrepresentable rather
                // than merely discouraged (see `ServeAnchor`).
                //
                // There are two presence encodings here and they answer
                // different questions, so it is worth saying which wins. The
                // **required read is authoritative about the wire**: an absent
                // `has_last_served_epoch`, or a `true` flag with the value
                // missing, is `Malformed` — the flag cannot vouch for a field
                // that did not arrive. The **flag is the daemon's assertion
                // about semantics**: "this record has never served", which is a
                // fact only the daemon holds. So `false` legitimately means the
                // value is absent and it is never read; every other
                // disagreement is a decode error, not a reconciliation.
                last_served: if req_bool(v, "has_last_served_epoch")? {
                    ServeAnchor::ServedAt(req_u64(v, "last_served_epoch")?)
                } else {
                    ServeAnchor::NeverServed
                },
                last_settled_slash: if req_bool(v, "has_last_settled_slash_epoch")? {
                    SlashWatermark::SettledThrough(req_u64(v, "last_settled_slash_epoch")?)
                } else {
                    SlashWatermark::NothingSettled
                },
            })
        } else {
            None
        };
        let epochs = opt_array(v, "epochs")?
            .iter()
            .map(decode_epoch)
            .collect::<Result<Vec<_>, _>>()?;
        let epoch_ids: Vec<u64> = epochs.iter().map(|e| e.settlement_epoch).collect();
        require_strictly_increasing(&epoch_ids, "epochs[].settlement_epoch")?;
        let chain_height = req_u64(v, "chain_height")?;
        let current_settled_epoch = req_u64(v, "current_settled_epoch")?;
        // The daemon derives both fields from one `db.height()` read
        // (`archival_claim_source.cpp`), so the pair is redundant on the
        // wire — and the two boundary systems downstream split it: the
        // step-1 window verdicts consume `current_settled_epoch`, while the
        // step-7 self-check (and on-chain verify) recompute settled from
        // `chain_height`. Enforce the invariant here so an inconsistent
        // reply is one loud `Malformed` refusal at the untrusted boundary,
        // never a cause-blind whole-batch `SelfCheckFailed` (deflated
        // settled) or a silently-forfeited claimable epoch (inflated
        // settled).
        let derived_settled = settlement_epoch_at_height(chain_height);
        if current_settled_epoch != derived_settled {
            return Err(EmissionSourceError::Malformed(format!(
                "`current_settled_epoch` {current_settled_epoch} inconsistent with \
                 `chain_height` {chain_height} (derives to {derived_settled})"
            )));
        }
        Ok(Self {
            // The typed-domain edge (rule 18): the raw wire u64 becomes a
            // ChainCount here, so no consumer can launder the count into a
            // BlockHeight without naming which chain fact it means.
            chain_height: ChainCount::from_raw(chain_height),
            current_settled_epoch,
            bond,
            epochs,
        })
    }
}

/// Issue the claim-source query and decode the response.
///
/// The request carries `p_id` **only** — the §7.2 watch item: no field of
/// this request can encode an epoch selection or the claimable subset, so
/// the daemon-visible query is identical for every claimant regardless of
/// serve history. Persona-side callers pass the persona transport
/// (`PRpc`), never the principal's daemon session (§7.4).
///
/// Production callers, both persona-side and both bound by the §7.4
/// transport pin above:
///
/// - [`orchestrate_emission_claim`](super::claim_orchestrator::orchestrate_emission_claim),
///   step 1 of the claim pipeline (the consumer the PR-1/PR-2 staging allows
///   named; the last of them dies here).
/// - [`EngineServeSetPinner`](super::stake_engine::serve_set_source::EngineServeSetPinner),
///   which derives a serving persona's shard obligations from the same
///   connected record (SH-2). It reads `bond.holdings` where the claim
///   pipeline reads the epoch set, so a transport audit has to see both.
pub async fn fetch_emission_claim_source<R: Rpc>(
    rpc: &R,
    p_id: &[u8; 32],
) -> Result<EmissionClaimSource, EmissionSourceError> {
    let result: Value = rpc
        .json_rpc_call(
            EMISSION_CLAIM_SOURCE_METHOD,
            Some(json!({ "p_id": hex::encode(p_id) })),
        )
        .await?;
    EmissionClaimSource::from_json(&result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::emission_claim::test_fixtures::source_json;
    use shekyl_archival_retention::{ARCHIVAL_REWARD_AGE_WEIGHT_MILLI, SETTLEMENT_EPOCH_BLOCKS};

    /// A response as the daemon's epee KV JSON store emits it: one window
    /// epoch with rows, one empty-row epoch (absent arrays omitted, as epee
    /// omits empty containers — the shared encoder reproduces that, so the
    /// absent-decodes-empty rule stays covered). Encoded through the
    /// crate's single test-side wire encoder
    /// (`emission_claim::test_fixtures::source_json`); the shape's
    /// independent pin is the C++ wire-contract test on the serializer
    /// side (`archival_claim_source_rpc.cpp`).
    /// The exit operands must arrive or the decode must fail — they must never
    /// default.
    ///
    /// This is the slice's safety boundary in one test. `release_cooldown_elapsed`
    /// and `slashes_settled_through` both treat an ABSENT serve anchor as
    /// permissive, which is right at the daemon (nothing served ⇒ nothing to cool
    /// down from) and wrong here, where absence can also mean "the field never
    /// arrived". If the decoder defaulted instead of erroring, an older daemon or
    /// a dropped field would make the wallet compute readiness from a value it
    /// never received and tell a user an irreversible exit was safe to take.
    ///
    /// So: every exit operand is a required field, and its absence is
    /// `Malformed`. There is no `ServeAnchor` variant for "unknown" — a decode
    /// that cannot answer refuses instead of guessing.
    ///
    /// **What this test covers, stated precisely.** It exercises the *decoder's*
    /// contract, not a shape today's wire produces: the C++ marshaler writes all
    /// three operands whenever `has_bond_record` is set, so a current daemon
    /// never omits them and this negative control cannot fire against one. Its
    /// value is forward-looking and is the reason it is worth keeping — a daemon
    /// that predates these fields, a field dropped in a future response edit, or
    /// a transport that elides scalars would all arrive here, and the decoder
    /// refuses rather than defaulting into the permissive branch. The
    /// wire-shape pin lives on the C++ side (`archival_claim_source_rpc.cpp`),
    /// where it belongs; this is the decoder's half.
    #[test]
    fn a_missing_exit_operand_is_a_decode_error_never_a_permissive_default() {
        for field in [
            "bonded_total_atomic",
            "has_last_served_epoch",
            "has_last_settled_slash_epoch",
        ] {
            let mut v = fixture();
            v.as_object_mut()
                .expect("fixture is an object")
                .remove(field);
            let err = EmissionClaimSource::from_json(&v)
                .expect_err("a missing exit operand must not decode");
            assert!(
                matches!(err, EmissionSourceError::Malformed(_)),
                "{field} absent must be Malformed, got {err:?}"
            );
        }
    }

    /// A flag that vouches for a field which did not arrive is a decode error,
    /// not a reconciliation.
    ///
    /// The two presence encodings answer different questions — the required read
    /// is authoritative about the wire, the flag is the daemon's assertion about
    /// semantics — so `has_last_served_epoch: true` with `last_served_epoch`
    /// missing has no consistent reading and must not be resolved into one. The
    /// dangerous resolution would be "trust the flag, default the value": that
    /// yields `ServedAt(0)`, the earliest possible anchor, which makes the
    /// cooldown look maximally elapsed.
    #[test]
    fn a_flag_without_its_value_is_malformed_not_reconciled() {
        let mut v = fixture();
        let obj = v.as_object_mut().expect("fixture is an object");
        obj.insert("has_last_served_epoch".into(), true.into());
        obj.remove("last_served_epoch");
        let err = EmissionClaimSource::from_json(&v)
            .expect_err("a flag vouching for a missing value must not decode");
        assert!(matches!(err, EmissionSourceError::Malformed(_)), "got {err:?}");

        // Same for the watermark, whose absence is fail-closed at consensus.
        let mut v = fixture();
        let obj = v.as_object_mut().expect("fixture is an object");
        obj.insert("has_last_settled_slash_epoch".into(), true.into());
        obj.remove("last_settled_slash_epoch");
        let err = EmissionClaimSource::from_json(&v)
            .expect_err("a flag vouching for a missing value must not decode");
        assert!(matches!(err, EmissionSourceError::Malformed(_)), "got {err:?}");
    }

    /// The flag carries the fact; the value never encodes it. A served-at-epoch-0
    /// record decodes as *served*, not as "never served" — the collapse a
    /// zero-means-absent encoding would produce, and the one that would flip the
    /// cooldown check from "not elapsed" to permissive.
    #[test]
    fn served_at_epoch_zero_decodes_as_served_not_as_never_served() {
        let mut v = fixture();
        let obj = v.as_object_mut().expect("fixture is an object");
        obj.insert("has_last_served_epoch".into(), true.into());
        obj.insert("last_served_epoch".into(), 0u64.into());
        let src = EmissionClaimSource::from_json(&v).expect("decodes");
        let bond = src.bond.expect("fixture has a bond record");
        assert_eq!(bond.last_served, ServeAnchor::ServedAt(0));
        assert_eq!(
            bond.last_served.as_verify_operand(),
            Some(0),
            "the verifier must see an anchor, not the permissive None"
        );
    }

    /// `NeverServed` is a real daemon answer and must still reach the verifier as
    /// `None` — the permissive branch is correct when the daemon *said* so. This
    /// is the other half of the pair: the mapping is not "always fail closed", it
    /// is "closed on unknown, faithful on known".
    #[test]
    fn never_served_reaches_the_verifier_as_the_permissive_none() {
        let src = EmissionClaimSource::from_json(&fixture()).expect("decodes");
        let bond = src.bond.expect("fixture has a bond record");
        assert_eq!(bond.last_served, ServeAnchor::NeverServed);
        assert_eq!(bond.last_served.as_verify_operand(), None);
        assert_eq!(bond.last_settled_slash.as_verify_operand(), None);
    }

    fn fixture() -> Value {
        source_json(&EmissionClaimSource {
            chain_height: ChainCount::from_raw(30001),
            current_settled_epoch: 3,
            bond: Some(BondContext {
                join_settlement_epoch: 1,
                holdings: HoldingsDescriptor {
                    kind: HoldingsKind::ShardSetCompact,
                    shard_ids: ShardSet::new(vec![4, 9]).unwrap(),
                },
                claimed_settlement_epochs: vec![1],
                bonded_total_atomic: 0,
                last_served: ServeAnchor::NeverServed,
                last_settled_slash: SlashWatermark::NothingSettled,
            }),
            epochs: vec![
                EpochSnapshot {
                    settlement_epoch: 1,
                    close_block_height: 20000,
                    sigma_work_milli: 5000,
                    budget_atomic: 777,
                    has_budget_row: true,
                    bonds: vec![BondRow {
                        join_settlement_epoch: 0,
                        is_foundation_complete_tree: false,
                        bad_intervals: vec![BadInterval {
                            start_epoch: 2,
                            end_exclusive: 3,
                        }],
                    }],
                    shards: vec![EpochCloseShard {
                        shard_id: 4,
                        freeze_height: 15,
                        has_segment: true,
                    }],
                    credit_pairs: vec![CreditPair {
                        bond_idx: 0,
                        shard_idx: 0,
                    }],
                    claimant_bond_idx: Some(0),
                },
                // The empty-row epoch: bonds/shards/credit_pairs are OMITTED
                // by the encoder (epee omit-empty), exercising the decoder's
                // absent-decodes-empty rule.
                EpochSnapshot {
                    settlement_epoch: 2,
                    close_block_height: 30000,
                    sigma_work_milli: 0,
                    budget_atomic: 0,
                    has_budget_row: false,
                    bonds: vec![],
                    shards: vec![],
                    credit_pairs: vec![],
                    claimant_bond_idx: None,
                },
            ],
        })
    }

    /// The encoder really omits the empty containers (the premise of the
    /// absent-decodes-empty coverage above — if it ever emitted `[]`, the
    /// fixture would silently stop exercising the epee omission rule).
    #[test]
    fn fixture_omits_empty_containers() {
        let v = fixture();
        let e2 = &v["epochs"][1];
        for field in ["bonds", "shards", "credit_pairs"] {
            assert!(
                e2.get(field).is_none(),
                "`{field}` must be absent (epee omit-empty), not an empty array"
            );
        }
    }

    #[test]
    fn decodes_fixture_field_for_field() {
        let src = EmissionClaimSource::from_json(&fixture()).unwrap();
        assert_eq!(src.chain_height, ChainCount::from_raw(30001));
        assert_eq!(src.current_settled_epoch, 3);

        let bond = src.bond.as_ref().unwrap();
        assert_eq!(bond.join_settlement_epoch, 1);
        assert_eq!(bond.holdings.kind, HoldingsKind::ShardSetCompact);
        assert_eq!(bond.holdings.shard_ids, [4, 9]);
        assert_eq!(bond.claimed_settlement_epochs, [1]);
        let record = bond.record();
        assert_eq!(record.join_settlement_epoch, 1);
        assert_eq!(record.claimed_settlement_epochs, [1]);

        assert_eq!(src.epochs.len(), 2);
        let e1 = &src.epochs[0];
        assert_eq!(e1.settlement_epoch, 1);
        assert_eq!(e1.close_block_height, 20000);
        assert_eq!(e1.sigma_work_milli, 5000);
        assert_eq!(e1.budget_atomic, 777);
        assert!(e1.has_budget_row);
        assert_eq!(e1.bonds.len(), 1);
        assert_eq!(
            e1.bonds[0].bad_intervals,
            [BadInterval {
                start_epoch: 2,
                end_exclusive: 3
            }]
        );
        assert_eq!(e1.shards.len(), 1);
        assert_eq!(
            e1.credit_pairs,
            [CreditPair {
                bond_idx: 0,
                shard_idx: 0
            }]
        );
        assert_eq!(e1.claimant_bond_idx, Some(0));

        // Sentinel + epee omit-empty-container behavior.
        let e2 = &src.epochs[1];
        assert!(!e2.has_budget_row);
        assert!(e2.bonds.is_empty());
        assert!(e2.shards.is_empty());
        assert!(e2.credit_pairs.is_empty());
        assert_eq!(e2.claimant_bond_idx, None);
    }

    #[test]
    fn view_construction_matches_verify_shape() {
        let src = EmissionClaimSource::from_json(&fixture()).unwrap();
        let e1 = &src.epochs[0];
        let bonds = e1.bonds_view();
        let source = e1.source(&bonds);
        assert_eq!(source.inputs.settlement_epoch, 1);
        assert_eq!(source.inputs.close_block_height, 20000);
        assert_eq!(
            source.inputs.settlement_epoch_blocks,
            SETTLEMENT_EPOCH_BLOCKS
        );
        assert_eq!(
            source.inputs.age_weight_milli,
            ARCHIVAL_REWARD_AGE_WEIGHT_MILLI
        );
        assert_eq!(source.inputs.bonds.len(), 1);
        assert_eq!(
            source.inputs.bonds[0].bad_intervals,
            [BadInterval {
                start_epoch: 2,
                end_exclusive: 3
            }]
        );
        assert_eq!(source.persisted_sigma_work_milli, 5000);
        assert_eq!(source.claimant_bond_idx, Some(0));
        assert_eq!(source.budget, 777);
    }

    #[test]
    fn no_bond_record_decodes_none_without_reading_bond_fields() {
        // A bond-less response zeroes part-A bond fields daemon-side; the
        // decode must not read them (has_bond_record is the gate).
        let v = json!({
            "status": "OK",
            "chain_height": 5,
            "current_settled_epoch": 0,
            "has_bond_record": false
        });
        let src = EmissionClaimSource::from_json(&v).unwrap();
        assert!(src.bond.is_none());
        assert!(src.epochs.is_empty());
    }

    #[test]
    fn missing_mandatory_scalar_is_loud() {
        let mut v = fixture();
        v.as_object_mut().unwrap().remove("current_settled_epoch");
        assert!(matches!(
            EmissionClaimSource::from_json(&v),
            Err(EmissionSourceError::Malformed(_))
        ));
    }

    #[test]
    fn non_ok_status_is_status_error_not_a_payload() {
        // A BUSY body carries zeroed payload fields that must never decode
        // as a valid "nothing claimable" source.
        let mut v = fixture();
        v["status"] = json!("BUSY");
        assert!(matches!(
            EmissionClaimSource::from_json(&v),
            Err(EmissionSourceError::Status(s)) if s == "BUSY"
        ));
    }

    #[test]
    fn missing_status_is_loud() {
        let mut v = fixture();
        v.as_object_mut().unwrap().remove("status");
        assert!(matches!(
            EmissionClaimSource::from_json(&v),
            Err(EmissionSourceError::Malformed(_))
        ));
    }

    #[test]
    fn unsorted_claimed_epochs_is_loud() {
        // The claimed set is a binary-search operand downstream; unsorted
        // input must be rejected at decode, never searched.
        let mut v = fixture();
        v["claimed_settlement_epochs"] = json!([5, 1]);
        assert!(matches!(
            EmissionClaimSource::from_json(&v),
            Err(EmissionSourceError::Malformed(_))
        ));
        // Duplicates violate *strictly* increasing too.
        let mut v = fixture();
        v["claimed_settlement_epochs"] = json!([1, 1]);
        assert!(matches!(
            EmissionClaimSource::from_json(&v),
            Err(EmissionSourceError::Malformed(_))
        ));
    }

    /// The settled/height pair is redundant (one `db.height()` read
    /// daemon-side); a reply where they disagree under the frozen mapping is
    /// malformed — refused at decode, never split across the builder's two
    /// boundary systems (window verdicts read `current_settled_epoch`, the
    /// step-7 self-check recomputes from `chain_height`).
    #[test]
    fn settled_epoch_inconsistent_with_chain_height_is_loud() {
        // Deflated settled: the builder's window floor would lag verify's
        // (whole-batch SelfCheckFailed on an expired admit).
        let mut v = fixture();
        v["current_settled_epoch"] = json!(2);
        assert!(matches!(
            EmissionClaimSource::from_json(&v),
            Err(EmissionSourceError::Malformed(_))
        ));
        // Inflated settled: genuinely claimable epochs would silently skip
        // as WindowExpired (forfeited rewards).
        let mut v = fixture();
        v["current_settled_epoch"] = json!(4);
        assert!(matches!(
            EmissionClaimSource::from_json(&v),
            Err(EmissionSourceError::Malformed(_))
        ));
        // The fixture itself is the consistent pair (sanity).
        assert_eq!(
            settlement_epoch_at_height(fixture()["chain_height"].as_u64().unwrap()),
            fixture()["current_settled_epoch"].as_u64().unwrap()
        );
    }

    #[test]
    fn unsorted_window_epochs_is_loud() {
        let mut v = fixture();
        v["epochs"][0]["settlement_epoch"] = json!(2);
        v["epochs"][1]["settlement_epoch"] = json!(1);
        assert!(matches!(
            EmissionClaimSource::from_json(&v),
            Err(EmissionSourceError::Malformed(_))
        ));
    }

    #[test]
    fn odd_bad_intervals_flat_is_loud() {
        let mut v = fixture();
        v["epochs"][0]["bonds"][0]["bad_intervals_flat"] = json!([2]);
        assert!(matches!(
            EmissionClaimSource::from_json(&v),
            Err(EmissionSourceError::Malformed(_))
        ));
    }

    #[test]
    fn unknown_holdings_kind_is_loud() {
        let mut v = fixture();
        v["holdings_kind"] = json!(7);
        assert!(matches!(
            EmissionClaimSource::from_json(&v),
            Err(EmissionSourceError::Malformed(_))
        ));
    }
}
