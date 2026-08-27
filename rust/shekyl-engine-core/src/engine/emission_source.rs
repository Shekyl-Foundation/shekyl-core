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

use std::fmt;

use serde_json::{json, Value};
use shekyl_archival_retention::{
    settlement_epoch_at_height, BadInterval, ClaimantBondRecord, CreditPair, EmissionEpochSource,
    EpochCloseBond, EpochCloseInputs, EpochCloseShard, HoldingsDescriptor, HoldingsKind, ShardSet,
};
use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_types::{ChainCount, PCanonicalId};

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
    pub const fn as_verify_operand(self) -> Option<u64> {
        match self {
            Self::NeverServed => None,
            Self::ServedAt(epoch) => Some(epoch),
        }
    }
}

/// Renders the distinction this type exists to keep, so a refusal that quotes
/// the anchor cannot flatten it back to a bare integer on the way to the user.
impl fmt::Display for ServeAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeverServed => f.write_str("never"),
            Self::ServedAt(epoch) => write!(f, "epoch {epoch}"),
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
    pub const fn as_verify_operand(self) -> Option<u64> {
        match self {
            Self::NothingSettled => None,
            Self::SettledThrough(epoch) => Some(epoch),
        }
    }
}

/// As [`ServeAnchor`]'s: the absent arm names itself rather than rendering as a
/// missing or defaulted number.
impl fmt::Display for SlashWatermark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NothingSettled => f.write_str("nothing settled"),
            Self::SettledThrough(epoch) => write!(f, "settled through epoch {epoch}"),
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
    pub bonded_total_atomic: u64,
    /// The record's interval-log length — `verify_unbond_bond_post`'s sixth
    /// and last record operand (`record_bad_interval_count`).
    ///
    /// No presence flag, because the field has no absent state: an empty log
    /// is length 0. The permissive-default hazard is the same as the anchors'
    /// and lands here instead — `0 < MAX_BOND_BAD_INTERVALS` **passes**, so a
    /// field that never arrived would read as "the log has room" and let an
    /// unconnectable exit be assembled. Hence a required read, like every other
    /// exit operand.
    pub bad_interval_count: usize,
    /// The release-cooldown anchor. See [`ServeAnchor`] for why this is not an
    /// `Option<u64>`.
    pub last_served: ServeAnchor,
    /// The slash scheduler's watermark. See [`SlashWatermark`].
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
                bad_interval_count: to_usize(
                    req_u64(v, "bad_interval_count")?,
                    "bad_interval_count",
                )?,
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

/// A claim-source response **paired with the `P` it was actually requested
/// for**, by the code that sent the request.
///
/// The pairing exists because `(p_id, response)` as two arguments is not a
/// binding — it is a *label*. A caller holding persona A's response and persona
/// B's id can pair them, and every downstream equality check then agrees with
/// the label rather than with the record the facts came from: readiness gets
/// computed from A's cooldown and watermark while B's post is built. On a path
/// whose confirmation is an irreversible persona-key wipe, that answer being
/// wrong is the whole hazard.
///
/// So the field is private and [`fetch_claim_source_for`] is the only
/// constructor, writing the id from the argument it just sent. There is no way
/// to express a mismatched pair.
///
/// This is one of **two** checks, not a replacement for the other. This one
/// proves the facts came back from a request that named this `P`. The
/// `AssembleUnbond` handler separately proves that `P` is the one whose
/// *handle* is being spent (`RecordPersonaMismatch`) — a caller can still fetch
/// A honestly and present it with B's handle, and that is the handler's arm to
/// refuse.
///
/// # What this type does NOT prove
///
/// **The pairing is request association, not response authentication.** It says
/// what the wallet *asked for*; it says nothing about whether the daemon
/// answered with that record. A stale cache, a misrouted reply, or a lying node
/// can return B's facts to a request naming A, and this type will label them A
/// honestly — every downstream equality check then agrees, because they are all
/// checking the label. Do not read `p_id()` as "these facts belong to this
/// persona".
///
/// **No echo — settled, not reopened here.** A responder-supplied `p_id` to
/// check against is self-certified and would authenticate nothing while looking
/// authoritative. That decision stands; the reasoning is pinned once in
/// `the_fetch_binds_the_response_to_the_id_it_asked_for` rather than re-argued
/// at every site that touches the pairing.
///
/// The residual is bounded. Consensus re-verifies every operand against the real
/// record, so wrong facts produce a **rejected transaction**, not a wrong state
/// transition, and the persona-key wipe is gated on confirmed on-chain evidence
/// rather than anything read here. The cost of a wrong answer is a wrong
/// *readiness verdict* on a screen that reads as irreversible — a UX failure on
/// a serious screen, not a fund-loss one.
///
/// The *handle* side is not this type's problem, and it is a live hazard rather
/// than a theoretical one — for a reason that is easy to get backwards. A wallet
/// activates one persona at a time, but it **holds many**, and the exit path is
/// precisely why the non-active ones stay resident: `ARCHIVAL_BOND_CONSTRUCTION.md`
/// keeps the bonded *union* rather than a clean lookahead window because the
/// archival model rotates *while bonded*, leaving a retired persona's bonds
/// on-chain as dormant balances, and "unbonding a retired persona later needs
/// that persona's `bond_spend` key" — dropping them "bricks unbonding". So the
/// persona being exited is routinely **not** the active one, several are held at
/// once, and a caller really can pair one persona's record with another's
/// handle. That is the arm `AssembleUnbond` refuses.
///
/// It is also why the exit must **not** copy `drain_to_principal`'s shape. That
/// façade resolves `active_persona()` and takes no slot parameter, which is
/// right for a `P`-lane spend and wrong here: applied to the exit it would brick
/// unbonding every retired-but-bonded persona. *One persona on the wire at a
/// time* is the invariant (no simultaneous wire activity — the firewall permits
/// the dormant balances); *"only the active persona can be unbonded"* is not,
/// and the two read alike.
#[derive(Debug, Clone)]
pub struct ClaimSourceFor {
    p_id: PCanonicalId,
    source: EmissionClaimSource,
}

impl ClaimSourceFor {
    /// The `P` the request named.
    #[must_use]
    pub fn p_id(&self) -> PCanonicalId {
        self.p_id
    }

    /// The decoded response.
    #[must_use]
    pub fn source(&self) -> &EmissionClaimSource {
        &self.source
    }

    /// Pair a response with an id **without** having sent the request.
    ///
    /// Test-only, and deliberately not `cfg(any(test, feature = ...))`: the
    /// production path has exactly one way to obtain a pairing, and this is the
    /// escape hatch that lets a test construct the mismatched state in order to
    /// assert it is refused.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn for_test(p_id: PCanonicalId, source: EmissionClaimSource) -> Self {
        Self { p_id, source }
    }
}

/// Fetch the claim source for `p_id`, keeping the two bound together.
///
/// **Not a convenience wrapper over [`fetch_emission_claim_source`] — it is the
/// binding.** The bare fetch returns facts with no record of whose they are, so
/// a consumer that needs to know (anything on the `Unbond` readiness/exit path)
/// would have to re-attach an id by hand, which is the mislabeling
/// [`ClaimSourceFor`] exists to make impossible. Reach for this one there, and
/// do not collapse the two: the delegation is a single line precisely so the
/// pair cannot drift, and the bare form stays for consumers (the claim
/// orchestrator, the serve-set pinner) that already carry `P` in their own
/// context and read only the record's contents.
#[allow(dead_code)] // PR-P4: retires with the `unstake` verb, which fetches the record.
pub async fn fetch_claim_source_for<R: Rpc>(
    rpc: &R,
    p_id: PCanonicalId,
) -> Result<ClaimSourceFor, EmissionSourceError> {
    let source = fetch_emission_claim_source(rpc, p_id.as_bytes()).await?;
    Ok(ClaimSourceFor { p_id, source })
}

#[cfg(test)]
#[path = "emission_source_tests.rs"]
mod tests;
