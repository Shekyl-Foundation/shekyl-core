// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Emission claim-source RPC client: request shape + response decode
//! (`EMISSION_CLAIM_BUILDER.md` §7, PR 1).
//!
//! The daemon-side handler (`shekyl-daemon-rpc`'s `archival_claim_show`)
//! serializes the gathered snapshot for every epoch in the claim window,
//! unconditionally. This module is the wallet-side twin: it decodes that
//! response into **exactly** the structs
//! verify already consumes — [`EmissionEpochSource`] + [`ClaimantBondRecord`]
//! views over owned rows. No builder-private mirror of either
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
//! Untrusted-daemon posture (the daemon's reply is untrusted bytes): the reply
//! decodes strictly against the method table's type — a member absent, of the
//! wrong shape, or unknown is no reply, never a default — and a refusal is an
//! error object, never a body. On the typed reply the decode enforces the
//! invariants the consumers rely on: `claimed` strictly increasing (the
//! `claimed_epochs_contains` binary-search operand), `epoch` in strictly
//! ascending order, and `settled_epoch` consistent with `height` under the
//! frozen mapping (`settlement_epoch_at_height` — the daemon derives both from
//! one read, and the builder's window boundaries and the step-7 self-check
//! split the pair downstream).
//!
//! The record carries the hash of the block it was gathered at (IG-Q84), so
//! it vouches for which chain it describes on its own
//! ([`CoherentChainView`]).

use std::fmt;

use shekyl_archival_retention::{
    settlement_epoch_at_height, BadInterval, ClaimantBondRecord, CreditPair, EmissionEpochSource,
    EpochCloseBond, EpochCloseInputs, EpochCloseShard, HoldingsDescriptor, HoldingsKind,
    ShardClose, ShardCloseWire, ShardSet,
};
use shekyl_rpc_client::{wire, Rpc, RpcError};
use shekyl_rpc_types::hash::HashHex;
use shekyl_rpc_types::wire::archival::{self as reply, ClaimSource, Holding, PersonaQuery};

use crate::engine::daemon::synced_chain_facts::{
    fetch_synced_chain_facts, AnchoredView, ChainAnchor, CoherentChainView, TimelineBreak,
};
use shekyl_types::{BlockHash, BlockHeight, ChainCount, PCanonicalId};

/// Claim-source fetch/decode failure.
#[derive(Debug, thiserror::Error)]
pub enum EmissionSourceError {
    /// Transport / JSON-RPC envelope failure.
    #[error(transparent)]
    Rpc(#[from] RpcError),
    /// The daemon's response decoded and does not hold together — an
    /// untrusted-input rejection (an inverted interval, an index past
    /// `usize`, an ordering-invariant violation, a settled epoch the height
    /// does not derive), never silently repaired.
    #[error("malformed emission claim-source response: {0}")]
    Malformed(String),
}

/// One gathered bond row, owned (mirrors the wire's `bond` entry; the
/// inclusive `failure` intervals become the record's end-exclusive ones at
/// decode).
#[derive(Debug, Clone)]
pub struct BondRow {
    pub join_settlement_epoch: u64,
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
    /// Absent close row (`budget: null`) ⇒ this epoch is unclaimable to the
    /// builder (mirrors the verify shim's reject).
    pub has_budget_row: bool,
    pub bonds: Vec<BondRow>,
    pub shards: Vec<EpochCloseShard>,
    pub credit_pairs: Vec<CreditPair>,
    /// `None` = the wire's `claimant: null`, no claiming bond.
    pub claimant_bond_idx: Option<usize>,
}

/// The whole-record release-cooldown anchor, as the **daemon folded it**.
///
/// Deliberately not an `Option<u64>` at rest, and the reason is a safety
/// boundary rather than a style preference. Both consensus predicates that
/// consume this operand treat an absent anchor as *permissive*:
/// `release_cooldown_elapsed` returns `true` on `None`, and
/// `slashes_settled_through` returns `true` on `None`. That is correct at the
/// daemon, where absence can only mean "no pass inside the cooldown's
/// window": the record never passed a draw, or its last pass is old enough
/// that its cooldown has elapsed and its epoch's slash deadline has run
/// (`release_last_served`) — nothing whose settlement an exit could outrun.
///
/// On this side of the wire a bare `None` could also mean "the field never
/// arrived", and that fact must be *fail-closed*: it would otherwise flow into
/// the same permissive branch and report an irreversible exit as ready on a
/// value the wallet never received. The wire therefore says the distinction
/// (`served_epoch: null` is "never served", RK-D23) instead of leaving it
/// inferred, the strict decode requires the member (an absent one is no
/// reply, never a default), and this type has no variant for "unknown" — so
/// the unsafe state cannot be constructed here at all, rather than being
/// constructible and merely discouraged.
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
    /// The record's current bonded balance — `verify_release_bond_post`'s first
    /// operand (`NothingToRelease` at zero) and the exact value a full exit's
    /// `bond_debit` must equal.
    pub bonded_total_atomic: u64,
    /// The record's interval-log length — `verify_release_bond_post`'s sixth
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
    /// the daemon gathers both from one read.
    pub chain_height: ChainCount,
    /// The hash of the block at [`chain_height`](Self::chain_height)'s tip,
    /// from the same read (IG-Q84): which chain the record describes.
    pub tip_hash: BlockHash,
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

fn integers(values: &[shekyl_rpc_types::kinds::Integer]) -> Vec<u64> {
    values.iter().map(|value| value.0).collect()
}

fn amount(value: &shekyl_units::wire::AtomicUnitsString) -> u64 {
    value.to_atomic_units().to_raw()
}

/// The wire's failure interval is inclusive; the record's is end-exclusive.
fn decode_failure(failure: &reply::Failure) -> Result<BadInterval, EmissionSourceError> {
    if failure.to.0 < failure.from.0 {
        return Err(EmissionSourceError::Malformed(format!(
            "failure interval {}..={} is inverted",
            failure.from.0, failure.to.0
        )));
    }
    let end_exclusive = failure.to.0.checked_add(1).ok_or_else(|| {
        EmissionSourceError::Malformed("failure interval ends past the last epoch".into())
    })?;
    Ok(BadInterval {
        start_epoch: failure.from.0,
        end_exclusive,
    })
}

fn decode_bond_row(bond: &reply::ClaimBond) -> Result<BondRow, EmissionSourceError> {
    Ok(BondRow {
        join_settlement_epoch: bond.joined_epoch.0,
        bad_intervals: bond
            .failure
            .iter()
            .map(decode_failure)
            .collect::<Result<_, _>>()?,
    })
}

fn decode_epoch(epoch: &reply::Epoch) -> Result<EpochSnapshot, EmissionSourceError> {
    let bonds = epoch
        .bond
        .iter()
        .map(decode_bond_row)
        .collect::<Result<Vec<_>, _>>()?;
    // The segment-keyed pair (CEN-L10); [`ShardClose::from_wire`] is the fold.
    let shards = epoch
        .shard
        .iter()
        .map(|shard| EpochCloseShard {
            shard_id: shard.id.0,
            close: ShardClose::from_wire(ShardCloseWire {
                has_segment: shard.segment,
                freeze_height: shard.freeze_height.0,
            }),
        })
        .collect();
    let credit_pairs = epoch
        .credit
        .iter()
        .map(|pair| {
            Ok(CreditPair {
                bond_idx: to_usize(pair.bond.0, "credit.bond")?,
                shard_idx: to_usize(pair.shard.0, "credit.shard")?,
            })
        })
        .collect::<Result<Vec<_>, EmissionSourceError>>()?;
    let claimant_bond_idx = epoch
        .claimant
        .0
        .map(|idx| to_usize(idx.0, "claimant"))
        .transpose()?;
    Ok(EpochSnapshot {
        settlement_epoch: epoch.id.0,
        close_block_height: epoch.closing_height.0,
        sigma_work_milli: epoch.work.0,
        budget_atomic: epoch.budget.0.as_ref().map_or(0, amount),
        has_budget_row: epoch.budget.0.is_some(),
        bonds,
        shards,
        credit_pairs,
        claimant_bond_idx,
    })
}

impl EmissionClaimSource {
    /// Decode the `archival_claim_show` reply.
    pub fn from_reply(reply: &ClaimSource) -> Result<Self, EmissionSourceError> {
        let bond = match reply.joined_epoch.0 {
            None => None,
            Some(joined) => {
                let claimed_settlement_epochs = integers(&reply.claimed);
                require_strictly_increasing(&claimed_settlement_epochs, "claimed")?;
                Some(BondContext {
                    join_settlement_epoch: joined.0,
                    holdings: HoldingsDescriptor {
                        kind: match reply.holding {
                            Holding::Shards => HoldingsKind::ShardSetCompact,
                            Holding::CompleteTree => HoldingsKind::CompleteTree,
                        },
                        // Daemon-response decoder boundary: the shard list is
                        // untrusted input, so it is validated at construction
                        // (bound + duplicate-free) like every other holdings
                        // decoder. The ShardSetError carries the specific
                        // fault — surface it.
                        shard_ids: ShardSet::new(integers(&reply.shard))
                            .map_err(|e| EmissionSourceError::Malformed(format!("shard: {e}")))?,
                    },
                    claimed_settlement_epochs,
                    bonded_total_atomic: amount(&reply.bond_total),
                    bad_interval_count: to_usize(reply.failure_count.0, "failure_count")?,
                    // `null` is the daemon's word for "never served" — a fact
                    // only the daemon holds. An absent member never reaches
                    // here: the decode refused it (see `ServeAnchor`).
                    last_served: reply
                        .served_epoch
                        .0
                        .map_or(ServeAnchor::NeverServed, |epoch| {
                            ServeAnchor::ServedAt(epoch.0)
                        }),
                    last_settled_slash: reply
                        .slash_epoch
                        .0
                        .map_or(SlashWatermark::NothingSettled, |epoch| {
                            SlashWatermark::SettledThrough(epoch.0)
                        }),
                })
            }
        };
        let epochs = reply
            .epoch
            .iter()
            .map(decode_epoch)
            .collect::<Result<Vec<_>, _>>()?;
        let epoch_ids: Vec<u64> = epochs.iter().map(|e| e.settlement_epoch).collect();
        require_strictly_increasing(&epoch_ids, "epoch.id")?;
        // The wire carries the tip's height, an ordinal (IG-Q45); the record
        // keeps the chain's count, one more, computed here once.
        let chain_height = reply.height.0.checked_add(1).ok_or_else(|| {
            EmissionSourceError::Malformed("`height` is the last representable block".into())
        })?;
        let current_settled_epoch = reply.settled_epoch.0;
        // The daemon derives both from one read, so the pair is redundant on
        // the wire — and the two boundary systems downstream split it: the
        // step-1 window verdicts consume `current_settled_epoch`, while the
        // step-7 self-check (and on-chain verify) recompute settled from the
        // count. Enforce the invariant here so an inconsistent reply is one
        // loud `Malformed` refusal at the untrusted boundary, never a
        // cause-blind whole-batch `SelfCheckFailed` (deflated settled) or a
        // silently-forfeited claimable epoch (inflated settled).
        let derived_settled = settlement_epoch_at_height(chain_height);
        if current_settled_epoch != derived_settled {
            return Err(EmissionSourceError::Malformed(format!(
                "`settled_epoch` {current_settled_epoch} inconsistent with `height` {} \
                 (derives to {derived_settled})",
                reply.height.0
            )));
        }
        Ok(Self {
            // The typed-domain edge (rule 18): the count becomes a
            // ChainCount here, so no consumer can launder it into a
            // BlockHeight without naming which chain fact it means.
            chain_height: ChainCount::from_raw(chain_height),
            tip_hash: BlockHash::from_bytes(reply.hash.to_bytes()),
            current_settled_epoch,
            bond,
            epochs,
        })
    }

    /// The block this record was gathered at: its own chain identity.
    pub(crate) fn anchor(&self) -> ChainAnchor {
        ChainAnchor {
            height: BlockHeight::from_raw(self.chain_height.to_raw().saturating_sub(1)),
            hash: self.tip_hash,
        }
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
    let reply = rpc
        .call::<wire::ArchivalClaimShow>(PersonaQuery {
            persona: HashHex::from_bytes(*p_id),
        })
        .await?;
    EmissionClaimSource::from_reply(&reply)
}

/// Whether the wallet can vouch for the record it is holding.
///
/// Exactly one of the two states, which is the point: the previous shape
/// was an `Option<view>` beside an `Option<reason>`, and "both `Some`" and
/// "both `None`" were representable states meaning nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Vouching {
    /// Both reads agree on a chain view; act on it.
    Vouched(CoherentChainView),
    /// The wallet holds the record but cannot vouch for it.
    Broken(TimelineBreak),
}

/// A claim source together with the wallet's ability to vouch for it.
///
/// # Why this is a type and not three call sites doing the same two awaits
///
/// `WSS-Q14` gave the wallet a witness; `WSS-25`'s review gave it a
/// reconciliation. Neither was enough on its own, because **both depend on
/// how the two reads were acquired**, and acquisition was left to each
/// caller:
///
/// - The witness must be read **before** the record, so that a record below
///   it is the signature of a rollback rather than ordinary chain advance. A
///   `tokio::join!` establishes no such ordering, and the resulting bug is
///   invisible at the call site — the code reads as if it had.
/// - The witness must be **retained** and reconciled against the record's
///   own height. A caller that reduces it to `matches!(…, Ok(Some(_)))` has
///   proved the daemon was synced *at some moment* and thrown away the only
///   thing that relates that moment to the record it is about to act on.
/// - The failure must keep its **class**. Collapsing "still syncing",
///   "answered garbage" and "unreachable" into one boolean sends operators
///   to the wrong subsystem.
///
/// Each of those is a discipline a call site can silently fail to follow,
/// and three call sites did. So the ordering, the reconciliation and the
/// classification move inside one constructor, and the pair can only be
/// obtained already correct. There is no way to write the unordered fetch,
/// because there is no exposed step to put in the wrong order.
#[derive(Clone, Debug)]
pub(crate) struct VouchedClaimSource {
    source: EmissionClaimSource,
    vouching: Vouching,
}

impl VouchedClaimSource {
    /// The decoded record. Always present — a daemon that is syncing still
    /// answers, and a consumer that only needs to *describe* what it holds
    /// (the serve-set witness) must keep doing so while refusing to *act*.
    pub(crate) fn source(&self) -> &EmissionClaimSource {
        &self.source
    }

    /// Take the record, once its vouching has been decided.
    ///
    /// Consuming rather than cloning: the acting lanes need to own the
    /// source, and a `clone` here would copy every epoch snapshot in it
    /// purely to satisfy a borrow.
    pub(crate) fn into_source(self) -> EmissionClaimSource {
        self.source
    }

    /// The view to act on, or the reason there is none.
    ///
    /// For consumers that **act on the record's contents** — signing a claim
    /// against its gather tip, reading an exit verdict out of its cooldown.
    /// A rolled-back record is refused here rather than clocked around,
    /// because no choice of clock repairs contents drawn from a view the
    /// chain has abandoned.
    pub(crate) fn actionable(&self) -> Result<AnchoredView, TimelineBreak> {
        match self.vouching {
            Vouching::Vouched(view) => view.anchored(),
            Vouching::Broken(why) => Err(why),
        }
    }
}

impl VouchedClaimSource {
    /// Pair a response with a vouching **without** having read a witness.
    ///
    /// Test-only, and deliberately not feature-gated, for the same reason
    /// [`ClaimSourceFor::for_test`] is not: production has exactly one way
    /// to obtain this pair, and this is the hatch that lets a test build the
    /// states production refuses in order to assert that it refuses them.
    /// Vouches at the record's own height, so a test that does not care
    /// about the sync axis reads as though it were synced.
    #[cfg(test)]
    pub(crate) fn for_test(source: EmissionClaimSource) -> Self {
        let facts = crate::engine::daemon::synced_chain_facts::SyncedChainFacts::new(
            source.chain_height,
            true,
            source.tip_hash,
        )
        .expect("test vouching is synchronized by construction");
        let vouching = Vouching::Vouched(CoherentChainView::reconcile(&facts, source.anchor()));
        Self { source, vouching }
    }

    /// Pair a response with an explicit vouching, for tests that assert what
    /// production **refuses**. Same hatch as [`Self::for_test`], same
    /// reason it is not feature-gated.
    #[cfg(test)]
    pub(crate) fn for_test_with_vouching(source: EmissionClaimSource, vouching: Vouching) -> Self {
        Self { source, vouching }
    }
}

/// Fetch the sync witness and then the claim source, and reconcile them.
///
/// **The order is the contract.** The witness is read first and awaited
/// before the record request is issued, so the record can only be equal or
/// later in wall-clock time; a record *height* below the witness is
/// therefore a rollback, not a race. Reversing these two lines would not
/// change what any caller reads — it would change what a rolled-back read
/// looks like, silently — which is exactly why callers do not get to write
/// them.
///
/// Deliberately **not** a `tokio::join!` of the two: the concurrency saved
/// is one round trip on a path that then signs a transaction, and the
/// ordering it destroys is the whole guarantee. Callers that want
/// concurrency can join *this* future with an independent one — a local
/// store read, say — which is safe because the ordering that matters is
/// internal.
///
/// **No bracket.** The record names the block it was gathered at, read in
/// the same snapshot (IG-Q84), so it says on its own which chain it
/// describes; a reorg that crosses the witness tip and catches back up
/// inside the window changes nothing a re-read could add. Two sequential
/// round trips: witness, record.
///
/// # Errors
///
/// [`EmissionSourceError`] only for the record read. A failed *facts* read
/// is not an error here: it is [`Vouching::Broken`],
/// because the record may still be worth describing even when it cannot be
/// acted on.
pub(crate) async fn fetch_vouched_claim_source<R: Rpc>(
    rpc: &R,
    p_id: &[u8; 32],
) -> Result<VouchedClaimSource, EmissionSourceError> {
    // Witness first, and awaited, before the record request is issued.
    let witness = fetch_synced_chain_facts(rpc).await;
    let source = fetch_emission_claim_source(rpc, p_id).await?;
    // The record names its own block, so it needs no re-read after it: the
    // witness is the sync gate and the height a record must not fall below.
    let vouching = match witness {
        Ok(Some(facts)) => Vouching::Vouched(CoherentChainView::reconcile(&facts, source.anchor())),
        Ok(None) => Vouching::Broken(TimelineBreak::DaemonSyncing),
        Err(e) => Vouching::Broken(TimelineBreak::from_facts_error(&e)),
    };
    Ok(VouchedClaimSource { source, vouching })
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
/// `AssembleRelease` handler separately proves that `P` is the one whose
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
/// on-chain as dormant balances, and "releasing a retired persona later needs
/// that persona's `bond_spend` key" — dropping them "bricks releasing". So the
/// persona being exited is routinely **not** the active one, several are held at
/// once, and a caller really can pair one persona's record with another's
/// handle. That is the arm `AssembleRelease` refuses.
///
/// It is also why the exit must **not** copy `drain_to_principal`'s shape. That
/// façade resolves `active_persona()` and takes no slot parameter, which is
/// right for a `P`-lane spend and wrong here: applied to the exit it would brick
/// releasing every retired-but-bonded persona. *One persona on the wire at a
/// time* is the invariant (no simultaneous wire activity — the firewall permits
/// the dormant balances); *"only the active persona can be released"* is not,
/// and the two read alike.
#[derive(Debug, Clone)]
pub struct ClaimSourceFor {
    p_id: PCanonicalId,
    vouched: VouchedClaimSource,
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
        self.vouched.source()
    }

    /// The chain view this record may be acted on against, or why it may
    /// not be.
    ///
    /// The **second** binding this type carries. Its own doc argues that
    /// `(p_id, response)` as two arguments is a label rather than a binding;
    /// exactly the same is true of `(witness, response)`, and for the same
    /// reason — a caller holding one persona's witness and another moment's
    /// record can pair them, and every downstream check then agrees with the
    /// pairing rather than with the chain. So the witness is acquired with
    /// the record, inside one constructor, and cannot be re-associated.
    pub(crate) fn actionable(&self) -> Result<AnchoredView, TimelineBreak> {
        self.vouched.actionable()
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
        Self {
            p_id,
            vouched: VouchedClaimSource::for_test(source),
        }
    }

    /// The binding in an explicit vouching state — the states the exit
    /// path must refuse, constructed so that refusal can be observed.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn for_test_with_vouching(
        p_id: PCanonicalId,
        source: EmissionClaimSource,
        vouching: Vouching,
    ) -> Self {
        Self {
            p_id,
            vouched: VouchedClaimSource::for_test_with_vouching(source, vouching),
        }
    }
}

/// Fetch the claim source for `p_id`, keeping the two bound together.
///
/// **Not a convenience wrapper over [`fetch_emission_claim_source`] — it is the
/// binding.** The bare fetch returns facts with no record of whose they are, so
/// a consumer that needs to know (anything on the `Release` readiness/exit path)
/// would have to re-attach an id by hand, which is the mislabeling
/// [`ClaimSourceFor`] exists to make impossible. Reach for this one there, and
/// do not collapse the two: the delegation is a single line precisely so the
/// pair cannot drift, and the bare form stays for consumers (the claim
/// orchestrator, the serve-set pinner) that already carry `P` in their own
/// context and read only the record's contents.
pub async fn fetch_claim_source_for<R: Rpc>(
    rpc: &R,
    p_id: PCanonicalId,
) -> Result<ClaimSourceFor, EmissionSourceError> {
    let vouched = fetch_vouched_claim_source(rpc, p_id.as_bytes()).await?;
    Ok(ClaimSourceFor { p_id, vouched })
}

#[cfg(test)]
#[path = "emission_source_tests.rs"]
mod tests;
