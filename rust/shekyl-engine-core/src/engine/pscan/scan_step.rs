// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-3/SP-5 — the dual-extractor scan-step: the bounded, public message/result
//! types and the pure [`run_dual_extractor`] the actor offloads.
//!
//! ## SP-3 — one block-iteration, two extractors
//!
//! [`run_dual_extractor`] sweeps each block of a [`BlockRange`] with **two**
//! extractors over the same decoded block
//! (`docs/design/ARCHIVAL_BOND_2D1_PSCAN_PLAN.md` §6 SP-3):
//!
//! 1. **Funding** (view-key, *secret*): each bonded persona's
//!    [`GuaranteedScanner`] recovers its owned outputs; their amounts sum per
//!    [`SettlementEpoch`]. The burning-bug-immune `Guaranteed` variant is forced
//!    by the input type (SP-1), so a corrupted-inflow `C_min` mis-size (DQ7) is
//!    unrepresentable here.
//! 2. **Bond-post** (cleartext, *no secret*): the block's `Input::BondPost`s whose
//!    `p_canonical_id` is one of ours are collected for SP-6 reconcile.
//!
//! ## SP-5 — runs inside the actor, offloaded; only public data crosses
//!
//! The [`StakeEngine`](crate::engine::stake_engine) handler clones the bonded
//! union's transient scanners (DQ5) and offloads [`run_dual_extractor`] to
//! `spawn_blocking`. The secret scanners live **only** inside that closure and
//! drop at its end; `view_sk` never crosses the actor boundary. The
//! [`ScanStepResult`] that comes back is public — per-epoch funding *deltas* and
//! public bond-post matches.
//!
//! ## Why the message carries blocks, not heights-only
//!
//! The design sketch had the actor fetch from a `BlockSource` inside the handler;
//! we refine that: the **task** owns the `BlockSource` and fetches
//! (`…PSCAN_PLAN.md` §6 SP-5, "the task owns … the `BlockSource`"), and
//! [`ScanStep`] carries the already-fetched blocks. Blocks are public chain data,
//! so this keeps network I/O out of the single-threaded actor mailbox (the
//! design's own anti-blocking concern, DQ6) without weakening the SP-4
//! anti-injection rule: the message carries blocks, **never** a `PFundingInflow`.
//!
//! ## A scan-step is a *partial* epoch — deltas, not a finalized inflow
//!
//! A settlement epoch is `SETTLEMENT_EPOCH_BLOCKS` (`10_000`) blocks; a bounded
//! scan-step covers far fewer. So a step **cannot** finalize SP-4's
//! `PFundingInflow` (which is a recompute over an epoch's *complete* confirmed
//! set). [`run_dual_extractor`] therefore returns per-epoch *deltas*; the driving
//! task (PR-B) accumulates them and finalizes the per-epoch inflow at epoch-close.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_archival_retention::consensus_state::settlement_epoch_at_height;
use shekyl_scanner::{GuaranteedScanner, ScannableBlock};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{BondPostKind, Input};

/// Hard ceiling on the blocks one [`ScanStep`] may carry — the **enforced** form
/// of DQ6's "bounded per message" (the actor holds `&mut self` across the offload,
/// so an unbounded batch stalls its mailbox and balloons memory). This is a
/// fail-closed **backstop** against a task bug or test misuse, *not* the tuning
/// knob: PR-B's driving task sizes real batches far smaller (sized against the
/// worst-case block, to interleave rotation/sign). [`run_dual_extractor`] rejects
/// anything over it.
pub(crate) const MAX_SCAN_STEP_BLOCKS: u64 = 1024;

/// A bounded, half-open block-height range `[start, end)` — the unit of one
/// scan-step. **Bounded per message** (DQ6): the driving task loops over small
/// ranges so the actor interleaves rotation/sign between batches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockRange {
    start: BlockHeight,
    /// Exclusive upper bound.
    end: BlockHeight,
}

impl BlockRange {
    /// Number of blocks in the range — always `>= 1`, since the type is **non-empty by
    /// construction** (see [`new`](Self::new)).
    pub(crate) fn block_count(&self) -> u64 {
        self.end.to_raw() - self.start.to_raw()
    }

    /// Height of the `i`-th block in the range (`start + i`). The caller must keep
    /// `i < len()`.
    fn height_at(&self, i: usize) -> BlockHeight {
        BlockHeight::from_raw(self.start.to_raw() + i as u64)
    }
}

// Constructor + bounds accessors: consumed by tests now and by the PR-B driving
// task (range construction + cursor bookkeeping). Held under a transient allow
// until that task lands — kept separate from the live `impl` above so the
// dead-code lint still covers `block_count`/`height_at`.
#[allow(dead_code)]
impl BlockRange {
    /// A **non-empty** half-open `[start, end)` range, or `None` if it would be empty or
    /// inverted (`start >= end`). Non-emptiness is the type invariant — a scan-step over zero
    /// blocks is meaningless, and downstream gates ([`CoverDiscovery::classify`](super::cover_discovery::CoverDiscovery))
    /// rely on every `BlockRange` covering at least one block — so the check lives here once
    /// rather than being re-asserted at each use.
    pub(crate) fn new(start: BlockHeight, end: BlockHeight) -> Option<Self> {
        (start.to_raw() < end.to_raw()).then_some(Self { start, end })
    }

    /// Inclusive lower bound.
    pub(crate) fn start(&self) -> BlockHeight {
        self.start
    }

    /// Exclusive upper bound.
    pub(crate) fn end(&self) -> BlockHeight {
        self.end
    }
}

/// The actor scan-step message (SP-5): a bounded range and its already-fetched
/// blocks, `blocks[i]` aligned to height `range.start + i`.
///
/// **Public input only.** Blocks are public chain data; there are no secrets and
/// — per SP-4's anti-injection rule — **no `PFundingInflow` inbound**. The only
/// in-crate sender is the P-scan task, which fetches from its `BlockSource`.
pub(crate) struct ScanStep {
    /// The bounded height range this step covers.
    pub(crate) range: BlockRange,
    /// Blocks aligned to `range`: `blocks[i]` is the block at `range.start + i`.
    /// `blocks.len()` must equal `range.len()`.
    pub(crate) blocks: Vec<ScannableBlock>,
}

/// One settlement epoch's confirmed funding **delta** from a single step
/// (public). A step is a partial epoch, so this is a contribution the task
/// accumulates; the per-epoch `PFundingInflow` is finalized at epoch-close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EpochInflowDelta {
    /// The settlement epoch the contributing blocks fall in.
    pub(crate) epoch: SettlementEpoch,
    /// Checked sum of the confirmed owned-output amounts in this step at `epoch`.
    pub(crate) amount: AtomicUnits,
}

/// A matched archival bond-post (public) — the cleartext half of the dual
/// extractor, for SP-6 reconcile. Carries the height and post-kind byte so a
/// later reconcile pass can act on lifecycle posts (e.g. `Unbond`) without a
/// re-scan.
///
/// `Debug` is **redacted**: the `(p_canonical_id, height, post_kind)` tuple is a row of
/// `P`'s persona-activity history (the firewall's whole purpose is to keep that
/// off-disk/off-log in the clear), so it carries the same no-clear-`Debug` discipline as
/// its persisted twin [`BondPostRecord`](shekyl_engine_state::pscan_state::BondPostRecord),
/// not the looser treatment a public amount-delta gets.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct BondPostMatch {
    /// Height of the block carrying the post (from the step's range).
    pub(crate) height: BlockHeight,
    /// The matched persona's cleartext canonical id (the domain newtype; the wire
    /// `[u8; 32]` is lifted at the match site below).
    pub(crate) p_canonical_id: PCanonicalId,
    /// Wire post-kind byte (`0` = JoinMarket; otherwise the `Other` tag).
    pub(crate) post_kind: u8,
}

impl std::fmt::Debug for BondPostMatch {
    /// Redacted — see the type docs. Never render the persona-history contents through
    /// a log / error / `{:?}` path.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BondPostMatch(<redacted persona-history>)")
    }
}

/// Public result of one scan-step — only public extraction outputs cross the
/// actor boundary (the secret scanners stay in the offload closure).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScanStepResult {
    /// The range this step covered (for the task's cursor bookkeeping).
    pub(crate) range: BlockRange,
    /// Per-epoch confirmed funding deltas (sorted by epoch).
    pub(crate) funding: Vec<EpochInflowDelta>,
    /// Bond-posts in this range whose `p_canonical_id` is one of ours.
    pub(crate) bond_post_matches: Vec<BondPostMatch>,
}

/// Why a dual-extraction failed. All arms fail **closed** — a corrupted scan
/// mis-sizes a privacy parameter (`C_min`), so we never paper over one.
#[derive(Debug)]
pub(crate) enum DualExtractError {
    /// `blocks.len()` did not equal `range.len()` — the task's range↔block
    /// alignment invariant was violated; refuse rather than mis-attribute.
    RangeBlockMismatch { range_len: u64, blocks: usize },
    /// The step exceeded [`MAX_SCAN_STEP_BLOCKS`] — the "bounded per message"
    /// invariant (DQ6) enforced, not merely contracted: an unbounded batch would
    /// stall the single-threaded actor mailbox and balloon memory. Fail closed so
    /// a task bug or test misuse cannot starve rotation/sign.
    StepTooLarge { len: u64, max: u64 },
    /// A persona scan returned an error (malformed block / unsupported protocol).
    Scan(shekyl_scanner::ScanError),
    /// An epoch's confirmed inflow summed past `u64::MAX` (an attacker-stuffed or
    /// impossible amount set). Fail closed rather than wrap a money total.
    InflowOverflow { epoch: SettlementEpoch },
}

impl std::fmt::Display for DualExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RangeBlockMismatch { range_len, blocks } => write!(
                f,
                "scan-step range covers {range_len} blocks but {blocks} were supplied"
            ),
            Self::StepTooLarge { len, max } => write!(
                f,
                "scan-step covers {len} blocks, over the {max}-block bound (DQ6)"
            ),
            Self::Scan(e) => write!(f, "persona scan failed: {e}"),
            Self::InflowOverflow { epoch } => {
                write!(f, "funding inflow overflowed u64 at epoch {epoch:?}")
            }
        }
    }
}

impl std::error::Error for DualExtractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Scan(e) => Some(e),
            Self::RangeBlockMismatch { .. }
            | Self::StepTooLarge { .. }
            | Self::InflowOverflow { .. } => None,
        }
    }
}

/// The wire post-kind byte (JoinMarket's dense tag is `0x00`,
/// `shekyl_wire::transaction` §9.11).
fn post_kind_byte(kind: &BondPostKind) -> u8 {
    match kind {
        BondPostKind::JoinMarket { .. } => 0,
        BondPostKind::Other(b) => *b,
    }
}

/// SP-3 — the dual extractor. Runs **off** the actor thread (the handler offloads
/// it to `spawn_blocking`); the secret `scanners` live only here and drop at
/// return (DQ5). Returns **only** public data.
///
/// `known_ids` is the bonded union's cleartext `p_canonical_id` set; `range` and
/// `blocks` are aligned (`blocks[i]` at `range.start + i`).
pub(crate) fn run_dual_extractor(
    mut scanners: Vec<GuaranteedScanner>,
    known_ids: &BTreeSet<PCanonicalId>,
    range: BlockRange,
    blocks: &[ScannableBlock],
) -> Result<ScanStepResult, DualExtractError> {
    // Enforce DQ6's bound first, rather than trust the caller (the actor mailbox
    // is blocked for the step's duration); then check the range↔block alignment.
    if range.block_count() > MAX_SCAN_STEP_BLOCKS {
        return Err(DualExtractError::StepTooLarge {
            len: range.block_count(),
            max: MAX_SCAN_STEP_BLOCKS,
        });
    }
    if blocks.len() as u64 != range.block_count() {
        return Err(DualExtractError::RangeBlockMismatch {
            range_len: range.block_count(),
            blocks: blocks.len(),
        });
    }

    // Per-epoch confirmed amounts, accumulated with a running checked add so an
    // overflow fails closed immediately and no per-output buffer is held. An
    // epoch entry is created lazily (only on a recovered output), so an epoch with
    // nothing of ours yields no delta rather than a spurious zero.
    let mut by_epoch: BTreeMap<SettlementEpoch, AtomicUnits> = BTreeMap::new();
    let mut bond_post_matches = Vec::new();

    for (i, block) in blocks.iter().enumerate() {
        let height = range.height_at(i);
        let epoch = SettlementEpoch::from_raw(settlement_epoch_at_height(height.to_raw()));

        // (b) public bond-post match — reads inputs, no secret, no clone.
        for tx in &block.transactions {
            for input in &tx.prefix.inputs {
                if let Input::BondPost(bp) = input {
                    // Lift the wire `[u8; 32]` into the domain id once, at the
                    // wire→domain boundary, then match + carry the typed value.
                    let id = PCanonicalId::from_bytes(bp.p_canonical_id);
                    if known_ids.contains(&id) {
                        bond_post_matches.push(BondPostMatch {
                            height,
                            p_canonical_id: id,
                            post_kind: post_kind_byte(&bp.kind),
                        });
                    }
                }
            }
        }

        // (a) funding — scan with each bonded persona's scanner. `scan` consumes
        // the block, so clone per scanner; an output belongs to at most one
        // persona, so no cross-scanner double-count.
        for scanner in &mut scanners {
            let recovered = scanner
                .scan(block.clone())
                .map_err(DualExtractError::Scan)?;
            for out in recovered.into_inner() {
                let acc = by_epoch.entry(epoch).or_insert(AtomicUnits::ZERO);
                *acc = acc
                    .checked_add(out.amount())
                    .ok_or(DualExtractError::InflowOverflow { epoch })?;
            }
        }
    }

    let funding = by_epoch
        .into_iter()
        .map(|(epoch, amount)| EpochInflowDelta { epoch, amount })
        .collect();

    Ok(ScanStepResult {
        range,
        funding,
        bond_post_matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
    use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
    use shekyl_crypto_pq::archival_p::{derive_archival_p_keys, ArchivalPKeys};
    use shekyl_crypto_pq::kem::HybridKemPublicKey;
    use shekyl_scanner::bench_fixtures::{
        build_typical_case_scannable_block, scannable_block_for_recipient,
    };
    use shekyl_wire::transaction::BondPost;
    use shekyl_wire::Holdings;

    use crate::engine::pscan::persona_scanner::guaranteed_scanner_for_persona;

    const SEED: [u8; MASTER_SEED_BYTES] = [0x07u8; MASTER_SEED_BYTES];

    fn persona(slot: u32) -> ArchivalPKeys {
        derive_archival_p_keys(&SEED, DerivationNetwork::Fakechain, SeedFormat::Raw32, slot)
            .expect("derive a test persona")
    }

    /// The cleartext canonical id the way an on-chain bond-post carries it.
    fn canonical_id(p: &ArchivalPKeys) -> PCanonicalId {
        let bytes = p
            .hybrid_bond_id()
            .to_canonical_bytes()
            .expect("hybrid id encodes");
        p_canonical_id_from_hybrid_pubkey(&bytes)
    }

    /// A block carrying one output addressed to `recipient`.
    fn funding_block(recipient: &ArchivalPKeys) -> ScannableBlock {
        let kem = HybridKemPublicKey {
            x25519: recipient.x25519_pk,
            ml_kem: recipient.ml_kem_ek.to_vec(),
        };
        scannable_block_for_recipient(1, &kem, recipient.spend_pk.as_canonical_bytes())
    }

    /// A JoinMarket bond-post for persona `p`.
    fn bond_post_for(p: &ArchivalPKeys) -> BondPost {
        BondPost {
            hybrid_public_key: p.hybrid_bond_id().to_canonical_bytes().expect("encode"),
            p_canonical_id: canonical_id(p).to_bytes(),
            kind: BondPostKind::JoinMarket {
                bond_spend_pk: Vec::new(),
            },
            holdings: Holdings::CompleteTree,
            bonded_total_atomic: 1_000,
            bond_credit: 1_000,
            bond_debit: 0,
        }
    }

    fn range(start: u64, end: u64) -> BlockRange {
        BlockRange::new(BlockHeight::from_raw(start), BlockHeight::from_raw(end)).expect("range")
    }

    #[test]
    fn block_range_is_non_empty_by_construction() {
        // The invariant the cover-discovery gate (and the scan loop) rely on: a `BlockRange`
        // always covers at least one block. Empty (`start == end`) and inverted
        // (`start > end`) both fail closed to `None`, so no empty range can ever reach a
        // consumer — there is no empty-window edge to re-guard downstream.
        assert!(
            BlockRange::new(BlockHeight::from_raw(5), BlockHeight::from_raw(5)).is_none(),
            "empty range rejected"
        );
        assert!(
            BlockRange::new(BlockHeight::from_raw(6), BlockHeight::from_raw(5)).is_none(),
            "inverted range rejected"
        );
        let r = BlockRange::new(BlockHeight::from_raw(5), BlockHeight::from_raw(6))
            .expect("single-block range is valid");
        assert_eq!(r.block_count(), 1);
    }

    #[test]
    fn funding_sums_owned_outputs_at_the_range_epoch() {
        let p = persona(0);
        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        // Height 20_001 → settlement epoch 2 (SETTLEMENT_EPOCH_BLOCKS = 10_000).
        let res = run_dual_extractor(
            vec![scanner],
            &BTreeSet::new(),
            range(20_001, 20_002),
            &[funding_block(&p)],
        )
        .expect("extract");

        assert_eq!(res.funding.len(), 1, "one epoch touched");
        assert_eq!(res.funding[0].epoch, SettlementEpoch::from_raw(2));
        assert!(
            res.funding[0].amount > AtomicUnits::ZERO,
            "the persona's own output was summed into the epoch delta"
        );
        assert!(res.bond_post_matches.is_empty());
    }

    #[test]
    fn bond_post_matches_only_known_canonical_ids() {
        let mine = persona(0);
        let other = persona(1);

        // A foreign block (no outputs we own) carrying two bond-posts: ours + a
        // stranger's. Adding inputs to an existing tx keeps its Ct valid.
        let mut block = build_typical_case_scannable_block(1);
        let tx = block.transactions.get_mut(0).expect("a non-miner tx");
        tx.prefix
            .inputs
            .push(Input::BondPost(Box::new(bond_post_for(&mine))));
        tx.prefix
            .inputs
            .push(Input::BondPost(Box::new(bond_post_for(&other))));

        let scanner = guaranteed_scanner_for_persona(&mine).expect("scanner");
        let known = BTreeSet::from([canonical_id(&mine)]);
        let res =
            run_dual_extractor(vec![scanner], &known, range(5, 6), &[block]).expect("extract");

        assert_eq!(
            res.bond_post_matches.len(),
            1,
            "only our canonical id matches; the stranger's post is ignored"
        );
        assert_eq!(res.bond_post_matches[0].p_canonical_id, canonical_id(&mine));
        assert_eq!(res.bond_post_matches[0].height, BlockHeight::from_raw(5));
        assert_eq!(res.bond_post_matches[0].post_kind, 0, "JoinMarket tag");
        assert!(
            res.funding.is_empty(),
            "no outputs we own in a foreign block"
        );
    }

    /// The Unbond-detection seam (2d-1 DQ8): the extractor carries the wire kind
    /// byte unchanged, and that byte equals the consensus `Unbond` discriminant the
    /// task's `record_unbonds` matches on. Pins the cross-crate byte equivalence
    /// (`shekyl-wire` `Other(b)` ↔ `archival_retention::BondPostKind::Unbond`)
    /// end-to-end so it cannot drift before the wire format freezes — the seam was
    /// otherwise only covered by tests that hand-set `post_kind`.
    #[test]
    fn extractor_carries_the_consensus_unbond_byte() {
        let unbond_byte = shekyl_archival_retention::BondPostKind::Unbond as u8;
        assert_eq!(unbond_byte, 2, "genesis-frozen Unbond discriminant");

        let mine = persona(0);
        let mut block = build_typical_case_scannable_block(1);
        let tx = block.transactions.get_mut(0).expect("a non-miner tx");
        // An Unbond bond-post: the consensus Unbond byte on the wire as `Other(b)`
        // (genesis wire is JoinMarket-only, so this models the post-genesis form).
        let mut post = bond_post_for(&mine);
        post.kind = BondPostKind::Other(unbond_byte);
        tx.prefix.inputs.push(Input::BondPost(Box::new(post)));

        let scanner = guaranteed_scanner_for_persona(&mine).expect("scanner");
        let known = BTreeSet::from([canonical_id(&mine)]);
        let res =
            run_dual_extractor(vec![scanner], &known, range(5, 6), &[block]).expect("extract");

        assert_eq!(res.bond_post_matches.len(), 1);
        assert_eq!(
            res.bond_post_matches[0].post_kind, unbond_byte,
            "the extractor carries the wire kind byte unchanged through to record_unbonds"
        );
    }

    #[test]
    fn dual_extracts_funding_and_bond_post_in_one_block() {
        let p = persona(0);
        let mut block = funding_block(&p);
        block.transactions[0]
            .prefix
            .inputs
            .push(Input::BondPost(Box::new(bond_post_for(&p))));

        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        let known = BTreeSet::from([canonical_id(&p)]);
        let res =
            run_dual_extractor(vec![scanner], &known, range(7, 8), &[block]).expect("extract");

        assert_eq!(res.funding.len(), 1, "funding recovered");
        assert_eq!(res.bond_post_matches.len(), 1, "bond-post matched");
    }

    #[test]
    fn rejects_a_range_block_count_mismatch() {
        let p = persona(0);
        let scanner = guaranteed_scanner_for_persona(&p).expect("scanner");
        // Range covers 3 blocks; only 1 supplied.
        let err = run_dual_extractor(
            vec![scanner],
            &BTreeSet::new(),
            range(0, 3),
            &[funding_block(&p)],
        )
        .expect_err("mismatch must fail closed");
        assert!(matches!(
            err,
            DualExtractError::RangeBlockMismatch {
                range_len: 3,
                blocks: 1
            }
        ));
    }

    #[test]
    fn rejects_a_step_over_the_dq6_bound() {
        // A range past the bound fails closed before any block work — the guard is
        // on the range size, so no oversized block vec is needed to exercise it.
        let err = run_dual_extractor(
            Vec::new(),
            &BTreeSet::new(),
            range(0, MAX_SCAN_STEP_BLOCKS + 1),
            &[],
        )
        .expect_err("an oversized step must fail closed");
        assert!(matches!(
            err,
            DualExtractError::StepTooLarge { len, max }
                if len == MAX_SCAN_STEP_BLOCKS + 1 && max == MAX_SCAN_STEP_BLOCKS
        ));
    }
}
