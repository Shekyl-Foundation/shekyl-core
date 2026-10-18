// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block at each stage of judgement: the untrusted [`Candidate`] going
//! into `form`, the [`StructurallyValid`] it hands to `validate`, and the
//! typed [`ValidatedBlock`] coming out inside a `ChainValid`.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::archival::AttestationWitness;
use shekyl_types::{
    BlockHash, BlockHeight, CurveTreeRoot, PowHash, PqcAuthHash, PrunableHash, Timestamp, TxHash,
};

use shekyl_wire::{Block, BlockHeader, Transaction};

use crate::archival::ArchivalDelta;
use crate::coverage::RuleCoverage;
use crate::drain::Drain;
use crate::fault::FormAttempt;
use crate::rule_set::{RuleSet, RuleSetId};
use crate::rules::block_weight::Weights;
use crate::rules::difficulty::Target;
use crate::rules::reward::PaidEmission;
use crate::verdict::TxSlot;
use crate::view::{AtHeight, HeaderView};

/// A transaction's identities, derived once (CEN-B6) beside its body.
///
/// The txid and the two **discardable components** it was built over: the
/// digest of the per-input `pqc_auths` (the txid's third component,
/// `PDM-Q-F26`) and the digest of the prunable region (its fourth, S-CHAIN-W
/// SCW-10) — the values the chain store records as `txs_pqc_auth_hash` and
/// `txs_prunable_hash` so a node that keeps only the skeleton can still
/// reconstruct the txid it accepted (`Transaction::hash_with_supplied_components`,
/// with the archival length the store measured at connect, `txs_archival_len`).
/// All three come from the same `validate`, copied from
/// [`Transaction::txid_parts`] so no consumer re-hashes a body and the store
/// never derives a consensus-visible value (C2-R8 Q4).
///
/// `pqc_auth_hash` is `None` exactly when the txid is **3-part** — a
/// coinbase, a serve-credit, the malformed gen-first and no-input shapes —
/// a fact about the identity, not about what was kept; see [`PqcAuthHash`].
/// For a coinbase `prunable_hash` is `keccak256("")` — what the C++ store
/// writes — not the txid's null-hash substitute; see [`PrunableHash`].
///
/// The store row this feeds (`txs_pqc_auth_hash`, `DAEMON_REDB_STORE.md`
/// §7.7 item 3) is held to a **three-leg** invariant, because under
/// `PDM-Q6` a hash row *without* its segment is the steady state of every
/// 4-part tx below the universal window `W`, not a fault:
///
/// 1. hash row present ⇔ txid 4-part — permanent, written at connect,
///    never deleted (`validate` rejects the shapes — gen-first or no-input
///    with auths — that could split "4-part" from "segment non-empty");
/// 2. segment present ⇒ hash row present — a body the store cannot verify
///    is the violation;
/// 3. hash row present ∧ segment absent ⇔ *discarded* — below `W` and not
///    a retention exception, or never held (a band-1 skeleton). One store
///    state with one meaning, however the node arrived at it.
///
/// So `None` here is *the txid has no third component*; leg 3 is *the
/// component exists and the bytes do not*. Different facts, never one
/// representation. A `PDM-Q6` ruling that keeps `pqc_auths` universal
/// retires the *row*, not the component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxIdentity {
    /// The transaction hash (txid).
    pub hash: TxHash,
    /// The txid's third component, or `None` for a 3-part txid.
    pub pqc_auth_hash: Option<PqcAuthHash>,
    /// `keccak256` of the prunable byte region.
    pub prunable_hash: PrunableHash,
}

impl TxIdentity {
    fn of(tx: &Transaction) -> Self {
        let parts = tx.txid_parts();
        Self {
            hash: parts.hash,
            pqc_auth_hash: parts.pqc_auth_hash,
            prunable_hash: parts.prunable_hash,
        }
    }
}

/// The untrusted input to `validate`: the block as received, plus the bodies
/// of the transactions its header lists, in listed order, plus the
/// attestation-witness sidecar that travelled beside them.
///
/// Public fields — this is the outside. Nothing about it has been checked,
/// including whether `transactions` are the bodies `block.transaction_hashes`
/// names; that is a 4.G rule and lands with its slice. One value rather than
/// two arguments (round-1 ruling Q9). `#[non_exhaustive]` so a further
/// component is a constructor-site addition, not a breaking struct literal
/// (the Q9 "non-breaking" claim; Copilot #753) — the witness was the first
/// such addition (DRS-E4 commit 5).
///
/// ```compile_fail
/// use shekyl_chain_rules::Candidate;
/// let _ = Candidate { block: todo!(), transactions: todo!(), attestation_witness: None };
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The block: header, miner transaction, listed transaction hashes.
    pub block: Block,
    /// The listed transactions' bodies, in the header's order.
    pub transactions: Vec<Transaction>,
    /// The attestation witness carried beside the block — **not in it**
    /// (`DRS_E4_ARCHIVAL_WRITER.md` §3.2 phase 5): the C++ sync wire's
    /// `block_complete_entry::attestation_witness`, `None` for an empty
    /// attestation set. CEN-B4's operand (`rules::attestation`, E6 slice 8
    /// row 10): `None` is judged as the empty set against the header's
    /// `attestation_root`, `Some` as the recompute over the coinbase's kept
    /// headers and every record's countersignature; the verdict carries it
    /// to the store, which records it at the block's height.
    pub attestation_witness: Option<AttestationWitness>,
}

impl Candidate {
    /// Every distinct `reference_block` the listed bodies name — the
    /// references a caller claims to `form` ([`ReferenceClaims`]). The
    /// miner transaction names none (CEN-H15: a coinbase carries no
    /// membership proof), so a coinbase-only block names nothing.
    #[must_use]
    pub fn proof_references(&self) -> BTreeSet<BlockHash> {
        self.transactions
            .iter()
            .filter_map(crate::rules::tx_against::proof_reference)
            .collect()
    }

    /// Assemble a candidate from the block as received and the listed
    /// bodies, in listed order, with no attestation witness — the shape of
    /// every block whose attestation set is empty, which is every block a
    /// format-2 capture carries (§3.2 phase 5: the RPC edge the corpus
    /// fetcher uses does not carry the sidecar).
    #[must_use]
    pub fn new(block: Block, transactions: Vec<Transaction>) -> Self {
        Self {
            block,
            transactions,
            attestation_witness: None,
        }
    }

    /// The same candidate with the sidecar attached.
    #[must_use]
    pub fn with_attestation_witness(mut self, witness: Option<AttestationWitness>) -> Self {
        self.attestation_witness = witness;
        self
    }
}

/// A candidate that passed the **stateless stage** (`form`): every rule
/// decidable without the chain, plus what those rules established and the
/// view-bound stage will read or verify.
///
/// The token between the two stages (`CHAIN_RULES_SLICE_2.md` §4.2). `form`
/// runs outside the write transaction, in parallel; `validate` takes this
/// type — never a bare `Candidate` — so the view-bound stage cannot be
/// reached without the stateless one, the same move that makes a
/// `ChainValid` unmintable outside `connect`. What it carries besides the
/// candidate:
///
/// * `rule_set` — the rules the caller **claimed** were in force, as the
///   set itself (not only its id). `validate` compares with `PartialEq`
///   and returns [`Stale::RuleSet`](crate::Stale::RuleSet) on a mismatch.
///   The id alone is not the set: a Fakechain `Fixed` target reuses
///   `RuleSetId::GENESIS` (Q10), so two sets at the same id can differ.
/// * `seed` — the block id the caller **claimed** sits at the seed height
///   (CEN-D3). `validate` verifies it against the committing view and
///   returns [`Stale::Seed`](crate::Stale::Seed) on a mismatch.
/// * `target` — the difficulty the caller **claimed** CEN-D4 derives for
///   the connecting height, a function of the headers below it alone.
///   `form` judges CEN-D1 against it, before any body work, so a block
///   short of its proof-of-work costs RandomX and nothing more. `validate`
///   and `alt_against` derive D4 over their view and return
///   [`Stale::Target`](crate::Stale::Target) on a mismatch.
/// * `pow` — the RandomX longhash under that seed (CEN-D2), computed here
///   because it is the most expensive call in the validator and this stage
///   runs outside the write transaction.
/// * `coverage` — every stateless row, the transactions' included: `form`
///   runs `tx_form` at the miner slot and every listed slot, and CEN-H19's
///   batch over the listed proofs, so the view-bound stage judges only what
///   reads the chain.
/// * `judged_at` — the wall clock at `form`. **This makes the verdict
///   time-dependent**: a `StructurallyValid`, and the `ChainValid` minted
///   from it, is no longer a pure function of `(candidate, view, rule_set)`.
///   The FTL leg (CEN-C1) was judged against *this* instant. The window is
///   small because the brand ties a `ChainValid` to a live batch, but
///   anything that caches or defers one lets that leg go stale silently —
///   which is why the instant is carried rather than forgotten: a consumer
///   can see how old the judgement is.
/// * `attempt` — which try at `form` this is, so a `Stale` fault can say
///   whether another is allowed ([`Retry`](crate::Retry)).
///
/// Constructed only by `form`; the fields are private and there is no
/// public constructor (G5):
///
/// ```compile_fail
/// use shekyl_chain_rules::StructurallyValid;
/// let forged = StructurallyValid {
///     candidate: todo!(),
///     rule_set: todo!(),
///     coverage: todo!(),
///     judged_at: todo!(),
///     seed: todo!(),
///     pow: todo!(),
///     attempt: todo!(),
///     references: todo!(),
/// };
/// ```
///
/// Not `Clone`: a stage token has one consumer.
#[must_use = "a StructurallyValid is the input to `validate`; dropping it discards the stateless stage's work"]
pub struct StructurallyValid {
    candidate: Candidate,
    rule_set: RuleSet,
    coverage: RuleCoverage,
    judged_at: Timestamp,
    hash: BlockHash,
    seed: BlockHash,
    target: Target,
    pow: PowHash,
    attempt: FormAttempt,
    /// Per listed slot, what its proof was verified against — `None` for a
    /// slot with nothing to verify or no claim to verify it under.
    references: Vec<Option<VerifiedReference>>,
}

impl StructurallyValid {
    /// Called by `form` once every stateless rule has passed, and nowhere
    /// else.
    #[expect(
        clippy::too_many_arguments,
        reason = "one field per stateless-stage output; a builder would let a caller omit one"
    )]
    pub(crate) const fn new(
        candidate: Candidate,
        rule_set: RuleSet,
        coverage: RuleCoverage,
        judged_at: Timestamp,
        hash: BlockHash,
        seed: BlockHash,
        target: Target,
        pow: PowHash,
        attempt: FormAttempt,
        references: Vec<Option<VerifiedReference>>,
    ) -> Self {
        Self {
            candidate,
            rule_set,
            coverage,
            judged_at,
            hash,
            seed,
            target,
            pow,
            attempt,
            references,
        }
    }

    /// What the listed transaction at `slot` had its proof verified
    /// against in `form`, if anything: `None` at the miner slot, at a slot
    /// with no proof, and at a slot whose reference the caller did not
    /// claim.
    #[must_use]
    pub fn verified_reference(&self, slot: TxSlot) -> Option<VerifiedReference> {
        match slot {
            TxSlot::Listed(n) => self.references.get(n).copied().flatten(),
            TxSlot::Miner | TxSlot::Lone => None,
        }
    }

    /// The candidate, still untrusted on every view-bound row.
    #[must_use]
    pub const fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    /// The rule set `form` judged under — a claim `validate` checks by
    /// value, not by id.
    #[must_use]
    pub const fn rule_set(&self) -> RuleSet {
        self.rule_set
    }

    /// The id of the set `form` judged under. What the store persists;
    /// not a proxy for set equality (a Fakechain `Fixed` target reuses
    /// [`RuleSetId::GENESIS`](crate::RuleSetId::GENESIS)).
    #[must_use]
    pub const fn rule_set_id(&self) -> RuleSetId {
        self.rule_set.id()
    }

    /// The stateless rows that ran and passed.
    #[must_use]
    pub const fn coverage(&self) -> &RuleCoverage {
        &self.coverage
    }

    /// The wall clock at `form` — the instant CEN-C1 was (or will be)
    /// judged against. See the type's docs on time-dependence.
    #[must_use]
    pub const fn judged_at(&self) -> Timestamp {
        self.judged_at
    }

    /// The block's identity (CEN-B6), derived once by `form` — stateless,
    /// outside any transaction — and read by every rule that needs it while
    /// the view-bound stage runs (CEN-E1 first; `CHAIN_RULES_SLICE_3.md`
    /// F8). `ValidatedBlock::derive` carries this value into the verdict;
    /// nothing derives the identity a second time.
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        self.hash
    }

    /// The seed the caller claimed for CEN-D3 — verified, not trusted, by
    /// `validate`.
    #[must_use]
    pub const fn seed(&self) -> BlockHash {
        self.seed
    }

    /// The target the caller claimed and `form` judged CEN-D1 against.
    /// `validate` and `alt_against` derive CEN-D4 over their view and
    /// return [`Stale::Target`](crate::Stale::Target) on a mismatch.
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    /// The longhash under the claimed seed (CEN-D2) — what CEN-D1 compares
    /// against the target once the seed is verified.
    #[must_use]
    pub const fn pow(&self) -> PowHash {
        self.pow
    }

    /// Which attempt at `form` produced this.
    #[must_use]
    pub const fn attempt(&self) -> FormAttempt {
        self.attempt
    }

    /// Hand the candidate and the stateless coverage to the view-bound
    /// stage, consuming the token.
    pub(crate) fn into_parts(self) -> (Candidate, RuleCoverage) {
        (self.candidate, self.coverage)
    }
}

impl fmt::Debug for StructurallyValid {
    // The candidate is summarised (identity + listed count), not dumped: a
    // block body is kilobytes and a failing assertion wants the token's claims.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructurallyValid")
            .field("hash", &self.hash)
            .field("transactions", &self.candidate.transactions.len())
            .field("rule_set", &self.rule_set)
            .field("coverage", &self.coverage)
            .field("judged_at", &self.judged_at)
            .field("seed", &self.seed)
            .field("target", &self.target)
            .field("pow", &self.pow)
            .field("attempt", &self.attempt)
            .field("references", &self.references)
            .finish()
    }
}

/// The typed payload a `ChainValid` wraps.
///
/// The candidate exactly as judged — the block is kept whole, so what the
/// store persists is what the rules saw — with every identity derived once:
/// `Block::hash`, and per transaction a [`TxIdentity`] copied from
/// [`Transaction::txid_parts`] (CEN-B6's definition applied), each paired
/// with its body. No consumer re-hashes and no two values can disagree
/// about which block or transaction they describe (ruling Q4/L4: one value
/// per identity).
///
/// Constructed only by `validate`. The fields are private and there is no
/// public constructor: a `ValidatedBlock` in hand was judged (G5).
///
/// ```compile_fail,E0451
/// use shekyl_chain_rules::ValidatedBlock;
/// let forged = ValidatedBlock {
///     hash: todo!(),
///     block: todo!(),
///     miner_tx: todo!(),
///     transactions: todo!(),
///     target: todo!(),
///     cumulative_difficulty: todo!(),
///     root_after: todo!(),
///     drain: todo!(),
///     weights: todo!(),
///     emission: todo!(),
///     archival: todo!(),
///     attestation_witness: todo!(),
///     pow: todo!(),
/// };
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedBlock {
    hash: BlockHash,
    block: Block,
    miner_tx: TxIdentity,
    transactions: Vec<(TxIdentity, Transaction)>,
    target: Target,
    cumulative_difficulty: CumulativeDifficulty,
    /// The curve-tree root **after** this block's drain — the state the next
    /// header must carry (CEN-B5) and a spend referencing `height + 1`
    /// anchors to (CEN-I12); recorded by `connect` at `curve_tree_roots[h+1]`.
    /// Derived here because the root determines future validity (DRS-E3
    /// §3.1, `CTW-Q1`): the authority over validity carries it, and the
    /// store persists what it is handed. Equal to `root_at(height)` when
    /// nothing matured at this height.
    root_after: CurveTreeRoot,
    /// What the drain at this height appended — each matured output paired
    /// with its leaf, and the growth those leaves produced — or `None` when
    /// no output matured (the tree and its root are unchanged).
    drain: Option<Drain>,
    /// The block's weight, its long-term weight, and the two medians it
    /// was judged under (CEN-G6/G6b, slice 7). On the verdict because
    /// every value is one the validator had to compute (slice 7 Q5): the
    /// store records `weight`, `long_term_weight` and the long-term
    /// effective median from here; the effective median is F14's limit
    /// and F14b's penalty operand.
    weights: Weights,
    /// The paid reward, its miner / staker split and the gross emission
    /// through this block (CEN-F14b, F16, G12; slice 7 commit 5). `connect`
    /// records `coins_generated` from here; the paid reward is F18's and
    /// G11's operand (wave B).
    emission: PaidEmission,
    /// What this block does to the archival state — record post-images,
    /// serve-credit keys, slashes, the accrual, the epoch close (DRS-E4
    /// §3.1, `ARW-Q1`). On the verdict because every value has reach into
    /// future validity and the store computes none of it: `connect` writes
    /// each part through its handle.
    archival: ArchivalDelta,
    /// The candidate's attestation-witness sidecar, judged by CEN-B4
    /// (`rules::attestation`, E6 slice 8 row 10) and carried through for
    /// `connect` to record at the block's height
    /// (`DRS_E4_ARCHIVAL_WRITER.md` §3.2 phase 5). Bytes a verdict holds
    /// have passed B4: the empty set against the mined root when `None`,
    /// the recompute and every countersignature when `Some`.
    attestation_witness: Option<AttestationWitness>,
    /// The PoW `form` computed under its seed, accepted by this verdict
    /// (CEN-D1/D2/D3). `connect` records it beside the block.
    pow: ProvenPow,
}

/// What a caller claims the chain holds at one `reference_block` — the
/// block's recorded height and the curve-tree root **at** that height
/// (CEN-I12's anchor). CEN-B5 holds every connected block's header
/// `curve_tree_root` to `root_at(height)`, so the root at a reference is a
/// fact of the header chain, and a caller that keeps the header chain ahead
/// of connect (the ingest driver's target ledger, the switch's stitched
/// view) can claim it the way it claims the seed and the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceClaim {
    /// The reference block's height on the chain the block connects onto.
    pub height: BlockHeight,
    /// The curve-tree root at that height — the anchor the proof was built
    /// over.
    pub root: CurveTreeRoot,
}

/// The claims `form` is handed for a block: one per distinct
/// `reference_block` hash its transactions name (`CHAIN_RULES_CRATE.md`
/// §4.6, the third claim). A reference with no claim is not verified in
/// `form`; `validate` then either refuses it on CEN-I10/I11 or, when those
/// pass, faults [`Stale::Reference`](crate::Stale::Reference) — there is no
/// second verify site.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReferenceClaims {
    claims: BTreeMap<BlockHash, ReferenceClaim>,
}

impl ReferenceClaims {
    /// No claims: every proof-bearing transaction is left for `validate`
    /// to fault.
    pub const EMPTY: Self = Self {
        claims: BTreeMap::new(),
    };

    /// Claim `(height, root)` for the block `reference` names.
    pub fn insert(&mut self, reference: BlockHash, height: BlockHeight, root: CurveTreeRoot) {
        self.claims
            .insert(reference, ReferenceClaim { height, root });
    }

    /// The claim for `reference`, if the caller made one.
    #[must_use]
    pub fn get(&self, reference: &BlockHash) -> Option<ReferenceClaim> {
        self.claims.get(reference).copied()
    }

    /// The claims for `candidate` from a lookup by identity: one per
    /// reference the listed bodies name ([`Candidate::proof_references`])
    /// that `lookup` answers. A reference it does not answer is not
    /// claimed. The shape for a caller holding its chain by hash — a
    /// switch plan's header map, a test's mock chain.
    #[must_use]
    pub fn gather(
        candidate: &Candidate,
        mut lookup: impl FnMut(&BlockHash) -> Option<ReferenceClaim>,
    ) -> Self {
        candidate
            .proof_references()
            .into_iter()
            .filter_map(|reference| lookup(&reference).map(|claim| (reference, claim)))
            .collect()
    }

    /// The claims for `candidate`, connecting at `connecting`, read off
    /// `view`'s headers across CEN-I11's window
    /// ([`admissible_references`](crate::admissible_references)): each
    /// header in the window whose identity a listed body names is claimed
    /// at its height with its header's `curve_tree_root` — the root at
    /// that height by CEN-B5, so a header chain is a chain of anchors. A
    /// block naming no reference reads nothing. A reference the window
    /// does not hold is not claimed, and `validate` refuses it on
    /// CEN-I10/I11 rather than faulting `Stale::Reference`.
    ///
    /// The production shape: the ingest driver's ledger ahead of connect,
    /// the switch's stitched view.
    ///
    /// # Errors
    ///
    /// The view's own fault; a window height the view answers `AboveTip`
    /// for is left unclaimed, not reported — `validate` names what is
    /// wrong with it.
    pub fn from_headers<'id, V: HeaderView<'id>>(
        view: &V,
        connecting: BlockHeight,
        candidate: &Candidate,
    ) -> Result<Self, V::Fault> {
        Self::named_in_window(view, connecting, &candidate.proof_references())
    }

    /// The claim for one transaction at `connecting` — the pool door's
    /// (DRS-E5 PR-b, `DRS_E5_POOL_ALT_PRUNE.md` §2.2): the reference it
    /// names, read off `view`'s headers across CEN-I11's window exactly as
    /// [`Self::from_headers`] reads a block's, so a transaction is judged
    /// against the claim a block carrying it would be. A transaction naming
    /// no reference reads nothing.
    ///
    /// # Errors
    ///
    /// As [`Self::from_headers`].
    pub fn for_transaction<'id, V: HeaderView<'id>>(
        view: &V,
        connecting: BlockHeight,
        tx: &Transaction,
    ) -> Result<Self, V::Fault> {
        let named: BTreeSet<BlockHash> = crate::rules::tx_against::proof_reference(tx)
            .into_iter()
            .collect();
        Self::named_in_window(view, connecting, &named)
    }

    /// Claim every header in CEN-I11's window at `connecting` whose identity
    /// is in `named`, at its height with its `curve_tree_root`.
    fn named_in_window<'id, V: HeaderView<'id>>(
        view: &V,
        connecting: BlockHeight,
        named: &BTreeSet<BlockHash>,
    ) -> Result<Self, V::Fault> {
        if named.is_empty() {
            return Ok(Self::EMPTY);
        }
        let Some((oldest, newest)) = crate::rules::tx_against::admissible_references(connecting)
        else {
            return Ok(Self::EMPTY);
        };
        let mut claims = Self::EMPTY;
        for raw in oldest.to_raw()..=newest.to_raw() {
            let height = BlockHeight::from_raw(raw);
            let AtHeight::Recorded(record) = view.header_at(height)? else {
                continue;
            };
            if named.contains(&record.hash) {
                claims.insert(record.hash, height, record.header.curve_tree_root);
            }
        }
        Ok(claims)
    }

    /// How many references are claimed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.claims.len()
    }

    /// Whether no reference is claimed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }
}

impl FromIterator<(BlockHash, ReferenceClaim)> for ReferenceClaims {
    fn from_iter<I: IntoIterator<Item = (BlockHash, ReferenceClaim)>>(iter: I) -> Self {
        Self {
            claims: iter.into_iter().collect(),
        }
    }
}

/// What one transaction's proof was verified against in `form`: the
/// reference it names and the claim it was verified under. Carried on the
/// [`StructurallyValid`] token per listed slot; `validate` compares it with
/// the context the chain yields (CEN-I10's height, CEN-I12's anchor) and
/// faults on a disagreement rather than verifying again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedReference {
    /// The `reference_block` the transaction names.
    pub reference: BlockHash,
    /// The claim the proof verified against.
    pub claim: ReferenceClaim,
}

/// The proof-of-work hash this node computed for a block (CEN-D2) under
/// the seed it was claimed and checked under (CEN-D3), and that the
/// verdict carrying it accepted (CEN-D1). A derived fact, recorded beside
/// the block as its cumulative difficulty is (`DRS_E5_POOL_ALT_PRUNE.md`,
/// 2026-10-15 ruling 3), so a switch can re-judge a block this node
/// already hashed without hashing it again. Only `form` produces one; a
/// verdict carries it out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenPow {
    seed: BlockHash,
    pow: PowHash,
}

impl ProvenPow {
    /// What `form` computed: the hash under the seed it was claimed under.
    pub(crate) const fn computed(seed: BlockHash, pow: PowHash) -> Self {
        Self { seed, pow }
    }

    /// The seed the hash was computed under.
    #[must_use]
    pub const fn seed(&self) -> BlockHash {
        self.seed
    }

    /// The RandomX longhash of the block's PoW preimage under [`Self::seed`].
    #[must_use]
    pub const fn pow(&self) -> PowHash {
        self.pow
    }

    /// The pair as a store reads it back: a recorded fact this node wrote.
    /// Not a proof — a substrate that answers from it is trusting its own
    /// store, under the store-integrity belts the recorded cumulative
    /// difficulty sits under.
    #[must_use]
    pub const fn recorded(seed: BlockHash, pow: PowHash) -> Self {
        Self { seed, pow }
    }
}

/// What `validate` derived for a block beyond its bytes — the values a
/// [`ValidatedBlock`] carries that no candidate declares. One struct so the
/// assembly names each by field rather than by position (seven of the same
/// few types would otherwise be transposable at the call).
pub(crate) struct Derived {
    /// CEN-D4's target.
    pub(crate) target: Target,
    /// CEN-D4's cumulative work through this block.
    pub(crate) cumulative_difficulty: CumulativeDifficulty,
    /// The root after this block's drain (DRS-E3).
    pub(crate) root_after: CurveTreeRoot,
    /// The drain, if anything matured (DRS-E3).
    pub(crate) drain: Option<Drain>,
    /// CEN-G6/G6b's weights and medians.
    pub(crate) weights: Weights,
    /// CEN-F14b / F16 / G12's paid emission.
    pub(crate) emission: PaidEmission,
    /// The archival transition (DRS-E4, CEN-L7).
    pub(crate) archival: ArchivalDelta,
    /// The PoW `form` computed, under the seed D3 checked (CEN-D1/D2).
    pub(crate) pow: ProvenPow,
}

impl ValidatedBlock {
    /// Assemble the verdict's block. Called by `validate` after the last
    /// rule has passed and nowhere else. The block's identity is **not**
    /// derived here: `form` derived it once under CEN-B6 and the token
    /// carried it (`StructurallyValid::hash`), because a view-bound rule
    /// reads it while the rules run (CEN-E1). The slice-1 placement —
    /// *"derived after the last rule has passed"* — rested on the premise
    /// that no rule reads the identity; E1 refuted the premise
    /// (`CHAIN_RULES_SLICE_3.md` F8, Q7). The transaction identities are
    /// derived here, once; the target and the cumulative work are CEN-D4's
    /// derivation, recorded where it ran; the weights are CEN-G6/G6b's,
    /// derived once every transaction was judged, and the paid emission
    /// is the reward chain's (F14b, F16, G12) over them, and the archival
    /// transition (DRS-E4, L7) is the last derivation over the judged
    /// block — all seven arrive as one [`Derived`], named field by field at
    /// the call site.
    pub(crate) fn derive(candidate: Candidate, hash: BlockHash, derived: Derived) -> Self {
        let Candidate {
            block,
            transactions,
            attestation_witness,
        } = candidate;
        let Derived {
            target,
            cumulative_difficulty,
            root_after,
            drain,
            weights,
            emission,
            archival,
            pow,
        } = derived;
        Self {
            hash,
            miner_tx: TxIdentity::of(&block.miner_transaction),
            block,
            transactions: transactions
                .into_iter()
                .map(|tx| (TxIdentity::of(&tx), tx))
                .collect(),
            target,
            cumulative_difficulty,
            root_after,
            drain,
            weights,
            emission,
            archival,
            attestation_witness,
            pow,
        }
    }

    /// The PoW this verdict accepted, under its seed (CEN-D1/D2/D3).
    #[must_use]
    pub const fn pow(&self) -> ProvenPow {
        self.pow
    }

    /// The candidate's attestation-witness sidecar, as CEN-B4 judged it
    /// (the field's docs). `connect` writes `archival_attestation_witness[h]`
    /// from it when `Some`; `None` writes no row.
    #[must_use]
    pub const fn attestation_witness(&self) -> Option<&AttestationWitness> {
        self.attestation_witness.as_ref()
    }

    /// The block's weight, long-term weight and the medians it was judged
    /// under (CEN-G6/G6b; the field's docs).
    #[must_use]
    pub const fn weights(&self) -> &Weights {
        &self.weights
    }

    /// What this block does to the archival state (DRS-E4; the field's
    /// docs). `connect` writes it part by part in the delta's order.
    #[must_use]
    pub const fn archival(&self) -> &ArchivalDelta {
        &self.archival
    }

    /// The paid reward, its split and the gross emission through this
    /// block (CEN-F14b, F16, G12; the field's docs).
    #[must_use]
    pub const fn emission(&self) -> &PaidEmission {
        &self.emission
    }

    /// The tree root after this block's drain (module docs on the field).
    #[must_use]
    pub const fn root_after(&self) -> CurveTreeRoot {
        self.root_after
    }

    /// What the drain at this height appended — each matured output paired
    /// with its leaf, and every layer chunk their growth wrote — or `None`
    /// when no output matured here. `connect` writes exactly this
    /// (DRS-E3 §3.2).
    #[must_use]
    pub const fn drain(&self) -> Option<&Drain> {
        self.drain.as_ref()
    }

    /// The difficulty this block was judged against (CEN-D4, D6).
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    /// Work through this block: the parent's cumulative difficulty plus
    /// the target. What the store records as `block_info.cumulative_
    /// difficulty` — derived here, never by the store (C2-R8 Q4; slice 2
    /// Q5).
    #[must_use]
    pub const fn cumulative_difficulty(&self) -> CumulativeDifficulty {
        self.cumulative_difficulty
    }

    /// The block's identity.
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        self.hash
    }

    /// The block as judged: header, miner transaction, listed hashes.
    #[must_use]
    pub const fn block(&self) -> &Block {
        &self.block
    }

    /// The header as judged.
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        &self.block.header
    }

    /// The miner transaction with its identities.
    #[must_use]
    pub const fn miner_tx(&self) -> (TxIdentity, &Transaction) {
        (self.miner_tx, &self.block.miner_transaction)
    }

    /// The listed transactions' bodies with their identities, in the
    /// header's order.
    #[must_use]
    pub fn transactions(&self) -> &[(TxIdentity, Transaction)] {
        &self.transactions
    }
}
