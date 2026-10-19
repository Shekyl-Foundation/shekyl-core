// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The router (`DRS_X_STORE_FLIP.md` DX-Q2 item 1, PR2-Q1): where an
//! arrival goes, decided on a [`ReadSnapshot`], and the claims `form` needs
//! for it, derived on the same snapshot.
//!
//! **Placement is by the block's parent:**
//! - the recorded tip → [`Placed::Extend`], the pipeline's path. This holds
//!   for a block the alt table already stores, too: its parent is the tip,
//!   so it is the heaviest chain, and its connect takes it out of the alt
//!   table (a block id has one home, `store/alt.rs`);
//! - a recorded or alternative block → [`Placed::Alt`], the switch's path
//!   (`OfferAlt`);
//! - neither → [`Placed::Unlinked`], with nothing stored. There is no orphan
//!   store: a peer cannot make this node hold a block it cannot place;
//! - a block the main chain records, or an alternative block whose parent
//!   is not the tip → [`Placed::AlreadyHeld`].
//!
//! **The router is not the writer.** The tip can move between a placement
//! and the connect it leads to. The claims make that safe without a lock:
//! the seed (CEN-D3), the target (CEN-D4) and the references are each
//! compared by equality in `validate`, so a stale claim is `Fault::Stale`,
//! never a verdict. A run whose snapshot no longer has it extending the
//! tip is [`ClaimStop::Moved`]: the heights below the run are not read,
//! and the service places the arrival again. A height change at connect
//! is the connector's `HeightClaim`. A same-height replacement is CEN-A2
//! there, and the service places that again too — this path only submits
//! a block whose parent was the tip.
//!
//! These functions read and return owned values: the snapshot never lives
//! across an `.await`.

use shekyl_chain_rules::{
    seed_height, target_claim, AtHeight, Candidate, Corrupt, Fault, HeaderRecord, HeaderView,
    InvalidBlock, ReferenceClaims, RuleSet, Target, Trust,
};
use shekyl_chain_store::store::{
    AltCannot, AltChain, AltView, ChainStore, ReadSnapshot, StoreCannot, StoreError,
};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_wire::Block;

use crate::cache_window::{self, AltSpend, SeedPair};
use crate::schedule::ChainRules;
use crate::target::TargetLedger;

/// Where an arrival goes (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placed {
    /// Its parent is the recorded tip: it connects at `height`.
    Extend {
        /// The height it connects at.
        height: BlockHeight,
    },
    /// Its parent is a recorded or alternative block other than the tip.
    Alt,
    /// Its parent chain reaches no block this node holds; `at` is the first
    /// hash on that walk neither table holds.
    Unlinked {
        /// The first unheld hash.
        at: BlockHash,
    },
    /// This node holds it already.
    AlreadyHeld,
}

/// Place `block` on a fresh snapshot of `store` (module docs).
///
/// # Errors
///
/// The store's.
pub fn place(store: &ChainStore, block: &Block) -> Result<Placed, StoreError> {
    let snap = store.begin_read()?;
    let hash = block.hash();
    let parent = block.header.previous;
    if snap.height_of(&hash)?.is_some() {
        return Ok(Placed::AlreadyHeld);
    }
    let Some(tip) = snap.tip()?.recorded else {
        // An empty chain extends only by genesis, whose parent is null.
        return Ok(if parent == BlockHash::NULL {
            Placed::Extend {
                height: BlockHeight::ZERO,
            }
        } else {
            Placed::Unlinked { at: parent }
        });
    };
    if tip.hash == parent {
        return Ok(Placed::Extend {
            height: tip
                .height
                .checked_add(BlockCount::ONE)
                .expect("a recorded tip has a successor height"),
        });
    }
    if snap.has_alt_block(&hash)? {
        return Ok(Placed::AlreadyHeld);
    }
    match AltChain::build(&snap, &parent) {
        Ok(_) => Ok(Placed::Alt),
        Err(StoreError::Cannot(StoreCannot::Alt(AltCannot::Unlinked { at }))) => {
            Ok(Placed::Unlinked { at })
        }
        Err(other) => Err(other),
    }
}

/// What `form` needs beside the candidate and the substrate, for one block.
#[derive(Clone, Debug)]
pub struct Claims {
    /// The height it connects at.
    pub height: BlockHeight,
    /// The rule set in force there.
    pub rule_set: RuleSet,
    /// CEN-D3's claim.
    pub seed: BlockHash,
    /// CEN-D4's claim.
    pub target: Target,
    /// The third claim: each reference's height and root.
    pub references: ReferenceClaims,
}

/// Why a run's claims stopped at one of its blocks.
#[derive(Debug)]
pub enum ClaimStop {
    /// CEN-D6 refused the block's target on its own headers: that block's
    /// verdict, so it is not formed.
    Refused {
        /// Its index in the run.
        index: usize,
        /// The verdict.
        refused: InvalidBlock,
    },
    /// The headers the window reads are corrupt: the writer's to judge.
    Corrupt {
        /// The connecting height whose window it was.
        height: BlockHeight,
        /// What was observed.
        corrupt: Corrupt,
    },
    /// The store could not be read.
    Store(StoreError),
    /// This snapshot's tip is not the parent the run was placed on.
    /// The window was not read. Place the arrival again.
    Moved,
}

impl From<StoreError> for ClaimStop {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// The claims for a run of blocks extending the tip, the first connecting
/// at `first`, each the next one's parent: the seed, target and reference
/// claims the pipeline's ledgers make (`seed`, `target` module docs), read
/// off one snapshot for every height below the run and off the run itself
/// above it.
///
/// # Errors
///
/// [`ClaimStop`]: the claims made before it are returned with it.
pub fn claim_run(
    store: &ChainStore,
    rules: ChainRules,
    first: BlockHeight,
    run: &[Candidate],
) -> (Vec<Claims>, Option<ClaimStop>) {
    let mut claims = Vec::with_capacity(run.len());
    let snap = match store.begin_read() {
        Ok(snap) => snap,
        Err(e) => return (claims, Some(ClaimStop::Store(e))),
    };
    match still_extends(&snap, first, run) {
        Ok(true) => {}
        Ok(false) => return (claims, Some(ClaimStop::Moved)),
        Err(e) => return (claims, Some(ClaimStop::Store(e))),
    }
    let mut ledger = TargetLedger::new();
    for (index, candidate) in run.iter().enumerate() {
        let height = BlockHeight::from_raw(first.to_raw() + index as u64);
        match claim_one(
            &snap,
            rules,
            &mut ledger,
            first,
            run,
            index,
            height,
            candidate,
        ) {
            Ok(claim) => claims.push(claim),
            Err(stop) => return (claims, Some(stop)),
        }
    }
    (claims, None)
}

#[expect(
    clippy::too_many_arguments,
    reason = "one block's claim reads the snapshot, the run and the ledger the run builds"
)]
fn claim_one(
    snap: &ReadSnapshot<'_>,
    rules: ChainRules,
    ledger: &mut TargetLedger,
    first: BlockHeight,
    run: &[Candidate],
    index: usize,
    height: BlockHeight,
    candidate: &Candidate,
) -> Result<Claims, ClaimStop> {
    let rule_set = rules.in_force(height);
    let seed = match seed_height(height) {
        None => BlockHash::NULL,
        Some(at) if at < first => recorded_hash(snap, at)?,
        Some(at) => run[usize::try_from(at.to_raw() - first.to_raw()).expect("inside the run")]
            .block
            .hash(),
    };
    for at in ledger.missing_for(height) {
        ledger.record(at, header_record(snap, at)?);
    }
    let target = match ledger.claim(height, &rule_set) {
        Ok(Ok(target)) => target,
        Ok(Err(refused)) => return Err(ClaimStop::Refused { index, refused }),
        Err(corrupt) => return Err(ClaimStop::Corrupt { height, corrupt }),
    };
    // Read before this block's own header joins the ledger: a block cannot
    // reference itself (CEN-I11).
    let references = match ReferenceClaims::from_headers(&*ledger, height, candidate) {
        Ok(references) => references,
        Err(never) => match never {},
    };
    ledger
        .extend(height, &candidate.block, target)
        .map_err(|corrupt| ClaimStop::Corrupt { height, corrupt })?;
    Ok(Claims {
        height,
        rule_set,
        seed,
        target,
        references,
    })
}

/// [`claim_alt`]'s answer: hash it, or refuse it before the target window
/// and before any cache is built.
#[derive(Clone, Debug)]
pub(crate) enum ClaimedAlt {
    /// Inside the band and the window. The target was read.
    Ready(Claims),
    /// The early gate's refusal. The target was not read.
    Spend(AltSpend),
}

/// The claims for an alternative arrival: the seed and the target on the
/// chain it is on, the stitched view below it. No reference claims: the
/// cheap tier judges headers (CEN-K4), and promotion verifies the proofs
/// under the plan's claims (`SwitchPlan::references_for`).
///
/// The fork and the seed are known before the target window is read. A
/// fork outside the band, or a seed the two cache slots do not hold, comes
/// back as [`ClaimedAlt::Spend`] and the target is not derived.
///
/// # Errors
///
/// [`ClaimStop`]; `Unlinked` comes back as the store's `AltCannot`, which
/// the caller places again.
pub(crate) fn claim_alt(
    store: &ChainStore,
    rules: ChainRules,
    candidate: &Candidate,
    window: &SeedPair,
    trust: &Trust,
) -> Result<ClaimedAlt, ClaimStop> {
    let snap = store.begin_read()?;
    let chain = AltChain::build(&snap, &candidate.block.header.previous)?;
    let height = chain.candidate_height();
    let fork = chain.fork();
    let rule_set = rules.in_force(height);
    let view = AltView::new(&snap, chain);
    let seed = match seed_height(height) {
        None => BlockHash::NULL,
        Some(at) => match view.header_at(at)? {
            AtHeight::Recorded(record) => record.hash,
            // The seed block is not on the chain this alternative can see.
            // It is not one of the two slots. Nothing is stored or hashed.
            AtHeight::AboveTip => {
                return Ok(ClaimedAlt::Spend(AltSpend::OutsideWindow { height }));
            }
        },
    };
    let outcome = cache_window::spend(&fork, &seed, height, &rule_set, trust, window);
    if !matches!(outcome, AltSpend::Hash) {
        return Ok(ClaimedAlt::Spend(outcome));
    }
    let target = match target_claim(&view, height, &rule_set) {
        Ok(Ok(target)) => target,
        Ok(Err(refused)) => return Err(ClaimStop::Refused { index: 0, refused }),
        Err(Fault::Corrupt(corrupt)) => return Err(ClaimStop::Corrupt { height, corrupt }),
        Err(Fault::View(e)) => return Err(ClaimStop::Store(e)),
        Err(Fault::Stale(stale)) => unreachable!("a derivation is never stale: {stale}"),
    };
    Ok(ClaimedAlt::Ready(Claims {
        height,
        rule_set,
        seed,
        target,
        references: ReferenceClaims::EMPTY,
    }))
}

/// The claims a producer makes for the block after the recorded tip, on
/// one snapshot: its height, the seed (CEN-D3) and the target (CEN-D4) —
/// what the miner's template producer pins and hands the miner.
///
/// # Errors
///
/// [`ClaimStop`].
pub fn claim_next(
    store: &ChainStore,
    rules: ChainRules,
) -> Result<(BlockHeight, BlockHash, Target), ClaimStop> {
    let snap = store.begin_read()?;
    let view = shekyl_chain_store::store::SnapshotView::new(&snap);
    let connecting = shekyl_chain_rules::Tip::connecting_height(view.tip()?.as_ref());
    let rule_set = rules.in_force(connecting);
    let seed = match seed_height(connecting) {
        None => BlockHash::NULL,
        Some(at) => recorded_hash(&snap, at)?,
    };
    match target_claim(&view, connecting, &rule_set) {
        Ok(Ok(target)) => Ok((connecting, seed, target)),
        Ok(Err(refused)) => Err(ClaimStop::Refused { index: 0, refused }),
        Err(Fault::Corrupt(corrupt)) => Err(ClaimStop::Corrupt {
            height: connecting,
            corrupt,
        }),
        Err(Fault::View(e)) => Err(ClaimStop::Store(e)),
        Err(Fault::Stale(stale)) => unreachable!("a derivation is never stale: {stale}"),
    }
}

/// Whether `run` still extends this snapshot.
///
/// `first` is the connecting height and the first block names the tip.
/// A rewind or a same-height replacement since the placement is not a
/// window this snapshot can derive: the heights below `first` would no
/// longer be recorded.
fn still_extends(
    snap: &ReadSnapshot<'_>,
    first: BlockHeight,
    run: &[Candidate],
) -> Result<bool, StoreError> {
    let tip = snap.tip()?.recorded;
    let (connecting, parent) = match tip {
        None => (BlockHeight::ZERO, BlockHash::NULL),
        Some(tip) => {
            let Some(connecting) = tip.height.checked_add(BlockCount::ONE) else {
                return Ok(false);
            };
            (connecting, tip.hash)
        }
    };
    let names_tip = run
        .first()
        .is_none_or(|candidate| candidate.block.header.previous == parent);
    Ok(connecting == first && names_tip)
}

/// The identity recorded at `height`. Above the tip, the run no longer
/// extends this snapshot.
fn recorded_hash(snap: &ReadSnapshot<'_>, height: BlockHeight) -> Result<BlockHash, ClaimStop> {
    match snap.block_info(height)? {
        AtHeight::Recorded(info) => Ok(info.hash),
        AtHeight::AboveTip => Err(ClaimStop::Moved),
    }
}

/// The header record at `height`, as the connector's `HeaderAt` reads it.
/// Above the tip, the run no longer extends this snapshot.
fn header_record(snap: &ReadSnapshot<'_>, height: BlockHeight) -> Result<HeaderRecord, ClaimStop> {
    let AtHeight::Recorded(info) = snap.block_info(height)? else {
        return Err(ClaimStop::Moved);
    };
    let AtHeight::Recorded(body) = snap.block(height)? else {
        return Err(ClaimStop::Moved);
    };
    Ok(HeaderRecord {
        hash: info.hash,
        header: body.block.header,
        cumulative_difficulty: info.cumulative_difficulty,
    })
}
