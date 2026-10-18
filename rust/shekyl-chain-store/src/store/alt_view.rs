// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`AltChain`] and [`AltView`]: the alt tier's view of a chain that is not
//! the recorded one (DRS-E5 slice 9 a3, `DRS_E5_POOL_ALT_PRUNE.md` §2.1).
//!
//! An alternative block is judged against the chain it extends — the main
//! chain up to the fork point, then the alt entries from there to the
//! block's parent — not against the recorded tip. The C++ rebuilt that
//! chain on every candidate (`build_alt_chain`, `blockchain.cpp:2019`) and
//! asserted its linkage while rebuilding (CEN-K2). Here the rebuild is
//! [`AltChain::build`], the linkage is the constructor's refusal, and the
//! stitched chain is a view the cheap-tier rules read through
//! [`HeaderView`] — **and only `HeaderView`**, plus the one fact the alt
//! tier takes beside the headers: the fork the chain describes
//! ([`AltChain::fork`]: its root and the recorded tip of the same
//! snapshot), which the view hands to `alt_against` itself as its
//! [`AltChainView`]. The two operands cannot come from two reads, and the
//! verdict the tier mints is what AL1 stores.
//!
//! # `HeaderView` only
//!
//! `AltView` implements no `ChainView`. An alt row carries what a header
//! rule reads — the hash, the header, the cumulative difficulty
//! (`HeaderRecord`) — and nothing an executed-chain rule reads: no supply
//! figure (CEN-K8; the alt record carries none), no tx count, no archival
//! fold, no key-image set, no tree. A rule that needs an executed fact is
//! a `BlockRule` bound on `ChainView`, and the compiler refuses to bind it
//! on this type; the belt is the type, not a fault inside a returned
//! value (`05-system-thinking.mdc`, "a type defends the call"). The view
//! carries no batch brand either: nothing judged over it can be a
//! `ChainValid` that `connect` accepts (C2-R8 Q3). Alt data still never
//! reaches the validator's `ChainView` (SAL-7).
//!
//! # Stitched by height
//!
//! `header_at(h)` is the recorded row at `h` for `h ≤ root` — the same
//! read `BatchView` makes, [`chain_reads::block_body`], so the two readers
//! cannot disagree about a main-chain header — and the alt entry at
//! `h − root − 1` above it; `tip` is the last alt entry, or the root when
//! the candidate's parent is itself a main-chain row. The recorded chain
//! above the fork point is not visible through this view: a block at
//! `root + 1` on the main chain and the alt entry at `root + 1` are two
//! answers to one height, and the alt tier reads the one it is judging.
//!
//! # K1a by construction
//!
//! The root is a recorded height, so a candidate over this chain sits at
//! `root + 1 + len ≥ 1` ([`AltChain::candidate_height`]): there is no
//! constructor through which an alternative genesis can be asked for
//! (CEN-K1a). A candidate whose parent is unknown is not a K1a case; it is
//! K2's orphan, and `build` refuses it before any height exists.
//!
//! # The chains the store holds
//!
//! [`ReadSnapshot::alternate_chains`] lists every stored chain: the tips of
//! [`AltLinks`](super::alt_reads::AltLinks), each walked by
//! [`AltChain::build`]. The listing and admission are one walk, so a cycle,
//! a height that disagrees with the links, and a chain that reaches no
//! recorded block are the same answers a candidate gets.

use std::collections::HashSet;

use shekyl_chain_rules::{AltChainView, AtHeight, Fork, HeaderRecord, HeaderView, Tip};
use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

use super::alt_reads::{AltEntry, AltLinks, ALT_BLOCKS_CELL};
use super::chain_reads::{self, undecodable};
use super::error::{AltCannot, StoreError};
use super::read::ReadSnapshot;
use crate::codec::AltBlock;

/// SI-7 reason when an alt row's recorded height is not the height its
/// `previous` chain derives: the row claims one place and links to another.
pub(super) const ALT_HEIGHT_MISMATCH: &str = "alt block's recorded height disagrees with its chain";

/// SI-7 reason when an alt chain's `previous` links return to a block the
/// walk already passed. A chain of hashes does not. A file written around
/// AL1 can: AL1 will not insert the cycle, and the row is already there.
pub(super) const ALT_LINKS_TO_ITSELF: &str = "alt block chain links to itself";

/// SI-7 reason when `block_heights` names a root above the recorded tip
/// read on the same snapshot. The height came from `height_of`, so the
/// corrupt cell is `block_heights`, not `alt_blocks`.
const ALT_ROOT_ABOVE_RECORDED_TIP: &str = "alt chain root is above the recorded tip";

/// The cell `height_of` reads. Named here so the inverted-root fault and
/// that read agree on the table.
const BLOCK_HEIGHTS_CELL: &str = "block_heights";

/// The alt entries from the fork point to a candidate's parent, walked
/// from the parent back to a recorded row (AL4 per step), ascending.
///
/// The root is where the chain leaves the recorded one; `entries[i]` is
/// the alt block at `root + 1 + i`. Zero entries is a chain whose parent is
/// a recorded row — the first alternative block off a fork point. The
/// [`Fork`] is built at the end of the walk, so a root above the recorded
/// tip is not a chain this type holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AltChain {
    fork: Fork,
    entries: Vec<AltEntry>,
}

impl AltChain {
    /// **CEN-K2.** The chain that ends at `prev_id`, or [`AltCannot::Unlinked`]
    /// naming the first hash neither `block_heights` nor `alt_blocks` holds.
    ///
    /// Walks `previous` pointers from `prev_id`: a recorded hash is the root
    /// (the recorded chain wins where a hash is both, as a promoted block's
    /// is until its alt row is removed); an alt row is an entry; neither is
    /// the orphan. Each `previous` is committed by its child's hash, and
    /// every alt row was held to hash to its key when read (AL4). A file
    /// written around that boundary can still link a chain to itself, so
    /// the walk records the hashes it has passed and a revisit is SI-7
    /// ([`ALT_LINKS_TO_ITSELF`]).
    ///
    /// Each entry's recorded height is then held to the height its position
    /// derives (`root + 1 + i`, the assertion the C++ rebuild made): a row
    /// that disagrees claims one place in the chain and links to another,
    /// and is SI-7 — the row's own bookkeeping cannot be read as the chain
    /// it is in.
    ///
    /// The recorded tip is read on the same snapshot, first: it is the
    /// other operand of the fork the chain describes ([`AltChain::fork`],
    /// CEN-E2's pop count), and an empty store holds nothing, so every
    /// parent is the orphan there before any walk.
    ///
    /// # Errors
    ///
    /// [`AltCannot::Unlinked`] for the orphan; SI-7 for an alt row that
    /// does not decode, does not hash to its key, sits at the wrong
    /// height, or links back to a block the walk already passed; engine
    /// errors pass through.
    pub fn build(snapshot: &ReadSnapshot<'_>, prev_id: &BlockHash) -> Result<Self, StoreError> {
        let Some(recorded_tip) = snapshot.tip()?.recorded else {
            return Err(AltCannot::Unlinked { at: *prev_id }.into());
        };
        let mut parent_first = Vec::new();
        let mut seen = HashSet::new();
        let mut cursor = *prev_id;
        let root = loop {
            if !seen.insert(cursor) {
                return Err(links_to_itself());
            }
            if let Some(height) = snapshot.height_of(&cursor)? {
                break Tip {
                    height,
                    hash: cursor,
                };
            }
            match snapshot.alt_block(&cursor)? {
                Some(block) => {
                    let previous = block.block().header.previous;
                    parent_first.push(AltEntry { id: cursor, block });
                    cursor = previous;
                }
                None => return Err(AltCannot::Unlinked { at: cursor }.into()),
            }
        };
        parent_first.reverse();
        let entries = parent_first;

        // A root above the tip is `block_heights` disagreeing with the tip
        // read first. Refused before a `Fork` exists: the type has no
        // inverted value, and the saturated span that used to admit one
        // is not a pop.
        let fork = Fork::new(root, recorded_tip).map_err(|_| {
            undecodable(
                BLOCK_HEIGHTS_CELL,
                CodecError::Invalid {
                    codec: BLOCK_HEIGHTS_CELL,
                    reason: ALT_ROOT_ABOVE_RECORDED_TIP,
                },
            )
            .into_plain()
        })?;

        let mut derived = fork.root().height;
        for entry in &entries {
            let Some(next) = derived.checked_add(BlockCount::ONE) else {
                return Err(height_mismatch());
            };
            derived = next;
            if entry.block.height() != derived {
                return Err(height_mismatch());
            }
        }
        Ok(Self { fork, entries })
    }

    /// The fork point: the recorded row the chain leaves from.
    #[must_use]
    pub const fn root(&self) -> Tip {
        self.fork.root()
    }

    /// The fork a block over this chain would cause — CEN-E2's operands,
    /// both from the snapshot the chain was built on. Infallible: [`build`]
    /// refused a root above the recorded tip before this value existed.
    ///
    /// [`build`]: Self::build
    #[must_use]
    pub const fn fork(&self) -> Fork {
        self.fork
    }

    /// The alt entries above the root, ascending; empty when the parent is
    /// the root itself.
    #[must_use]
    pub fn entries(&self) -> &[AltEntry] {
        &self.entries
    }

    /// The chain's last block — the candidate's parent: the last entry, or
    /// the root.
    #[must_use]
    pub fn parent(&self) -> Tip {
        self.entries.last().map_or(self.root(), |e| Tip {
            height: e.block.height(),
            hash: e.id,
        })
    }

    /// **CEN-K1a.** The height a candidate over this chain sits at:
    /// `root + 1 + len`. Never zero — the root is a recorded height — so
    /// an alternative genesis has no constructor. A parent at the last
    /// representable height has no next height; that is a bug in the
    /// chain, not a height of `u64::MAX`.
    #[must_use]
    pub fn candidate_height(&self) -> BlockHeight {
        self.parent()
            .height
            .checked_add(BlockCount::ONE)
            .expect("AltChain: the candidate height overflowed u64")
    }
}

impl ReadSnapshot<'_> {
    /// Every alternative chain, one per tip, in the alt table's key order.
    ///
    /// A tip is an alt block no stored alt block names as its parent
    /// ([`AltLinks::tips`]). Each chain is [`AltChain::build`] from that
    /// tip, so the listing, admission, the height check and the cycle belt
    /// are one walk. Entries run from the block just above the recorded
    /// root up to the tip. The root's hash is the main-chain parent the
    /// lowest block names.
    ///
    /// An empty table is no chains. A tip whose chain reaches no recorded
    /// block is [`AltCannot::Unlinked`]: the invariant that every stored
    /// chain reaches the main chain is broken, and the caller decides what
    /// that means. A cycle, or a height that disagrees with the links, is
    /// SI-7.
    ///
    /// # Errors
    ///
    /// [`AltCannot::Unlinked`]; SI-7; engine faults.
    pub fn alternate_chains(&self) -> Result<Vec<AltChain>, StoreError> {
        let entries = self.alt_blocks()?;
        let links = AltLinks::of(&entries);
        let mut chains = Vec::new();
        for tip in links.tips(&entries) {
            chains.push(AltChain::build(self, &tip.id)?);
        }
        Ok(chains)
    }
}

fn alt_blocks_invalid(reason: &'static str) -> StoreError {
    undecodable(
        ALT_BLOCKS_CELL,
        CodecError::Invalid {
            codec: AltBlock::NAME,
            reason,
        },
    )
    .into_plain()
}

fn height_mismatch() -> StoreError {
    alt_blocks_invalid(ALT_HEIGHT_MISMATCH)
}

fn links_to_itself() -> StoreError {
    alt_blocks_invalid(ALT_LINKS_TO_ITSELF)
}

/// The alt tier's [`HeaderView`]: a committed snapshot stitched with an
/// [`AltChain`] (module docs). No `ChainView`, no brand, no archival read.
pub struct AltView<'s> {
    snapshot: &'s ReadSnapshot<'s>,
    chain: AltChain,
}

impl<'s> AltView<'s> {
    /// The view over `chain`, which [`AltChain::build`] walked on this
    /// `snapshot` — the same snapshot, so the rows below the root the view
    /// reads are the rows the walk reached.
    #[must_use]
    pub const fn new(snapshot: &'s ReadSnapshot<'s>, chain: AltChain) -> Self {
        Self { snapshot, chain }
    }

    /// The chain this view is stitched over.
    #[must_use]
    pub const fn chain(&self) -> &AltChain {
        &self.chain
    }
}

impl<'id> AltChainView<'id> for AltView<'_> {
    /// [`AltChain::fork`]: the chain the view is stitched over names it,
    /// on the snapshot the view reads.
    fn fork(&self) -> Fork {
        self.chain.fork()
    }
}

impl<'id> HeaderView<'id> for AltView<'_> {
    type Fault = StoreError;

    /// The candidate's parent ([`AltChain::parent`]): the last alt entry,
    /// or the root. Never `None` — a chain was built, so it has a last row.
    fn tip(&self) -> Result<Option<Tip>, StoreError> {
        Ok(Some(self.chain.parent()))
    }

    /// Below or at the root, the recorded row through the one body
    /// `BatchView::header_at` reads (`chain_reads::block_body`: the blob
    /// must hash to the identity `block_info` records, CEN-B6); above it,
    /// the alt entry's hash, header and cumulative difficulty; above the
    /// parent, [`AtHeight::AboveTip`]. A recorded row at or below the root
    /// that is missing or undecodable is SI-7, as on every reader.
    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, StoreError> {
        let root = self.chain.root().height;
        if height <= root {
            let txn = self.snapshot.txn();
            let tip = chain_reads::tip_of(txn).map_err(chain_reads::ReadFault::into_plain)?;
            return Ok(
                match chain_reads::block_body(txn, tip.as_ref(), height.to_raw())
                    .map_err(chain_reads::ReadFault::into_plain)?
                {
                    AtHeight::AboveTip => AtHeight::AboveTip,
                    AtHeight::Recorded((info, block)) => AtHeight::Recorded(HeaderRecord {
                        hash: info.hash,
                        header: block.header,
                        cumulative_difficulty: info.cumulative_difficulty,
                    }),
                },
            );
        }
        let Some(above_root) = height.checked_sub(root) else {
            return Ok(AtHeight::AboveTip);
        };
        let Some(index) = above_root.to_raw().checked_sub(1) else {
            return Ok(AtHeight::AboveTip);
        };
        let Ok(index) = usize::try_from(index) else {
            return Ok(AtHeight::AboveTip);
        };
        Ok(self
            .chain
            .entries
            .get(index)
            .map_or(AtHeight::AboveTip, |entry| {
                AtHeight::Recorded(HeaderRecord {
                    hash: entry.id,
                    header: entry.block.block().header.clone(),
                    cumulative_difficulty: entry.block.cumulative_difficulty(),
                })
            }))
    }
}
