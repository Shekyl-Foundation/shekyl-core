// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.G — the block body as a whole (E6 slice 7,
//! `CHAIN_RULES_SLICE_7.md` §4): the rows that hold *across* a block's listed
//! transactions after each has passed `tx_form` and `tx_against` on its
//! own. G2 is the stateless row (`form`). G1 runs before the slot loop;
//! G7, G9 and G10 run beside L1 after it.
//!
//! # CEN-G1 — no listed transaction is already on the chain (slice 7 commit 7)
//!
//! **What the C++ does, read at `blockchain.cpp:5511–5522`:** the hash loop's
//! first act, before a body is even fetched, is `m_db->tx_exists(tx_id)` —
//! a listed identity the chain already holds refuses the block
//! (`reject_block_form`). The Rust read is [`ChainView::has_transaction`]
//! (slice 7 commit 3; the store's `tx_indices`, miner transactions
//! included). Two arms, both refused at `Locus::Tx { slot: Listed(n) }` —
//! the slot whose hash the rule looked up (Q8's first test): **on the
//! chain** (the C++'s), and **earlier in this block** — the same identity
//! listed twice, refused at the second occurrence; the C++ has no separate
//! check for it because the first occurrence is in the batch by the time
//! the second is looked up, and the Rust judges the whole block against the
//! chain *before* it, so the intra-block arm is this rule's to carry.
//!
//! **Order is the finding (Q8's second test).** G1's chain arm shares its
//! trigger with CEN-I7 — a re-listed spend's key image is spent — and its
//! intra-block arm with CEN-L1. Run after the slot loop, G1 would never fire
//! on a spend: I7 refuses at `Locus::Input` in the loop and L1 catches the
//! double before G1 sees the hash. So G1 runs **before** the slot loop, the
//! C++'s own order (`tx_exists` `:5516` before `check_tx_inputs` `:5639`),
//! and `body_tests` pins it with a re-listed spend that must be refused on
//! G1 — a flipped order makes I7 the row, and the test asserts the row.
//!
//! G1 reads the **declared** hashes, not the bodies': G2 has already
//! established, in `form`, that the two agree — so the identities are the
//! ones the header carries and no body is hashed twice.
//!
//! # CEN-G7, G9, G10 — cross-transaction uniqueness of the archival keys
//!
//! After the slot loop, beside L1 (`blockchain.cpp:5670–5812`, three
//! passes over every listed body's inputs): no two serve-credit vins with
//! one `(P, shard, E)` (**G7**, `D-SC-C`), no two emission claims naming one
//! `(P, E)` — an emission vin claims a *list* of epochs, each a pair
//! (**G9**), and at most one bond post per `P`, whatever its kind (**G10**).
//! G9's and G10's decision bodies are `shekyl-archival-retention`'s, the
//! same ones the C++ calls (`emission_block_claims_unique`,
//! `bond_post_block_unique`): one owner, both languages. G7's is this
//! module's own set-membership scan (`second_occurrence`) over the parsed
//! `(P, shard, E)` triples: its retention-crate body was the D-SC-C arm of
//! the serve-credit C++ mirror, deleted 2026-10-02 (DRS-E4 commit 10d) with
//! the rest of that mirror — see `docs/FOLLOWUPS.md` "Serve-credit
//! acceptance (CEN-J8–J10) has no Rust rule". The C++ keeps its own G7
//! (`blockchain.cpp:5670`), on `ArchivalPairEpochKey`'s big-endian bytes;
//! this scan is over the same three fields, so the two agree wherever both
//! parse the vin. What this crate adds for all three is the **locus** —
//! `Locus::Input { slot, input }` at the **second** occurrence, the vin the
//! colliding key was read from. Should the scan find no second occurrence
//! after the body refused (it cannot; both are set-membership over the same
//! keys), the refusal falls to `Locus::Block`, never to a panic.
//!
//! **A vin that does not parse is not this rule's.** The parse of an
//! emission vin is CEN-J19's row (slice 8 row 8, `tx_emission`), of a
//! serve-credit vin CEN-J1's — a successor row scoped out of slice 8
//! (§1.2) and still pending; until it lands, an unparseable serve-credit
//! vin has no key to collide on and passes G7 — the gap is J1's and the
//! family pins it there, not here. The C++ reaches these passes only after
//! `check_tx_inputs` has parsed every vin, so it treats a failure here as an
//! internal inconsistency; the Rust order puts the parse rows in the slot
//! loop, before this one: J19 refuses first, and J1 will when it exists.
//!
//! **Deliberately not a rule (ratified 2026-07-12, `blockchain.cpp:5738`):**
//! a serve-credit response and a Release for the same `P` in one block is
//! benign under the settled release semantics and is not refused.
//!
//! # CEN-G2 — the declared list and the carried bodies agree
//!
//! A block declares its listed transactions by hash (`transaction_hashes`)
//! and travels with their bodies positionally. **What the C++ does, read at
//! `blockchain.cpp:5505–5590`:** `handle_block_to_main_chain` iterates the
//! header's hashes and resolves each from the pool or the block's own
//! supplement; a hash that resolves to nothing is `MISSING_TXS` — not a
//! refusal but a "do not connect, ask for the bodies" — and a body is never
//! *checked* against the hash it came in under, because in the C++ the hash
//! is the lookup key and the body is what the key returned. The Rust
//! pipeline receives bodies positionally (`Candidate::transactions`, in the
//! header's order), so the agreement the C++ gets by construction is a
//! **rule** here: one the census names and slice 7 Q7 classed as a
//! [`FormRule`] — L1's *class* (a property of the candidate's bytes alone,
//! no view), not L1's *severity*. Until it landed, a reordered or
//! substituted body connected and the store assigned its outputs in body
//! order (§3.1; measured by `body_pairing_tests`, slice 7 commit 2) — the
//! curve tree's drain order, which is why G2 is a precondition for E3's
//! correctness and not a tidiness rule.
//!
//! **The loci, from slice 7 Q8's first test** (a locus is derivable from the
//! refusal's own evidence): a **length** mismatch is refused at
//! [`Locus::Block`] — the rule's evidence is two lengths and names no slot;
//! the **first index** whose body hashes to something other than the
//! declared hash is refused at `Locus::Tx { slot: Listed(i) }` — the rule
//! computed exactly *i*. Length first, so an index arm never reads past the
//! shorter list; first mismatch only, so the locus is the one the rule
//! established rather than "every slot that disagrees".
//!
//! **What G2 is not.** No rule compares a merkle root to anything: the tree
//! hash over the declared list is an input to the block's identity
//! (`Block::pow_blob`; B6 records it, D2 judges the PoW over it), so a
//! different list is a different block, not a mismatch. G2 is the one
//! hash-against-hash comparison in 4.G, per index by construction.
//! `MISSING_TXS` — the pool's "I do not hold this body yet" — is the
//! ingest's affair before a `Candidate` exists; a candidate that reaches
//! `form` has as many bodies as it has, and G2 judges what it has.

use std::collections::BTreeSet;
use std::io::Cursor;

use shekyl_archival_retention::{
    bond_post_block_unique, emission_block_claims_unique, p_canonical_id_from_hybrid_pubkey,
    ArchivalServeCreditResponse,
};
use shekyl_types::TxHash;
use shekyl_wire::{Input, Transaction};

use crate::census::CenRow;
use crate::rules::tx_emission::J19;
use crate::rules::{BlockContext, BlockRule, FormContext, FormRule, Rule};
use crate::verdict::{InvalidBlock, Locus, TxSlot, Verdict};
use crate::view::ChainView;

/// CEN-G2: every declared hash is the hash of the body carried at its
/// index, and there are exactly as many bodies as hashes.
pub(crate) struct G2;

impl Rule for G2 {
    const ROW: CenRow = CenRow::G2;
}

impl FormRule for G2 {
    fn check(cx: &FormContext<'_>) -> Verdict<()> {
        let declared = &cx.candidate.block.transaction_hashes;
        let carried = &cx.candidate.transactions;
        if declared.len() != carried.len() {
            return Err(InvalidBlock::new(Self::ROW, Locus::Block));
        }
        match declared
            .iter()
            .zip(carried)
            .position(|(hash, body)| Transaction::hash(body) != *hash)
        {
            None => Ok(()),
            Some(first) => Err(InvalidBlock::new(
                Self::ROW,
                Locus::Tx {
                    slot: TxSlot::Listed(first),
                },
            )),
        }
    }
}

/// CEN-G1: no listed transaction is already on the chain, nor listed
/// twice in this block. Runs **before** the slot loop (module docs).
pub(crate) struct G1;

impl Rule for G1 {
    const ROW: CenRow = CenRow::G1;
}

impl BlockRule for G1 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        let mut listed_here: BTreeSet<TxHash> = BTreeSet::new();
        for (n, hash) in cx.candidate().block.transaction_hashes.iter().enumerate() {
            // The intra-block arm first: it costs no read, and a hash that
            // is both on the chain and doubled is refused at its second
            // listing either way.
            if !listed_here.insert(*hash) || view.has_transaction(hash)? {
                return Ok(Err(InvalidBlock::new(
                    Self::ROW,
                    Locus::Tx {
                        slot: TxSlot::Listed(n),
                    },
                )));
            }
        }
        Ok(Ok(()))
    }
}

/// The key one archival input contributes to its block-level uniqueness
/// pass — what G7, G9 and G10 collide on. `None` for a non-archival input
/// and for an archival vin that does not parse (the parse is CEN-J1's and
/// CEN-J19's refusal; a vin without a key cannot collide, module docs).
/// Public so the E2 mutation family can build a duplicate against the same
/// parse the rules use, rather than a second one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchivalKey {
    /// A serve-credit vin's `(P, shard, E)` — CEN-G7.
    ServeCredit {
        /// `P_canonical_id`.
        p: [u8; 32],
        /// The shard served.
        shard: u64,
        /// The settlement epoch credited.
        epoch: u64,
    },
    /// An emission vin's claims — one `(P, E)` per settlement epoch — CEN-G9.
    Claims {
        /// `P_canonical_id`, derived from the vin's hybrid pubkey as the
        /// C++ extractor derives it.
        p: [u8; 32],
        /// The epochs claimed, in vin order.
        epochs: Vec<u64>,
    },
    /// A bond post's `P` — CEN-G10, whatever the post's kind.
    BondPost {
        /// `P_canonical_id`.
        p: [u8; 32],
    },
}

impl ArchivalKey {
    /// The key `input` carries, if it is a parseable archival vin.
    #[must_use]
    pub fn of(input: &Input) -> Option<Self> {
        match input {
            Input::ServeCredit { canonical_bytes } => {
                let kept =
                    ArchivalServeCreditResponse::read_exact(&mut Cursor::new(canonical_bytes))
                        .ok()?;
                Some(Self::ServeCredit {
                    p: kept.p_canonical_id,
                    shard: kept.shard_id,
                    epoch: kept.settlement_epoch,
                })
            }
            Input::ArchivalRewardEmission { canonical_bytes } => {
                // CEN-J19's parse — length-exact, as the FFI extractor's.
                let vin = J19::parse(canonical_bytes)?;
                Some(Self::Claims {
                    p: *p_canonical_id_from_hybrid_pubkey(&vin.p_pubkey).as_bytes(),
                    epochs: vin.settlement_epochs,
                })
            }
            Input::BondPost(post) => Some(Self::BondPost {
                p: *post.p_canonical_id.as_bytes(),
            }),
            Input::Gen(_) | Input::ToKey { .. } => None,
        }
    }
}

/// Every listed body's inputs with their loci, in block order — the
/// iteration the three archival passes and their loci share.
fn listed_inputs<'a>(cx: &'a BlockContext<'_>) -> impl Iterator<Item = (Locus, &'a Input)> + 'a {
    cx.candidate()
        .transactions
        .iter()
        .enumerate()
        .flat_map(|(n, tx)| {
            tx.prefix
                .inputs
                .iter()
                .enumerate()
                .map(move |(input, item)| {
                    (
                        Locus::Input {
                            slot: TxSlot::Listed(n),
                            input,
                        },
                        item,
                    )
                })
        })
}

/// The first key that repeats in `keys`, by position — the locus arm for
/// the two decision bodies that answer only yes/no.
fn second_occurrence<K: Ord>(keys: &[(Locus, K)]) -> Option<Locus> {
    let mut seen = BTreeSet::new();
    keys.iter()
        .find(|(_, key)| !seen.insert(key))
        .map(|(locus, _)| *locus)
}

/// G7's collision key: `(P, shard, E)` — the three fields the C++'s
/// `ArchivalPairEpochKey` encodes, as values rather than bytes.
type ServeCreditKey = ([u8; 32], u64, u64);

/// CEN-G7: no two serve-credit vins in one block carry the same
/// `(P, shard, E)`.
pub(crate) struct G7;

impl Rule for G7 {
    const ROW: CenRow = CenRow::G7;
}

impl BlockRule for G7 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        let triples: Vec<(Locus, ServeCreditKey)> = listed_inputs(cx)
            .filter_map(|(locus, item)| match ArchivalKey::of(item) {
                Some(ArchivalKey::ServeCredit { p, shard, epoch }) => {
                    Some((locus, (p, shard, epoch)))
                }
                _ => None,
            })
            .collect();
        Ok(match second_occurrence(&triples) {
            None => Ok(()),
            Some(locus) => Err(InvalidBlock::new(Self::ROW, locus)),
        })
    }
}

/// CEN-G9: no two emission claims in one block name the same `(P, E)`.
pub(crate) struct G9;

impl Rule for G9 {
    const ROW: CenRow = CenRow::G9;
}

impl BlockRule for G9 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        let mut pairs: Vec<(Locus, ([u8; 32], u64))> = Vec::new();
        for (locus, item) in listed_inputs(cx) {
            if let Some(ArchivalKey::Claims { p, epochs }) = ArchivalKey::of(item) {
                pairs.extend(epochs.into_iter().map(|epoch| (locus, (p, epoch))));
            }
        }
        let keys: Vec<([u8; 32], u64)> = pairs.iter().map(|(_, key)| *key).collect();
        Ok(if emission_block_claims_unique(&keys) {
            Ok(())
        } else {
            Err(InvalidBlock::new(
                Self::ROW,
                second_occurrence(&pairs).unwrap_or(Locus::Block),
            ))
        })
    }
}

/// CEN-G10: at most one bond post per `P` in one block, whatever its kind.
pub(crate) struct G10;

impl Rule for G10 {
    const ROW: CenRow = CenRow::G10;
}

impl BlockRule for G10 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        let ids: Vec<(Locus, [u8; 32])> = listed_inputs(cx)
            .filter_map(|(locus, item)| match ArchivalKey::of(item) {
                Some(ArchivalKey::BondPost { p }) => Some((locus, p)),
                _ => None,
            })
            .collect();
        let keys: Vec<[u8; 32]> = ids.iter().map(|(_, id)| *id).collect();
        Ok(if bond_post_block_unique(&keys) {
            Ok(())
        } else {
            Err(InvalidBlock::new(
                Self::ROW,
                second_occurrence(&ids).unwrap_or(Locus::Block),
            ))
        })
    }
}

#[cfg(test)]
#[path = "body_tests.rs"]
mod body_tests;
