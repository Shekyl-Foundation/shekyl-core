// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.B — CEN-B4, the block's attestation set
//! (`CHAIN_RULES_SLICE_8.md` §3.5, row 10): the kept headers in the
//! coinbase's `tx_extra` and the witness carried beside the block recompute
//! to the header's `attestation_root`, and every pass record's
//! `P`-countersignature verifies under the connecting chain's anchor
//! window. CEN-A3 ("an empty set commits the empty root") is this rule's
//! empty-witness arm, never a row of its own.
//!
//! # What the C++ does, read at `dev`
//!
//! `verify_block_attestation` (`blockchain.cpp:5131–5219`), called from
//! both admission arms **before** `prevalidate_miner_transaction`: it parses
//! the coinbase extra for the first `0x0B` field (unparseable extra →
//! `HEADERS_UNREADABLE`, a loud refusal and never the committed empty set;
//! no tag → the empty blob), reads each distinct pass `p_id`'s bond hybrid
//! pubkey, fills the SF-D8 anchor window from the connecting chain for the
//! block's predecessor, and hands all of it to
//! `shekyl_archival_verify_attestation`, whose body is
//! [`AttestationSet`] — parse, root, then
//! countersignatures.
//!
//! # What lands here
//!
//! The same three calls over the same operands, read off the view instead
//! of marshalled through pointers. The rule is **always evaluated**: a
//! candidate with no sidecar is judged as the empty witness against the
//! mined root, which is what every block whose set is empty commits
//! ([`empty_attestation_root`](shekyl_archival_retention::empty_attestation_root)),
//! and the pass this produces is a judged pass, not a gap. What the FFI keeps and this rule does not need: the
//! pair-set equality between C++'s step-1 parse and Rust's step-2 parse
//! (one parse here), the anchor-table shape check (the window is filled
//! from `block_at`, not from a caller), and the null-pointer verdicts.
//!
//! **Order.** After D1 and before the slot loop (`validate`): the C++ runs
//! it before the coinbase is judged, so a coinbase whose extra does not
//! parse is refused **here**, not at CEN-I20 — the row the census names
//! for that extra is this one.
//!
//! **Reach.** The record arm's window needs a predecessor at or above
//! [`PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT`](shekyl_archival_retention::PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT);
//! below it a block that carries a pass record is refused (there is no window to anchor in — the genesis
//! boundary), and the first 725 blocks of any chain commit the empty set.
//! Today the coinbase grammar CEN-I20 adopts admits no `0x0B` field, so a
//! block with a non-empty set is refused at I20 after passing here; the
//! record arm is reachable through this rule alone and witnessed by the
//! shared body's pins (`shekyl-ffi`, `attestation_verify_tests`). Slice 8
//! records that as a finding, not a gap in this rule.

use shekyl_archival_retention::{
    AttestationSet, PassAnchorWindow, PASS_ANCHOR_HASH_LEN, PASS_ANCHOR_WINDOW_LEN,
};
use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_types::{BlockCount, BlockHeight, PCanonicalId};
use shekyl_wire::tx_extra::{parse, TxExtraField};

use crate::census::CenRow;
use crate::rules::{BlockContext, BlockRule, Rule};
use crate::verdict::{refused, Locus, Verdict};
use crate::view::{AtHeight, ChainView};

/// CEN-B4: `attestation_root` recomputes over the coinbase's kept headers
/// paired with the sidecar witness, and every pass record's
/// countersignature verifies under the predecessor's anchor window against
/// its bond's committed hybrid pubkey (module docs).
///
/// The refusals, in the C++'s order: the coinbase extra does not parse;
/// the header blob is not whole 49-byte records or exceeds the cap; the
/// witness does not decode or does not pair with the pass headers; the
/// recompute differs from the mined root; a record below the anchor
/// threshold; a record whose persona has no bond; a record anchored
/// outside the window; a signature that fails. Every one is this row at
/// [`Locus::Block`] — the census splits none of them.
pub(crate) struct B4;

impl Rule for B4 {
    const ROW: CenRow = CenRow::B4;
}

impl BlockRule for B4 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        let candidate = cx.candidate();

        // The kept headers: the first `0x0B` field of a coinbase extra that
        // parses; none is the committed empty set; an extra that does not
        // parse is refused here, never read as empty.
        let Ok(fields) = parse(&candidate.block.miner_transaction.prefix.extra) else {
            return refused(Self::ROW, Locus::Block);
        };
        let headers: &[u8] = fields
            .iter()
            .find_map(|field| match field {
                TxExtraField::ArchivalAttestation(blob) => Some(blob.as_slice()),
                _ => None,
            })
            .unwrap_or(&[]);
        let witness: &[u8] = candidate
            .attestation_witness
            .as_ref()
            .map_or(&[], |w| w.as_bytes());

        let Ok(set) = AttestationSet::parse(headers, witness) else {
            return refused(Self::ROW, Locus::Block);
        };
        if set
            .verify_root(candidate.block.header.attestation_root.as_bytes())
            .is_err()
        {
            return refused(Self::ROW, Locus::Block);
        }
        if set.records().is_empty() {
            // The empty-witness arm (A3): the recompute above — the mined
            // root equals `empty_attestation_root()` — is the whole
            // judgement; no window and no bond is read.
            return Ok(Ok(()));
        }

        // The record arm: the window from the connecting chain, each
        // record's bond from the view.
        let window = anchor_window(view, cx.connecting)?;
        let mut pubkeys: Vec<([u8; 32], Option<HybridPublicKey>)> = Vec::new();
        for record in set.records() {
            if pubkeys.iter().any(|(p_id, _)| *p_id == record.p_id) {
                continue;
            }
            let pubkey = view
                .bond_record(&PCanonicalId::from_bytes(record.p_id))?
                .and_then(|bond| HybridPublicKey::from_canonical_bytes(&bond.hybrid_pubkey).ok());
            pubkeys.push((record.p_id, pubkey));
        }
        let pubkey_of = |p_id: &[u8; 32]| -> Option<&HybridPublicKey> {
            pubkeys
                .iter()
                .find(|(id, _)| id == p_id)
                .and_then(|(_, pk)| pk.as_ref())
        };
        match set.verify_countersignatures(window.as_ref(), pubkey_of) {
            Ok(()) => Ok(Ok(())),
            Err(_) => refused(Self::ROW, Locus::Block),
        }
    }
}

/// The SF-D8 anchor window for a candidate at `connecting`, filled from
/// the connecting chain: the block hashes at
/// `[pred − depth − L, pred − depth]` where `pred = connecting − 1` is the
/// validated predecessor (`fill_pass_anchor_window`, `blockchain.cpp`).
/// `None` when no window exists — at genesis (no predecessor) or for a
/// predecessor below
/// [`PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT`](shekyl_archival_retention::PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT).
///
/// Every height in the window is below the predecessor, so a conforming
/// view has it recorded; an `AboveTip` there is reported as no window and
/// the record arm refuses, which is the only decision a rule can take on
/// a chain with a hole in it (G11).
pub(crate) fn anchor_window<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
) -> Result<Option<PassAnchorWindow>, V::Fault> {
    let Some(predecessor) = connecting.checked_sub_count(BlockCount::from_raw(1)) else {
        return Ok(None);
    };
    let Some((first, len)) = PassAnchorWindow::shape_for_predecessor(predecessor) else {
        return Ok(None);
    };
    debug_assert_eq!(len, PASS_ANCHOR_WINDOW_LEN);
    let mut hashes: Vec<[u8; PASS_ANCHOR_HASH_LEN]> = Vec::with_capacity(len);
    for offset in 0..len {
        let height = first
            .checked_add(BlockCount::from_raw(offset as u64))
            .expect("window heights lie below the predecessor");
        match view.block_at(height)? {
            AtHeight::Recorded(block) => hashes.push(*block.hash.as_bytes()),
            AtHeight::AboveTip => return Ok(None),
        }
    }
    Ok(PassAnchorWindow::from_table(predecessor, &hashes).ok())
}

#[cfg(test)]
#[path = "attestation_tests.rs"]
mod attestation_tests;
