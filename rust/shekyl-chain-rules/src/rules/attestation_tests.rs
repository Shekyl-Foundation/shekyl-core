// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for CEN-B4 (`CHAIN_RULES_SLICE_8.md` §3.5, row 10). The
//! empty-witness arm is every fixture in this crate — `candidate_on`
//! commits the empty root and carries no sidecar — so the positive pin is
//! that the pipeline *judges* it (B4 is in coverage, A3's content), and the
//! negatives are a root that is not the empty set's with nothing supplied
//! (the A3 falsifier), an unreadable coinbase extra (refused here, before
//! I20 can see it), a header blob or witness that does not parse, and the
//! record arm's two refusals this crate can witness without a bond on the
//! view: a signed record below the anchor threshold, and one whose persona
//! has no bond record. A hole in the window and a stored key that is not
//! canonical are `Corrupt`, witnessed by the mock's two job-3 instruments,
//! not refusals. The accept of a signed record runs the same body
//! the daemon's FFI pins (`shekyl-ffi`, `attestation_verify_tests::
//! valid_block_verifies`); a chain that posts the bond and mints the
//! `0x0B` field is not mintable under CEN-I20's grammar today (slice 8
//! §5.1, row 10 finding), so the arm is not re-witnessed here.

use super::*;
use crate::block::Candidate;
use crate::census::CenRow;
use crate::fault::{Corrupt, PerHeightRecord, ViewRead};
use crate::harness::fixture::{candidate, candidate_on, chain_of};
use crate::harness::{
    assert_refused, defined, formed_on, infallible, judged, MockChain, NonCanonicalHybridKey,
    WithheldRead,
};
use crate::rule_set::RuleSet;
use crate::rules::BlockContext;
use crate::trust::Trust;
use crate::validate::validate;
use crate::verdict::{ChainValid, Locus, Verdict};
use crate::view::{AtHeight, ChainView, Tip};
use shekyl_archival_retention::{
    attestation_root, empty_attestation_root, p_canonical_id_from_hybrid_pubkey,
    pass_countersignature_message, AttestationHeader, AttestationKind, BlockAttestationWitness,
    PassRecord, PassWitness, ATTESTATION_HEADER_LEN, PASS_ANCHOR_DEPTH_BLOCKS,
    PASS_ANCHOR_LAG_BLOCKS, PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT, PASS_ANCHOR_WINDOW_LEN,
    PASS_NONCE_LEN,
};
use shekyl_crypto_pq::output::sign_pqc_auth_for_output;
use shekyl_crypto_pq::signature::{HybridSignature, SCHEME_DOMAIN_ATTESTATION};
use shekyl_types::archival::AttestationWitness;
use shekyl_types::{AttestationRoot, BlockCount, BlockHeight, PCanonicalId};
use shekyl_wire::tx_extra::{parse, serialize, TxExtraField};

/// Run B4 on its own against `chain`.
fn check_alone_on(chain: &MockChain, candidate: &Candidate) -> Verdict<()> {
    let formed = formed_on(chain, candidate.clone());
    chain.with_view(|view| {
        defined(B4::check(
            &BlockContext::for_tests(&formed, chain.tip(), None),
            &view,
        ))
    })
}

/// Judge a candidate through the pipeline against `chain`.
fn judge_on(chain: &MockChain, candidate: Candidate) -> Verdict<()> {
    let formed = formed_on(chain, candidate);
    chain.with_view(|view| {
        judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .map(|_valid: ChainValid<_>| ())
    })
}

/// `candidate` with its header's `attestation_root` replaced.
fn with_root(mut candidate: Candidate, root: [u8; 32]) -> Candidate {
    candidate.block.header.attestation_root = AttestationRoot::from_bytes(root);
    candidate
}

/// `candidate` with `field` appended to its coinbase extra.
fn with_coinbase_field(mut candidate: Candidate, field: TxExtraField) -> Candidate {
    let extra = &mut candidate.block.miner_transaction.prefix.extra;
    let mut fields = parse(extra).expect("the fixture coinbase extra parses");
    fields.push(field);
    *extra = serialize(&fields).expect("fields serialize");
    candidate
}

/// A pass record signed by a fixture persona (seed-derived, the same
/// signer every archival fixture uses) over the SF-D8 transcript for the
/// connecting chain's hash at `anchor`, and the header, witness and root
/// a block carrying exactly that record commits.
struct SignedRecord {
    p_id: [u8; 32],
    header: Vec<u8>,
    witness: AttestationWitness,
    root: [u8; 32],
}

fn signed_record(chain: &MockChain, anchor: BlockHeight) -> SignedRecord {
    const SHARD: u64 = 3;
    const EPOCH: u64 = 1;
    const NONCE: [u8; PASS_NONCE_LEN] = [0x5A; PASS_NONCE_LEN];
    const DIGEST: [u8; 32] = [0xD1; 32];
    let anchor_hash = chain.with_view(|view| match view.block_at(anchor) {
        Ok(AtHeight::Recorded(block)) => *block.hash.as_bytes(),
        Ok(AtHeight::AboveTip) => unreachable!("the anchor is on the chain"),
        Err(never) => match never {},
    });
    let msg = pass_countersignature_message(&NONCE, anchor, &anchor_hash, SHARD, &DIGEST);
    let signed = sign_pqc_auth_for_output(&[0xA7; 64], 0, SCHEME_DOMAIN_ATTESTATION, &msg)
        .expect("a fixture seed signs");
    let p_id = *p_canonical_id_from_hybrid_pubkey(&signed.hybrid_public_key).as_bytes();
    let signature =
        HybridSignature::from_canonical_bytes(&signed.signature).expect("signature decodes");
    let record = PassRecord {
        p_id,
        shard_id: SHARD,
        settlement_epoch: EPOCH,
        nonce: NONCE,
        anchor_height: anchor,
        delivery_digest: DIGEST,
        signature: signature.clone(),
    };
    let header = AttestationHeader {
        p_id,
        shard_id: SHARD,
        settlement_epoch: EPOCH,
        kind: AttestationKind::Pass,
    };
    let witness = BlockAttestationWitness {
        passes: vec![PassWitness {
            nonce: NONCE,
            anchor_height: anchor,
            delivery_digest: DIGEST,
            signature,
        }],
    }
    .to_canonical_bytes()
    .expect("witness bytes");
    SignedRecord {
        p_id,
        header: header.to_canonical_bytes().to_vec(),
        witness: AttestationWitness::new(witness).expect("a non-empty witness"),
        root: attestation_root(std::slice::from_ref(&record)).expect("root"),
    }
}

/// A candidate on `chain` carrying exactly `record`: the header in the
/// coinbase extra, the witness beside the block, the root in the header.
fn carrying(chain: &MockChain, record: SignedRecord) -> Candidate {
    let candidate = with_coinbase_field(
        candidate_on(chain, Vec::new()),
        TxExtraField::ArchivalAttestation(record.header),
    );
    with_root(candidate, record.root).with_attestation_witness(Some(record.witness))
}

/// A chain long enough that a candidate on its tip has a window: the
/// predecessor is the threshold height, so the window is `[0, L]`.
fn chain_with_window() -> MockChain {
    chain_of(PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT.to_raw() + 1)
}

// --- the empty-witness arm (A3) ------------------------------------------

#[test]
fn cen_b4_empty_set_against_the_empty_root_is_a_judged_pass() {
    let chain = chain_of(3);
    let candidate = candidate_on(&chain, Vec::new());
    assert!(candidate.attestation_witness.is_none());
    assert_eq!(
        candidate.block.header.attestation_root.as_bytes(),
        &empty_attestation_root()
    );
    assert_eq!(check_alone_on(&chain, &candidate), Ok(()));
    let formed = formed_on(&chain, candidate);
    let valid = chain.with_view(|view| {
        *judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("the fixture candidate is valid")
        .coverage()
    });
    assert!(
        valid.contains(CenRow::B4),
        "B4 is always evaluated — no sidecar is the empty witness, judged"
    );
}

/// The A3 falsifier: a root that is not the empty set's, with no sidecar
/// and no `0x0B` field, is refused here — at B4, by the recompute.
#[test]
fn cen_b4_non_empty_root_with_nothing_supplied_is_refused() {
    let chain = chain_of(3);
    let candidate = with_root(candidate_on(&chain, Vec::new()), [0x33; 32]);
    assert_refused(check_alone_on(&chain, &candidate), CenRow::B4, Locus::Block);
    assert_refused(judge_on(&chain, candidate), CenRow::B4, Locus::Block);
}

#[test]
fn cen_b4_genesis_commits_the_empty_root_too() {
    let genesis = candidate(Vec::new());
    assert_eq!(check_alone_on(&MockChain::default(), &genesis), Ok(()));
    assert_refused(
        judge_on(&MockChain::default(), with_root(genesis, [0x33; 32])),
        CenRow::B4,
        Locus::Block,
    );
}

// --- the operands do not parse -------------------------------------------

/// An extra that does not parse is refused **here**, before the coinbase
/// reaches I19/I20 in the slot loop — the C++'s order, and never read as
/// the committed empty set.
#[test]
fn cen_b4_unreadable_coinbase_extra_is_refused_here_not_at_i20() {
    let chain = chain_of(3);
    let mut candidate = candidate_on(&chain, Vec::new());
    candidate.block.miner_transaction.prefix.extra = vec![0xFF, 0x01, 0x02];
    assert!(parse(&candidate.block.miner_transaction.prefix.extra).is_err());
    assert_refused(check_alone_on(&chain, &candidate), CenRow::B4, Locus::Block);
    assert_refused(judge_on(&chain, candidate), CenRow::B4, Locus::Block);
}

#[test]
fn cen_b4_header_blob_not_whole_records_is_refused() {
    let chain = chain_of(3);
    let candidate = with_coinbase_field(
        candidate_on(&chain, Vec::new()),
        TxExtraField::ArchivalAttestation(vec![0u8; ATTESTATION_HEADER_LEN - 1]),
    );
    assert_refused(check_alone_on(&chain, &candidate), CenRow::B4, Locus::Block);
}

#[test]
fn cen_b4_witness_that_does_not_decode_is_refused() {
    let chain = chain_of(3);
    let candidate = candidate_on(&chain, Vec::new())
        .with_attestation_witness(Some(AttestationWitness::new(vec![0xEE; 7]).expect("bytes")));
    assert_refused(check_alone_on(&chain, &candidate), CenRow::B4, Locus::Block);
}

/// The empty set's one carrier is `None`. A sidecar spelling it as an
/// eight-byte zero count would pass the root recompute and reach the store
/// as a present row for a block whose peers record none — so the block is
/// refused here, by the codec's canonical form, not recorded.
#[test]
fn cen_b4_zero_count_sidecar_is_refused_not_recorded() {
    let chain = chain_of(3);
    let bytes = 0u64.to_le_bytes().to_vec();
    assert!(BlockAttestationWitness::from_canonical_bytes(&bytes).is_err());
    let candidate = candidate_on(&chain, Vec::new())
        .with_attestation_witness(Some(AttestationWitness::new(bytes).expect("bytes")));
    assert_eq!(
        candidate.block.header.attestation_root.as_bytes(),
        &empty_attestation_root(),
        "the root alone would admit it: the refusal is the canonical form's"
    );
    assert_refused(check_alone_on(&chain, &candidate), CenRow::B4, Locus::Block);
    assert_refused(judge_on(&chain, candidate), CenRow::B4, Locus::Block);
}

/// A well-formed record whose root was mined wrong: the recompute refuses
/// before any signature is read (the root is checked first).
#[test]
fn cen_b4_root_mismatch_is_refused_before_signatures() {
    let chain = chain_with_window();
    let record = signed_record(&chain, BlockHeight::ZERO);
    let candidate = with_root(carrying(&chain, record), empty_attestation_root());
    assert_refused(check_alone_on(&chain, &candidate), CenRow::B4, Locus::Block);
}

// --- the record arm ------------------------------------------------------

/// A signed record on a chain whose predecessor is below the anchor
/// threshold: no window exists, so the block is refused — the genesis
/// boundary.
#[test]
fn cen_b4_record_below_the_anchor_threshold_is_refused() {
    let chain = chain_of(2);
    let record = signed_record(&chain, BlockHeight::ZERO);
    let candidate = carrying(&chain, record);
    assert_refused(check_alone_on(&chain, &candidate), CenRow::B4, Locus::Block);
}

/// A signed record with a window, naming a persona the view has no bond
/// for: refused. The window is filled (below) and the bond read before the
/// signature is evaluated, as the FFI orders it.
#[test]
fn cen_b4_record_whose_persona_has_no_bond_is_refused() {
    let chain = chain_with_window();
    let record = signed_record(&chain, BlockHeight::ZERO);
    let candidate = carrying(&chain, record);
    assert_refused(check_alone_on(&chain, &candidate), CenRow::B4, Locus::Block);
}

// --- the window ----------------------------------------------------------

/// The window B4 fills from the view is the C++'s `fill_pass_anchor_window`:
/// `[pred − depth − L, pred − depth]` for `pred = connecting − 1`, the
/// chain's hashes at those heights.
#[test]
fn cen_b4_anchor_window_is_filled_from_the_connecting_chain() {
    let min_pred = PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT;
    let chain = chain_of(min_pred.to_raw() + 10);
    let connecting = Tip::connecting_height(chain.tip().as_ref());
    let predecessor = connecting
        .checked_sub_count(BlockCount::from_raw(1))
        .expect("a chain has a predecessor");
    let window = chain
        .with_view(|view| defined(anchor_window(&view, connecting)))
        .expect("above the threshold there is a window");
    let last = predecessor
        .checked_sub_count(PASS_ANCHOR_DEPTH_BLOCKS)
        .expect("fits");
    let first = last
        .checked_sub_count(PASS_ANCHOR_LAG_BLOCKS)
        .expect("fits");
    assert_eq!(window.first(), first);
    assert_eq!(window.last(), last);
    for offset in 0..PASS_ANCHOR_WINDOW_LEN as u64 {
        let height = first
            .checked_add(BlockCount::from_raw(offset))
            .expect("fits");
        let expected = chain.with_view(|view| match infallible(view.block_at(height)) {
            AtHeight::Recorded(block) => *block.hash.as_bytes(),
            AtHeight::AboveTip => unreachable!("below the predecessor"),
        });
        assert_eq!(window.hash_at(height), Some(&expected));
    }
    assert_eq!(
        window.hash_at(last.checked_add(BlockCount::from_raw(1)).expect("fits")),
        None
    );
}

#[test]
fn cen_b4_no_window_below_the_threshold_or_at_genesis() {
    let min_pred = PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT;
    // Predecessor exactly at the threshold: a window, starting at genesis.
    let chain = chain_of(min_pred.to_raw() + 1);
    let connecting = Tip::connecting_height(chain.tip().as_ref());
    let window = chain.with_view(|view| defined(anchor_window(&view, connecting)));
    assert_eq!(window.map(|w| w.first()), Some(BlockHeight::ZERO));
    // One below: none.
    let chain = chain_of(min_pred.to_raw());
    let connecting = Tip::connecting_height(chain.tip().as_ref());
    assert!(chain
        .with_view(|view| defined(anchor_window(&view, connecting)))
        .is_none());
    // Genesis: no predecessor at all.
    assert!(MockChain::default()
        .with_view(|view| defined(anchor_window(&view, BlockHeight::ZERO)))
        .is_none());
}

/// A height inside the window answers `AboveTip` while the tip still says
/// the chain is dense. That is a hole below the predecessor, so the window
/// read and the rule both halt. It is not an absent window, and not B4.
#[test]
fn cen_b4_a_hole_in_the_anchor_window_is_corrupt_not_a_refusal() {
    let chain = chain_with_window();
    let record = signed_record(&chain, BlockHeight::ZERO);
    let candidate = carrying(&chain, record);
    let formed = formed_on(&chain, candidate);
    let connecting = Tip::connecting_height(chain.tip().as_ref());
    let hole = ViewRead::Corrupt(Corrupt::HoleBelowTip {
        at: BlockHeight::ZERO,
        record: PerHeightRecord::Block,
    });
    chain.with_view(|inner| {
        let view = inner.withholding(WithheldRead::BlockAt(BlockHeight::ZERO));
        assert_eq!(anchor_window(&view, connecting), Err(hole));
        assert_eq!(
            B4::check(&BlockContext::for_tests(&formed, chain.tip(), None), &view,),
            Err(hole)
        );
    });
}

/// Four bytes. A canonical hybrid public key is a versioned encoding, so
/// these cannot parse — the same fixture length the slash fold uses when
/// the key is not the subject.
const NOT_A_HYBRID_KEY: [u8; 4] = [0xb1; 4];

/// The persona's record is present and its hybrid key is not canonical.
/// Absence of a record is B4's refusal; bytes the grammar rejects are the
/// store's, so the rule halts instead of treating the bond as missing.
#[test]
fn cen_b4_a_non_canonical_bond_key_is_corrupt_not_an_absent_bond() {
    let chain = chain_with_window();
    let record = signed_record(&chain, BlockHeight::ZERO);
    let persona = PCanonicalId::from_bytes(record.p_id);
    let candidate = carrying(&chain, record);
    let formed = formed_on(&chain, candidate);
    let key = NonCanonicalHybridKey::from_bytes(NOT_A_HYBRID_KEY)
        .expect("four bytes are not a canonical hybrid public key");
    chain.with_view(|inner| {
        let view = inner.with_non_canonical_bond(persona, key);
        let served =
            infallible(view.bond_record(&persona)).expect("the planted persona has a record");
        assert_eq!(infallible(view.bond_records()), vec![(persona, served)]);
        assert_eq!(
            B4::check(&BlockContext::for_tests(&formed, chain.tip(), None), &view,),
            Err(ViewRead::Corrupt(Corrupt::BondHybridKeyMalformed {
                persona
            }))
        );
    });
}
