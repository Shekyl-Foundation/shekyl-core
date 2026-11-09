// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for CEN-B4 as the switch's C2 leaves it: the coinbase extra
//! parses, its attestation set is empty, the block carries no bundle
//! references, and the header commits the empty bundle root. The positive
//! pin is that the pipeline *judges* every fixture's empty section (B4 is
//! in coverage); the negatives are a root that is not the empty bundle
//! root, an unreadable coinbase extra (refused here, before I20 can see
//! it), a header blob that does not parse, a signed pass record under
//! either root (the header commits to bundles, `SCS-P34`, so a record has
//! nothing that binds it), and a block carrying references even under
//! their own root: admission is not live until C3.

use super::*;
use crate::block::Candidate;
use crate::census::CenRow;
use crate::harness::fixture::{candidate, candidate_on, chain_of};
use crate::harness::{assert_refused, defined, formed_on, judged, MockChain};
use crate::rule_set::RuleSet;
use crate::rules::BlockContext;
use crate::trust::Trust;
use crate::validate::validate;
use crate::verdict::{Locus, Verdict};
use crate::view::{AtHeight, HeaderView};
use shekyl_archival_retention::{
    attestation_root, bundle_root, empty_bundle_root, p_canonical_id_from_hybrid_pubkey,
    pass_countersignature_message, AttestationHeader, AttestationKind, BundleKept, BundleRef,
    PassBitmap, PassRecord, ATTESTATION_HEADER_LEN, PASS_NONCE_LEN,
};
use shekyl_crypto_pq::output::sign_pqc_auth_for_output;
use shekyl_crypto_pq::signature::{HybridSignature, SCHEME_DOMAIN_ATTESTATION};
use shekyl_types::archival::BundleReferences;
use shekyl_types::{BlockHeight, BundleRoot};
use shekyl_wire::tx_extra::{parse, serialize, TxExtraField};

/// Run B4 on its own against `chain`.
fn check_alone_on(chain: &MockChain, candidate: &Candidate) -> Verdict<()> {
    let formed = crate::harness::token_for_one_rule(chain, candidate.clone());
    chain.with_view(|view| {
        defined(B4::check(
            &BlockContext::for_tests(&formed, chain.tip(), None),
            &view,
        ))
    })
}

/// Judge a candidate through both stages against `chain`.
fn judge_on(chain: &MockChain, candidate: Candidate) -> Verdict<()> {
    crate::harness::judge_on(chain, candidate)
}

/// `candidate` with its header's `bundle_root` replaced.
fn with_root(mut candidate: Candidate, root: [u8; 32]) -> Candidate {
    candidate.block.header.bundle_root = BundleRoot::from_bytes(root);
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
/// connecting chain's hash at `anchor`, and the header and attestation
/// root a block carrying exactly that record committed before the switch.
struct SignedRecord {
    header: Vec<u8>,
    root: [u8; 32],
}

fn signed_record(chain: &MockChain, anchor: BlockHeight) -> SignedRecord {
    const SHARD: u64 = 3;
    const EPOCH: u64 = 1;
    const NONCE: [u8; PASS_NONCE_LEN] = [0x5A; PASS_NONCE_LEN];
    const DIGEST: [u8; 32] = [0xD1; 32];
    let anchor_hash = chain.with_view(|view| match view.header_at(anchor) {
        Ok(AtHeight::Recorded(record)) => *record.hash.as_bytes(),
        Ok(AtHeight::AboveTip) => unreachable!("the anchor is on the chain"),
        Err(never) => match never {},
    });
    let msg = pass_countersignature_message(
        shekyl_archival_retention::PassStream::Economy,
        &NONCE,
        anchor,
        &anchor_hash,
        SHARD,
        &DIGEST,
    );
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
        signature,
    };
    let header = AttestationHeader {
        p_id,
        shard_id: SHARD,
        settlement_epoch: EPOCH,
        kind: AttestationKind::Pass,
    };
    SignedRecord {
        header: header.to_canonical_bytes().to_vec(),
        root: attestation_root(std::slice::from_ref(&record)).expect("root"),
    }
}

/// A candidate on `chain` carrying exactly `record`: the header in the
/// coinbase extra, the record's root in the header.
fn carrying(chain: &MockChain, record: SignedRecord) -> Candidate {
    let candidate = with_coinbase_field(
        candidate_on(chain, Vec::new()),
        TxExtraField::ArchivalAttestation(record.header),
    );
    with_root(candidate, record.root)
}

/// A well-formed reference to a zero-draw bundle for `h`.
fn reference_for(h: u64) -> BundleRef {
    let none = PassBitmap::new(0, &[]).expect("an empty bitmap");
    BundleRef::new(
        BundleKept {
            h: BlockHeight::from_raw(h),
            seed: [0x5E; 32],
            passes: none.clone(),
            support: none,
        },
        [0x77; 32],
    )
}

// --- the empty section (A3) ----------------------------------------------

#[test]
fn cen_b4_empty_set_against_the_empty_root_is_a_judged_pass() {
    let chain = chain_of(3);
    let candidate = candidate_on(&chain, Vec::new());
    assert!(candidate.bundle_references.is_none());
    assert_eq!(
        candidate.block.header.bundle_root.as_bytes(),
        &empty_bundle_root()
    );
    assert_eq!(check_alone_on(&chain, &candidate), Ok(()));
    let formed = formed_on(&chain, candidate);
    let valid = chain.with_view(|view| {
        *judged(validate(formed, &view, &RuleSet::GENESIS, &Trust::UNPINNED))
            .expect("the fixture candidate is valid")
            .coverage()
    });
    assert!(
        valid.contains(CenRow::B4),
        "B4 is always evaluated — no sidecar is the empty section, judged"
    );
}

/// The A3 falsifier: a root that is not the empty section's, with no
/// sidecar and no `0x0B` field, is refused here — at B4.
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

/// An extra that does not parse is refused by B4 on its own — never read as
/// the committed empty set — and, through both stages, by CEN-I19 at the
/// miner slot in `form`. The C++ runs `verify_block_attestation` before the
/// coinbase's extra checks, so there B4 names the block; here the miner
/// slot's `tx_form` is stateless and runs in `form`, before any view-bound
/// row (#1081's review, item 1: stateless verification leaves the single
/// writer). One refusal either way; the row differs, as stated.
#[test]
fn cen_b4_unreadable_coinbase_extra_is_refused_alone_and_by_i19_in_form() {
    let chain = chain_of(3);
    let mut candidate = candidate_on(&chain, Vec::new());
    candidate.block.miner_transaction.prefix.extra = vec![0xFF, 0x01, 0x02];
    assert!(parse(&candidate.block.miner_transaction.prefix.extra).is_err());
    assert_refused(check_alone_on(&chain, &candidate), CenRow::B4, Locus::Block);
    assert_refused(
        judge_on(&chain, candidate),
        CenRow::I19,
        Locus::Tx {
            slot: crate::verdict::TxSlot::Miner,
        },
    );
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

// --- references, before admission is live -------------------------------

/// A block that carries references is refused, even under the root those
/// references make: no block admits a bundle until C3 replaces this half
/// of B4 with the section check and the verifier. Red edit: drop the
/// references check — the block under its own root is admitted.
#[test]
fn cen_b4_a_block_with_references_is_refused_until_admission_is_live() {
    let chain = chain_of(3);
    let reference = reference_for(1);
    let own_root = bundle_root(std::slice::from_ref(&reference)).expect("one reference");
    let references =
        BundleReferences::new(vec![reference.encode()]).expect("one non-empty reference");
    let under_its_own = with_root(candidate_on(&chain, Vec::new()), own_root)
        .with_bundle_references(Some(references));
    assert_refused(
        check_alone_on(&chain, &under_its_own),
        CenRow::B4,
        Locus::Block,
    );
    assert_refused(
        judge_on(&chain, under_its_own.clone()),
        CenRow::B4,
        Locus::Block,
    );
    let under_empty = with_root(under_its_own, empty_bundle_root());
    assert_refused(
        check_alone_on(&chain, &under_empty),
        CenRow::B4,
        Locus::Block,
    );
}

/// A signed pass record is refused whatever the header's root: under the
/// attestation root its set recomputes to, and under the empty bundle
/// root. The header commits to bundles (`SCS-P34`), so nothing binds a
/// record. Red edit: drop the empty-set check — the record under the
/// empty bundle root is admitted.
#[test]
fn cen_b4_a_pass_record_is_refused_under_either_root() {
    let chain = chain_of(3);
    let record = signed_record(&chain, BlockHeight::ZERO);
    let attestation = record.root;
    let under_its_own = carrying(&chain, record);
    assert_eq!(
        under_its_own.block.header.bundle_root.as_bytes(),
        &attestation
    );
    assert_refused(
        check_alone_on(&chain, &under_its_own),
        CenRow::B4,
        Locus::Block,
    );
    let under_empty = with_root(under_its_own, empty_bundle_root());
    assert_refused(
        check_alone_on(&chain, &under_empty),
        CenRow::B4,
        Locus::Block,
    );
}
