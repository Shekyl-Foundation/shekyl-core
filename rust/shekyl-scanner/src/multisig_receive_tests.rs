// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Option E′ receive path through the scanner (`docs/PQC_MULTISIG.md`
//! §8): a 3-of-5 group's output, built by the production constructor and
//! carried in a transaction whose `extra` passes CEN-I19, is found by every
//! member's scanner and is spendable; a solo wallet does not see it; and a
//! damaged or missing `0x0D` entry leaves it received but unspendable.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use shekyl_address::multisig_address::MultisigAddressPayload;
use shekyl_address::Network;
use shekyl_crypto_pq::kem::{
    HybridKemPublicKey, HybridKemSecretKey, HybridX25519MlKem, KeyEncapsulation,
};
use shekyl_crypto_pq::multisig_output::{construct_multisig_output, MultisigOutputData};
use shekyl_curve_generators::T;
use shekyl_engine_state::UnspendableReason;
use shekyl_wire::tx_extra::{self, KemCiphertext, MultisigEntry};
use shekyl_wire::Ct;
use zeroize::Zeroizing;

use crate::bench_fixtures::{make_bench_wallet, scannable_block_for_recipient};
use crate::extra::{Extra, ExtraField};
use crate::scan::{MultisigMemberScan, ScannableBlock};
use crate::{Scanner, ViewPair};

const NET: [u8; 16] = [0x4E; 16];
const AMOUNT: u64 = 7_000_000;

struct Group {
    address: MultisigAddressPayload,
    b: Scalar,
    spend: EdwardsPoint,
    group_sk: HybridKemSecretKey,
    member_sks: Vec<HybridKemSecretKey>,
}

fn kem_bytes(pk: &HybridKemPublicKey) -> Vec<u8> {
    let mut out = pk.x25519.to_vec();
    out.extend_from_slice(&pk.ml_kem);
    out
}

fn group(n: u8, m: u8) -> Group {
    let kem = HybridX25519MlKem;
    let b = Scalar::from_bytes_mod_order([0x21; 32]);
    let y = Scalar::from_bytes_mod_order([0x23; 32]);
    let b_point = ED25519_BASEPOINT_POINT * b;
    let y_point = *T * y;
    let (group_pk, group_sk) = kem.keypair_generate().unwrap();
    let (member_pks, member_sks): (Vec<_>, Vec<_>) =
        (0..n).map(|_| kem.keypair_generate().unwrap()).unzip();
    let address = MultisigAddressPayload::new(
        Network::Testnet,
        n,
        m,
        b_point.compress().to_bytes(),
        y_point.compress().to_bytes(),
        kem_bytes(&group_pk),
        member_pks.iter().map(kem_bytes).collect(),
    )
    .unwrap();
    Group {
        address,
        b,
        spend: b_point + y_point,
        group_sk,
        member_sks,
    }
}

fn entry(out: &MultisigOutputData) -> MultisigEntry {
    MultisigEntry::new(
        0,
        out.member_kem_ciphertexts
            .iter()
            .map(|ct| KemCiphertext::from_bytes(ct.as_slice().try_into().unwrap()))
            .collect(),
        out.enc_key_hashes.clone(),
    )
    .unwrap()
}

/// A one-output block whose output pays the group, built by the production
/// constructor and carried through the production extra writer. `edit`
/// sees the `0x0D` entry list before it is written.
fn group_block(g: &Group, edit: impl FnOnce(&mut Vec<MultisigEntry>)) -> ScannableBlock {
    let out = construct_multisig_output(&[0x42; 32], &g.address, AMOUNT, 0, &NET).unwrap();
    let mut entries = vec![entry(&out)];
    edit(&mut entries);

    // Start from a conforming one-output block and put the group's output
    // in its place.
    let other = make_bench_wallet();
    let spend = other.view_pair.spend().compress().to_bytes();
    let mut block = scannable_block_for_recipient(1, &other.wallet_kem_pk, &spend);
    let tx_pubkey = Scalar::from_bytes_mod_order([0x42; 32]) * ED25519_BASEPOINT_POINT;
    let mut kem = out.kem_ciphertext_x25519.to_vec();
    kem.extend_from_slice(&out.kem_ciphertext_ml_kem);
    let mut extra = Extra::for_hybrid_transfer(tx_pubkey, [kem]);
    extra.push_pqc_leaf_entries(out.pqc_leaf.entry_bytes().to_vec());
    extra.push_pqc_multisig(entries);
    let extra = extra.serialize();
    block.transactions[0].modify(|tx| {
        tx.prefix.outputs[0].key = out.output_key;
        tx.prefix.outputs[0].view_tag = out.view_tag_prefilter;
        tx.prefix.extra = extra;
        let Ct::Fcmp { base, .. } = &mut tx.ct else {
            unreachable!("the fixture is an FCMP++ spend")
        };
        base.commitments[0] = out.commitment;
        base.enc_amounts[0] = out.enc_amount_wire().to_bytes();
        base.enc_labels[0] = out.enc_label_wire().to_bytes();
    });
    block
}

fn member_scanner(g: &Group, i: u8) -> Scanner {
    let pair = ViewPair::new(
        g.spend,
        Zeroizing::new(Scalar::from_bytes_mod_order([0x07; 32])),
        Zeroizing::new(g.group_sk.x25519),
        Zeroizing::new(g.group_sk.ml_kem.clone()),
    )
    .unwrap();
    let member = &g.member_sks[usize::from(i)];
    Scanner::new_multisig_member(
        pair,
        Zeroizing::new(g.b.to_bytes()),
        MultisigMemberScan::new(
            i,
            g.address.n_total(),
            g.address.m_required(),
            Zeroizing::new(member.x25519),
            Zeroizing::new(member.ml_kem.clone()),
            NET,
        ),
    )
}

fn scan_one(g: &Group, i: u8, block: ScannableBlock) -> Option<UnspendableReason> {
    let found = member_scanner(g, i).scan(block).unwrap().into_inner();
    assert_eq!(found.len(), 1, "member {i} finds the group's output");
    assert_eq!(found[0].amount().to_raw(), AMOUNT);
    found[0].unspendable()
}

/// The slice's receive gate: the extra passes CEN-I19 (with its `0x0D`
/// clause), and all five members of a 3-of-5 find the output spendable.
#[test]
fn every_member_of_a_three_of_five_finds_the_output_spendable() {
    let g = group(5, 3);
    let block = group_block(&g, |_| {});
    let tx = block.transactions[0].tx();
    let fields = tx_extra::parse(&tx.prefix.extra).unwrap();
    tx_extra::check_pqc_field_shape_of(&fields, tx.prefix.outputs.len())
        .expect("the multisig output's extra passes CEN-I19");
    for i in 0..5 {
        assert_eq!(scan_one(&g, i, block.clone()), None, "member {i}");
    }
}

/// A solo wallet does not see a group's output.
#[test]
fn a_solo_wallet_does_not_see_the_group_output() {
    let g = group(3, 2);
    let block = group_block(&g, |_| {});
    let wallet = make_bench_wallet();
    let found = Scanner::new(wallet.view_pair, wallet.spend_secret)
        .scan(block)
        .unwrap()
        .into_inner();
    assert!(found.is_empty());
}

/// A damaged entry or a missing one: the output is still found (the group
/// owns it and sees the amount), and it is received but unspendable.
#[test]
fn a_damaged_or_missing_entry_is_received_but_unspendable() {
    let g = group(3, 2);
    let damaged = group_block(&g, |entries| {
        let e = &entries[0];
        let mut hashes = e.enc_key_hashes().to_vec();
        hashes[0] ^= 1;
        entries[0] = MultisigEntry::new(e.out_idx(), e.member_cts().to_vec(), hashes).unwrap();
    });
    assert_eq!(
        scan_one(&g, 0, damaged),
        Some(UnspendableReason::MultisigHashesUndecryptable)
    );

    let missing = group_block(&g, Vec::clear);
    assert!(
        !tx_extra::parse(&missing.transactions[0].tx().prefix.extra)
            .unwrap()
            .iter()
            .any(|f| matches!(f, tx_extra::TxExtraField::PqcMultisig(_))),
        "an empty entry list writes no 0x0D field"
    );
    assert_eq!(
        scan_one(&g, 1, missing),
        Some(UnspendableReason::MultisigEntryAbsent)
    );
}

/// The extra view hands the scanner the entry for the right output.
#[test]
fn the_extra_view_finds_the_entry_by_output_index() {
    let g = group(2, 2);
    let block = group_block(&g, |_| {});
    let extra = Extra::read(&mut block.transactions[0].tx().prefix.extra.as_slice()).unwrap();
    assert!(extra.pqc_multisig_entry(0).is_some());
    assert!(extra.pqc_multisig_entry(1).is_none());
    assert!(extra
        .0
        .iter()
        .any(|f| matches!(f, ExtraField::PqcMultisig(e) if e.len() == 1)));
}
