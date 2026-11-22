// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`receive_group_output`] on outputs built by the production constructor:
//! every member receives the same coin; a damaged output is refused with the
//! reach R-35 gives its reason; an output that is not the group's is none of
//! the member's business.

use super::*;
use crate::kem::{HybridKemSecretKey, HybridX25519MlKem, KeyEncapsulation};
use crate::multisig_output::{construct_multisig_output, MultisigOutputData};
use crate::TxKey;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use shekyl_address::multisig_address::MultisigAddressPayload;
use shekyl_address::Network;
use shekyl_curve_generators::T;
use shekyl_network::NetworkId;

const NET: NetworkId = [0x4E; 16];
const AMOUNT: u64 = 7_000;
const N: u8 = 5;
const M: u8 = 3;

struct Group {
    address: MultisigAddressPayload,
    b: [u8; 32],
    spend_key: [u8; 32],
    group_sk: HybridKemSecretKey,
    group_dk: MlKemDecapsKey,
    member_sks: Vec<HybridKemSecretKey>,
}

fn kem_bytes(pk: &crate::kem::HybridKemPublicKey) -> Vec<u8> {
    let mut out = pk.x25519.to_vec();
    out.extend_from_slice(&pk.ml_kem);
    out
}

fn group() -> Group {
    let kem = HybridX25519MlKem;
    let b = Scalar::random(&mut rand::rngs::OsRng);
    let y = Scalar::random(&mut rand::rngs::OsRng);
    let b_point = curve25519_dalek::constants::ED25519_BASEPOINT_POINT * b;
    let y_point = *T * y;
    let (group_pk, group_sk) = kem.keypair_generate().unwrap();
    let (member_pks, member_sks): (Vec<_>, Vec<_>) =
        (0..N).map(|_| kem.keypair_generate().unwrap()).unzip();
    let address = MultisigAddressPayload::new(
        Network::Testnet,
        N,
        M,
        b_point.compress().to_bytes(),
        y_point.compress().to_bytes(),
        kem_bytes(&group_pk),
        member_pks.iter().map(kem_bytes).collect(),
    )
    .unwrap();
    let group_dk = MlKemDecapsKey::from_bytes(&group_sk.ml_kem).unwrap();
    Group {
        address,
        b: b.to_bytes(),
        spend_key: (b_point + y_point).compress().to_bytes(),
        group_sk,
        group_dk,
        member_sks,
    }
}

fn keys(g: &Group) -> GroupScanKeys<'_> {
    GroupScanKeys {
        view_x25519: &g.group_sk.x25519,
        view_ml_kem: &g.group_dk,
        spend_key: &g.spend_key,
        b: &g.b,
    }
}

fn member(g: &Group, i: u8) -> MultisigMemberView<'_> {
    MultisigMemberView {
        member_index: i,
        n_total: N,
        m_required: M,
        member_kem_secret: &g.member_sks[usize::from(i)],
        network: &NET,
    }
}

/// An output paying the group at position 0 of a one-output transaction,
/// as the chain would carry it.
struct Paid {
    out: MultisigOutputData,
    leaf: [u8; PQC_LEAF_ENTRY_LEN],
    enc_amount: [u8; 9],
    enc_label: [u8; 9],
}

fn pay(g: &Group) -> Paid {
    let tx_key = TxKey::random().expect("the OS draws a key");
    let (position, ()) = tx_key.place(vec![()]).pop().unwrap();
    let out = construct_multisig_output(position, &g.address, AMOUNT, &NET).unwrap();
    Paid {
        leaf: out.pqc_leaf.entry_bytes(),
        enc_amount: out.enc_amount_wire().to_bytes(),
        enc_label: out.enc_label_wire().to_bytes(),
        out,
    }
}

fn on_chain(p: &Paid) -> GroupOutputOnChain<'_> {
    let (amount, amount_tag) = p.enc_amount.split_at(8);
    let (label, label_tag) = p.enc_label.split_at(8);
    GroupOutputOnChain {
        output_index: 0,
        output_key: &p.out.output_key,
        commitment: &p.out.commitment,
        enc_amount: amount.try_into().unwrap(),
        amount_tag: amount_tag[0],
        enc_label: label.try_into().unwrap(),
        label_tag: label_tag[0],
        view_tag: p.out.view_tag_prefilter,
        source_x25519_ct: &p.out.kem_ciphertext_x25519,
        source_ml_kem_ct: &p.out.kem_ciphertext_ml_kem,
        leaf_entry: Some(&p.leaf),
        entry: Some(GroupEntryOnChain {
            out_idx: 0,
            member_cts: p
                .out
                .member_kem_ciphertexts
                .iter()
                .map(|ct| {
                    let (x25519, ml_kem) = ct.split_at(X25519_KEM_CT_LEN);
                    (x25519.try_into().unwrap(), ml_kem)
                })
                .collect(),
            enc_key_hashes: &p.out.enc_key_hashes,
        }),
    }
}

fn refusal(received: Option<GroupReceived>) -> GroupRefusal {
    match received {
        Some(GroupReceived::Refused(refusal)) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Every member receives one coin: the same output, amount, key image and
/// committed form, and its own ciphertexts.
#[test]
fn every_member_receives_the_same_coin() {
    let g = group();
    let p = pay(&g);
    let receipts: Vec<GroupReceipt> = (0..N)
        .map(
            |i| match receive_group_output(&keys(&g), &member(&g, i), &on_chain(&p)) {
                Some(GroupReceived::Coin(receipt)) => receipt,
                other => panic!("member {i}: expected a coin, got {other:?}"),
            },
        )
        .collect();
    for (i, receipt) in receipts.iter().enumerate() {
        assert_eq!(receipt.output_index(), 0);
        assert_eq!(receipt.amount(), AMOUNT);
        assert_eq!(receipt.output_key(), &p.out.output_key);
        assert_eq!(receipt.commitment(), &p.out.commitment);
        assert_eq!(receipt.key_image(), receipts[0].key_image());
        assert_eq!(receipt.committed_form(), receipts[0].committed_form());
        assert_eq!(receipt.leaf_point(), &p.out.pqc_leaf.point);
        assert_eq!(receipt.source_x25519_ct(), &p.out.kem_ciphertext_x25519);
        assert_eq!(
            receipt.source_ml_kem_ct(),
            p.out.kem_ciphertext_ml_kem.as_slice()
        );
        let (own_x25519, own_ml_kem) = p.out.member_kem_ciphertexts[i].split_at(X25519_KEM_CT_LEN);
        assert_eq!(receipt.own_x25519_ct().as_slice(), own_x25519);
        assert_eq!(receipt.own_ml_kem_ct(), own_ml_kem);
    }
}

/// Another group's output is none of this member's business.
#[test]
fn another_groups_output_is_not_received() {
    let g = group();
    let other = group();
    let p = pay(&other);
    assert!(receive_group_output(&keys(&g), &member(&g, 0), &on_chain(&p)).is_none());
}

/// A missing leaf or `0x0D` entry is the group's loss.
#[test]
fn a_missing_entry_is_lost_to_everyone() {
    let g = group();
    let p = pay(&g);
    let mut output = on_chain(&p);
    output.leaf_entry = None;
    let refused = refusal(receive_group_output(&keys(&g), &member(&g, 0), &output));
    assert_eq!(refused.reason(), GroupRefusalReason::LeafEntryAbsent);
    assert_eq!(refused.reach(), RefusalReach::Everyone);
    assert_eq!(refused.amount(), AMOUNT);

    let mut output = on_chain(&p);
    output.entry = None;
    let refused = refusal(receive_group_output(&keys(&g), &member(&g, 0), &output));
    assert_eq!(refused.reason(), GroupRefusalReason::EntryAbsent);
    assert_eq!(refused.reach(), RefusalReach::Everyone);
}

/// Hashes that do not decrypt, and a leaf that does not commit to them, are
/// lost to every member alike.
#[test]
fn a_group_level_failure_is_lost_to_everyone() {
    let g = group();
    let mut p = pay(&g);
    p.out.enc_key_hashes[0] ^= 1;
    for i in 0..N {
        let refused = refusal(receive_group_output(
            &keys(&g),
            &member(&g, i),
            &on_chain(&p),
        ));
        assert_eq!(
            refused.reason(),
            GroupRefusalReason::Check(MultisigReceiveError::HashesUndecryptable)
        );
        assert_eq!(refused.reach(), RefusalReach::Everyone);
    }

    let mut p = pay(&g);
    p.leaf[PQC_LEAF_ENTRY_LEN - 1] ^= 1;
    for i in 0..N {
        let refused = refusal(receive_group_output(
            &keys(&g),
            &member(&g, i),
            &on_chain(&p),
        ));
        assert_eq!(
            refused.reason(),
            GroupRefusalReason::Check(MultisigReceiveError::LeafMismatch)
        );
        assert_eq!(refused.reach(), RefusalReach::Everyone);
    }
}

/// One member's damaged ciphertext is that member's loss only: the others
/// receive the coin.
#[test]
fn a_member_level_failure_is_that_members_loss_only() {
    let g = group();
    let mut p = pay(&g);
    let damaged = 2u8;
    let ct = &mut p.out.member_kem_ciphertexts[usize::from(damaged)];
    let last = ct.len() - 1;
    ct[last] ^= 1;
    for i in 0..N {
        let received = receive_group_output(&keys(&g), &member(&g, i), &on_chain(&p));
        if i == damaged {
            let refused = refusal(received);
            assert!(matches!(
                refused.reason(),
                GroupRefusalReason::Check(
                    MultisigReceiveError::MemberDecap | MultisigReceiveError::MemberKeyHash
                )
            ));
            assert_eq!(refused.reach(), RefusalReach::ThisMember);
        } else {
            assert!(
                matches!(received, Some(GroupReceived::Coin(_))),
                "member {i}"
            );
        }
    }
}

/// The group's checks run first: an output whose hashes do not decrypt is
/// the group's loss even for the member whose own ciphertext is also
/// damaged, so a member-only verdict always means the group can spend it.
#[test]
fn group_checks_come_before_the_members_own() {
    let g = group();
    let mut p = pay(&g);
    p.out.enc_key_hashes[0] ^= 1;
    let ct = &mut p.out.member_kem_ciphertexts[0];
    let last = ct.len() - 1;
    ct[last] ^= 1;
    let refused = refusal(receive_group_output(
        &keys(&g),
        &member(&g, 0),
        &on_chain(&p),
    ));
    assert_eq!(refused.reach(), RefusalReach::Everyone);
}

/// Every check's reach, in one table (R-35).
#[test]
fn each_reason_has_its_reach() {
    use MultisigReceiveError as E;
    let table = [
        (GroupRefusalReason::LeafEntryAbsent, RefusalReach::Everyone),
        (GroupRefusalReason::EntryAbsent, RefusalReach::Everyone),
        (
            GroupRefusalReason::Check(E::GroupSize),
            RefusalReach::Everyone,
        ),
        (
            GroupRefusalReason::Check(E::HashesUndecryptable),
            RefusalReach::Everyone,
        ),
        (
            GroupRefusalReason::Check(E::DuplicateKeyHash),
            RefusalReach::Everyone,
        ),
        (
            GroupRefusalReason::Check(E::LeafMismatch),
            RefusalReach::Everyone,
        ),
        (
            GroupRefusalReason::Check(E::MemberDecap),
            RefusalReach::ThisMember,
        ),
        (
            GroupRefusalReason::Check(E::MemberKeyHash),
            RefusalReach::ThisMember,
        ),
    ];
    for (reason, reach) in table {
        assert_eq!(reason.reach(), reach, "{reason:?}");
    }
}

/// The compressed group spend key is what a payer builds to.
#[test]
fn the_spend_key_is_the_addresses_points() {
    let g = group();
    let b = CompressedEdwardsY(*g.address.b_group())
        .decompress()
        .unwrap();
    let y = CompressedEdwardsY(*g.address.y_group())
        .decompress()
        .unwrap();
    assert_eq!((b + y).compress().to_bytes(), g.spend_key);
}
