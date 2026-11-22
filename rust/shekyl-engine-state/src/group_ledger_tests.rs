// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A group ledger holds what a member's receive check returned, and reads it
//! back as it was written: coins from receipts, refusals of both kinds with
//! their reasons, and its versions refused when they are not this build's.

use super::*;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use shekyl_address::multisig_address::MultisigAddressPayload;
use shekyl_address::Network;
use shekyl_crypto_pq::kem::{
    HybridKemPublicKey, HybridKemSecretKey, HybridX25519MlKem, KeyEncapsulation, MlKemDecapsKey,
    X25519_KEM_CT_LEN,
};
use shekyl_crypto_pq::leaf_commitment::PQC_LEAF_ENTRY_LEN;
use shekyl_crypto_pq::multisig_output::{
    construct_multisig_output, MultisigMemberView, MultisigOutputData,
};
use shekyl_crypto_pq::multisig_receive::{
    receive_group_output, GroupEntryOnChain, GroupOutputOnChain, GroupReceived, GroupScanKeys,
};
use shekyl_crypto_pq::TxKey;

const NET: [u8; 16] = [0x4E; 16];
const AMOUNT: u64 = 9_000;
const N: u8 = 3;
const M: u8 = 2;

struct Group {
    address: MultisigAddressPayload,
    b: zeroize::Zeroizing<[u8; 32]>,
    spend_key: [u8; 32],
    group_sk: HybridKemSecretKey,
    group_dk: MlKemDecapsKey,
    member_sks: Vec<HybridKemSecretKey>,
}

fn kem_bytes(pk: &HybridKemPublicKey) -> Vec<u8> {
    let mut out = pk.x25519.to_vec();
    out.extend_from_slice(&pk.ml_kem);
    out
}

fn group() -> Group {
    let kem = HybridX25519MlKem;
    // Any two prime-order points serve: the test pays the group and reads
    // the receipt back, and signs nothing.
    let b = Scalar::from_bytes_mod_order([0x21; 32]);
    let b_point = ED25519_BASEPOINT_POINT * b;
    let y_point = ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order([0x23; 32]);
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
        b: zeroize::Zeroizing::new(b.to_bytes()),
        spend_key: (b_point + y_point).compress().to_bytes(),
        group_sk,
        group_dk,
        member_sks,
    }
}

/// Pay the group, let `damage` edit what the chain carries, and receive the
/// output as member `i`.
fn receive_as(
    g: &Group,
    i: u8,
    damage: impl FnOnce(&mut MultisigOutputData, &mut [u8; PQC_LEAF_ENTRY_LEN]),
) -> GroupReceived {
    let tx_key = TxKey::random().expect("the OS draws a key");
    let (position, ()) = tx_key.place(vec![()]).pop().unwrap();
    let mut out = construct_multisig_output(position, &g.address, AMOUNT, &NET).unwrap();
    let mut leaf = out.pqc_leaf.entry_bytes();
    damage(&mut out, &mut leaf);
    let enc_amount = out.enc_amount_wire().to_bytes();
    let enc_label = out.enc_label_wire().to_bytes();
    let member_cts = out
        .member_kem_ciphertexts
        .iter()
        .map(|ct| {
            let (x25519, ml_kem) = ct.split_at(X25519_KEM_CT_LEN);
            (x25519.try_into().unwrap(), ml_kem)
        })
        .collect();
    let on_chain = GroupOutputOnChain {
        output_index: 0,
        output_key: &out.output_key,
        commitment: &out.commitment,
        enc_amount: enc_amount[..8].try_into().unwrap(),
        amount_tag: enc_amount[8],
        enc_label: enc_label[..8].try_into().unwrap(),
        label_tag: enc_label[8],
        view_tag: out.view_tag_prefilter,
        source_x25519_ct: &out.kem_ciphertext_x25519,
        source_ml_kem_ct: &out.kem_ciphertext_ml_kem,
        leaf_entry: Some(&leaf),
        entry: Some(GroupEntryOnChain {
            out_idx: 0,
            member_cts,
            enc_key_hashes: &out.enc_key_hashes,
        }),
    };
    let keys = GroupScanKeys {
        view_x25519: &g.group_sk.x25519,
        view_ml_kem: &g.group_dk,
        spend_key: &g.spend_key,
        b: &g.b,
    };
    let member = MultisigMemberView {
        member_index: i,
        n_total: N,
        m_required: M,
        member_kem_secret: &g.member_sks[usize::from(i)],
        network: &NET,
    };
    receive_group_output(&keys, &member, &on_chain).expect("the output is the group's")
}

fn place(global: u64) -> ChainPlace {
    ChainPlace {
        tx_hash: TxHash::from_bytes([0x77; 32]),
        global_output_index: GlobalOutputIndex::from_raw(global),
        block_height: BlockHeight::from_raw(40),
        eligible_height: BlockHeight::from_raw(50),
    }
}

fn coin(received: GroupReceived, at: ChainPlace) -> GroupCoin {
    match received {
        GroupReceived::Coin(receipt) => GroupCoin::received(&receipt, at),
        GroupReceived::Refused(refusal) => panic!("expected a coin, got {refusal:?}"),
    }
}

fn refused(received: GroupReceived, at: ChainPlace) -> RefusedGroupOutput {
    match received {
        GroupReceived::Refused(refusal) => RefusedGroupOutput::refused(&refusal, at),
        GroupReceived::Coin(receipt) => panic!("expected a refusal, got {receipt:?}"),
    }
}

/// A coin holds what the receipt attested and where the scanner put it.
#[test]
fn a_coin_is_its_receipt_at_its_place() {
    let g = group();
    let received = receive_as(&g, 1, |_, _| {});
    let GroupReceived::Coin(receipt) = &received else {
        panic!("expected a coin");
    };
    let coin = GroupCoin::received(receipt, place(7));
    assert_eq!(coin.amount(), AtomicUnits::from_raw(AMOUNT));
    assert_eq!(coin.output_key(), receipt.output_key());
    assert_eq!(coin.commitment(), receipt.commitment());
    assert_eq!(coin.key_image(), receipt.key_image());
    assert_eq!(coin.committed_form(), receipt.committed_form());
    assert_eq!(coin.leaf_point(), receipt.leaf_point());
    assert_eq!(&coin.own_ciphertext().x25519, receipt.own_x25519_ct());
    assert_eq!(coin.own_ciphertext().ml_kem, receipt.own_ml_kem_ct());
    assert_eq!(&coin.source_ciphertext().x25519, receipt.source_x25519_ct());
    assert_eq!(coin.internal_output_index(), OutputIndexInTx::from_raw(0));
    assert_eq!(coin.global_output_index(), GlobalOutputIndex::from_raw(7));
    assert_eq!(coin.block_height(), BlockHeight::from_raw(40));
    assert_eq!(coin.eligible_height(), BlockHeight::from_raw(50));
    assert_eq!(coin.spent(), None);
}

/// Each refusal records its reason and who it is lost to (R-35): a damaged
/// hash list is lost to everyone; a damaged ciphertext of this member's is
/// group funds this member cannot sign for.
#[test]
fn a_refusal_records_its_reason_and_reach() {
    let g = group();
    let everyone = refused(
        receive_as(&g, 0, |out, _| out.enc_key_hashes[0] ^= 1),
        place(8),
    );
    assert_eq!(
        everyone.reason(),
        UnspendableReason::MultisigHashesUndecryptable
    );
    assert_eq!(everyone.kind(), GroupRefusalKind::LostToEveryone);
    assert!(!everyone.counts_in_group_balance());
    assert_eq!(everyone.amount(), AtomicUnits::from_raw(AMOUNT));

    let this_member = refused(
        receive_as(&g, 2, |out, _| {
            let ct = &mut out.member_kem_ciphertexts[2];
            let last = ct.len() - 1;
            ct[last] ^= 1;
        }),
        place(9),
    );
    assert!(matches!(
        this_member.reason(),
        UnspendableReason::MultisigMemberDecap | UnspendableReason::MultisigMemberKeyHash
    ));
    assert_eq!(this_member.kind(), GroupRefusalKind::LostToThisMember);
    assert!(this_member.counts_in_group_balance());

    let leaf = refused(
        receive_as(&g, 1, |_, leaf| leaf[PQC_LEAF_ENTRY_LEN - 1] ^= 1),
        place(10),
    );
    assert_eq!(leaf.reason(), UnspendableReason::MultisigLeafMismatch);
    assert_eq!(leaf.kind(), GroupRefusalKind::LostToEveryone);
}

/// Every refusal maps to its own persisted reason, and its reach to its
/// kind (R-35's table).
#[test]
fn every_refusal_has_its_own_reason() {
    use shekyl_crypto_pq::multisig_output::MultisigReceiveError as E;
    use shekyl_crypto_pq::multisig_receive::GroupRefusalReason as R;
    let table = [
        (
            R::LeafEntryAbsent,
            UnspendableReason::PqcLeafEntryAbsent,
            GroupRefusalKind::LostToEveryone,
        ),
        (
            R::EntryAbsent,
            UnspendableReason::MultisigEntryAbsent,
            GroupRefusalKind::LostToEveryone,
        ),
        (
            R::Check(E::GroupSize),
            UnspendableReason::MultisigGroupSize,
            GroupRefusalKind::LostToEveryone,
        ),
        (
            R::Check(E::HashesUndecryptable),
            UnspendableReason::MultisigHashesUndecryptable,
            GroupRefusalKind::LostToEveryone,
        ),
        (
            R::Check(E::DuplicateKeyHash),
            UnspendableReason::MultisigDuplicateKeyHash,
            GroupRefusalKind::LostToEveryone,
        ),
        (
            R::Check(E::LeafMismatch),
            UnspendableReason::MultisigLeafMismatch,
            GroupRefusalKind::LostToEveryone,
        ),
        (
            R::Check(E::MemberDecap),
            UnspendableReason::MultisigMemberDecap,
            GroupRefusalKind::LostToThisMember,
        ),
        (
            R::Check(E::MemberKeyHash),
            UnspendableReason::MultisigMemberKeyHash,
            GroupRefusalKind::LostToThisMember,
        ),
    ];
    let mut reasons = std::collections::BTreeSet::new();
    for (refusal, reason, kind) in table {
        assert_eq!(unspendable_reason(refusal), reason, "{refusal:?}");
        assert_eq!(GroupRefusalKind::from(refusal.reach()), kind, "{refusal:?}");
        assert!(
            reasons.insert(reason.rpc_name()),
            "{refusal:?} shares a reason"
        );
    }
}

/// A group ledger reads back as written: its coin, both refusals, spent
/// marks and the scan pointer.
#[test]
fn a_group_ledger_round_trips() {
    let g = group();
    let mut ledger = GroupWalletLedger::empty();
    let mut spent_coin = coin(receive_as(&g, 0, |_, _| {}), place(1));
    let spent = SpentAt {
        height: BlockHeight::from_raw(60),
        tx_hash: TxHash::from_bytes([0x88; 32]),
    };
    spent_coin.mark_spent(spent);
    ledger.ledger.outputs.push(GroupOutput::Coin(spent_coin));
    ledger.ledger.outputs.push(GroupOutput::Coin(coin(
        receive_as(&g, 0, |_, _| {}),
        place(2),
    )));
    ledger.ledger.outputs.push(GroupOutput::Refused(refused(
        receive_as(&g, 0, |out, _| out.enc_key_hashes[0] ^= 1),
        place(3),
    )));
    ledger.ledger.tip = BlockchainTip::new(
        BlockHeight::from_raw(70),
        shekyl_types::BlockHash::from_bytes([0x99; 32]),
    );

    let bytes = ledger.to_postcard_bytes().unwrap();
    let back = GroupWalletLedger::from_postcard_bytes(&bytes).unwrap();
    assert_eq!(back.to_postcard_bytes().unwrap(), bytes);
    assert_eq!(back.ledger.coins().count(), 2);
    assert_eq!(back.ledger.unspent_coins().count(), 1);
    assert_eq!(back.ledger.refused().count(), 1);
    let first = back.ledger.coins().next().unwrap();
    assert_eq!(first.spent(), Some(spent));
    let GroupOutput::Coin(original) = &ledger.ledger.outputs[0] else {
        unreachable!()
    };
    assert_eq!(first.committed_form(), original.committed_form());
    assert_eq!(back.ledger.tip, ledger.ledger.tip);
}

/// Another format version is refused by name, before the body is read; a
/// block of another version is refused too.
#[test]
fn another_version_is_refused() {
    let mut ledger = GroupWalletLedger::empty();
    ledger.format_version = GROUP_WALLET_LEDGER_FORMAT_VERSION + 1;
    let bytes = ledger.to_postcard_bytes().unwrap();
    assert!(matches!(
        GroupWalletLedger::from_postcard_bytes(&bytes),
        Err(WalletLedgerError::UnsupportedGroupFormatVersion { file, binary })
            if file == GROUP_WALLET_LEDGER_FORMAT_VERSION + 1
                && binary == GROUP_WALLET_LEDGER_FORMAT_VERSION
    ));
    // A version from a later build, with a body this build cannot read.
    let mut later = postcard::to_allocvec(&(GROUP_WALLET_LEDGER_FORMAT_VERSION + 1)).unwrap();
    later.extend_from_slice(&[0xFF; 8]);
    assert!(matches!(
        GroupWalletLedger::from_postcard_bytes(&later),
        Err(WalletLedgerError::UnsupportedGroupFormatVersion { .. })
    ));

    let mut ledger = GroupWalletLedger::empty();
    ledger.ledger.block_version = GROUP_LEDGER_BLOCK_VERSION + 1;
    let bytes = ledger.to_postcard_bytes().unwrap();
    assert!(matches!(
        GroupWalletLedger::from_postcard_bytes(&bytes),
        Err(WalletLedgerError::UnsupportedBlockVersion {
            block: "group ledger",
            ..
        })
    ));
}

/// A committed form that does not parse is not read back as one.
#[test]
fn a_committed_form_that_does_not_parse_is_refused() {
    let g = group();
    let mut ledger = GroupWalletLedger::empty();
    ledger.ledger.outputs.push(GroupOutput::Coin(coin(
        receive_as(&g, 0, |_, _| {}),
        place(4),
    )));
    let mut bytes = ledger.to_postcard_bytes().unwrap();
    // The committed form is `0x02 ‖ n ‖ m ‖ hashes`; its first byte follows
    // its length prefix. Find it by its encoding and change the threshold
    // to one the form refuses (m above n).
    let GroupOutput::Coin(c) = &ledger.ledger.outputs[0] else {
        unreachable!()
    };
    let form = c.committed_form().to_bytes();
    let at = bytes
        .windows(form.len())
        .position(|w| w == form.as_slice())
        .expect("the form is in the encoding");
    bytes[at + 2] = N + 1;
    assert!(matches!(
        GroupWalletLedger::from_postcard_bytes(&bytes),
        Err(WalletLedgerError::Postcard(_))
    ));
}
