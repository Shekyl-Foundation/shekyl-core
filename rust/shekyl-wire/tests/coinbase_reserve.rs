// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The coinbase reserve is the grammar's maximum, built through the codec.
//!
//! The number is printed, not pinned. A grammar change moves
//! [`max_coinbase_weight`] and this test still holds. This test is the
//! cover: a grammar change that moves the codec without the sum fails
//! [`the_maximal_coinbase_weighs_what_the_grammar_sums`].

use shekyl_wire::transaction::{
    max_coinbase_weight, Ct, CtBase, Input, Output, Transaction, TxPrefix, COINBASE_RESERVE,
    COINBASE_RESERVE_MARGIN, CT_COMMITMENT_LEN, CT_ENC_FIELD_LEN, OUTPUT_KEY_LEN, TX_WEIGHT_LIMIT,
};
use shekyl_wire::tx_extra::{
    build_coinbase_extra, check_tx_extra_shape, coinbase_extra_len, conforming_pqc_leaf_blob,
    ExtraSubject, TxExtraField, COINBASE_NONCE_BYTES, CONFORMING_DRAW_COMMITMENT,
    HYBRID_KEM_CT_BYTES, TX_EXTRA_PUBKEY_LEN,
};

fn extra_for(n: usize) -> Vec<u8> {
    build_coinbase_extra(
        [0x11; TX_EXTRA_PUBKEY_LEN],
        &[0xA5; COINBASE_NONCE_BYTES],
        CONFORMING_DRAW_COMMITMENT,
        n,
        &vec![0x44; HYBRID_KEM_CT_BYTES * n],
        &conforming_pqc_leaf_blob(n),
    )
    .unwrap_or_else(|err| panic!("the grammar admits {n} outputs: {err}"))
}

fn coinbase(amount: u64, height: u64, unlock_time: u64, extra: Vec<u8>) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time,
            inputs: vec![Input::Gen(height)],
            outputs: vec![Output {
                amount,
                key: [0x22; OUTPUT_KEY_LEN],
                view_tag: 1,
            }],
            extra,
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![[0x11; CT_ENC_FIELD_LEN]],
            enc_labels: vec![[0x33; CT_ENC_FIELD_LEN]],
            commitments: vec![[0x44; CT_COMMITMENT_LEN]],
        }),
    }
}

#[test]
fn the_maximal_coinbase_weighs_what_the_grammar_sums() {
    let extra = extra_for(1);
    assert_eq!(extra.len(), coinbase_extra_len(1));
    let maximal = coinbase(u64::MAX, u64::MAX, u64::MAX, extra);
    assert_eq!(maximal.weight(), max_coinbase_weight());
    assert_eq!(
        COINBASE_RESERVE,
        max_coinbase_weight() + COINBASE_RESERVE_MARGIN
    );

    let minimal = coinbase(0, 0, 0, extra_for(1));
    assert!(minimal.weight() < maximal.weight());
    assert!(minimal.weight() <= COINBASE_RESERVE);
    eprintln!(
        "coinbase reserve {COINBASE_RESERVE} = max {} + margin {COINBASE_RESERVE_MARGIN}; \
         TX_WEIGHT_LIMIT {TX_WEIGHT_LIMIT}; minimal coinbase {} B; maximal coinbase {} B",
        max_coinbase_weight(),
        minimal.weight(),
        maximal.weight()
    );

    // A tag the grammar refuses is not a heavier coinbase. The shape check
    // rejects it, so it never reaches the reserve.
    let mut fields = maximal
        .prefix
        .parse_extra()
        .expect("the constructor parses");
    fields.push(TxExtraField::ArchivalAttestation(vec![0xAB; 4]));
    assert!(
        check_tx_extra_shape(&fields, 1, ExtraSubject::Coinbase).is_err(),
        "an attestation in a coinbase is refused"
    );
}
