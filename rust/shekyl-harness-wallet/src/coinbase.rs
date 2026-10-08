// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A coinbase as the miner's wallet will scan it: one real output paying
//! a [`Recipient`], composed from the two owners the block template
//! composes from and nothing above them (the crate docs' second-oracle
//! property).
//!
//! The tx secret is a function of the height ([`tx_key`]), so for one
//! recipient at one height the output key, the view tag, the KEM
//! ciphertexts and the PQC leaf entry are fixed whatever the amount — the
//! amount moves exactly three fields: the amount itself, the commitment
//! and the encrypted amount. [`repay`] re-derives those three and touches
//! nothing else, which is what lets a pricer settle a fixture's coinbase
//! after the fact without rebuilding the block around it.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use shekyl_crypto_pq::output::{construct_output, OutputData};
use shekyl_wire::tx_extra::{self, COINBASE_NONCE_BYTES};
use shekyl_wire::{Ct, CtBase, Input, Output, Transaction, TxPrefix};
use zeroize::Zeroizing;

use crate::Recipient;

/// The coinbase tx secret `r` for a block at `height`: the height in the
/// low eight bytes under a fixed `0x0A` fill. The fill keeps the value
/// below the group order with a non-zero top, so it is already reduced
/// and never zero — no reduction step whose output a reader would have to
/// reason about.
#[must_use]
pub fn tx_key(height: u64) -> Zeroizing<[u8; 32]> {
    let mut r = Zeroizing::new([0x0A; 32]);
    r[..8].copy_from_slice(&height.to_le_bytes());
    r
}

/// The tx public key `r·G` for [`tx_key`]`(height)` — what the `0x01`
/// field of a coinbase at `height` carries.
#[must_use]
pub fn tx_pubkey(height: u64) -> [u8; 32] {
    let r = Zeroizing::new(Scalar::from_bytes_mod_order(*tx_key(height)));
    EdwardsPoint::mul_base(&r).compress().to_bytes()
}

/// The output paying `amount` to `recipient` at `height`, as output `0`.
///
/// # Panics
///
/// A recipient whose spend key is not a canonical, torsion-free,
/// non-identity point, or whose ML-KEM key is not 1184 bytes, is not a
/// wallet this crate derived — a harness bug, not an input to handle.
fn output(recipient: &Recipient, height: u64, amount: u64) -> OutputData {
    construct_output(
        &tx_key(height),
        &recipient.x25519_pk,
        &recipient.ml_kem_ek,
        &recipient.spend_public,
        amount,
        0,
    )
    .expect("a harness-derived recipient is a valid output target")
}

/// A coinbase for a block at `height` paying `amount` to `recipient` in
/// one output, with the given `unlock_time`.
///
/// Shaped as the census asks of a coinbase and as the template builds
/// one: one `Input::Gen(height)` (CEN-F1, F5), one output (F4) whose key
/// and mask are the shared secret's (F9, F10), `Ct::Null` with one
/// committed base (F3), and the grammar's `extra` for one output —
/// `[0x01 r·G, 0x02 nonce(8), 0x06 KEM, 0x07 leaf]` — built by the
/// grammar's one constructor (I19, I20). The nonce is zero: no rule reads
/// its value. `unlock_time` is the caller's: CEN-F6 says what it must be
/// for a block the validator will pass, and a fixture built to exercise
/// the store at the top of the height range needs the bytes, not the
/// verdict.
///
/// # Panics
///
/// See [`output`]; and the grammar constructor refuses nothing a
/// one-output composition hands it.
#[must_use]
pub fn paying(recipient: &Recipient, height: u64, unlock_time: u64, amount: u64) -> Transaction {
    let od = output(recipient, height, amount);
    let mut kem_blob =
        Vec::with_capacity(od.kem_ciphertext_x25519.len() + od.kem_ciphertext_ml_kem.len());
    kem_blob.extend_from_slice(&od.kem_ciphertext_x25519);
    kem_blob.extend_from_slice(&od.kem_ciphertext_ml_kem);
    let leaf_blob = od.pqc_leaf.entry_bytes();
    let extra = tx_extra::build_coinbase_extra(
        tx_pubkey(height),
        &[0; COINBASE_NONCE_BYTES],
        1,
        &kem_blob,
        &leaf_blob,
    )
    .expect("the grammar's one layout builds for one output");
    Transaction {
        prefix: TxPrefix {
            unlock_time,
            inputs: vec![Input::Gen(height)],
            outputs: vec![Output {
                amount,
                key: od.output_key,
                view_tag: od.view_tag_prefilter,
            }],
            extra,
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![od.enc_amount_wire().to_bytes()],
            enc_labels: vec![od.enc_label_wire().to_bytes()],
            commitments: vec![od.commitment],
        }),
    }
}

/// What a coinbase pays, read back off the transaction: the fields a
/// store records for its one output and a spender later needs. The
/// read-side mirror of [`repay`], which writes the amount-bound half of
/// these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paid {
    /// The height the coinbase claims (`Input::Gen`).
    pub height: u64,
    /// Output `0`'s cleartext amount.
    pub amount: u64,
    /// Output `0`'s one-time key.
    pub key: [u8; 32],
    /// Output `0`'s commitment, from the `Null` ct base.
    pub commitment: [u8; 32],
}

/// Read [`Paid`] off `tx`, or `None` when `tx` is not shaped as a
/// coinbase with a committed output — the same shape test [`repay`]
/// applies before it writes.
pub fn paid(tx: &Transaction) -> Option<Paid> {
    let Some(Input::Gen(height)) = tx.prefix.inputs.first() else {
        return None;
    };
    let first = tx.prefix.outputs.first()?;
    let Ct::Null(base) = &tx.ct else {
        return None;
    };
    Some(Paid {
        height: *height,
        amount: first.amount,
        key: first.key,
        commitment: *base.commitments.first()?,
    })
}

/// Re-pay output `0` of a coinbase built by [`paying`] with `amount`:
/// the amount, the commitment and the encrypted amount are re-derived
/// for the height the coinbase claims; the key, the view tag, the label
/// and the `extra` do not depend on the amount and are left as they
/// stand.
///
/// Returns `false`, having written nothing, when `tx` is not shaped as a
/// coinbase with an output — no `Input::Gen` first, no output, or a
/// `Ct` that is not `Null` with a committed base for output `0`. Such a
/// transaction has nothing this function can price.
pub fn repay(tx: &mut Transaction, recipient: &Recipient, amount: u64) -> bool {
    let Some(Input::Gen(height)) = tx.prefix.inputs.first() else {
        return false;
    };
    let height = *height;
    let Some(first) = tx.prefix.outputs.first_mut() else {
        return false;
    };
    let Ct::Null(base) = &mut tx.ct else {
        return false;
    };
    let (Some(commitment), Some(enc_amount)) =
        (base.commitments.first_mut(), base.enc_amounts.first_mut())
    else {
        return false;
    };
    let od = output(recipient, height, amount);
    first.amount = amount;
    *commitment = od.commitment;
    *enc_amount = od.enc_amount_wire().to_bytes();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MinerWallet;

    #[test]
    fn repay_moves_exactly_the_three_amount_fields() {
        let who = MinerWallet::harness().recipient();
        let built = paying(who, 7, 67, 500);
        let mut repaid = paying(who, 7, 67, 0);
        assert!(repay(&mut repaid, who, 500));
        assert_eq!(repaid, built);
    }

    #[test]
    fn paid_reads_back_what_paying_wrote() {
        let who = MinerWallet::harness().recipient();
        let tx = paying(who, 11, 71, 42);
        let got = paid(&tx).expect("a coinbase");
        assert_eq!(got.height, 11);
        assert_eq!(got.amount, 42);
        assert_eq!(got.key, tx.prefix.outputs[0].key);
        let Ct::Null(base) = &tx.ct else {
            panic!("coinbase ct is Null")
        };
        assert_eq!(got.commitment, base.commitments[0]);
    }

    #[test]
    fn a_different_amount_leaves_the_key_and_extra_fixed() {
        let who = MinerWallet::harness().recipient();
        let a = paying(who, 3, 63, 1);
        let b = paying(who, 3, 63, 2);
        assert_eq!(a.prefix.outputs[0].key, b.prefix.outputs[0].key);
        assert_eq!(a.prefix.outputs[0].view_tag, b.prefix.outputs[0].view_tag);
        assert_eq!(a.prefix.extra, b.prefix.extra);
        assert_ne!(a.ct, b.ct);
    }

    #[test]
    fn repay_declines_what_is_not_a_coinbase() {
        let who = MinerWallet::harness().recipient();
        let mut no_outputs = paying(who, 1, 61, 0);
        no_outputs.prefix.outputs.clear();
        assert!(!repay(&mut no_outputs, who, 9));
    }
}
