// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transaction weight model: what [`Transaction::write`] emits for a spend
//! of a given shape, plus the Bp+ clawback, without building the transaction.
//!
//! It lives beside the writer it mirrors (`ICD-R1`,
//! `docs/design/CEN_I4_INPUT_CAP_DERIVATION.md`) and every function is a
//! `const fn`, because consensus constants are computed from it at compile
//! time. The proof's length is [`FcmpPlusPlus::proof_size`], the closed form
//! over the circuit's padded rows, and not a measured table; the measured table
//! is this module's test vectors (`weight_tests`).
//!
//! Counts are plain `usize` here. `shekyl-tx-weight` holds the bounded count
//! types, the spend-shape types and the fee loop on top of this model. Its
//! `tests/weight_gate.rs` holds the model equal to the bytes the builder emits
//! across the whole shape space.
//!
//! [`Transaction::write`]: super::Transaction::write

use shekyl_crypto_pq::kem::HYBRID_KEM_CT_LEN;
use shekyl_curve_generators::MAX_TREE_DEPTH;
use shekyl_fcmp_proofs::FcmpPlusPlus;

use super::{
    bp_plus_weight_clawback, MAX_FCMP_INPUTS, PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN,
    TX_VERSION,
};
use crate::tx_extra::PQC_LEAF_ENTRY_LEN;
use crate::varint::varint_len;

// Each constant is one field of `Transaction::write`. Sizes with a canonical
// home are imported, not re-typed.

/// `Input::ToKey`: tag + varint(amount=0) + varint(key_offsets=0) + key_image.
const INPUT_TO_KEY_WEIGHT: usize = 1 + 1 + 1 + 32;
/// `Output`: varint(amount=0) + tag + one-time key + view_tag.
const OUTPUT_WEIGHT: usize = 1 + 1 + 32 + 1;
/// `CtBase` per output: enc_amount + enc_label + commitment.
const CT_BASE_PER_OUTPUT_WEIGHT: usize = 9 + 9 + 32;
/// `reference_block` hash in the ct base.
const REFERENCE_BLOCK_LEN: usize = 32;
/// `pseudoOut` commitment per input in the prunable.
const PSEUDO_OUT_LEN: usize = 32;
/// `ExtraField::PublicKey`: tag + Edwards point.
pub const EXTRA_PUBKEY_FIELD_WEIGHT: usize = 1 + 32;

/// The longest FCMP++ proof over every input count and depth the protocol
/// admits: the conservative answer of [`fcmp_proof_len`] for a depth no
/// transaction can carry.
pub const FCMP_PROOF_LEN_MAX: usize = {
    let mut max = 0;
    let mut n_in = 1;
    while n_in <= MAX_FCMP_INPUTS {
        let mut depth = 1;
        while depth <= MAX_TREE_DEPTH as usize {
            let len = FcmpPlusPlus::proof_size(n_in, depth);
            if len > max {
                max = len;
            }
            depth += 1;
        }
        n_in += 1;
    }
    max
};

/// The FCMP++ proof's length in bytes for `n_in` inputs at `tree_depth`.
///
/// A depth outside `1..=MAX_TREE_DEPTH`, or no inputs, answers
/// [`FCMP_PROOF_LEN_MAX`], so a fee estimate stays conservative rather than
/// panicking or under-paying.
#[must_use]
pub const fn fcmp_proof_len(n_in: usize, tree_depth: u8) -> usize {
    if n_in == 0 || tree_depth == 0 || tree_depth > MAX_TREE_DEPTH {
        return FCMP_PROOF_LEN_MAX;
    }
    FcmpPlusPlus::proof_size(n_in, tree_depth as usize)
}

/// The **single** `ExtraField::PqcKemCiphertext` (`0x06`) field: tag +
/// varint(len) + `n_out` concatenated per-output ciphertexts — the packing
/// `Extra::for_hybrid_transfer` emits, which every reader slices at
/// `o * HYBRID_KEM_CT_LEN`.
#[must_use]
pub const fn extra_kem_field_weight(n_out: usize) -> usize {
    let blob = n_out * HYBRID_KEM_CT_LEN;
    1 + varint_len(blob as u64) + blob
}

/// `ExtraField::PqcLeafEntries` (`0x07`): tag + varint(len) + `n_out × 64`
/// leaf entries (`CM ‖ record`, `PL-D3` / `PL-D3a`) — a consensus-required
/// field (CEN-I19: a transaction with outputs is refused without it).
#[must_use]
pub const fn extra_leaf_hashes_field_weight(n_out: usize) -> usize {
    let blob = n_out * PQC_LEAF_ENTRY_LEN;
    1 + varint_len(blob as u64) + blob
}

/// One per-input `PqcAuth` carrying a `key_len`-byte key blob and a
/// `sig_len`-byte signature blob: auth_version + scheme_id + flags(u16) +
/// varint(key_len) ‖ key + varint(sig_len) ‖ sig.
#[must_use]
pub const fn pqc_auth_weight_of(key_len: usize, sig_len: usize) -> usize {
    1 + 1 + 2 + varint_len(key_len as u64) + key_len + varint_len(sig_len as u64) + sig_len
}

/// One per-input `PqcAuth` of a single signer: a solo hybrid key and
/// signature.
#[must_use]
pub const fn pqc_auth_weight() -> usize {
    pqc_auth_weight_of(PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN)
}

/// Padded output count the Bp+ aggregates over — next power of two, ≥ 1.
#[must_use]
pub const fn padded_outputs(n_out: usize) -> usize {
    n_out.next_power_of_two()
}

/// Serialized Bp+ size: 6 fixed points + varint(|L|)‖L + varint(|R|)‖R, where
/// `|L| == |R| == 6 + log2(n_padded)` (the proof's L/R vector length).
#[must_use]
pub const fn bp_plus_weight(n_out: usize) -> usize {
    let nlr = 6 + padded_outputs(n_out).trailing_zeros() as usize;
    6 * 32 + 2 * (varint_len(nlr as u64) + nlr * 32)
}

/// Bp+ verification clawback for the predicted output count: the canonical
/// [`bp_plus_weight_clawback`] at the `n_padded` a built transaction's proof
/// would yield, so the model and `Transaction::weight` share one formula.
#[must_use]
pub const fn bp_plus_clawback_weight(n_out: usize) -> usize {
    bp_plus_weight_clawback(padded_outputs(n_out))
}

/// The one field model: the weight of a spend of `n_in` inputs each authorized
/// by `auth_weight` bytes, and `n_out` outputs whose `tx_extra` adds
/// `multisig_extra` bytes of `0x0D` entries. Each term is one field of
/// `Transaction::write`, in wire order.
#[must_use]
pub const fn spend_weight(
    n_in: usize,
    n_out: usize,
    tree_depth: u8,
    fee: u64,
    auth_weight: usize,
    multisig_extra: usize,
) -> usize {
    let fcmp = fcmp_proof_len(n_in, tree_depth);
    let extra_len = EXTRA_PUBKEY_FIELD_WEIGHT
        + extra_kem_field_weight(n_out)
        + extra_leaf_hashes_field_weight(n_out)
        + multisig_extra;
    varint_len(TX_VERSION) // version
        + varint_len(0) // unlock_time
        + varint_len(n_in as u64) // vin count
        + n_in * INPUT_TO_KEY_WEIGHT // vin elements
        + varint_len(n_out as u64) // vout count
        + n_out * OUTPUT_WEIGHT // vout elements
        + varint_len(extra_len as u64) // tx_extra length prefix
        + extra_len // tx_extra body
        + 1 // ct type tag: one u8 (a byte width, not CT_TYPE_FCMP's value)
        + varint_len(fee) // fee
        + REFERENCE_BLOCK_LEN // reference_block
        + n_out * CT_BASE_PER_OUTPUT_WEIGHT // ct base (per output)
        + n_in * auth_weight // per-input PQC auth
        + varint_len(1) // prunable nbp
        + bp_plus_weight(n_out) // bulletproof+
        + varint_len(tree_depth as u64) // tree_depth
        + varint_len(fcmp as u64) // fcmp_proof length prefix
        + fcmp // fcmp_proof body
        + n_in * PSEUDO_OUT_LEN // pseudoOuts
        + bp_plus_clawback_weight(n_out) // Bp+ verification clawback
}

/// The **archival length** of a solo spend of this shape: `|pqc_auths| +
/// |prunable|`, the two segments a prune discards and the bytes that count
/// toward a shard's `W` (`TxSegments::archival_len`, SHT-Q2). The partial sum
/// of [`spend_weight`]'s fields from the per-input PQC auths through
/// `pseudoOuts`; independent of the fee and of the Bp+ clawback.
#[must_use]
pub const fn archival_len(n_in: usize, n_out: usize, tree_depth: u8) -> usize {
    let fcmp = fcmp_proof_len(n_in, tree_depth);
    n_in * pqc_auth_weight() // the `pqc_auths` segment
        + varint_len(1) // prunable nbp
        + bp_plus_weight(n_out) // bulletproof+
        + varint_len(tree_depth as u64) // tree_depth
        + varint_len(fcmp as u64) // fcmp_proof length prefix
        + fcmp // fcmp_proof body
        + n_in * PSEUDO_OUT_LEN // pseudoOuts
}
