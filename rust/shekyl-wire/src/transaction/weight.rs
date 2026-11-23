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
use shekyl_curve_generators::{
    FCMP_HELIOS_GENERATORS, FCMP_SELENE_GENERATORS, MAX_TREE_DEPTH, MIN_SPEND_LAYERS,
};
use shekyl_fcmp_proofs::fcmps::Fcmp;
use shekyl_fcmp_proofs::FcmpPlusPlus;

use super::{
    bp_plus_weight_clawback, MAX_FCMP_INPUTS, MAX_OUTPUTS, MIN_NON_COINBASE_OUTPUTS,
    PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN, TX_VERSION, TX_WEIGHT_LIMIT,
};
use crate::tx_extra::PQC_LEAF_ENTRY_LEN;
use crate::varint::{varint_len, MAX_VARINT_LEN};

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
    weight_with_proof(
        n_in,
        n_out,
        tree_depth,
        fee,
        auth_weight,
        multisig_extra,
        fcmp_proof_len(n_in, tree_depth),
    )
}

/// [`spend_weight`] given the proof's length. The input cap is computed through
/// this and the closed form, because [`fcmp_proof_len`]'s fallback reads the
/// cap.
const fn weight_with_proof(
    n_in: usize,
    n_out: usize,
    tree_depth: u8,
    fee: u64,
    auth_weight: usize,
    multisig_extra: usize,
    fcmp: usize,
) -> usize {
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

// ── What consensus admits ───────────────────────────────────────────────────

/// The floor of the maximum tree depth (`ICD-R9`, step 1), set on the chain's
/// own limit. The tree holds every output ever created, so this bounds
/// cumulative outputs. An output weighs 1 269 bytes, so the store's 1 GB/day
/// write budget (PB-R2) allows at most about 788 000 outputs a day, and depth
/// 12 (about 10^17 outputs) is about 360 million years of that.
///
/// The write budget is a design budget and block size is dynamic, so this is
/// re-checked when EUP-5 G rules block growth.
pub const TREE_DEPTH_FLOOR: u8 = 12;

/// The weight of the lightest spend of this shape: a solo signer and a
/// one-byte fee varint, on the closed-form proof.
const fn lightest_weight(n_in: usize, n_out: usize, tree_depth: u8) -> usize {
    weight_with_proof(
        n_in,
        n_out,
        tree_depth,
        0,
        pqc_auth_weight(),
        0,
        FcmpPlusPlus::proof_size(n_in, tree_depth as usize),
    )
}

/// The most inputs the weight limit admits for `n_out` outputs at `tree_depth`.
const fn inputs_under_weight_limit(n_out: usize, tree_depth: u8) -> usize {
    let mut n_in = 0;
    while lightest_weight(n_in + 1, n_out, tree_depth) <= TX_WEIGHT_LIMIT {
        n_in += 1;
    }
    n_in
}

/// The input cap (`ICD-R1`): the most inputs the weight limit admits at the
/// lightest legal shape, over every legal depth. [`MAX_FCMP_INPUTS`] is this.
pub(super) const fn derive_input_cap() -> usize {
    let mut cap = 0;
    let mut depth = MIN_SPEND_LAYERS;
    while depth <= MAX_TREE_DEPTH {
        let n_in = inputs_under_weight_limit(MIN_NON_COINBASE_OUTPUTS, depth);
        if n_in > cap {
            cap = n_in;
        }
        depth += 1;
    }
    cap
}

/// The most generator rows, per curve, any legal transaction's proof needs
/// on a tree no deeper than `max_depth` (`ICD-R2`): the largest
/// `ipa_rows(N(d), d)` over those depths, not `ipa_rows(cap, max_depth)`, which
/// would overstate the second curve.
const fn generator_rows_through(max_depth: u8) -> (usize, usize) {
    let (mut selene, mut helios) = (0, 0);
    let mut depth = MIN_SPEND_LAYERS;
    while depth <= max_depth {
        let n_in = inputs_under_weight_limit(MIN_NON_COINBASE_OUTPUTS, depth);
        let (c1, c2) = Fcmp::<()>::ipa_rows(n_in, depth as usize);
        if c1 > selene {
            selene = c1;
        }
        if c2 > helios {
            helios = c2;
        }
        depth += 1;
    }
    (selene, helios)
}

/// The maximum tree depth's derivation (`ICD-R9`, step 2): the deepest tree that
/// needs no more generators than [`TREE_DEPTH_FLOOR`] does.
const fn deepest_depth_free_of_generators() -> u8 {
    let floor = generator_rows_through(TREE_DEPTH_FLOOR);
    let mut depth = TREE_DEPTH_FLOOR;
    loop {
        let next = generator_rows_through(depth + 1);
        if next.0 != floor.0 || next.1 != floor.1 {
            return depth;
        }
        depth += 1;
    }
}

// The constants held below this crate are the derivations computed here. A
// weight-limit change that moves one fails the build until it is moved
// (`ICD-R2`, `ICD-R8`, `ICD-R9`).
const _: () = {
    let (selene, helios) = generator_rows_through(MAX_TREE_DEPTH);
    assert!(
        selene == FCMP_SELENE_GENERATORS,
        "FCMP_SELENE_GENERATORS is not the largest row count a legal proof needs"
    );
    assert!(
        helios == FCMP_HELIOS_GENERATORS,
        "FCMP_HELIOS_GENERATORS is not the largest row count a legal proof needs"
    );
    assert!(
        MAX_TREE_DEPTH == deepest_depth_free_of_generators(),
        "MAX_TREE_DEPTH is not the deepest tree needing no more generators than the floor"
    );
};

/// The most inputs a mineable transaction of `n_out` outputs carries at
/// `tree_depth`, or 0 when no transaction has that output count or depth.
///
/// This is the **consensus** shape space: what can be mined (CEN-I1's output
/// minimum, `MAX_OUTPUTS`, the legal depths, and CEN-H3's weight limit at the
/// lightest signer and fee). Relay policy keeps its own narrower rules on top.
/// A heavier signer or a wider fee can still put a shape at this count over the
/// limit, and CEN-H3 refuses it.
#[must_use]
pub const fn max_inputs_at(n_out: usize, tree_depth: u8) -> usize {
    if n_out < MIN_NON_COINBASE_OUTPUTS
        || n_out > MAX_OUTPUTS
        || tree_depth < MIN_SPEND_LAYERS
        || tree_depth > MAX_TREE_DEPTH
    {
        return 0;
    }
    inputs_under_weight_limit(n_out, tree_depth)
}

/// Whether consensus can mine a spend of this shape: see [`max_inputs_at`].
#[must_use]
pub const fn is_legal_shape(n_in: usize, n_out: usize, tree_depth: u8) -> bool {
    n_in >= 1 && n_in <= max_inputs_at(n_out, tree_depth)
}

/// The weight of the heaviest mineable solo spend of `n_out` outputs, over
/// every legal depth and fee width: at each depth the most inputs that fit,
/// with the widest fee varint the weight limit still admits. 0 when no
/// transaction has that output count.
#[must_use]
pub const fn heaviest_legal_weight(n_out: usize) -> usize {
    let mut heaviest = 0;
    let mut depth = MIN_SPEND_LAYERS;
    while depth <= MAX_TREE_DEPTH {
        let n_in = max_inputs_at(n_out, depth);
        if n_in > 0 {
            let widest_fee = lightest_weight(n_in, n_out, depth) + (MAX_VARINT_LEN - 1);
            let weight = if widest_fee < TX_WEIGHT_LIMIT {
                widest_fee
            } else {
                TX_WEIGHT_LIMIT
            };
            if weight > heaviest {
                heaviest = weight;
            }
        }
        depth += 1;
    }
    heaviest
}
