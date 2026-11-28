// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Spend shapes, bounded input/output counts and the fee loop, on top of the
//! weight model in `shekyl_wire::transaction::weight`.
//!
//! [`predict_weight`] is that model at a solo spend's auth, so it equals the
//! post-build `Transaction::weight()` **without constructing a transaction** —
//! pinned by the `predict_weight_matches_wire_weight` test (the single-source
//! guarantee). [`predict_spend_weight`] is the same model for any spend's
//! [`SpendShape`]: its [`Signer`] (a single signer, or a multisig group whose
//! inputs each carry the group's key blob and `m`-signature container, scheme
//! 2) and the groups it pays, each output paying a group carrying its `0x0D`
//! entry.
//!
//! **Two parity tests, different jobs.** The one named above builds a wire
//! `Transaction` *by hand* at five shapes, so it pins the field model against a
//! second reading of the wire layout. `tests/weight_gate.rs` — the FL-R20
//! weight gate — asserts the same equality against the bytes the **builder**
//! emits, across every `n_in x n_out x L` a spend can take and every `u64` fee
//! varint length. Under FL-R23's zero relay slack a one-byte prediction error
//! is a hard bounce, so that gate is what justifies deleting the inherited 2%
//! admission cushion; edit the model and run it.
//!
//! The wallet fee path **and** `shekyl-economics-sim`'s W9 stuffer arm read
//! this crate (§12.3 D-1), so they share one weight model. The fee loop is
//! [`converge_weight_fee_by`]: the caller supplies the pricer, so the lattice
//! stays out of this crate. [`converge_weight_fee`] is that loop with the
//! unrounded product. It stays apart from the wire crate because a fee loop and
//! wallet shape types are wallet-side API, and the wire is the consensus
//! transport (`ICD-R1`). The proof length's *validation* against real
//! synthetic-tree measurements stays in engine-core (where the measurement
//! machinery lives) and calls the `pub` [`fcmp_proof_size`] here.
#![deny(unsafe_code)]

use shekyl_crypto_pq::multisig::{
    MultisigKeyBlob, MultisigSigContainer, MAX_MULTISIG_PARTICIPANTS, MIN_MULTISIG_THRESHOLD,
};
use shekyl_curve_io::varint_len;
use shekyl_wire::transaction::weight::{
    self, bp_plus_clawback_weight, fcmp_proof_len, pqc_auth_weight, pqc_auth_weight_of,
};
use shekyl_wire::tx_extra::MultisigEntry;
#[cfg(test)]
use {
    shekyl_crypto_pq::kem::HYBRID_KEM_CT_LEN,
    shekyl_wire::transaction::weight::{
        extra_kem_field_weight, extra_leaf_hashes_field_weight, EXTRA_PUBKEY_FIELD_WEIGHT,
    },
    shekyl_wire::transaction::{PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN},
    shekyl_wire::tx_extra::PQC_LEAF_ENTRY_LEN,
};
// Consensus limits from their UPSTREAM home (constraint 1 — never via
// shekyl-tx-builder's re-export, which would invert the arrow). `MAX_TREE_DEPTH`
// and `MAX_OUTPUTS` are re-exported (`pub use`) so consumers that price real tx
// shapes (the economics sim's leaf-stuffer, DQ-2G) can single-source them through
// this crate — the sanctioned window into the weight model — instead of depping
// shekyl-wire directly; the cap stays crate-internal under this crate's name.
pub use shekyl_curve_generators::{ProofLayers, SpendLayers, MAX_TREE_DEPTH, MIN_SPEND_LAYERS};
pub use shekyl_wire::transaction::weight::{
    is_legal_shape, max_buildable_inputs, max_inputs_at, NonCoinbaseOutputs,
};
use shekyl_wire::transaction::MAX_FCMP_INPUTS as MAX_INPUTS;
pub use shekyl_wire::transaction::{MAX_OUTPUTS, MIN_NON_COINBASE_OUTPUTS};

// ── Bounded input/output counts ─────────────────────────────────────────────

macro_rules! bounded_count {
    ($name:ident, $max:expr, $what:literal) => {
        #[doc = concat!("Transaction ", $what, " count, bounded to `1..=", stringify!($max), "`.")]
        ///
        /// Constructed via [`Self::clamped`] at the fee-path boundary; the bound
        /// is a type invariant, so consumers do plain (overflow-free) arithmetic.
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub struct $name(usize);

        impl $name {
            /// Wrap a raw count, clamping into `1..=MAX`. An out-of-range value
            /// caps at the bound (the prior clamp/saturate behaviour): a valid tx
            /// is exact, and an oversize request still fails at build validation,
            /// so the predictor never sees a value that could overflow.
            #[must_use]
            pub fn clamped(n: usize) -> Self {
                Self(n.clamp(1, $max))
            }

            /// The count as a `usize`, guaranteed in `1..=MAX`.
            #[must_use]
            pub const fn get(self) -> usize {
                self.0
            }
        }
    };
}

bounded_count!(InputCount, MAX_INPUTS, "input");
bounded_count!(OutputCount, MAX_OUTPUTS, "output");

// ── Multisig groups ─────────────────────────────────────────────────────────

/// An `m`-of-`n` multisig group's size, bounded as a group address bounds
/// it: `MIN_MULTISIG_THRESHOLD ≤ m ≤ n ≤ MAX_MULTISIG_PARTICIPANTS`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct GroupSize {
    n: u8,
    m: u8,
}

impl GroupSize {
    /// The size of an `m`-of-`n` group, or `None` if no group has it.
    #[must_use]
    pub const fn new(n: u8, m: u8) -> Option<Self> {
        if MIN_MULTISIG_THRESHOLD <= m && m <= n && n <= MAX_MULTISIG_PARTICIPANTS {
            Some(Self { n, m })
        } else {
            None
        }
    }

    /// The member count `n`.
    #[must_use]
    pub const fn n(self) -> u8 {
        self.n
    }

    /// The threshold `m`.
    #[must_use]
    pub const fn m(self) -> u8 {
        self.m
    }
}

/// Who authorizes a spend's inputs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Signer {
    /// One wallet: each input carries a single hybrid key and signature.
    Solo,
    /// A multisig group (scheme 2): each input's key blob names the group's
    /// `n` members and carries `m` signers' keys, and its container `m`
    /// signatures.
    Group(GroupSize),
}

/// The shape of a spend: its counts, its signer, and the size of every
/// group it pays, a group's change included, in output order.
#[derive(Clone, Copy, Debug)]
pub struct SpendShape<'a> {
    /// The inputs, every one the signer's.
    pub n_in: InputCount,
    /// The outputs, those paying a group among them.
    pub n_out: OutputCount,
    /// The on-chain tree depth the spend proves under.
    pub tree_depth: u8,
    /// Who signs the inputs.
    pub signer: Signer,
    /// The groups the spend pays, one per output paying a group: each such
    /// output carries a `0x0D` entry with one ciphertext per member.
    pub group_payees: &'a [GroupSize],
}

// ── The shapes consensus admits ─────────────────────────────────────────────

/// Every `(inputs, outputs)` shape consensus can mine at `tree_depth`, from the
/// one legal-shape function in the wire ([`max_inputs_at`]): a search over
/// transaction shapes reads this, so it never picks one no node admits. Empty
/// at a depth no spend proves under.
pub fn legal_shapes_at(layers: SpendLayers) -> impl Iterator<Item = (InputCount, OutputCount)> {
    NonCoinbaseOutputs::each().flat_map(move |outputs| {
        (1..=max_inputs_at(outputs, layers)).map(move |n_in| {
            (
                InputCount::clamped(n_in),
                OutputCount::clamped(outputs.get()),
            )
        })
    })
}

// ── The model at a shape ────────────────────────────────────────────────────

/// FCMP++ proof size in bytes for `n_in` inputs at `tree_depth`: the closed form
/// the weight model reads. `pub` so engine-core's validation tests (which own
/// the synthetic-tree measurement machinery) can cross-check it against real
/// proofs.
#[must_use]
pub fn fcmp_proof_size(n_in: InputCount, layers: ProofLayers) -> usize {
    fcmp_proof_len(n_in.get(), layers)
}

/// One per-input `PqcAuth` of `signer`: a solo hybrid key and signature,
/// or an `m`-of-`n` group's key blob and `m`-signature container (scheme
/// 2), at their canonical lengths.
fn signer_pqc_auth_weight(signer: Signer) -> usize {
    match signer {
        Signer::Solo => pqc_auth_weight(),
        Signer::Group(group) => pqc_auth_weight_of(
            MultisigKeyBlob::expected_len(group.n, group.m),
            MultisigSigContainer::expected_sig_len(group.m),
        ),
    }
}

/// `ExtraField::PqcMultisig` (`0x0D`): tag + varint(len) + one entry per
/// output paying a group, each sized by that group's member count. Absent
/// (zero bytes) when the spend pays no group.
fn extra_multisig_field_weight(group_payees: &[GroupSize]) -> usize {
    if group_payees.is_empty() {
        return 0;
    }
    let blob: usize = group_payees
        .iter()
        .map(|payee| MultisigEntry::wire_len(payee.n))
        .sum();
    1 + varint_len(blob as u64) + blob
}

/// Structural weight predictor (§3.10.1) — a byte-for-byte mirror of
/// `shekyl_wire::Transaction::write` plus the Bp+ clawback, so it equals
/// `Transaction::weight()` for the tx the builder will produce from these counts.
#[must_use]
pub fn predict_weight(
    n_in: InputCount,
    n_out: OutputCount,
    layers: ProofLayers,
    fee: u64,
) -> usize {
    weight::spend_weight(n_in.get(), n_out.get(), layers, fee, pqc_auth_weight(), 0)
}

/// [`predict_weight`] for any [`SpendShape`]: each input's auth is its
/// signer's (a solo key and signature, or a group's key blob and
/// `m`-signature container), and each output paying a group carries its
/// `0x0D` entry. A solo shape paying no group is [`predict_weight`]. It
/// equals the signed spend's `Transaction::weight()`, pinned against real
/// 2-of-3 and 3-of-5 group spends in `shekyl-multisig`'s ceremony gate.
/// Consensus weight is that serialized size; this is the wallet's estimate
/// of it before signing.
///
/// `None` when the shape pays more groups than it has outputs.
#[must_use]
pub fn predict_spend_weight(shape: &SpendShape<'_>, fee: u64) -> Option<usize> {
    if shape.group_payees.len() > shape.n_out.get() {
        return None;
    }
    let layers = ProofLayers::new(shape.tree_depth)?;
    Some(weight::spend_weight(
        shape.n_in.get(),
        shape.n_out.get(),
        layers,
        fee,
        signer_pqc_auth_weight(shape.signer),
        extra_multisig_field_weight(shape.group_payees),
    ))
}

/// Bytes in the longest `u64` varint. [`varint_len`]`(u64::MAX)` is this;
/// the test beside [`converge_weight_fee`] pins the equality, so a wider
/// encoding has to move the iteration bound with it.
const U64_VARINT_BYTES_MAX: usize = 10;

/// Passes [`converge_weight_fee_by`] may take. A pass that is not yet the
/// fixed point changes `varint_len(fee)`, and a `u64` has at most
/// [`U64_VARINT_BYTES_MAX`] such lengths. One further pass is the agreement
/// check, so the loop returns by equality rather than by exhaustion.
const WEIGHT_FEE_FIXPOINT_PASSES: usize = U64_VARINT_BYTES_MAX + 1;

/// [`converge_fee_by`] over the predicted weight of a spend of these counts:
/// the wallet's fee for a shape it has not built yet.
#[must_use]
pub fn converge_weight_fee_by(
    n_in: InputCount,
    n_out: OutputCount,
    layers: ProofLayers,
    seed: u64,
    price: impl Fn(u64) -> Option<u64>,
) -> Option<u64> {
    converge_fee_by(
        |fee| u64::try_from(predict_weight(n_in, n_out, layers, fee)).ok(),
        seed,
        price,
    )
}

/// [`converge_weight_fee_by`] for any [`SpendShape`]: the fee fixed point
/// of [`predict_spend_weight`], through the same loop ([`converge_fee_by`]).
/// A solo shape paying no group converges to what [`converge_weight_fee_by`]
/// does. `None` also when the shape pays more groups than it has outputs.
#[must_use]
pub fn converge_spend_fee_by(
    shape: &SpendShape<'_>,
    seed: u64,
    price: impl Fn(u64) -> Option<u64>,
) -> Option<u64> {
    converge_fee_by(
        |fee| u64::try_from(predict_spend_weight(shape, fee)?).ok(),
        seed,
        price,
    )
}

/// The weight of a transaction measured at `measured_fee`, were it to pay
/// `fee` instead: the fee reaches the weight only through `varint(fee)` (the
/// field list [`predict_weight`] sums), so the rest of the measurement
/// stands. `None` when the result does not fit in `u64`. For a shape
/// [`predict_weight`] does not model, a caller measures one build and
/// converges on this ([`converge_fee_by`]).
#[must_use]
pub fn weight_at_fee(measured_weight: u64, measured_fee: u64, fee: u64) -> Option<u64> {
    let width = |fee: u64| u64::try_from(varint_len(fee)).ok();
    measured_weight
        .checked_sub(width(measured_fee)?)?
        .checked_add(width(fee)?)
}

/// The one fee loop. `weight_at` is the transaction's weight paying a given
/// fee, `price` maps a weight to the fee that weight is charged, and the fee
/// comes back as the weight's next argument because the wire carries
/// `varint(fee)`.
///
/// The pricer belongs to the caller. This crate does not round: the wallet
/// passes the lattice, and an unrounded product is [`converge_weight_fee`].
/// A `None` from either closure is `None`. The loop returns when two passes
/// agree. Running out of passes is unreachable for a monotone pricer — each
/// disagreeing pass consumes one varint length — and is a `debug_assert`,
/// then `None`, never a guessed fee.
#[must_use]
pub fn converge_fee_by(
    weight_at: impl Fn(u64) -> Option<u64>,
    seed: u64,
    price: impl Fn(u64) -> Option<u64>,
) -> Option<u64> {
    let mut fee = seed;
    for _ in 0..WEIGHT_FEE_FIXPOINT_PASSES {
        let weight = weight_at(fee)?;
        let next = price(weight)?;
        if next == fee {
            return Some(fee);
        }
        fee = next;
    }
    debug_assert!(
        false,
        "fee fixed point did not agree within {WEIGHT_FEE_FIXPOINT_PASSES} passes"
    );
    None
}

/// Unrounded fee fixed point: `fee = rate_per_weight × weight(fee)`, from a
/// seed of 0. `None` when the product does not fit in `u64`.
///
/// The lattice is not applied here. A caller that pays what the wallet pays
/// passes its lattice pricer to [`converge_weight_fee_by`] instead of
/// rounding this result afterwards.
#[must_use]
pub fn converge_weight_fee(
    rate_per_weight: u64,
    n_in: InputCount,
    n_out: OutputCount,
    layers: ProofLayers,
) -> Option<u64> {
    converge_weight_fee_by(n_in, n_out, layers, 0, |weight| {
        weight.checked_mul(rate_per_weight)
    })
}

/// The **archival length** of the tx the builder would produce from these
/// counts: `|pqc_auths| + |prunable|` — the two segments a prune discards and
/// the bytes that count toward a shard's `W`
/// (`shekyl_wire::TxSegments::archival_len`, SHT-Q2). The partial sum of
/// [`predict_weight`]'s field list from the per-input PQC auths through
/// `pseudoOuts`, so a built spend's `Transaction::archival_len()` equals this
/// without constructing the transaction — pinned beside the weight parity in
/// this crate's tests and over the builder's whole shape space in
/// `tests/weight_gate.rs`.
///
/// Independent of the fee (the fee varint is in the pruned segment) and of
/// the Bp+ clawback (a fee-weight term, not bytes). This is the one place the
/// per-transaction archival length is predicted from a shape; the economics
/// sim's archival-burden model reads it here rather than carrying a bytes-per-
/// transaction mean (DQ-2G dep-don't-mirror; `ARCHIVAL_SHARD_COUNT_CUTOVER.md`
/// §D, the `SHARD_BYTES` row).
#[must_use]
pub fn predict_archival_len(n_in: InputCount, n_out: OutputCount, layers: ProofLayers) -> usize {
    weight::archival_len(n_in.get(), n_out.get(), layers)
}

/// Serialized byte size **and** fee weight for the tx the builder would produce
/// from these counts, as one `(size, weight)` pair.
///
/// The two differ by exactly the Bp+ verification clawback
/// (`bp_plus_clawback_weight`, zero for `n_padded <= 2`): `weight` is what the
/// fee model charges ([`predict_weight`], equal to `Transaction::weight()`),
/// `size` is the wire bytes (`Transaction::write`'s length). Derived by
/// subtraction from the one predictor rather than re-summing the field model, so
/// the byte model stays single-source.
#[must_use]
pub fn predict_size_and_weight(
    n_in: InputCount,
    n_out: OutputCount,
    layers: ProofLayers,
    fee: u64,
) -> (usize, usize) {
    let weight = predict_weight(n_in, n_out, layers, fee);
    let size = weight - bp_plus_clawback_weight(n_out.get());
    (size, weight)
}

/// Marginal weight of one additional input, evaluated at the reference
/// depth `D_ref = MAX_TREE_DEPTH`.
///
/// The depth is fixed, not a parameter, and that is the point: this
/// number sets the wallet's dust boundary
/// (`shekyl_rpc_client::tx_fee::dust_threshold`), and a dust bar that
/// tracked the live tree depth would *reclassify outputs the wallet
/// already holds* every time the tree grew a level — an output that was
/// economical to spend on Monday becoming dust on Tuesday, with no
/// action by its owner. Pinning `D_ref` at the maximum makes the bar
/// conservative (it never under-states the cost of spending an input)
/// and stable for the life of the chain. The signature carries that
/// decision so no caller can quietly re-open it.
#[must_use]
pub fn marginal_input_weight_at_d_ref() -> usize {
    let fee = 0;
    let n_out = OutputCount::clamped(1);
    let depth = SpendLayers::DEEPEST.as_proof();
    predict_weight(InputCount::clamped(2), n_out, depth, fee).saturating_sub(predict_weight(
        InputCount::clamped(1),
        n_out,
        depth,
        fee,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_into_range() {
        assert_eq!(InputCount::clamped(0).get(), 1, "zero clamps up to 1");
        assert_eq!(InputCount::clamped(3).get(), 3, "in-range is exact");
        assert_eq!(
            InputCount::clamped(MAX_INPUTS).get(),
            MAX_INPUTS,
            "MAX is exact"
        );
        assert_eq!(
            InputCount::clamped(MAX_INPUTS + 5).get(),
            MAX_INPUTS,
            "oversize caps at MAX_INPUTS"
        );
        assert_eq!(
            InputCount::clamped(usize::MAX).get(),
            MAX_INPUTS,
            "usize::MAX caps"
        );

        assert_eq!(OutputCount::clamped(0).get(), 1);
        assert_eq!(OutputCount::clamped(MAX_OUTPUTS).get(), MAX_OUTPUTS);
        assert_eq!(
            OutputCount::clamped(MAX_OUTPUTS + 1).get(),
            MAX_OUTPUTS,
            "with-change +1 over the limit caps at MAX_OUTPUTS"
        );
    }

    #[test]
    fn predict_weight_increases_with_inputs_and_outputs() {
        let w1 = predict_weight(
            InputCount::clamped(1),
            OutputCount::clamped(1),
            ProofLayers::ONE,
            1_000,
        );
        let w2 = predict_weight(
            InputCount::clamped(2),
            OutputCount::clamped(1),
            ProofLayers::ONE,
            1_000,
        );
        let w3 = predict_weight(
            InputCount::clamped(1),
            OutputCount::clamped(2),
            ProofLayers::ONE,
            1_000,
        );
        assert!(w2 > w1);
        assert!(w3 > w1);
    }

    /// The returned fee is `rate × weight(fee)`, and two passes from zero are
    /// not that point when the second product crosses a varint boundary.
    ///
    /// `24_184` is the wallet's pinned rate. After the weight model moved
    /// (PL-D3) that rate settles in two passes, so it witnesses agreement
    /// with the wallet's mask-1 absolute and nothing about the bound. `23_840`
    /// is the neighbour that still has one varint length left after two
    /// passes: the shortfall is exactly one byte of rate.
    #[test]
    fn converge_weight_fee_is_the_varint_fixed_point() {
        assert_eq!(varint_len(u64::MAX), U64_VARINT_BYTES_MAX);
        let (n_in, n_out, depth) = (
            InputCount::clamped(1),
            OutputCount::clamped(1),
            ProofLayers::ONE,
        );

        let fixed = |rate: u64| {
            let fee = converge_weight_fee(rate, n_in, n_out, depth).expect("the product fits");
            let weight = u64::try_from(predict_weight(n_in, n_out, depth, fee)).unwrap();
            assert_eq!(fee, weight.checked_mul(rate).unwrap(), "rate {rate}");
            fee
        };
        assert_eq!(fixed(24_184), 272_336_024);

        let rate = 23_840u64;
        let mut two_passes = 0u64;
        for _ in 0..2 {
            let weight = u64::try_from(predict_weight(n_in, n_out, depth, two_passes)).unwrap();
            two_passes = weight.checked_mul(rate).unwrap();
        }
        let fee = fixed(rate);
        assert_eq!(
            fee - two_passes,
            rate,
            "two passes {two_passes} undershoot {fee} by one varint byte of rate"
        );
    }

    #[test]
    fn predict_weight_caps_oversize_counts() {
        // Counts are type-bounded, so an out-of-range value is unrepresentable:
        // `clamped` caps it at the bound and the predictor yields a finite MAX-count
        // weight (no overflow/panic, no wrap below a normal weight that would under-pay).
        let capped = predict_weight(
            InputCount::clamped(usize::MAX),
            OutputCount::clamped(usize::MAX),
            SpendLayers::DEEPEST.as_proof(),
            u64::MAX,
        );
        let normal = predict_weight(
            InputCount::clamped(2),
            OutputCount::clamped(2),
            SpendLayers::DEEPEST.as_proof(),
            1_000,
        );
        assert!(
            capped > normal,
            "capped MAX-count weight must exceed a normal weight"
        );
    }

    /// `predict_weight` must equal `shekyl_wire::Transaction::weight()` for the tx
    /// shape the builder produces from the same counts — **the single-source
    /// guarantee** (D-1 constraint 3: this test travels with the predictor).
    /// Builds a wire tx whose field *sizes* mirror a real spend (real `Extra`
    /// serializer, so the tx_extra term is validated non-circularly; real Bp+
    /// `|L|`, real PQC pk/sig lengths, KAT fcmp proof) across input/output scaling
    /// and the >2-output clawback.
    #[test]
    fn predict_weight_matches_wire_weight() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use shekyl_scanner::extra::Extra;
        use shekyl_wire::{
            BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, Transaction, TxPrefix,
        };

        for &(n_in, n_out, depth, fee) in &[
            (1usize, 1usize, 1u8, 0u64),
            (1, 2, 2, 103_760),
            (2, 2, 8, 1_000),
            (2, 3, 4, 50_000), // n_out=3 ⇒ 4 padded ⇒ non-zero clawback
            (3, 4, 12, 7),
        ] {
            let nlr = 6 + weight::padded_outputs(n_out).trailing_zeros() as usize;
            let bp = BpPlus {
                a: [0; 32],
                a1: [0; 32],
                b: [0; 32],
                r1: [0; 32],
                s1: [0; 32],
                d1: [0; 32],
                l: vec![[0; 32]; nlr],
                r: vec![[0; 32]; nlr],
            };
            let extra = {
                let mut e = Extra::for_hybrid_transfer(
                    ED25519_BASEPOINT_POINT,
                    (0..n_out).map(|_| vec![0u8; HYBRID_KEM_CT_LEN]),
                );
                // The 0x07 leaf-hash blob the transfer path appends (sign_bridge.rs)
                // — real serializer, same as the KEM term.
                e.push_pqc_leaf_entries(vec![0u8; n_out * PQC_LEAF_ENTRY_LEN]);
                e.serialize()
            };
            let tx = Transaction {
                prefix: TxPrefix {
                    unlock_time: TxPrefix::NO_UNLOCK_TIME,
                    inputs: (0..n_in)
                        .map(|_| Input::fcmp_spend(shekyl_types::KeyImage::from_bytes([0; 32])))
                        .collect(),
                    outputs: (0..n_out)
                        .map(|_| Output {
                            amount: 0,
                            key: [0; 32],
                            view_tag: 0,
                        })
                        .collect(),
                    extra,
                },
                ct: Ct::Fcmp {
                    fee,
                    reference_block: shekyl_types::BlockHash::NULL,
                    base: CtBase {
                        enc_amounts: vec![[0; 9]; n_out],
                        enc_labels: vec![[0; 9]; n_out],
                        commitments: vec![[0; 32]; n_out],
                    },
                    pqc_auths: (0..n_in)
                        .map(|_| PqcAuth {
                            auth_version: PqcAuth::VERSION,
                            scheme_id:
                                shekyl_crypto_pq::signature::HYBRID_SCHEME_ID_ED25519_ML_DSA_65,
                            flags: PqcAuth::NO_FLAGS,
                            hybrid_public_key: vec![0u8; PQC_HYBRID_SINGLE_KEY_LEN],
                            hybrid_signature: vec![0u8; PQC_HYBRID_SINGLE_SIG_LEN],
                        })
                        .collect(),
                    prunable: Some(Prunable {
                        // Spend fixture: no pass records (RF-D1).
                        bulletproofs: vec![bp],
                        tree_depth: u64::from(depth),
                        fcmp_proof: vec![
                            0u8;
                            fcmp_proof_size(
                                InputCount::clamped(n_in),
                                ProofLayers::known(depth)
                            )
                        ],
                        pseudo_outs: vec![[0; 32]; n_in],
                    }),
                },
            };
            assert_eq!(
                predict_weight(
                    InputCount::clamped(n_in),
                    OutputCount::clamped(n_out),
                    ProofLayers::known(depth),
                    fee,
                ),
                tx.weight(),
                "predict_weight ≠ wire weight for n_in={n_in} n_out={n_out} depth={depth} fee={fee}"
            );
            let (size, weight) = predict_size_and_weight(
                InputCount::clamped(n_in),
                OutputCount::clamped(n_out),
                ProofLayers::known(depth),
                fee,
            );
            assert_eq!(
                weight,
                tx.weight(),
                "predict_size_and_weight weight ≠ wire weight for n_in={n_in} n_out={n_out}"
            );
            assert_eq!(
                size,
                tx.serialized_len(),
                "predict_size_and_weight size ≠ wire serialized_len for n_in={n_in} n_out={n_out}"
            );
            assert_eq!(
                predict_archival_len(
                    InputCount::clamped(n_in),
                    OutputCount::clamped(n_out),
                    ProofLayers::known(depth),
                ),
                usize::try_from(tx.archival_len().to_raw()).expect("archival length fits usize"),
                "predict_archival_len ≠ wire archival_len for n_in={n_in} n_out={n_out} depth={depth}"
            );
        }
    }

    /// A group's size is what an address admits: `2 ≤ m ≤ n ≤ 5`.
    #[test]
    fn a_group_size_is_one_an_address_admits() {
        assert!(GroupSize::new(2, 2).is_some());
        assert!(GroupSize::new(5, 3).is_some());
        assert!(GroupSize::new(5, 5).is_some());
        assert!(GroupSize::new(1, 1).is_none());
        assert!(GroupSize::new(3, 1).is_none());
        assert!(GroupSize::new(3, 4).is_none());
        assert!(GroupSize::new(6, 2).is_none());
    }

    /// A spend outweighs the solo spend paying no group by exactly its
    /// signer's auths and its `0x0D` entries, each at the crypto and wire
    /// crates' own lengths: a solo spend paying a 3-of-5 group carries that
    /// group's entry and solo auths, a group spend the group's auths too.
    /// A solo shape paying no group is `predict_weight`; a shape paying
    /// more groups than it has outputs has no weight.
    #[test]
    fn a_spend_weighs_its_signers_auths_and_its_payees_entries() {
        let three_of_five = GroupSize::new(5, 3).unwrap();
        let other_group = GroupSize::new(3, 2).unwrap();
        let layers = ProofLayers::known(7);
        let (n_in, n_out, fee) = (InputCount::clamped(2), OutputCount::clamped(3), 900);
        let solo = predict_weight(n_in, n_out, layers, fee);
        let weigh = |signer: Signer, group_payees: &[GroupSize]| {
            predict_spend_weight(
                &SpendShape {
                    n_in,
                    n_out,
                    tree_depth: layers.get(),
                    signer,
                    group_payees,
                },
                fee,
            )
        };
        // The `0x0D` field for `payees`, and the byte the `tx_extra`
        // length prefix may grow by with it.
        let extra_base = EXTRA_PUBKEY_FIELD_WEIGHT
            + extra_kem_field_weight(n_out.get())
            + extra_leaf_hashes_field_weight(n_out.get());
        let entries_weight = |payees: &[GroupSize]| {
            let entries: usize = payees.iter().map(|g| MultisigEntry::wire_len(g.n())).sum();
            let field = 1 + varint_len(entries as u64) + entries;
            field + varint_len((extra_base + field) as u64) - varint_len(extra_base as u64)
        };
        let group_auth = pqc_auth_weight_of(
            MultisigKeyBlob::expected_len(three_of_five.n(), three_of_five.m()),
            MultisigSigContainer::expected_sig_len(three_of_five.m()),
        );
        let group_auths = n_in.get() * (group_auth - pqc_auth_weight());

        assert_eq!(weigh(Signer::Solo, &[]), Some(solo));
        assert_eq!(
            weigh(Signer::Solo, &[three_of_five]),
            Some(solo + entries_weight(&[three_of_five]))
        );
        assert_eq!(
            weigh(Signer::Group(three_of_five), &[three_of_five, other_group]),
            Some(solo + group_auths + entries_weight(&[three_of_five, other_group]))
        );
        assert_eq!(
            weigh(Signer::Group(three_of_five), &[]),
            Some(solo + group_auths)
        );
        assert_eq!(
            weigh(
                Signer::Solo,
                &[other_group; MAX_OUTPUTS + 1][..=n_out.get()]
            ),
            None
        );
    }
}

#[cfg(test)]
mod marginal_input_weight_pin {
    use super::*;

    /// The dust boundary's marginal-input weight, pinned so any weight-model
    /// movement is a loud, reviewed change to the dust bar. The second
    /// assertion records the 2026-08-16 retirement fact: the provisional
    /// `MARGINAL_INPUT_WEIGHT = 3457` stub (zero FCMP proof increment)
    /// understated this by the whole per-input proof increment — a future
    /// "simplification" back to a proofless constant must fail here.
    #[test]
    fn marginal_input_weight_is_pinned() {
        let w = marginal_input_weight_at_d_ref();
        assert_eq!(w, 7728, "weight-model movement changes the dust boundary");
        assert!(
            w > 3457,
            "the marginal weight must exceed the retired proofless stub"
        );
    }

    /// A product that does not fit is `None`. Restoring `saturating_mul`
    /// makes this return `Some(u64::MAX)`.
    #[test]
    fn an_unrepresentable_product_is_not_a_fee() {
        let (n_in, n_out, depth) = (
            InputCount::clamped(1),
            OutputCount::clamped(1),
            ProofLayers::ONE,
        );
        assert_eq!(converge_weight_fee(u64::MAX, n_in, n_out, depth), None);
        assert_eq!(
            converge_weight_fee_by(n_in, n_out, depth, 0, |_| None),
            None,
            "a pricer refusal propagates"
        );
    }
}
