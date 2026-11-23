// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Structural transaction-weight predictor + bounded input/output counts.
//!
//! [`predict_weight`] mirrors `shekyl_wire::Transaction::write` byte-for-byte
//! (and adds the same Bp+ clawback), so it equals the post-build
//! `Transaction::weight()` **without constructing a transaction** — pinned by
//! the `predict_weight_matches_wire_weight` test (the single-source
//! guarantee). The `fcmp_proof_size` term reads the measured 2a-3 KAT table.
//! [`predict_spend_weight`] is the same field model for any spend's
//! [`SpendShape`]: its [`Signer`] (a single signer, or a multisig group
//! whose inputs each carry the group's key blob and `m`-signature
//! container, scheme 2) and the groups it pays, each output paying a group
//! carrying its `0x0D` entry.
//!
//! **Two parity tests, different jobs.** The one named above builds a wire
//! `Transaction` *by hand* at five shapes, so it pins the field model against a
//! second reading of the wire layout. `tests/weight_gate.rs` — the FL-R20
//! weight gate — asserts the same equality against the bytes the **builder**
//! emits, across every `n_in x n_out x L` a spend can take and every `u64` fee
//! varint length. Under FL-R23's zero relay slack a one-byte prediction error
//! is a hard bounce, so that gate is what justifies deleting the inherited 2%
//! admission cushion; edit this function and run it.
//!
//! Hoisted from `shekyl-engine-core` (§12.3 D-1) so the wallet fee path **and**
//! `shekyl-economics-sim`'s W9 stuffer arm share one single-sourced weight model
//! rather than a replicated byte formula. The fee loop is
//! [`converge_weight_fee_by`]: the caller supplies the pricer, so the lattice
//! stays out of this crate. [`converge_weight_fee`] is that loop with the
//! unrounded product. The dependency surface stays the wire layout + proof sizes
//! ({`shekyl-wire`, `shekyl-fcmp`, `shekyl-crypto-pq`, `shekyl-curve-io`}),
//! no RPC or wallet types. The FCMP proof-size KAT's *validation* against real
//! synthetic-tree measurements stays in engine-core (where the measurement
//! machinery lives) and calls the `pub` [`fcmp_proof_size`] here.
#![deny(unsafe_code)]

use shekyl_crypto_pq::kem::HYBRID_KEM_CT_LEN;
use shekyl_crypto_pq::multisig::{
    MultisigKeyBlob, MultisigSigContainer, MAX_MULTISIG_PARTICIPANTS, MIN_MULTISIG_THRESHOLD,
};
use shekyl_curve_io::varint_len;
use shekyl_wire::tx_extra::{MultisigEntry, PQC_LEAF_ENTRY_LEN};
// Consensus proof-system limits from their UPSTREAM home (constraint 1 — never
// via shekyl-tx-builder's re-export, which would invert the arrow). `MAX_TREE_DEPTH`
// and `MAX_OUTPUTS` are re-exported (`pub use`) so consumers that price real tx
// shapes (the economics sim's leaf-stuffer, DQ-2G) can single-source them through
// this crate — the sanctioned window into the weight model — instead of depping
// shekyl-fcmp / shekyl-wire directly; `MAX_INPUTS` stays crate-internal.
use shekyl_fcmp::MAX_INPUTS;
pub use shekyl_fcmp::MAX_TREE_DEPTH;
pub use shekyl_wire::transaction::MAX_OUTPUTS;
use shekyl_wire::transaction::{
    bp_plus_weight_clawback, PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN, TX_VERSION,
};

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

// ── Wire-exact component sizes ──────────────────────────────────────────────
// Each constant is one field of `shekyl_wire::Transaction::write`; `predict_weight`
// sums them so it equals `Transaction::weight()` exactly. Sizes with a canonical
// home are imported, not re-typed (the hybrid PQC pk/sig lengths come from
// `shekyl_wire`).

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
const EXTRA_PUBKEY_FIELD_WEIGHT: usize = 1 + 32;

/// Measured FCMP++ proof sizes in bytes, indexed `[n_in][tree_depth]` over
/// `n_in ∈ 0..=8` and `tree_depth ∈ 0..=24` (row/col 0 are unused sentinels).
///
/// Emitted by `kat_emit_fcmp_proof_size_table` (in engine-core, where the
/// synthetic-tree measurement machinery lives) from the depth-consistent
/// single-path synthetic trees (PF7). The depth-1 column equals the
/// independently-known depth-1 row, which cross-validates the measurement. The
/// series is **non-monotonic** in depth (the FCMP++ inner-product argument
/// rounds), so this is a lookup table, not a closed-form per-layer increment.
/// engine-core's `kat_fcmp_proof_size_grid` validates every cell against
/// re-measurement (`#[ignore]`; ~slow); `kat_fcmp_proof_size_depth1_row` guards
/// the depth-1 column in CI. Both call the `pub` [`fcmp_proof_size`] below.
///
/// Re-measured 2026-09-14 with `PL-D3` (`FCMP_SPEND_LINKABILITY.md` §6.2): the
/// in-circuit commitment-opening leg adds one claimed point and a discrete-log
/// gadget per input and removes the per-input extra-scalar branch, so every
/// cell moved (single-input proofs +128 B at depth 1; multi-input proofs
/// smaller than before at most depths — census companion §8).
const FCMP_PROOF_SIZE_KAT: [[usize; 25]; 9] = [
    [0; 25],
    [
        0, 3872, 4512, 4896, 5536, 5920, 6560, 5984, 6624, 6880, 6304, 6560, 6944, 7200, 7584,
        7840, 8224, 7648, 6944, 7200, 7456, 7584, 7840, 8096, 8352,
    ],
    [
        0, 5760, 7040, 6208, 7488, 8000, 7808, 7360, 8128, 8512, 8064, 8448, 8960, 9344, 9856,
        10240, 10752, 10304, 9728, 10112, 10496, 10752, 11136, 11520, 11904,
    ],
    [
        0, 5664, 7584, 8352, 8800, 8224, 8288, 8800, 9568, 10208, 10976, 10528, 10208, 10720,
        11360, 11872, 12384, 12896, 13536, 13920, 14432, 14944, 14624, 14432, 14816,
    ],
    [
        0, 6784, 9344, 8768, 9344, 10112, 10176, 9984, 11008, 11648, 11456, 12096, 12864, 13504,
        14272, 14912, 15680, 15488, 15168, 15808, 16448, 16960, 17600, 18240, 18880,
    ],
    [
        0, 6304, 8288, 9312, 10016, 9824, 11104, 11872, 11936, 12704, 13728, 14624, 15520, 15456,
        15392, 16032, 16800, 17568, 18464, 19232, 20000, 20640, 21408, 22176, 22944,
    ],
    [
        0, 7168, 9536, 10688, 11520, 11328, 11776, 12672, 13824, 14848, 16000, 15936, 16000, 16896,
        17920, 18816, 19712, 20608, 21632, 22400, 23296, 24192, 24256, 24448, 25216,
    ],
    [
        0, 8032, 10784, 10720, 11680, 12832, 13408, 14432, 15712, 15904, 16224, 17248, 18400,
        19424, 20576, 21472, 22496, 23520, 24672, 25696, 25760, 25952, 26976, 28000, 29024,
    ],
    [
        0, 8768, 11904, 11840, 12928, 14208, 14784, 15104, 16640, 17792, 18112, 19264, 20544,
        21696, 22976, 24128, 25408, 25728, 25920, 27072, 28224, 29248, 30400, 31552, 32704,
    ],
];

/// Compile-time guard tying the table's dimensions to the canonical proof-system
/// limits: the rows cover `n_in ∈ 0..=MAX_INPUTS` and the columns
/// `tree_depth ∈ 0..=MAX_TREE_DEPTH` (index 0 unused). If either limit changes,
/// this fails to compile — forcing a table regeneration — rather than silently
/// falling back to `FCMP_PROOF_SIZE_MAX` for the newly-reachable cells (which
/// could under-estimate fees if real proofs there exceed the current max).
const _: () = {
    assert!(FCMP_PROOF_SIZE_KAT.len() == MAX_INPUTS + 1);
    assert!(FCMP_PROOF_SIZE_KAT[0].len() == MAX_TREE_DEPTH as usize + 1);
};

/// Largest cell of [`FCMP_PROOF_SIZE_KAT`]; the conservative fallback for an
/// out-of-range cell that should be unreachable (`n_in ∈ 1..=MAX_INPUTS`,
/// `tree_depth ∈ 1..=MAX_TREE_DEPTH`).
///
/// Derived from the table at compile time, not hardcoded, so regenerating the
/// table can never leave the fallback stale — under-estimating fees (a
/// non-conservative drift) or over-estimating them.
const FCMP_PROOF_SIZE_MAX: usize = {
    let mut max = 0;
    let mut i = 0;
    while i < FCMP_PROOF_SIZE_KAT.len() {
        let row = &FCMP_PROOF_SIZE_KAT[i];
        let mut j = 0;
        while j < row.len() {
            if row[j] > max {
                max = row[j];
            }
            j += 1;
        }
        i += 1;
    }
    max
};

/// Measured FCMP++ proof size in bytes for `n_in` inputs at `tree_depth`. `pub`
/// so engine-core's KAT-validation tests (which own the synthetic-tree
/// measurement machinery) can cross-check the table without re-hosting it.
#[must_use]
pub fn fcmp_proof_size(n_in: InputCount, tree_depth: u8) -> usize {
    // `n_in` is type-bounded to `1..=MAX_INPUTS`, so the row always hits a measured
    // cell; an out-of-range `tree_depth` falls back to the largest measured size so
    // the fee estimate stays conservative rather than panicking or under-paying.
    FCMP_PROOF_SIZE_KAT
        .get(n_in.get())
        .and_then(|row| row.get(usize::from(tree_depth)).copied())
        .filter(|&v| v != 0)
        .unwrap_or(FCMP_PROOF_SIZE_MAX)
}

/// The **single** `ExtraField::PqcKemCiphertext` (`0x06`) field: tag +
/// varint(len) + `n_out` concatenated per-output ciphertexts — the packing
/// `Extra::for_hybrid_transfer` emits, which every reader slices at
/// `o * HYBRID_KEM_CT_LEN`.
///
/// **Was one field PER OUTPUT** until the parallel `0x06` fix on `dev`
/// (`5cd252883`); this crate carried the pre-fix shape through the D-1 hoist and
/// is corrected here at the merge. The delta is only the 15 saved tag+varint
/// pairs (~45 B on a 1-in/16-out tx, ~0.13 %), but the predictor must byte-mirror
/// `Transaction::write` exactly — the traveling parity test is the arbiter.
fn extra_kem_field_weight(n_out: usize) -> usize {
    let blob = n_out * HYBRID_KEM_CT_LEN;
    1 + varint_len(blob as u64) + blob
}

/// `ExtraField::PqcLeafEntries` (`0x07`): tag + varint(len) + `n_out × 64`
/// leaf entries (`CM ‖ record`, `PL-D3` / `PL-D3a`) — a consensus-required
/// field (CEN-I19: a transaction with outputs is refused without it); the
/// transfer path appends it (sign_bridge.rs, PR-4b), so every predicted spend
/// carries it.
fn extra_leaf_hashes_field_weight(n_out: usize) -> usize {
    let blob = n_out * PQC_LEAF_ENTRY_LEN;
    1 + varint_len(blob as u64) + blob
}

/// One per-input `PqcAuth` carrying a `key_len`-byte key blob and a
/// `sig_len`-byte signature blob: auth_version + scheme_id + flags(u16) +
/// varint(key_len) ‖ key + varint(sig_len) ‖ sig.
fn pqc_auth_weight_of(key_len: usize, sig_len: usize) -> usize {
    1 + 1 + 2 + varint_len(key_len as u64) + key_len + varint_len(sig_len as u64) + sig_len
}

/// One per-input `PqcAuth` of a single signer: a solo hybrid key and
/// signature.
fn pqc_auth_weight() -> usize {
    pqc_auth_weight_of(PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN)
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

/// Padded output count the Bp+ aggregates over — next power of two, ≥ 1.
fn padded_outputs(n_out: OutputCount) -> usize {
    // `n_out` is type-bounded to `1..=MAX_OUTPUTS`, so `next_power_of_two` is in
    // range with no clamp needed.
    n_out.get().next_power_of_two()
}

/// Serialized Bp+ size: 6 fixed points + varint(|L|)‖L + varint(|R|)‖R, where
/// `|L| == |R| == 6 + log2(n_padded)` (the proof's L/R vector length).
fn bp_plus_weight(n_out: OutputCount) -> usize {
    let nlr = 6 + padded_outputs(n_out).trailing_zeros() as usize;
    6 * 32 + 2 * (varint_len(nlr as u64) + nlr * 32)
}

/// Bp+ verification clawback for the predicted output count. Delegates to the
/// canonical [`shekyl_wire::transaction::bp_plus_weight_clawback`] so the
/// predictor and `weight()` share one formula; `padded_outputs` supplies the same
/// `n_padded` a built tx's proof would yield (`n_out` is type-bounded to
/// `1..=MAX_OUTPUTS` by [`OutputCount`], so no separate clamp is needed).
fn bp_plus_clawback_weight(n_out: OutputCount) -> usize {
    bp_plus_weight_clawback(padded_outputs(n_out))
}

/// Structural weight predictor (§3.10.1) — a byte-for-byte mirror of
/// `shekyl_wire::Transaction::write` plus the Bp+ clawback, so it equals
/// `Transaction::weight()` for the tx the builder will produce from these counts.
#[must_use]
pub fn predict_weight(n_in: InputCount, n_out: OutputCount, tree_depth: u8, fee: u64) -> usize {
    spend_weight(n_in, n_out, tree_depth, fee, pqc_auth_weight(), 0)
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
    Some(spend_weight(
        shape.n_in,
        shape.n_out,
        shape.tree_depth,
        fee,
        signer_pqc_auth_weight(shape.signer),
        extra_multisig_field_weight(shape.group_payees),
    ))
}

/// The one field model: a spend of `n_in` inputs each authorized by
/// `auth_weight` bytes, and `n_out` outputs whose `tx_extra` adds
/// `multisig_extra` bytes of `0x0D` entries.
fn spend_weight(
    n_in: InputCount,
    n_out: OutputCount,
    tree_depth: u8,
    fee: u64,
    auth_weight: usize,
    multisig_extra: usize,
) -> usize {
    // `n_in`/`n_out` are type-bounded (`1..=MAX_INPUTS` / `1..=MAX_OUTPUTS`), so every
    // per-count product and the field sum stay far below `usize` overflow — plain
    // arithmetic, no saturation. Each entry below is one field of
    // `shekyl_wire::Transaction::write`, in wire order.
    let fcmp = fcmp_proof_size(n_in, tree_depth);
    let bp = bp_plus_weight(n_out);
    let bp_clawback = bp_plus_clawback_weight(n_out);
    let n_in = n_in.get();
    let n_out = n_out.get();
    let extra_len = EXTRA_PUBKEY_FIELD_WEIGHT
        + extra_kem_field_weight(n_out)
        + extra_leaf_hashes_field_weight(n_out)
        + multisig_extra;
    [
        varint_len(TX_VERSION),            // version
        varint_len(0u64),                  // unlock_time
        varint_len(n_in as u64),           // vin count
        n_in * INPUT_TO_KEY_WEIGHT,        // vin elements
        varint_len(n_out as u64),          // vout count
        n_out * OUTPUT_WEIGHT,             // vout elements
        varint_len(extra_len as u64),      // tx_extra length prefix
        extra_len,                         // tx_extra body
        1,                   // ct type tag — one u8 (a byte width, not CT_TYPE_FCMP's value)
        varint_len(fee),     // fee
        REFERENCE_BLOCK_LEN, // reference_block
        n_out * CT_BASE_PER_OUTPUT_WEIGHT, // ct base (per output)
        n_in * auth_weight,  // per-input PQC auth
        varint_len(1u64),    // prunable nbp
        bp,                  // bulletproof+
        varint_len(u64::from(tree_depth)), // tree_depth
        varint_len(fcmp as u64), // fcmp_proof length prefix
        fcmp,                // fcmp_proof body
        n_in * PSEUDO_OUT_LEN, // pseudoOuts
        bp_clawback,         // Bp+ verification clawback
    ]
    .into_iter()
    .sum()
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
    tree_depth: u8,
    seed: u64,
    price: impl Fn(u64) -> Option<u64>,
) -> Option<u64> {
    converge_fee_by(
        |fee| u64::try_from(predict_weight(n_in, n_out, tree_depth, fee)).ok(),
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
    tree_depth: u8,
) -> Option<u64> {
    converge_weight_fee_by(n_in, n_out, tree_depth, 0, |weight| {
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
pub fn predict_archival_len(n_in: InputCount, n_out: OutputCount, tree_depth: u8) -> usize {
    let fcmp = fcmp_proof_size(n_in, tree_depth);
    let bp = bp_plus_weight(n_out);
    let n_in = n_in.get();
    [
        n_in * pqc_auth_weight(),          // the `pqc_auths` segment
        varint_len(1u64),                  // prunable nbp
        bp,                                // bulletproof+
        varint_len(u64::from(tree_depth)), // tree_depth
        varint_len(fcmp as u64),           // fcmp_proof length prefix
        fcmp,                              // fcmp_proof body
        n_in * PSEUDO_OUT_LEN,             // pseudoOuts
    ]
    .into_iter()
    .sum()
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
    tree_depth: u8,
    fee: u64,
) -> (usize, usize) {
    let weight = predict_weight(n_in, n_out, tree_depth, fee);
    let size = weight - bp_plus_clawback_weight(n_out);
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
    predict_weight(InputCount::clamped(2), n_out, MAX_TREE_DEPTH, fee).saturating_sub(
        predict_weight(InputCount::clamped(1), n_out, MAX_TREE_DEPTH, fee),
    )
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
        let w1 = predict_weight(InputCount::clamped(1), OutputCount::clamped(1), 1, 1_000);
        let w2 = predict_weight(InputCount::clamped(2), OutputCount::clamped(1), 1, 1_000);
        let w3 = predict_weight(InputCount::clamped(1), OutputCount::clamped(2), 1, 1_000);
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
        let (n_in, n_out, depth) = (InputCount::clamped(1), OutputCount::clamped(1), 1u8);

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
            MAX_TREE_DEPTH,
            u64::MAX,
        );
        let normal = predict_weight(
            InputCount::clamped(2),
            OutputCount::clamped(2),
            MAX_TREE_DEPTH,
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
            let nlr = 6 + padded_outputs(OutputCount::clamped(n_out)).trailing_zeros() as usize;
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
                        fcmp_proof: vec![0u8; fcmp_proof_size(InputCount::clamped(n_in), depth)],
                        pseudo_outs: vec![[0; 32]; n_in],
                    }),
                },
            };
            assert_eq!(
                predict_weight(InputCount::clamped(n_in), OutputCount::clamped(n_out), depth, fee),
                tx.weight(),
                "predict_weight ≠ wire weight for n_in={n_in} n_out={n_out} depth={depth} fee={fee}"
            );
            let (size, weight) = predict_size_and_weight(
                InputCount::clamped(n_in),
                OutputCount::clamped(n_out),
                depth,
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
                predict_archival_len(InputCount::clamped(n_in), OutputCount::clamped(n_out), depth),
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
        let (n_in, n_out, layers, fee) = (InputCount::clamped(2), OutputCount::clamped(3), 7, 900);
        let solo = predict_weight(n_in, n_out, layers, fee);
        let weigh = |signer: Signer, group_payees: &[GroupSize]| {
            predict_spend_weight(
                &SpendShape {
                    n_in,
                    n_out,
                    tree_depth: layers,
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
        // 9136 → 9008 with PL-D3 (2026-09-14): the opening leg replaces the
        // per-input extra-scalar branch, so the marginal input weight fell.
        assert_eq!(w, 9008, "weight-model movement changes the dust boundary");
        assert!(
            w > 3457,
            "the marginal weight must exceed the retired proofless stub"
        );
    }

    /// A product that does not fit is `None`. Restoring `saturating_mul`
    /// makes this return `Some(u64::MAX)`.
    #[test]
    fn an_unrepresentable_product_is_not_a_fee() {
        let (n_in, n_out, depth) = (InputCount::clamped(1), OutputCount::clamped(1), 1u8);
        assert_eq!(converge_weight_fee(u64::MAX, n_in, n_out, depth), None);
        assert_eq!(
            converge_weight_fee_by(n_in, n_out, depth, 0, |_| None),
            None,
            "a pricer refusal propagates"
        );
    }
}
