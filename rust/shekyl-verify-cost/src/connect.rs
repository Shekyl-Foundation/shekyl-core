// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared fixture support for the GAP-7 cold-block connect bench
//! (`benches/block_connect_verify.rs`) and its pins
//! (`tests/block_connect_pins.rs`).
//!
//! Builds one **shape-true connect transaction**: the FCMP++ admission fixture
//! (real proof, via [`crate::relay::build_fixture`]), a real hybrid
//! Ed25519+ML-DSA-65 signature made by the wallet's signer, a real Bp+
//! aggregate range proof over `n_out` commitments, and the assembled
//! `shekyl_wire::Transaction` whose `weight()` — the single owner of
//! transaction weight, which CEN-H3 (`shekyl-chain-rules` `rules/tx.rs`)
//! judges — is what the bench's budget math and the pins' cap-saturation
//! assertions run on.
//!
//! Nothing here is semantically block-valid end to end (the outputs' keys are
//! synthetic, the extra's KEM ciphertexts are random bytes, the proof and the
//! signature are over stand-in messages); what IS real is every component a
//! **verifier pays for** — proof bytes, signature bytes, commitment count,
//! serialized layout — because those are the axes the bench measures. So the
//! bench calls the bodies `form` runs at each listed slot rather than `form`
//! itself, which would refuse the transaction at its first stand-in. The pins
//! assert exactly that split: the crypto components verify (positive limb),
//! and the wire round-trips at the claimed shape.

use rand_core::{CryptoRng, RngCore};

use curve25519_dalek::scalar::Scalar;
use shekyl_bulletproofs::{verify_batch, BatchEntry, Bulletproof};
use shekyl_crypto_pq::error::PqcVerifyError;
use shekyl_crypto_pq::kem::{SharedSecret, SHARED_SECRET_LEN};
use shekyl_crypto_pq::output::sign_pqc_auth_for_output;
use shekyl_crypto_pq::signature::{
    verify_pqc_auth, HYBRID_SCHEME_ID_ED25519_ML_DSA_65, SCHEME_DOMAIN_PQC_AUTH_TX,
};
use shekyl_curve_io::CompressedPoint;
use shekyl_curve_primitives::Commitment;
use shekyl_types::SigningPayloadHash;
use shekyl_wire::transaction::{
    BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, Transaction, TxPrefix,
};
use shekyl_wire::tx_extra::HYBRID_KEM_CT_BYTES;

use crate::relay;

/// A real hybrid Ed25519+ML-DSA-65 auth: key, signature, and the message it
/// signs. Production signs each input's `signed_hash(i)`
/// (`PqcSigningPreimage::signed_hash`), which needs the finished
/// transaction; the fixture signs a stand-in of the same type and width,
/// since what the bench prices is the verify, whose cost depends on the
/// message's length, not its content.
pub struct PqcAuthFixture {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub message: SigningPayloadHash,
}

/// Fill byte of [`stand_in_signed_hash`]. Distinct from a real
/// `signed_hash`, and stable so a seeded signature over it replays.
const STAND_IN_SIGNED_HASH_FILL: u8 = 0x5a;

/// Output index passed to the wallet signer for a fixture key.
///
/// Each fixture signature draws a fresh combined shared secret, so the key
/// is output 0 of that secret: the index a one-output derivation uses.
/// [`build_pqc_auth`] and the drift gate's seeded signer both pass it.
pub const PQC_AUTH_FIXTURE_OUTPUT_INDEX: u64 = 0;

/// The stand-in for input `input`'s signing hash: a distinct message per
/// input, of `signed_hash(i)`'s type and width ([`SigningPayloadHash::LEN`]).
///
/// # Panics
///
/// If `input` is past a byte, which no input index under the consensus cap
/// (8) is.
#[must_use]
pub fn stand_in_signed_hash(input: usize) -> SigningPayloadHash {
    let mut bytes = [STAND_IN_SIGNED_HASH_FILL; SigningPayloadHash::LEN];
    bytes[0] = u8::try_from(input).expect("an input index fits a byte");
    SigningPayloadHash::from_bytes(bytes)
}

/// Derive a keypair and sign `message` through the wallet's own signer
/// ([`sign_pqc_auth_for_output`], under the tx-auth domain the verifier
/// reads), from a combined shared secret drawn from `rng` — so the byte
/// lengths entering the wire fixture are the production encodings, not
/// guesses. The secret is a [`SharedSecret`], wiped when this returns.
pub fn build_pqc_auth<R: RngCore + CryptoRng>(
    rng: &mut R,
    message: SigningPayloadHash,
) -> PqcAuthFixture {
    let mut combined_ss = SharedSecret([0u8; SHARED_SECRET_LEN]);
    rng.fill_bytes(&mut combined_ss.0);
    let signed = sign_pqc_auth_for_output(
        &combined_ss.0,
        PQC_AUTH_FIXTURE_OUTPUT_INDEX,
        SCHEME_DOMAIN_PQC_AUTH_TX,
        message.as_bytes(),
    )
    .expect("pqc sign");
    PqcAuthFixture {
        public_key: signed.hybrid_public_key,
        signature: signed.signature,
        message,
    }
}

/// One hybrid verification through CEN-I18's body
/// ([`verify_pqc_auth`], the single-signer scheme) — the call `form` makes per input, and the
/// pool door's and the submit verifier's K13 make too.
pub fn pqc_verify(auth: &PqcAuthFixture) -> Result<(), PqcVerifyError> {
    pqc_verify_against(auth, &auth.message)
}

/// Verify `auth` against an arbitrary message — the negative limb's hook.
pub fn pqc_verify_against(
    auth: &PqcAuthFixture,
    message: &SigningPayloadHash,
) -> Result<(), PqcVerifyError> {
    verify_pqc_auth(
        HYBRID_SCHEME_ID_ED25519_ML_DSA_65,
        &auth.public_key,
        &auth.signature,
        message,
    )
}

/// A real Bp+ aggregate range proof over `n_out` commitments, plus the
/// commitments it must verify against.
///
/// The verifier is the shipped one: [`verify_batch`] is CEN-H19's body
/// (`shekyl-chain-rules` `rules/range_proof.rs`) and the submit verifier's
/// N8 leg, so its cost is the acceptance path's own, not a proxy's.
pub struct BpFixture {
    pub proof: Bulletproof,
    pub commitments: Vec<CompressedPoint>,
}

/// Prove `n_out` in-range amounts with the production prover
/// (`Bulletproof::prove_plus` — the call `shekyl-tx-builder`'s
/// `sign_transaction` makes).
pub fn build_bp<R: RngCore + CryptoRng>(rng: &mut R, n_out: usize) -> BpFixture {
    let commitments: Vec<Commitment> = (0..n_out)
        .map(|i| {
            let i = u64::try_from(i).expect("n_out fits u64");
            Commitment::new(Scalar::from(i + 7), 1_000 + i)
        })
        .collect();
    let compressed = commitments
        .iter()
        .map(|c| c.calculate().compress().into())
        .collect();
    let proof = Bulletproof::prove_plus(rng, commitments).expect("bp+ prove");
    BpFixture {
        proof,
        commitments: compressed,
    }
}

/// Verify the Bp+ fixture as a batch of one under derived weights — what the
/// pool door does at `TxSlot::Lone` (`H19::verify_lone`) and the submit
/// verifier's N8 leg does, so the timed figure includes the seed's cSHAKE.
/// `true` is the only acceptable result for a fixture the bench times
/// (self-witness, same rule as [`relay::AdmissionStatus::verified`]).
pub fn bp_verify(fx: &BpFixture) -> bool {
    bp_verify_block(fx, 1)
}

/// Verify `copies` of the fixture's proof as ONE batch — what `form` does
/// after its slot loop, folding every listed transaction's range proof into
/// a single [`verify_batch`] (CEN-H19). The budget fill duplicates one
/// transaction, so the block's batch is that proof `copies` times; the
/// multiexp does not deduplicate entries, so the cost is that of `copies`
/// distinct proofs of the shape.
pub fn bp_verify_block(fx: &BpFixture, copies: usize) -> bool {
    let entry = BatchEntry {
        proof: &fx.proof,
        commitments: &fx.commitments,
    };
    let batch: Vec<BatchEntry<'_>> = (0..copies)
        .map(|_| BatchEntry {
            proof: entry.proof,
            commitments: entry.commitments,
        })
        .collect();
    verify_batch(&batch)
}

/// Everything the cold-block connect path pays for one transaction, at one
/// shape — plus the wire form that prices it.
pub struct ConnectTxFixture {
    pub adm: relay::AdmissionFixture,
    pub pqc: PqcAuthFixture,
    pub bp: BpFixture,
    pub wire_bytes: Vec<u8>,
    /// `Transaction::weight()` — serialized length + Bp+ clawback, the value
    /// block weight and fees are charged against.
    pub weight: usize,
    pub n_in: usize,
    pub n_out: usize,
}

/// Build the full per-tx fixture at shape `(n_in, n_out)`.
///
/// The admission fixture carries the real FCMP++ proof; the wire assembly
/// mirrors `shekyl-tx-builder`'s `build_wire_tx` field for field (the Bp+
/// bytes round-trip through `BpPlus::from_bytes` exactly as the builder's
/// pinned layout test does), so `weight()` prices real component lengths.
pub fn build_connect_tx<R: RngCore + CryptoRng>(
    rng: &mut R,
    n_in: usize,
    n_out: usize,
    tree_depth: u8,
    layout: relay::ChunkLayout,
) -> ConnectTxFixture {
    let adm = relay::build_fixture(rng, n_in, n_out, tree_depth, layout);
    let pqc = build_pqc_auth(rng, stand_in_signed_hash(0));
    let bp = build_bp(rng, n_out);

    // Inputs: n_in FCMP++ spends, key images from the admission fixture.
    let inputs: Vec<Input> = adm
        .key_images
        .iter()
        .map(|ki| Input::ToKey {
            amount: 0,
            key_offsets: Vec::new(),
            key_image: *ki.as_bytes(),
        })
        .collect();
    assert_eq!(inputs.len(), n_in, "admission fixture input arity");

    // Outputs: n_out view-tagged keys (synthetic key bytes; the verifier cost
    // of an output lives in Bp+/CT, which are real above).
    let outputs: Vec<Output> = (0..n_out)
        .map(|i| {
            let tag = u8::try_from(i).expect("n_out <= 16");
            Output {
                amount: 0,
                key: [tag + 1; 32],
                view_tag: tag,
            }
        })
        .collect();

    // tx_extra through the CODEC-OWNED serializer (`shekyl_wire::tx_extra::
    // serialize`) — one length-prefixed 0x06 blob carrying ALL outputs' KEM
    // ciphertexts concatenated, one length-prefixed 0x07 blob carrying all
    // leaf entries, exactly as the codec's `read_blob`/`write_blob` pair
    // encodes them. A hand-rolled form would be the duplicate-the-format
    // trap (GTWF §9.6a's "not self-describing" and "per output" sentences
    // both describe a layout the codec does not have); the serializer is
    // the single source, and the pins assert the interior through
    // `parse_extra`.
    let kem_concat: Vec<u8> = (0..n_out)
        .flat_map(|i| {
            std::iter::repeat_n(u8::try_from(i).expect("n_out <= 16"), HYBRID_KEM_CT_BYTES)
        })
        .collect();
    // One admissible 64-byte `0x07` entry per output (`CM ‖ record`, PL-D3):
    // admission checks every entry's point (`check_pqc_leaf_entries`), so
    // the filler must be a real point, not a byte pattern. The record half
    // is unchecked by consensus; a per-output nibble keeps entries distinct.
    let leaf_concat: Vec<u8> = (0..n_out)
        .flat_map(|i| {
            let mut entry = shekyl_wire::tx_extra::conforming_pqc_leaf_entry();
            entry[63] = 0xB0u8 | (u8::try_from(i).expect("n_out <= 16") & 0x0F);
            entry
        })
        .collect();
    let extra = shekyl_wire::tx_extra::serialize(&[
        shekyl_wire::tx_extra::TxExtraField::PqcKemCiphertext(kem_concat),
        shekyl_wire::tx_extra::TxExtraField::PqcLeafEntries(leaf_concat),
    ])
    .expect("tx_extra serialize");

    // Bp+ bytes: oxide `write` and wire `BpPlus` share the exact layout
    // (pinned by tx-builder's `bulletproof_oxide_layout_parses_as_wire_bpplus`).
    let mut bp_bytes = Vec::new();
    bp.proof.write(&mut bp_bytes).expect("bp+ write");
    let bp_plus = BpPlus::from_bytes(&bp_bytes).expect("bp+ bytes parse as wire BpPlus");

    let pqc_auths: Vec<PqcAuth> = (0..n_in)
        .map(|_| PqcAuth {
            auth_version: 1,
            scheme_id: HYBRID_SCHEME_ID_ED25519_ML_DSA_65,
            flags: 0,
            hybrid_public_key: pqc.public_key.clone(),
            hybrid_signature: pqc.signature.clone(),
        })
        .collect();

    let commitments: Vec<[u8; 32]> = bp.commitments.iter().map(|c| c.0).collect();

    let tx = Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs,
            outputs,
            extra,
        },
        ct: Ct::Fcmp {
            fee: 1,
            reference_block: shekyl_types::BlockHash::from_bytes([0xAB; 32]),
            base: CtBase {
                enc_amounts: vec![[0u8; 9]; n_out],
                enc_labels: vec![[0u8; 9]; n_out],
                commitments,
            },
            pqc_auths,
            prunable: Some(Prunable {
                bulletproofs: vec![bp_plus],
                tree_depth: u64::from(tree_depth.max(2)) - 1,
                fcmp_proof: adm.proof.clone(),
                pseudo_outs: adm.pseudo_outs.clone(),
                serve_credit_pruned: Vec::new(),
            }),
        },
    };

    let mut wire_bytes = Vec::new();
    tx.write(&mut wire_bytes).expect("wire write");
    let weight = tx.weight();

    ConnectTxFixture {
        adm,
        pqc,
        bp,
        wire_bytes,
        weight,
        n_in,
        n_out,
    }
}

/// Parse the fixture's wire bytes through the production parser — the bench's
/// parse term. Returns the parsed tx so the pins can assert shape agreement.
pub fn parse_wire(fx: &ConnectTxFixture) -> Transaction {
    Transaction::from_bytes(&fx.wire_bytes).expect("wire parse")
}
