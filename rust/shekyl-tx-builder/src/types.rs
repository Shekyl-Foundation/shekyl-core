//! Public data types for the transaction builder.
//!
//! These structs form the API boundary: callers construct [`SpendInput`],
//! [`OutputInfo`], and [`TreeContext`], pass them to [`crate::sign_transaction`],
//! and receive [`SignedProofs`] on success.

use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

/// A single output entry within a Selene leaf chunk.
///
/// Each entry represents one UTXO in the same chunk as the input being spent.
/// The chunk data is needed by the FCMP++ prover to reconstruct the bottom
/// layer of the Merkle tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafEntry {
    /// Compressed Ed25519 output public key O.
    pub output_key: [u8; 32],
    /// Key image generator I = Hp(O).
    pub key_image_gen: [u8; 32],
    /// Pedersen commitment C to the output amount.
    pub commitment: [u8; 32],
    /// PQC leaf hash H(pqc_pk) for this output.
    pub h_pqc: [u8; 32],
}

/// A spendable input with its secret keys, curve tree membership proof path,
/// and PQC authentication material.
///
/// # Field layout
///
/// All 32-byte arrays are compressed Ed25519 points or scalars in
/// little-endian canonical encoding. The `pqc_secret_key` is the full
/// ML-DSA-65 secret key (4032 bytes) concatenated with the Ed25519 secret
/// key, in the canonical encoding produced by `shekyl-crypto-pq`.
#[derive(Clone, Debug, Deserialize)]
pub struct SpendInput {
    /// Compressed one-time output public key O (Ed25519).
    pub output_key: [u8; 32],
    /// Pedersen commitment to the input amount: C = mask*G + amount*H.
    pub commitment: [u8; 32],
    /// Cleartext amount in atomic units. Must be non-zero.
    pub amount: u64,
    /// Ephemeral spend secret key x where O = x*G + y*T.
    pub spend_key_x: [u8; 32],
    /// Blinding factor / mask y.
    pub spend_key_y: [u8; 32],
    /// Hash of the PQC public key for this output: H(pqc_pk).
    pub h_pqc: [u8; 32],
    /// Derived hybrid secret key (Ed25519 + ML-DSA-65) for PQC signing.
    /// Encoded in canonical form via `HybridSecretKey::to_canonical_bytes()`.
    /// Zeroized on drop.
    pub pqc_secret_key: Vec<u8>,

    /// All outputs in the same Selene leaf chunk as this input.
    /// Each entry contains (O, I, C, h_pqc). Must be non-empty and contain
    /// at most `SELENE_CHUNK_WIDTH` entries.
    pub leaf_chunk: Vec<LeafEntry>,
    /// Selene (C1) branch layers, ordered bottom-to-top.
    /// Each inner `Vec<[u8; 32]>` contains the sibling hashes at that level.
    pub c1_layers: Vec<Vec<[u8; 32]>>,
    /// Helios (C2) branch layers, ordered bottom-to-top.
    pub c2_layers: Vec<Vec<[u8; 32]>>,
}

impl Drop for SpendInput {
    fn drop(&mut self) {
        self.spend_key_x.zeroize();
        self.spend_key_y.zeroize();
        self.pqc_secret_key.zeroize();
    }
}

/// A transaction output with the data needed for commitment and ECDH encoding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputInfo {
    /// Compressed one-time destination key (Ed25519).
    pub dest_key: [u8; 32],
    /// Amount in atomic units. Must be non-zero.
    pub amount: u64,
    /// ECDH scalar derived from tx_key and dest_key, used for amount encoding.
    /// This is `Hs(shared_secret || output_index)` — 32 bytes.
    pub amount_key: [u8; 32],
}

/// Curve tree context at the reference block height.
///
/// # Important distinction
///
/// `tree_root` is the Selene hash root extracted from the block header's
/// `curve_tree_root` field. It is **not** the block hash. Confusing these
/// was the root cause of the prover bug this crate was created to fix.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeContext {
    /// Hash of the reference block (stored in rctSig.referenceBlock).
    pub reference_block: [u8; 32],
    /// Curve tree root at the reference block height (passed to prover).
    pub tree_root: [u8; 32],
    /// Tree depth (number of layers). Must be >= 1.
    pub tree_depth: u8,
}

/// Per-input PQC authentication data (hybrid signature).
///
/// Contains the serialized hybrid signature (Ed25519 + ML-DSA-65) and the
/// serialized public key needed for verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqcAuth {
    /// Authentication version (currently 1).
    pub auth_version: u8,
    /// Serialized hybrid signature (Ed25519 + ML-DSA-65) in canonical encoding.
    pub signature: Vec<u8>,
    /// Serialized hybrid public key in canonical encoding.
    pub public_key: Vec<u8>,
}

/// Result of signing: everything needed to populate rctSig and pqc_auths.
///
/// The caller takes these fields and inserts them into the transaction's
/// `rct_signatures` and `pqc_auths` at the protocol layer. The `SignedProofs`
/// struct intentionally does *not* know about the full transaction format —
/// it only produces the cryptographic material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedProofs {
    /// Serialized Bulletproof+ range proof.
    pub bulletproof_plus: Vec<u8>,
    /// Per-output Pedersen commitments (compressed points, scalarmult8 applied).
    pub commitments: Vec<[u8; 32]>,
    /// Per-output ECDH-encoded amounts (compact v2 format, 8 bytes each).
    pub ecdh_amounts: Vec<[u8; 8]>,
    /// Per-input pseudo-output commitments (from FCMP prover).
    pub pseudo_outs: Vec<[u8; 32]>,
    /// Opaque FCMP++ membership proof blob.
    pub fcmp_proof: Vec<u8>,
    /// Per-input PQC authentication (ML-DSA-65 hybrid signatures).
    pub pqc_auths: Vec<PqcAuth>,
    /// Reference block hash (echo back for rctSig).
    pub reference_block: [u8; 32],
    /// Tree depth (echo back for rctSig).
    pub tree_depth: u8,
}
