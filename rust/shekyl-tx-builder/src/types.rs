//! Public data types for the transaction builder.
//!
//! These structs form the API boundary: callers construct [`SpendInput`],
//! [`OutputInfo`], and [`TreeContext`], pass them to [`crate::sign_transaction`],
//! and receive [`SignedProofs`] on success.
//!
//! In-process Rust types only: the JSON form they carried was the C++ signing
//! FFI's contract, deleted with it (the wallet is Rust).

use shekyl_crypto_pq::output::EncryptedOutputField;
use shekyl_types::{BlockHash, CurveTreeRoot, TxSignableHash};
use shekyl_units::AtomicUnits;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug)]
pub struct LeafEntry {
    /// Compressed Ed25519 output public key O.
    pub output_key: [u8; 32],
    /// Key image generator I = Hp(O).
    pub key_image_gen: [u8; 32],
    /// Pedersen commitment C to the output amount.
    pub commitment: [u8; 32],
    /// The leaf's 4th scalar for this output: `CM.x`, the Wei25519
    /// x-coordinate of its PQC leaf commitment (`PL-D3`).
    pub cm_x: [u8; 32],
}

/// A spendable input with its secret keys, curve tree membership proof path,
/// and PQC authentication material.
///
/// # Field layout
///
/// All 32-byte arrays are compressed Ed25519 points or scalars in
/// little-endian canonical encoding. PQC signing uses `combined_ss` and
/// `output_index` to derive the keypair internally via
/// `sign_pqc_auth_for_output` — the ML-DSA secret key never exists as a
/// field on this struct.
#[derive(Clone, Debug)]
pub struct SpendInput {
    /// Compressed one-time output public key O (Ed25519).
    pub output_key: [u8; 32],
    /// Pedersen commitment to the input amount: C = mask*G + amount*H.
    pub commitment: [u8; 32],
    /// Cleartext amount in atomic units. Must be non-zero.
    pub amount: AtomicUnits,
    /// Ephemeral spend secret key x where O = x*G + y*T.
    pub spend_key_x: [u8; 32],
    /// SAL output-key secret y where O = xG + yT.
    pub spend_key_y: [u8; 32],
    /// Pedersen commitment mask z where C = zG + amount*H.
    pub commitment_mask: [u8; 32],
    // The input's own PQC leaf commitment `CM = k·G_k + r·J` and blind `r`
    // (`PL-D3`) are not fields: the signer re-derives both from `combined_ss`
    // and `output_index` (`shekyl_crypto_pq::leaf_commitment::derive_pqc_leaf`) —
    // the same derivation that produced the published `0x07` entry — and
    // checks the derived `CM.x` against this output's entry in `leaf_chunk`
    // before proving ([`crate::error::TxBuilderError::PqcLeafMismatch`]).
    /// Combined KEM shared secret (X25519 || ML-KEM) for PQC key derivation.
    /// Zeroized on drop.
    pub combined_ss: Vec<u8>,
    /// Output index within the transaction for PQC key derivation.
    pub output_index: u64,

    /// All outputs in the same Selene leaf chunk as this input.
    /// Each entry contains (O, I, C, CM.x). Must be non-empty and contain
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
        self.commitment_mask.zeroize();
        self.combined_ss.zeroize();
    }
}

/// A transaction output with the data needed for commitment and ECDH encoding.
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct OutputInfo {
    /// Compressed one-time destination key (Ed25519).
    pub dest_key: [u8; 32],
    /// Amount in atomic units. Must be non-zero.
    pub amount: AtomicUnits,
    /// HKDF-derived commitment mask z where C = z*G + amount*H.
    /// Pre-derived by `shekyl_construct_output` via HKDF from the shared secret.
    #[zeroize]
    pub commitment_mask: [u8; 32],
    /// Encrypted amount (9 bytes): [0..8] = amount XOR k_amount, [8] =
    /// amount_tag. In process, obtainable only from
    /// `OutputData::enc_amount_wire()`; the type's `Deserialize` impl is the
    /// one other route, and it exists for the FFI JSON boundary where the far
    /// side computed the encryption — see [`EncryptedOutputField`].
    ///
    /// Not zeroized, deliberately: this is ciphertext bound for the chain, so
    /// wiping the local copy protects nothing. The secret it was derived under
    /// (`k_amount`) is wiped by `OutputData`'s own `ZeroizeOnDrop`.
    #[zeroize(skip)]
    pub enc_amount: EncryptedOutputField,
    /// Encrypted label (9 bytes): [0..8] = plaintext XOR k_label, [8] =
    /// label_tag; sentinel plaintext at V3.0 launch. In process, obtainable
    /// only from `OutputData::enc_label_wire()`, so an unencrypted label
    /// cannot be constructed on this path. The type's `Deserialize` impl is
    /// the one other route, and it exists for the FFI JSON boundary where the
    /// far side computed the encryption — see [`EncryptedOutputField`].
    #[zeroize(skip)]
    pub enc_label: EncryptedOutputField,
}

/// Curve tree context at the reference block height.
///
/// Mirrors the curve-tree crate's `TreeContext`: `reference_block` is the
/// block identity, `tree_root` is the header-committed [`CurveTreeRoot`].
/// The two cannot be swapped — that mix-up was the prover bug this crate
/// was created to fix. Bytes for the transform-shaped proof crate are
/// taken at the `prove` call, not here.
#[derive(Clone, Debug)]
pub struct TreeContext {
    /// Hash of the reference block (stored in CtSig.referenceBlock).
    pub reference_block: BlockHash,
    /// Curve tree root at the reference block height (passed to the prover
    /// as bytes at the proof-crate boundary).
    pub tree_root: CurveTreeRoot,
    /// Tree depth (number of layers). Must be >= 1.
    pub tree_depth: u8,
}

/// Consensus authentication version for a hybrid spend or extra slot.
///
/// `shekyl_wire::PqcAuth` requires this value; [`crate::sign_pqc_auths`] and
/// [`crate::open_spend`] write it, and a placeholder slot hashed in phase 1
/// carries the same version as the signature that later replaces it.
pub const PQC_AUTH_VERSION: u8 = 1;

/// Per-input PQC authentication data (hybrid signature).
///
/// Contains the serialized hybrid signature (Ed25519 + ML-DSA-65) and the
/// serialized public key needed for verification.
#[derive(Clone, Debug)]
pub struct PqcAuth {
    /// Authentication version. Production slots use [`PQC_AUTH_VERSION`].
    pub auth_version: u8,
    /// Serialized hybrid signature (Ed25519 + ML-DSA-65) in canonical encoding.
    pub signature: Vec<u8>,
    /// Serialized hybrid public key in canonical encoding.
    pub public_key: Vec<u8>,
}

/// Result of signing: everything needed to populate CtSig and pqc_auths.
///
/// The caller takes these fields and inserts them into the transaction's
/// `ct_signatures` and `pqc_auths` at the protocol layer. The `SignedProofs`
/// struct intentionally does *not* know about the full transaction format —
/// it only produces the cryptographic material.
#[derive(Clone, Debug)]
pub struct SignedProofs {
    /// Serialized Bulletproof+ range proof.
    pub bulletproof_plus: Vec<u8>,
    /// Per-output Pedersen commitments: the real prime-order `C = mask*G +
    /// amount*H` (compressed points, **no** cofactor scaling). This is the form
    /// consensus stores in `outPk[i].mask` and the form the wallet scanner
    /// recomputes and byte-compares against
    /// (`shekyl-crypto-pq` `scan_output_recover_with_ml_kem_dk`), so it must
    /// not be `8*C`. The Bulletproof+ `V` vector carries the cofactored `C/8`
    /// form internally; the two are reconciled inside the BP+ verifier.
    pub commitments: Vec<[u8; 32]>,
    /// Per-output encrypted amounts (9 bytes each: [0..8] = XOR-encrypted, [8] = HKDF tag).
    pub enc_amounts: Vec<EncryptedOutputField>,
    /// Per-output encrypted labels (9 bytes each).
    pub enc_labels: Vec<EncryptedOutputField>,
    /// Per-input pseudo-output commitments (from FCMP prover).
    pub pseudo_outs: Vec<[u8; 32]>,
    /// Opaque FCMP++ membership proof blob.
    pub fcmp_proof: Vec<u8>,
    /// Per-input PQC authentication (ML-DSA-65 hybrid signatures).
    pub pqc_auths: Vec<PqcAuth>,
    /// Reference block hash (echo back for CtSig).
    pub reference_block: BlockHash,
    /// Tree depth (echo back for CtSig).
    pub tree_depth: u8,
    /// The `tx_signable` the FCMP++ proof was made over (the signing
    /// envelope §2.2). [`crate::open_spend`] holds the assembled
    /// transaction to it: a layout whose prefix or base differs from what
    /// was proved is refused there, not by the daemon.
    pub tx_signable: TxSignableHash,
}
