//! Public data types for the transaction builder.
//!
//! These structs form the API boundary: callers construct [`SpendInput`],
//! [`OutputInfo`], and [`TreeContext`], pass them to [`crate::sign_transaction`],
//! and receive [`SignedProofs`] on success.
//!
//! 32-byte fields serialize as hex strings in JSON (via [`hex_bytes32`] for
//! raw arrays and [`hex_typed_hash`] for `hash32!` identities), matching
//! the C++ FFI convention.

use serde::{Deserialize, Serialize};
use shekyl_crypto_pq::output::EncryptedOutputField;
use shekyl_types::{BlockHash, CurveTreeRoot};
use shekyl_units::AtomicUnits;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Serde helper: hex-encode/decode `[u8; 32]`.
pub mod hex_bytes32 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
        })
    }
}

/// Hex serde for any [`shekyl_types::Hash32Bytes`] identity — one helper for the family,
/// so typing another field does not mint another `hex_block_hash` copy.
/// JSON form is the same 64 lowercase hex characters [`hex_bytes32`] emits.
pub mod hex_typed_hash {
    use serde::{Deserializer, Serializer};
    use shekyl_types::Hash32Bytes;

    pub fn serialize<S, T>(hash: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Hash32Bytes,
    {
        super::hex_bytes32::serialize(hash.as_bytes(), serializer)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: Hash32Bytes,
    {
        super::hex_bytes32::deserialize(deserializer).map(T::from_bytes)
    }
}

/// Serde helper: hex-encode/decode `[u8; 8]`.
#[allow(dead_code)]
mod hex_bytes8 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 8], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 8 bytes, got {}", v.len()))
        })
    }
}

/// Serde helper: hex-encode/decode `Vec<[u8; 32]>`.
mod hex_vec32 {
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(items: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hexes: Vec<String> = items.iter().map(hex::encode).collect();
        hexes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hexes: Vec<String> = Vec::deserialize(deserializer)?;
        hexes
            .into_iter()
            .map(|s| {
                let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
                v.try_into().map_err(|v: Vec<u8>| {
                    serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
                })
            })
            .collect()
    }
}

/// Serde helper: hex-encode/decode `Vec<Vec<[u8; 32]>>` (branch layers).
#[allow(dead_code)]
pub mod hex_layers {
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(layers: &[Vec<[u8; 32]>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let outer: Vec<Vec<String>> = layers
            .iter()
            .map(|layer| layer.iter().map(hex::encode).collect())
            .collect();
        outer.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<[u8; 32]>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let outer: Vec<Vec<String>> = Vec::deserialize(deserializer)?;
        outer
            .into_iter()
            .map(|layer| {
                layer
                    .into_iter()
                    .map(|s| {
                        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
                        v.try_into().map_err(|v: Vec<u8>| {
                            serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
                        })
                    })
                    .collect()
            })
            .collect()
    }
}

/// Serde helper: hex-encode/decode `Vec<u8>`.
pub mod hex_blob {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// A single output entry within a Selene leaf chunk.
///
/// Each entry represents one UTXO in the same chunk as the input being spent.
/// The chunk data is needed by the FCMP++ prover to reconstruct the bottom
/// layer of the Merkle tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafEntry {
    /// Compressed Ed25519 output public key O.
    #[serde(with = "hex_bytes32")]
    pub output_key: [u8; 32],
    /// Key image generator I = Hp(O).
    #[serde(with = "hex_bytes32")]
    pub key_image_gen: [u8; 32],
    /// Pedersen commitment C to the output amount.
    #[serde(with = "hex_bytes32")]
    pub commitment: [u8; 32],
    /// The leaf's 4th scalar for this output: `CM.x`, the Wei25519
    /// x-coordinate of its PQC leaf commitment (`PL-D3`).
    #[serde(with = "hex_bytes32")]
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
#[derive(Clone, Debug, Deserialize)]
pub struct SpendInput {
    /// Compressed one-time output public key O (Ed25519).
    #[serde(with = "hex_bytes32")]
    pub output_key: [u8; 32],
    /// Pedersen commitment to the input amount: C = mask*G + amount*H.
    #[serde(with = "hex_bytes32")]
    pub commitment: [u8; 32],
    /// Cleartext amount in atomic units. Must be non-zero.
    pub amount: AtomicUnits,
    /// Ephemeral spend secret key x where O = x*G + y*T.
    #[serde(with = "hex_bytes32")]
    pub spend_key_x: [u8; 32],
    /// SAL output-key secret y where O = xG + yT.
    #[serde(with = "hex_bytes32")]
    pub spend_key_y: [u8; 32],
    /// Pedersen commitment mask z where C = zG + amount*H.
    #[serde(with = "hex_bytes32")]
    pub commitment_mask: [u8; 32],
    // The input's own PQC leaf commitment `CM = k·G_k + r·J` and blind `r`
    // (`PL-D3`) are not fields: the signer re-derives both from `combined_ss`
    // and `output_index` (`shekyl_crypto_pq::leaf_commitment::derive_pqc_leaf`) —
    // the same derivation that produced the published `0x07` entry — and
    // checks the derived `CM.x` against this output's entry in `leaf_chunk`
    // before proving ([`crate::error::TxBuilderError::PqcLeafMismatch`]).
    /// Combined KEM shared secret (X25519 || ML-KEM) for PQC key derivation.
    /// Zeroized on drop.
    #[serde(with = "hex_blob")]
    pub combined_ss: Vec<u8>,
    /// Output index within the transaction for PQC key derivation.
    pub output_index: u64,

    /// All outputs in the same Selene leaf chunk as this input.
    /// Each entry contains (O, I, C, CM.x). Must be non-empty and contain
    /// at most `SELENE_CHUNK_WIDTH` entries.
    pub leaf_chunk: Vec<LeafEntry>,
    /// Selene (C1) branch layers, ordered bottom-to-top.
    /// Each inner `Vec<[u8; 32]>` contains the sibling hashes at that level.
    #[serde(with = "hex_layers")]
    pub c1_layers: Vec<Vec<[u8; 32]>>,
    /// Helios (C2) branch layers, ordered bottom-to-top.
    #[serde(with = "hex_layers")]
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
#[derive(Clone, Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct OutputInfo {
    /// Compressed one-time destination key (Ed25519).
    #[serde(with = "hex_bytes32")]
    pub dest_key: [u8; 32],
    /// Amount in atomic units. Must be non-zero.
    pub amount: AtomicUnits,
    /// HKDF-derived commitment mask z where C = z*G + amount*H.
    /// Pre-derived by `shekyl_construct_output` via HKDF from the shared secret.
    #[serde(with = "hex_bytes32")]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeContext {
    /// Hash of the reference block (stored in CtSig.referenceBlock).
    #[serde(with = "hex_typed_hash")]
    pub reference_block: BlockHash,
    /// Curve tree root at the reference block height (passed to the prover
    /// as bytes at the proof-crate boundary).
    #[serde(with = "hex_typed_hash")]
    pub tree_root: CurveTreeRoot,
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
    #[serde(with = "hex_blob")]
    pub signature: Vec<u8>,
    /// Serialized hybrid public key in canonical encoding.
    #[serde(with = "hex_blob")]
    pub public_key: Vec<u8>,
}

/// Result of signing: everything needed to populate CtSig and pqc_auths.
///
/// The caller takes these fields and inserts them into the transaction's
/// `ct_signatures` and `pqc_auths` at the protocol layer. The `SignedProofs`
/// struct intentionally does *not* know about the full transaction format —
/// it only produces the cryptographic material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedProofs {
    /// Serialized Bulletproof+ range proof.
    #[serde(with = "hex_blob")]
    pub bulletproof_plus: Vec<u8>,
    /// Per-output Pedersen commitments: the real prime-order `C = mask*G +
    /// amount*H` (compressed points, **no** cofactor scaling). This is the form
    /// consensus stores in `outPk[i].mask` and the form the wallet scanner
    /// recomputes and byte-compares against
    /// (`shekyl-crypto-pq` `scan_output_recover_with_ml_kem_dk`), so it must
    /// not be `8*C`. The Bulletproof+ `V` vector carries the cofactored `C/8`
    /// form internally; the two are reconciled inside the BP+ verifier.
    #[serde(with = "hex_vec32")]
    pub commitments: Vec<[u8; 32]>,
    /// Per-output encrypted amounts (9 bytes each: [0..8] = XOR-encrypted, [8] = HKDF tag).
    pub enc_amounts: Vec<EncryptedOutputField>,
    /// Per-output encrypted labels (9 bytes each).
    pub enc_labels: Vec<EncryptedOutputField>,
    /// Per-input pseudo-output commitments (from FCMP prover).
    #[serde(with = "hex_vec32")]
    pub pseudo_outs: Vec<[u8; 32]>,
    /// Opaque FCMP++ membership proof blob.
    #[serde(with = "hex_blob")]
    pub fcmp_proof: Vec<u8>,
    /// Per-input PQC authentication (ML-DSA-65 hybrid signatures).
    pub pqc_auths: Vec<PqcAuth>,
    /// Reference block hash (echo back for CtSig).
    #[serde(with = "hex_typed_hash")]
    pub reference_block: BlockHash,
    /// Tree depth (echo back for CtSig).
    pub tree_depth: u8,
}
