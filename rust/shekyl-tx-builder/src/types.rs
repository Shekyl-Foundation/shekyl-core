//! Public data types for the transaction builder.
//!
//! These structs form the API boundary: callers construct [`SpendInput`],
//! [`OutputInfo`], and [`TreeContext`], pass them to [`crate::sign_transaction`],
//! and receive [`SignedProofs`] on success.
//!
//! All `[u8; 32]` fields serialize/deserialize as hex strings when used with
//! JSON (via the `hex_bytes` module), matching the C++ FFI convention.

use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

/// Serde helper: hex-encode/decode `[u8; 32]`.
mod hex_bytes32 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
        })
    }
}

/// Serde helper: hex-encode/decode `[u8; 8]`.
#[allow(dead_code)]
mod hex_bytes8 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 8], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 8], D::Error>
    where D: Deserializer<'de> {
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

    pub fn serialize<S>(items: &Vec<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let hexes: Vec<String> = items.iter().map(|b| hex::encode(b)).collect();
        hexes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where D: Deserializer<'de> {
        let hexes: Vec<String> = Vec::deserialize(deserializer)?;
        hexes.into_iter().map(|s| {
            let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
            v.try_into().map_err(|v: Vec<u8>| {
                serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
            })
        }).collect()
    }
}

/// Serde helper: hex-encode/decode `Vec<[u8; 8]>`.
mod hex_vec8 {
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(items: &Vec<[u8; 8]>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let hexes: Vec<String> = items.iter().map(|b| hex::encode(b)).collect();
        hexes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 8]>, D::Error>
    where D: Deserializer<'de> {
        let hexes: Vec<String> = Vec::deserialize(deserializer)?;
        hexes.into_iter().map(|s| {
            let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
            v.try_into().map_err(|v: Vec<u8>| {
                serde::de::Error::custom(format!("expected 8 bytes, got {}", v.len()))
            })
        }).collect()
    }
}

/// Serde helper: hex-encode/decode `Vec<Vec<[u8; 32]>>` (branch layers).
#[allow(dead_code)]
mod hex_layers {
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(layers: &Vec<Vec<[u8; 32]>>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let outer: Vec<Vec<String>> = layers
            .iter()
            .map(|layer| layer.iter().map(|b| hex::encode(b)).collect())
            .collect();
        outer.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<[u8; 32]>>, D::Error>
    where D: Deserializer<'de> {
        let outer: Vec<Vec<String>> = Vec::deserialize(deserializer)?;
        outer.into_iter().map(|layer| {
            layer.into_iter().map(|s| {
                let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
                v.try_into().map_err(|v: Vec<u8>| {
                    serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
                })
            }).collect()
        }).collect()
    }
}

/// Serde helper: hex-encode/decode `Vec<u8>`.
mod hex_blob {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de> {
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
    /// PQC leaf hash H(pqc_pk) for this output.
    #[serde(with = "hex_bytes32")]
    pub h_pqc: [u8; 32],
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
    pub amount: u64,
    /// Ephemeral spend secret key x where O = x*G + y*T.
    #[serde(with = "hex_bytes32")]
    pub spend_key_x: [u8; 32],
    /// SAL output-key secret y where O = xG + yT.
    #[serde(with = "hex_bytes32")]
    pub spend_key_y: [u8; 32],
    /// Pedersen commitment mask z where C = zG + amount*H.
    #[serde(with = "hex_bytes32")]
    pub commitment_mask: [u8; 32],
    /// Hash of the PQC public key for this output: H(pqc_pk).
    #[serde(with = "hex_bytes32")]
    pub h_pqc: [u8; 32],
    /// Combined KEM shared secret (X25519 || ML-KEM) for PQC key derivation.
    /// Zeroized on drop.
    #[serde(with = "hex_blob")]
    pub combined_ss: Vec<u8>,
    /// Output index within the transaction for PQC key derivation.
    pub output_index: u64,

    /// All outputs in the same Selene leaf chunk as this input.
    /// Each entry contains (O, I, C, h_pqc). Must be non-empty and contain
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputInfo {
    /// Compressed one-time destination key (Ed25519).
    #[serde(with = "hex_bytes32")]
    pub dest_key: [u8; 32],
    /// Amount in atomic units. Must be non-zero.
    pub amount: u64,
    /// ECDH scalar derived from tx_key and dest_key, used for amount encoding.
    /// This is `Hs(shared_secret || output_index)` — 32 bytes.
    #[serde(with = "hex_bytes32")]
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
    #[serde(with = "hex_bytes32")]
    pub reference_block: [u8; 32],
    /// Curve tree root at the reference block height (passed to prover).
    #[serde(with = "hex_bytes32")]
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
    #[serde(with = "hex_blob")]
    pub signature: Vec<u8>,
    /// Serialized hybrid public key in canonical encoding.
    #[serde(with = "hex_blob")]
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
    #[serde(with = "hex_blob")]
    pub bulletproof_plus: Vec<u8>,
    /// Per-output Pedersen commitments (compressed points, scalarmult8 applied).
    #[serde(with = "hex_vec32")]
    pub commitments: Vec<[u8; 32]>,
    /// Per-output ECDH-encoded amounts (compact v2 format, 8 bytes each).
    #[serde(with = "hex_vec8")]
    pub ecdh_amounts: Vec<[u8; 8]>,
    /// Per-input pseudo-output commitments (from FCMP prover).
    #[serde(with = "hex_vec32")]
    pub pseudo_outs: Vec<[u8; 32]>,
    /// Opaque FCMP++ membership proof blob.
    #[serde(with = "hex_blob")]
    pub fcmp_proof: Vec<u8>,
    /// Per-input PQC authentication (ML-DSA-65 hybrid signatures).
    pub pqc_auths: Vec<PqcAuth>,
    /// Reference block hash (echo back for rctSig).
    #[serde(with = "hex_bytes32")]
    pub reference_block: [u8; 32],
    /// Tree depth (echo back for rctSig).
    pub tree_depth: u8,
}
