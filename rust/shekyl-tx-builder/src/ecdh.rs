//! Compact v2 ECDH amount encoding.
//!
//! Replicates the `ecdhEncode` v2 path from the C++ code:
//! - `amount_enc = amount_bytes[0..8] XOR ecdhHash(shared_secret)[0..8]`
//! - mask is derived separately via `genCommitmentMask(shared_secret)`
//!
//! The "shared secret" is the 32-byte `amount_key` provided per output.

use shekyl_primitives::keccak256;

/// Domain tag prepended to the shared secret before hashing to produce the
/// ECDH blinding stream. Matches the C++ `ENCRYPTED_AMOUNT` constant used
/// by `ecdhHash`.
const ECDH_HASH_PREFIX: &[u8] = b"amount";

/// Domain tag for commitment mask derivation.
/// Matches the C++ `genCommitmentMask` path: `Hs("commitment_mask" || shared_secret)`.
#[allow(dead_code)]
const COMMITMENT_MASK_PREFIX: &[u8] = b"commitment_mask";

/// Compute the 8-byte ECDH hash for compact amount encoding.
///
/// `ecdhHash(key) = Keccak256("amount" || key)[0..8]`
fn ecdh_hash(shared_secret: &[u8; 32]) -> [u8; 8] {
    let mut preimage = Vec::with_capacity(ECDH_HASH_PREFIX.len() + 32);
    preimage.extend_from_slice(ECDH_HASH_PREFIX);
    preimage.extend_from_slice(shared_secret);
    let hash = keccak256(&preimage);
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}

/// Derive the commitment mask scalar from the shared secret.
///
/// `mask = Hs("commitment_mask" || shared_secret)` where Hs is
/// Keccak256-to-scalar (reduced mod l).
#[allow(dead_code)]
pub(crate) fn gen_commitment_mask(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(COMMITMENT_MASK_PREFIX.len() + 32);
    preimage.extend_from_slice(COMMITMENT_MASK_PREFIX);
    preimage.extend_from_slice(shared_secret);
    let scalar = shekyl_primitives::keccak256_to_scalar(&preimage);
    scalar.to_bytes()
}

/// Encrypt an amount using compact v2 ECDH encoding.
///
/// Returns the 8-byte encrypted amount (XOR of LE amount bytes with `ecdhHash`).
pub(crate) fn ecdh_encode_amount(amount: u64, shared_secret: &[u8; 32]) -> [u8; 8] {
    let amount_bytes = amount.to_le_bytes();
    let hash = ecdh_hash(shared_secret);
    let mut encoded = [0u8; 8];
    for i in 0..8 {
        encoded[i] = amount_bytes[i] ^ hash[i];
    }
    encoded
}
