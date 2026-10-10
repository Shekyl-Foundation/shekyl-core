// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The nested hybrid combiner (SA-R-1) and the canonical four-byte header,
//! shared by every hybrid signature scheme in this crate.
//!
//! ```text
//! preimage  = cSHAKE256-64(customization = domain, input = scheme_id ‖ message)
//! σ_pq      = PQ.Sign(preimage)                       // PQ-inner
//! σ_ed      = Ed25519.Sign(preimage ‖ σ_pq)           // classical-outer
//! ```
//!
//! A scheme is this body plus three things of its own: a scheme byte, a
//! post-quantum signer, and a post-quantum verifier. Everything a scheme
//! could get wrong by restating it lives here once — the framing byte in the
//! preimage, the order of the two halves, the bytes Ed25519 signs, and the
//! order verification checks them in — so two schemes cannot drift apart on
//! the construction they both claim to be.
//!
//! The scheme byte is bound **inside** the signed preimage as well as written
//! in the header (SA-R-5). A signature made under one scheme therefore does
//! not verify under another even if its bytes are re-headed: the two
//! preimages differ in their first input byte.
//!
//! See [`crate::signature`] for the construction's rationale (the 64-byte
//! width, fails-closed nesting) and for the version byte's role.

use crate::CryptoError;
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey,
    PUBLIC_KEY_LENGTH as ED25519_PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH as ED25519_SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH,
};

/// The scheme's domain-separated inner preimage:
/// `cSHAKE256-64(customization = domain, input = scheme_id ‖ message)`.
///
/// 64 bytes, not 32: this digest is the signed content, so its collision
/// resistance bounds both halves' unforgeability. Do not narrow it.
///
/// An empty `domain` is refused with `Err`: the cSHAKE helper would assert,
/// and a consensus API must fail closed rather than abort.
pub(crate) fn preimage(
    scheme_id: u8,
    domain: &[u8],
    message: &[u8],
) -> Result<[u8; 64], CryptoError> {
    if domain.is_empty() {
        return Err(CryptoError::InvalidInput(
            "scheme domain must be non-empty".into(),
        ));
    }
    let mut framed = Vec::with_capacity(1 + message.len());
    framed.push(scheme_id);
    framed.extend_from_slice(message);
    Ok(shekyl_crypto_hash::cshake256_64(domain, &framed))
}

/// The classical-outer message, `inner ‖ σ_pq`: the exact bytes Ed25519
/// signs. One definition, so sign and verify cannot disagree about it.
fn outer_message(inner: &[u8; 64], sigma_pq: &[u8]) -> Vec<u8> {
    let mut outer = Vec::with_capacity(inner.len() + sigma_pq.len());
    outer.extend_from_slice(inner);
    outer.extend_from_slice(sigma_pq);
    outer
}

/// The one nested-sign body. `sign_pq` signs the inner preimage with the
/// scheme's post-quantum half; the classical half then signs
/// `inner ‖ σ_pq`. Nesting order is load-bearing — do not flip it.
///
/// Returns `(σ_ed, σ_pq)`.
pub(crate) fn sign_nested<P: AsRef<[u8]>>(
    scheme_id: u8,
    ed25519_secret: &[u8; ED25519_SECRET_KEY_LENGTH],
    domain: &[u8],
    message: &[u8],
    sign_pq: impl FnOnce(&[u8; 64]) -> Result<P, CryptoError>,
) -> Result<([u8; ED25519_SIGNATURE_LENGTH], P), CryptoError> {
    let signing_key = SigningKey::from_bytes(ed25519_secret);
    let inner = preimage(scheme_id, domain, message)?;
    let sigma_pq = sign_pq(&inner)?;
    // A verifier that skips the PQ half cannot reconstruct this message.
    let sigma_ed = signing_key.sign(&outer_message(&inner, sigma_pq.as_ref()));
    Ok((sigma_ed.to_bytes(), sigma_pq))
}

/// What a nested signature consists of, as the verifier receives it: the
/// classical key and the two signature halves.
///
/// `sigma_pq` is the one post-quantum signature. Verification of that half
/// and the classical outer message both read this slice, so a scheme cannot
/// check one byte string and wrap another.
pub(crate) struct NestedSignature<'a> {
    pub(crate) ed25519_public: &'a [u8; ED25519_PUBLIC_KEY_LENGTH],
    pub(crate) ed25519_signature: &'a [u8],
    /// The post-quantum signature, `σ_pq`.
    pub(crate) sigma_pq: &'a [u8],
}

/// The one nested-verify body.
///
/// Checks run in a fixed order, the one the ML-DSA scheme has always had:
/// the Ed25519 key and signature are decoded, then `prepare_pq` decodes the
/// post-quantum key, then the preimage is built (an empty domain is refused
/// here), then the post-quantum half is verified over the preimage and
/// `signature.sigma_pq`, and only then the classical half over
/// `inner ‖ σ_pq`. The PQ half goes first because the classical outer is
/// meaningless around an invalid inner.
///
/// `verify_pq` receives that same `sigma_pq`, the slice the classical
/// half wraps.
///
/// `Result<()>`, never `Result<bool>`: there is no `Ok(false)` to mishandle.
pub(crate) fn verify_nested<K>(
    scheme_id: u8,
    signature: &NestedSignature<'_>,
    domain: &[u8],
    message: &[u8],
    prepare_pq: impl FnOnce() -> Result<K, CryptoError>,
    verify_pq: impl FnOnce(&K, &[u8; 64], &[u8]) -> bool,
) -> Result<(), CryptoError> {
    let verifying_key = VerifyingKey::from_bytes(signature.ed25519_public)
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let sigma_ed = Ed25519Signature::try_from(signature.ed25519_signature)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;
    let pq_key = prepare_pq()?;

    let inner = preimage(scheme_id, domain, message)?;
    if !verify_pq(&pq_key, &inner, signature.sigma_pq) {
        return Err(CryptoError::SignatureVerificationFailed);
    }
    verifying_key
        .verify(&outer_message(&inner, signature.sigma_pq), &sigma_ed)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

// ---------------------------------------------------------------------------
// The canonical encoding: a four-byte header, then two length-prefixed halves
// ---------------------------------------------------------------------------

/// Bytes of framing around the two halves: `version(1) ‖ scheme(1) ‖
/// reserved(2) ‖ len(4) ‖ … ‖ len(4) ‖ …`.
pub(crate) const CANONICAL_OVERHEAD: usize = 1 + 1 + 2 + 4 + 4;

/// Encode `version ‖ scheme ‖ 0u16 ‖ len(first) ‖ first ‖ len(second) ‖
/// second`. The caller has already established both lengths; they are the
/// scheme's fixed sizes and fit `u32`.
// CLIPPY: every caller passes a scheme's fixed key or signature length.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn encode_canonical(version: u8, scheme: u8, first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CANONICAL_OVERHEAD + first.len() + second.len());
    out.push(version);
    out.push(scheme);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(first.len() as u32).to_le_bytes());
    out.extend_from_slice(first);
    out.extend_from_slice(&(second.len() as u32).to_le_bytes());
    out.extend_from_slice(second);
    out
}

/// Decode the canonical form, accepting exactly one `(version, scheme)` and
/// exactly the two lengths given. Anything else — another version, another
/// scheme byte, a non-zero reserved field, either length off, a trailing
/// byte — is refused; `what` names the object in the error.
pub(crate) fn decode_canonical(
    bytes: &[u8],
    version: u8,
    scheme: u8,
    first_len: usize,
    second_len: usize,
    what: &'static str,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut cursor = 0usize;
    let got_version = read_u8(bytes, &mut cursor)?;
    let got_scheme = read_u8(bytes, &mut cursor)?;
    let reserved = read_u16(bytes, &mut cursor)?;
    let got_first_len = read_u32(bytes, &mut cursor)? as usize;
    let first = read_vec(bytes, &mut cursor, got_first_len)?;
    let got_second_len = read_u32(bytes, &mut cursor)? as usize;
    let second = read_vec(bytes, &mut cursor, got_second_len)?;

    if cursor != bytes.len()
        || got_version != version
        || got_scheme != scheme
        || reserved != 0
        || got_first_len != first_len
        || got_second_len != second_len
    {
        return Err(CryptoError::SerializationError(what.into()));
    }
    Ok((first, second))
}

fn truncated() -> CryptoError {
    CryptoError::SerializationError("truncated canonical encoding".into())
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, CryptoError> {
    let v = *bytes.get(*cursor).ok_or_else(truncated)?;
    *cursor += 1;
    Ok(v)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, CryptoError> {
    let end = cursor.checked_add(2).ok_or_else(truncated)?;
    let slice = bytes.get(*cursor..end).ok_or_else(truncated)?;
    *cursor = end;
    Ok(u16::from_le_bytes(slice.try_into().expect("two bytes")))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, CryptoError> {
    let end = cursor.checked_add(4).ok_or_else(truncated)?;
    let slice = bytes.get(*cursor..end).ok_or_else(truncated)?;
    *cursor = end;
    Ok(u32::from_le_bytes(slice.try_into().expect("four bytes")))
}

fn read_vec(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<Vec<u8>, CryptoError> {
    let end = cursor.checked_add(len).ok_or_else(truncated)?;
    let slice = bytes.get(*cursor..end).ok_or_else(truncated)?;
    *cursor = end;
    Ok(slice.to_vec())
}
