// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet message signing — the A2 surface, implemented exactly as ratified
//! in `docs/design/WALLET_MESSAGE_SIGNING.md` (round closed 2026-08-08).
//!
//! A transferable attestation binding a message to a Shekyl address:
//! a **nested hybrid** of SLH-DSA-SHA2-192s (inner) and Ed25519 (outer)
//! over a domain-separated preimage that binds the signer's classical
//! address segment, the network, and a mode byte (SM-R-3).
//!
//! # Nesting order is load-bearing (SM-R-3)
//!
//! `σ_pq = SLH.Sign(preimage)`, `σ_ed = Ed25519.Sign(preimage ‖ σ_pq)`.
//! Unforgeability is order-independent; separability is not: the inner
//! component remains a standalone-verifiable artifact, the outer does not.
//! With PQ inner, an Ed25519-only verifier **cannot verify at all** — the
//! degenerate implementation fails closed instead of silently verifying
//! classical-only. Do not flip this order; the ruling exists to foreclose
//! exactly that.
//!
//! # The signing identity (SM-R-4)
//!
//! Derived on demand from the wallet master seed — one HKDF-SHA512 expand
//! of **72 bytes** under [`MSG_SIGN_SEED_DOMAIN`], sliced in order into
//! `SK.seed ‖ SK.prf ‖ PK.seed` at `n = 24` bytes each (SLH-DSA-192s'
//! `n` is 24, not the 32 a category-3 reflex suggests), fed to the
//! `fips205` deterministic keygen. Mnemonic-recoverable by construction;
//! never persisted; the secret half zeroizes on drop.
//!
//! # Wire form (SM-R-5)
//!
//! `shekylmsgsig1.<base64url(canonical)>` where `canonical =`
//! `layout_version ‖ scheme ‖ mode ‖ σ_pq ‖ σ_ed ‖ checksum`. The prefix's
//! `1` is the **envelope/armoring** version (never fed into the preimage);
//! the leading canonical byte is the **payload layout version**, the same
//! value bound into the preimage as `sig_format_version`. base64url is
//! unpadded and canonical-strict; the decode ceiling applies to the
//! **encoded length, before decoding**. The 4-byte cSHAKE checksum is not
//! security — verification is the integrity check — it exists so decode
//! can honestly distinguish "corrupted paste" from "not from that address"
//! (rule 82).
//!
//! # Verification (SM-R-6)
//!
//! Session-less and pure: message, signature, and address material are all
//! public, caller-supplied inputs. Verification is constant-time with
//! respect to **nothing** — stated so nobody adds timing hardening where
//! it buys nothing. The FIPS 205/204 `ctx` parameter is pinned **empty**
//! on both halves (SM-R-3 R3-a); all domain separation lives in the
//! cSHAKE customization strings below.

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey,
    SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH,
};
use fips205::slh_dsa_sha2_192s;
use fips205::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::CryptoError;

/// Preimage domain (SM-R-3): the cSHAKE customization string over the
/// assembled binding input. Doubles as the hybrid binding label — it is
/// what separates this surface from every other signing transcript.
pub const MSG_SIGN_DOMAIN: &[u8] = b"shekyl/msg-sign-v1";

/// Message pre-hash domain (SM-R-3): the message is hashed under its own
/// customization string before entering the preimage.
pub const MSG_HASH_DOMAIN: &[u8] = b"shekyl/msg-hash-v1";

/// Signing-identity derivation domain (SM-R-4): the literal, not a
/// template — rule 30's inventory collision-checks literals. If the
/// algorithm ever changes it is a new domain string and a new address
/// version, since the address commits to the key.
pub const MSG_SIGN_SEED_DOMAIN: &[u8] = b"shekyl/msg-sign-seed-slh-dsa-192s-v1";

/// Armored-checksum domain (SM-R-5): the 4-byte trailer that lets decode
/// distinguish corruption from mismatch. Not security.
pub const MSG_SIG_CHECKSUM_DOMAIN: &[u8] = b"shekyl/msg-sig-ck-v1";

/// Payload layout version — the same single value appears as the leading
/// canonical byte and inside the preimage as `sig_format_version`
/// (SM-R-5 R5-c: one value, two appearances; the armored prefix's `1` is
/// the separate envelope version).
pub const MSG_SIG_LAYOUT_VERSION: u8 = 1;

/// Scheme byte: SLH-DSA-SHA2-192s + Ed25519, nested (SM-R-8). Append-only.
pub const MSG_SIG_SCHEME_SLH_192S_ED25519: u8 = 0x01;

/// Mode byte: spend-tier — the only mode. Future modes append, never
/// renumber (SM-R-3; the view-tier reservation was deliberately deleted).
pub const MSG_SIG_MODE_SPEND: u8 = 0x01;

/// Armored prefix. The trailing `1` is the envelope/armoring version.
pub const MSG_SIG_PREFIX: &str = "shekylmsgsig1.";

/// SLH-DSA-192s security parameter `n` (24 — deliberately spelled as a
/// literal per SM-R-4 R4-a, because the category-3 reflex is 32 and a
/// wrong split silently produces a valid-but-different keypair).
pub const SLH_192S_N: usize = 24;

/// The identity derivation's HKDF output: `SK.seed ‖ SK.prf ‖ PK.seed`.
pub const MSG_SIGN_IDENTITY_SEED_LEN: usize = 3 * SLH_192S_N;

/// SLH-DSA-SHA2-192s public key length (the 48 bytes the v2 address
/// carries inline, fork (ii)).
pub const SLH_192S_PK_LEN: usize = slh_dsa_sha2_192s::PK_LEN;

/// SLH-DSA-SHA2-192s signature length.
pub const SLH_192S_SIG_LEN: usize = slh_dsa_sha2_192s::SIG_LEN;

/// Canonical payload length: fixed by construction (SM-R-5 — every field
/// is fixed-width; reject-don't-truncate means exact-length or refuse).
pub const MSG_SIG_CANONICAL_LEN: usize =
    3 + SLH_192S_SIG_LEN + ED25519_SIGNATURE_LENGTH + MSG_SIG_CHECKSUM_LEN;

/// Checksum trailer length.
pub const MSG_SIG_CHECKSUM_LEN: usize = 4;

/// Hard ceiling on the **encoded** armored string length, enforced before
/// any decoding (SM-R-5 R5-b: bounding decoded output after decode would
/// allocate an attacker's bytes from a shorter input — the `shekyl-levin`
/// `decompress_payload` pre-allocation discipline). Covers either
/// parameter set (192s ≈ 21.7 KB, 192f ≈ 47.7 KB encoded) so a pre-freeze
/// s→f flip does not reopen it.
pub const MSG_SIG_MAX_ENCODED_LEN: usize = 64 * 1024;

const _: () = assert!(SLH_192S_PK_LEN == 2 * SLH_192S_N);
const _: () = assert!(slh_dsa_sha2_192s::N == SLH_192S_N);
// 3 + 16224 + 64 + 4 — the ~21.7 KB-encoded blob the round priced.
const _: () = assert!(MSG_SIG_CANONICAL_LEN == 16_295);

/// Message-signing errors, split on the SM-R-6 boundary: a *shape* error
/// is the caller's bug; a *verification failure* is an answer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageSigError {
    /// The armored string is not shaped like a signature at all —
    /// wrong prefix, over the ceiling, non-canonical base64url, wrong
    /// decoded length, unknown version/scheme/mode bytes.
    #[error("malformed signature string: {0}")]
    Malformed(&'static str),
    /// Shaped correctly but the checksum does not match: the paste was
    /// corrupted in transit. Distinct from `VerifyFailed` by ruling
    /// (rule 82) — this is "your copy is damaged", not "not the signer".
    #[error("signature string corrupted (checksum mismatch)")]
    Corrupted,
    /// Well-formed, intact, and **not** a valid signature by the claimed
    /// address over this message on this network.
    #[error("signature does not verify for this address and message")]
    VerifyFailed,
    /// Key material failed to parse (a caller bug on the sign side).
    #[error("invalid key material")]
    InvalidKey,
}

/// Derive the wallet-level SLH-DSA-192s signing identity from the master
/// seed (SM-R-4): one HKDF-SHA512 expand of 72 bytes under the literal
/// domain, sliced in order into `SK.seed ‖ SK.prf ‖ PK.seed` — a single
/// expand, ruled explicitly, because three separate expands with distinct
/// info strings produce different (equally valid-looking) keys and only
/// one layout can be the spec.
pub fn derive_message_signing_identity(
    master_seed: &[u8],
) -> Result<(slh_dsa_sha2_192s::PublicKey, slh_dsa_sha2_192s::PrivateKey), CryptoError> {
    let hk = Hkdf::<Sha512>::new(Some(MSG_SIGN_SEED_DOMAIN), master_seed);
    let mut okm = Zeroizing::new([0u8; MSG_SIGN_IDENTITY_SEED_LEN]);
    hk.expand(b"", okm.as_mut())
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF expand for SLH identity".into()))?;

    let mut sk_seed = Zeroizing::new([0u8; SLH_192S_N]);
    let mut sk_prf = Zeroizing::new([0u8; SLH_192S_N]);
    let mut pk_seed = [0u8; SLH_192S_N];
    sk_seed.copy_from_slice(&okm[..SLH_192S_N]);
    sk_prf.copy_from_slice(&okm[SLH_192S_N..2 * SLH_192S_N]);
    pk_seed.copy_from_slice(&okm[2 * SLH_192S_N..]);

    // fips205's deterministic keygen (FIPS 205 Algorithm 18 via
    // KeyGen::keygen_with_seeds). PrivateKey is ZeroizeOnDrop (verified
    // at the crate, SM-R-4 R4-b).
    Ok(slh_dsa_sha2_192s::KG::keygen_with_seeds(
        &sk_seed, &sk_prf, &pk_seed,
    ))
}

/// The 48-byte public half of the signing identity — what the v2 address
/// carries inline (fork (ii)).
pub fn derive_message_signing_public_key(
    master_seed: &[u8],
) -> Result<[u8; SLH_192S_PK_LEN], CryptoError> {
    let (pk, _sk) = derive_message_signing_identity(master_seed)?;
    Ok(pk.into_bytes())
}

/// Assemble the signing preimage (SM-R-3):
///
/// ```text
/// preimage = cSHAKE256("shekyl/msg-sign-v1",
///     sig_format_version ‖ network_id ‖ mode ‖
///     len(classical_segment) as u16 LE ‖ classical_segment ‖
///     cSHAKE256("shekyl/msg-hash-v1", message))
/// ```
///
/// The length prefix makes the framing unambiguous by construction
/// (R3-b): under fork (ii) the segment is variable-length across address
/// versions, and unambiguity must not rest on accidental properties.
pub fn message_preimage(network_id: u8, classical_segment: &[u8], message: &[u8]) -> [u8; 32] {
    let msg_hash = shekyl_crypto_hash::cshake256_32(MSG_HASH_DOMAIN, message);
    let mut buf = Vec::with_capacity(3 + 2 + classical_segment.len() + 32);
    buf.push(MSG_SIG_LAYOUT_VERSION);
    buf.push(network_id);
    buf.push(MSG_SIG_MODE_SPEND);
    // CLIPPY: segment lengths are address-segment-sized, far below u16::MAX.
    #[allow(clippy::cast_possible_truncation)]
    buf.extend_from_slice(&(classical_segment.len() as u16).to_le_bytes());
    buf.extend_from_slice(classical_segment);
    buf.extend_from_slice(&msg_hash);
    shekyl_crypto_hash::cshake256_32(MSG_SIGN_DOMAIN, &buf)
}

/// Sign a message (SM-R-3/R-6): nested hybrid, hedged, `ctx` empty.
///
/// The caller supplies the master seed (the SLH identity derives on
/// demand and its secret half drops-and-wipes before return), the
/// Ed25519 spend secret, and the wallet's own bound classical segment.
pub fn sign_message(
    master_seed: &[u8],
    spend_sk: &[u8; 32],
    network_id: u8,
    classical_segment: &[u8],
    message: &[u8],
) -> Result<String, MessageSigError> {
    let preimage = message_preimage(network_id, classical_segment, message);

    let (_pk, slh_sk) =
        derive_message_signing_identity(master_seed).map_err(|_| MessageSigError::InvalidKey)?;
    // Hedged (`true`): fips205 feeds opt_rand on top of SK.prf, so a bad
    // RNG degrades to the deterministic construction, not to catastrophe
    // (SM-R-6). ctx pinned empty (SM-R-3 R3-a).
    let sig_pq = slh_sk
        .try_sign(&preimage, b"", true)
        .map_err(|_| MessageSigError::InvalidKey)?;

    let ed_signing = SigningKey::from_bytes(spend_sk);
    let mut outer = Vec::with_capacity(32 + SLH_192S_SIG_LEN);
    outer.extend_from_slice(&preimage);
    outer.extend_from_slice(&sig_pq);
    let sig_ed: Ed25519Signature = ed_signing.sign(&outer);

    let mut canonical = Vec::with_capacity(MSG_SIG_CANONICAL_LEN);
    canonical.push(MSG_SIG_LAYOUT_VERSION);
    canonical.push(MSG_SIG_SCHEME_SLH_192S_ED25519);
    canonical.push(MSG_SIG_MODE_SPEND);
    canonical.extend_from_slice(&sig_pq);
    canonical.extend_from_slice(&sig_ed.to_bytes());
    let ck = shekyl_crypto_hash::cshake256_32(MSG_SIG_CHECKSUM_DOMAIN, &canonical);
    canonical.extend_from_slice(&ck[..MSG_SIG_CHECKSUM_LEN]);
    debug_assert_eq!(canonical.len(), MSG_SIG_CANONICAL_LEN);

    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&canonical);
    Ok(format!("{MSG_SIG_PREFIX}{encoded}"))
}

/// Decode and shape-check an armored signature string. Ceiling first
/// (on the encoded length), prefix, canonical-strict base64url, exact
/// canonical length, then the checksum — so the error taxonomy comes out
/// in SM-R-6's order: `Malformed` (shape) before `Corrupted` (damage).
fn decode_armored(armored: &str) -> Result<Vec<u8>, MessageSigError> {
    if armored.len() > MSG_SIG_MAX_ENCODED_LEN {
        return Err(MessageSigError::Malformed(
            "over the encoded-length ceiling",
        ));
    }
    let encoded = armored
        .strip_prefix(MSG_SIG_PREFIX)
        .ok_or(MessageSigError::Malformed("missing shekylmsgsig1. prefix"))?;
    if encoded.contains('=') {
        // Unpadded is pinned (SM-R-5): one signature, one spelling.
        return Err(MessageSigError::Malformed("padded base64url"));
    }
    use base64::Engine as _;
    // The general-purpose engine rejects non-alphabet characters and
    // non-zero trailing bits in the final symbol — canonical-form-strict.
    let canonical = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| MessageSigError::Malformed("non-canonical base64url"))?;
    if canonical.len() != MSG_SIG_CANONICAL_LEN {
        return Err(MessageSigError::Malformed("wrong canonical length"));
    }
    let (body, ck) = canonical.split_at(MSG_SIG_CANONICAL_LEN - MSG_SIG_CHECKSUM_LEN);
    let expect = shekyl_crypto_hash::cshake256_32(MSG_SIG_CHECKSUM_DOMAIN, body);
    if ck != &expect[..MSG_SIG_CHECKSUM_LEN] {
        return Err(MessageSigError::Corrupted);
    }
    Ok(canonical)
}

/// Verify a message signature (SM-R-6): session-less, pure, all inputs
/// public. `slh_pk` is the 48-byte key the address carries (fork (ii));
/// `spend_pk` is the address's Ed25519 spend key.
pub fn verify_message(
    spend_pk: &[u8; 32],
    slh_pk: &[u8; SLH_192S_PK_LEN],
    network_id: u8,
    classical_segment: &[u8],
    message: &[u8],
    armored: &str,
) -> Result<(), MessageSigError> {
    let canonical = decode_armored(armored)?;
    if canonical[0] != MSG_SIG_LAYOUT_VERSION {
        return Err(MessageSigError::Malformed("unknown layout version"));
    }
    if canonical[1] != MSG_SIG_SCHEME_SLH_192S_ED25519 {
        return Err(MessageSigError::Malformed("unknown scheme"));
    }
    if canonical[2] != MSG_SIG_MODE_SPEND {
        return Err(MessageSigError::Malformed("unknown mode"));
    }
    let sig_pq: &[u8] = &canonical[3..3 + SLH_192S_SIG_LEN];
    let sig_ed: &[u8] =
        &canonical[3 + SLH_192S_SIG_LEN..3 + SLH_192S_SIG_LEN + ED25519_SIGNATURE_LENGTH];

    let preimage = message_preimage(network_id, classical_segment, message);

    // Inner half: SLH-DSA over the preimage, ctx empty. The AND is
    // structural — a verifier without this dependency cannot get here.
    let slh_public = slh_dsa_sha2_192s::PublicKey::try_from_bytes(slh_pk)
        .map_err(|_| MessageSigError::InvalidKey)?;
    let sig_pq_arr: &[u8; SLH_192S_SIG_LEN] =
        sig_pq.try_into().expect("length fixed by canonical split");
    if !slh_public.verify(&preimage, sig_pq_arr, b"") {
        return Err(MessageSigError::VerifyFailed);
    }

    // Outer half: Ed25519 over preimage ‖ σ_pq — stripping the PQ half
    // structurally invalidates this one.
    let ed_public = VerifyingKey::from_bytes(spend_pk).map_err(|_| MessageSigError::InvalidKey)?;
    let sig_ed_arr: [u8; ED25519_SIGNATURE_LENGTH] =
        sig_ed.try_into().expect("length fixed by canonical split");
    let mut outer = Vec::with_capacity(32 + SLH_192S_SIG_LEN);
    outer.extend_from_slice(&preimage);
    outer.extend_from_slice(sig_pq);
    if ed_public
        .verify(&outer, &Ed25519Signature::from_bytes(&sig_ed_arr))
        .is_err()
    {
        return Err(MessageSigError::VerifyFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const SEED: [u8; 64] = [0x42u8; 64];
    const SPEND_SK: [u8; 32] = [0x24u8; 32];
    const NETWORK: u8 = 1; // testnet discriminant
    const SEGMENT: &[u8] = &[0x01; 81]; // v1-shaped bound segment stand-in

    fn spend_pk() -> [u8; 32] {
        SigningKey::from_bytes(&SPEND_SK).verifying_key().to_bytes()
    }

    fn slh_pk() -> [u8; SLH_192S_PK_LEN] {
        derive_message_signing_public_key(&SEED).expect("derive")
    }

    /// SM-R-4 R4-a KAT: fixed master seed → fixed public key. Pins the
    /// 72-byte single-expand slice order — a wrong split (or an n=32
    /// reflex) produces a valid-but-DIFFERENT keypair, which only this
    /// pin catches.
    #[test]
    fn identity_derivation_is_pinned() {
        let pk = slh_pk();
        let hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "223362985b174e2dad8d9e8794e90e4529a8d623bd8cbe1f5b1e32211781d008\
             6332670f317931255b51bd61a25b88a5",
            "SLH identity derivation moved — seed split or domain changed"
        );
    }

    /// End-to-end round trip.
    #[test]
    fn sign_verify_round_trips() {
        let armored =
            sign_message(&SEED, &SPEND_SK, NETWORK, SEGMENT, b"hello shekyl").expect("sign");
        assert!(armored.starts_with(MSG_SIG_PREFIX));
        assert!(!armored.contains('='), "unpadded is pinned");
        verify_message(
            &spend_pk(),
            &slh_pk(),
            NETWORK,
            SEGMENT,
            b"hello shekyl",
            &armored,
        )
        .expect("verify");
    }

    /// Every binding input flips the verdict: message, network, segment,
    /// keys. (The §4 tamper battery, binding half.)
    #[test]
    fn verification_binds_every_input() {
        let armored = sign_message(&SEED, &SPEND_SK, NETWORK, SEGMENT, b"msg").expect("sign");
        let ok = |m: &[u8], n: u8, seg: &[u8]| {
            verify_message(&spend_pk(), &slh_pk(), n, seg, m, &armored)
        };
        assert_eq!(ok(b"msg", NETWORK, SEGMENT), Ok(()));
        assert_eq!(
            ok(b"msh", NETWORK, SEGMENT),
            Err(MessageSigError::VerifyFailed)
        );
        assert_eq!(ok(b"msg", 0, SEGMENT), Err(MessageSigError::VerifyFailed));
        assert_eq!(
            ok(b"msg", NETWORK, &[0x02; 81]),
            Err(MessageSigError::VerifyFailed)
        );
        let other_spend = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            verify_message(&other_spend, &slh_pk(), NETWORK, SEGMENT, b"msg", &armored),
            Err(MessageSigError::VerifyFailed)
        );
        let other_slh = derive_message_signing_public_key(&[7u8; 64]).unwrap();
        assert_eq!(
            verify_message(&spend_pk(), &other_slh, NETWORK, SEGMENT, b"msg", &armored),
            Err(MessageSigError::VerifyFailed)
        );
    }

    /// The armored-format tamper battery: every canonical field flipped
    /// independently must refuse, with the SM-R-6 error taxonomy —
    /// in-body flips are `Corrupted` (the checksum sees them), version/
    /// scheme/mode bytes only reach `Malformed` when re-checksummed.
    #[test]
    fn armored_tamper_battery() {
        use base64::Engine as _;
        let armored = sign_message(&SEED, &SPEND_SK, NETWORK, SEGMENT, b"m").expect("sign");
        let verify = |s: &str| verify_message(&spend_pk(), &slh_pk(), NETWORK, SEGMENT, b"m", s);

        // Prefix and padding shapes.
        assert!(matches!(
            verify(&armored.replace("shekylmsgsig1.", "shekylmsgsig2.")),
            Err(MessageSigError::Malformed(_))
        ));
        assert!(matches!(
            verify(&format!("{armored}=")),
            Err(MessageSigError::Malformed(_))
        ));
        // Over-ceiling input refused before decode.
        let huge = format!("{}{}", MSG_SIG_PREFIX, "A".repeat(MSG_SIG_MAX_ENCODED_LEN));
        assert!(matches!(verify(&huge), Err(MessageSigError::Malformed(_))));
        // Truncation → wrong canonical length.
        let truncated = &armored[..armored.len() - 8];
        assert!(matches!(
            verify(truncated),
            Err(MessageSigError::Malformed(_))
        ));

        // A flipped body byte is CORRUPTION (checksum catches it first).
        let engine = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut canonical = engine
            .decode(armored.strip_prefix(MSG_SIG_PREFIX).unwrap())
            .unwrap();
        canonical[100] ^= 0x01;
        let corrupted = format!("{}{}", MSG_SIG_PREFIX, engine.encode(&canonical));
        assert_eq!(verify(&corrupted), Err(MessageSigError::Corrupted));

        // Version/scheme/mode flips with a RECOMPUTED checksum are shape
        // errors — the string is intact, just not ours.
        for idx in 0..3usize {
            let mut c = engine
                .decode(armored.strip_prefix(MSG_SIG_PREFIX).unwrap())
                .unwrap();
            c[idx] ^= 0x01;
            let body_len = MSG_SIG_CANONICAL_LEN - MSG_SIG_CHECKSUM_LEN;
            let ck = shekyl_crypto_hash::cshake256_32(MSG_SIG_CHECKSUM_DOMAIN, &c[..body_len]);
            c[body_len..].copy_from_slice(&ck[..MSG_SIG_CHECKSUM_LEN]);
            let s = format!("{}{}", MSG_SIG_PREFIX, engine.encode(&c));
            assert!(
                matches!(verify(&s), Err(MessageSigError::Malformed(_))),
                "byte {idx} flip must be a shape refusal"
            );
        }
    }

    /// Cross-half battery (§4): the hybrid is AND, never OR — a signature
    /// whose PQ half was re-signed by a different identity fails even
    /// though its Ed25519 half is honest, and vice versa is unreachable
    /// by construction (σ_ed covers σ_pq).
    #[test]
    fn cross_half_and_never_or() {
        use base64::Engine as _;
        let engine = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let armored = sign_message(&SEED, &SPEND_SK, NETWORK, SEGMENT, b"m").expect("sign");
        let mut canonical = engine
            .decode(armored.strip_prefix(MSG_SIG_PREFIX).unwrap())
            .unwrap();

        // Replace σ_pq with a valid signature from a DIFFERENT SLH
        // identity over the same preimage; keep the honest σ_ed.
        let preimage = message_preimage(NETWORK, SEGMENT, b"m");
        let (_pk2, sk2) = derive_message_signing_identity(&[9u8; 64]).unwrap();
        let sig_pq2 = sk2.try_sign(&preimage, b"", true).unwrap();
        canonical[3..3 + SLH_192S_SIG_LEN].copy_from_slice(&sig_pq2);
        let body_len = MSG_SIG_CANONICAL_LEN - MSG_SIG_CHECKSUM_LEN;
        let ck = shekyl_crypto_hash::cshake256_32(MSG_SIG_CHECKSUM_DOMAIN, &canonical[..body_len]);
        canonical[body_len..].copy_from_slice(&ck[..MSG_SIG_CHECKSUM_LEN]);
        let spliced = format!("{}{}", MSG_SIG_PREFIX, engine.encode(&canonical));

        // The inner half fails against the claimed slh_pk; and even
        // against sk2's own pk, the OUTER half now fails because σ_ed
        // covers the original σ_pq — the nesting doing its job.
        assert_eq!(
            verify_message(&spend_pk(), &slh_pk(), NETWORK, SEGMENT, b"m", &spliced),
            Err(MessageSigError::VerifyFailed)
        );
        let pk2 = derive_message_signing_public_key(&[9u8; 64]).unwrap();
        assert_eq!(
            verify_message(&spend_pk(), &pk2, NETWORK, SEGMENT, b"m", &spliced),
            Err(MessageSigError::VerifyFailed)
        );
    }

    /// SM-R-3 R3-a: the `ctx` pin. A signature produced with a non-empty
    /// FIPS 205 context must NOT verify — proving our verify path passes
    /// `ctx = ""` and that the pin is load-bearing, not decorative.
    #[test]
    fn nonempty_ctx_signature_is_rejected() {
        use base64::Engine as _;
        let engine = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let preimage = message_preimage(NETWORK, SEGMENT, b"m");
        let (_pk, sk) = derive_message_signing_identity(&SEED).unwrap();
        let sig_pq_bad_ctx = sk
            .try_sign(&preimage, MSG_SIGN_DOMAIN, true)
            .expect("sign with wrong ctx");

        let ed = SigningKey::from_bytes(&SPEND_SK);
        let mut outer = Vec::new();
        outer.extend_from_slice(&preimage);
        outer.extend_from_slice(&sig_pq_bad_ctx);
        let sig_ed = ed.sign(&outer);

        let mut canonical = Vec::with_capacity(MSG_SIG_CANONICAL_LEN);
        canonical.push(MSG_SIG_LAYOUT_VERSION);
        canonical.push(MSG_SIG_SCHEME_SLH_192S_ED25519);
        canonical.push(MSG_SIG_MODE_SPEND);
        canonical.extend_from_slice(&sig_pq_bad_ctx);
        canonical.extend_from_slice(&sig_ed.to_bytes());
        let ck = shekyl_crypto_hash::cshake256_32(MSG_SIG_CHECKSUM_DOMAIN, &canonical);
        canonical.extend_from_slice(&ck[..MSG_SIG_CHECKSUM_LEN]);
        let s = format!("{}{}", MSG_SIG_PREFIX, engine.encode(&canonical));

        assert_eq!(
            verify_message(&spend_pk(), &slh_pk(), NETWORK, SEGMENT, b"m", &s),
            Err(MessageSigError::VerifyFailed),
            "a non-empty ctx must not verify — the empty-ctx pin is load-bearing"
        );
    }

    /// Domain strings are distinct (the collision check the inventory
    /// relies on) and the preimage is length-prefix framed.
    #[test]
    fn domains_distinct_and_framing_unambiguous() {
        let domains: [&[u8]; 4] = [
            MSG_SIGN_DOMAIN,
            MSG_HASH_DOMAIN,
            MSG_SIGN_SEED_DOMAIN,
            MSG_SIG_CHECKSUM_DOMAIN,
        ];
        for (i, a) in domains.iter().enumerate() {
            for b in domains.iter().skip(i + 1) {
                assert_ne!(a, b, "domain collision");
            }
        }
        // Length-prefix framing: shifting a byte across the
        // segment/message-hash boundary changes the preimage.
        let p1 = message_preimage(0, &[0xAA, 0xBB], b"x");
        let p2 = message_preimage(0, &[0xAA], b"x");
        assert_ne!(p1, p2);
    }
}
