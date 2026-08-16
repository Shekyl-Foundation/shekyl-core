// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet message signing — the A2 surface, implemented exactly as ratified
//! in `docs/design/WALLET_MESSAGE_SIGNING.md` (round closed 2026-08-08).
//!
//! A transferable attestation binding a message to a Shekyl address:
//! a **nested hybrid** of SLH-DSA-SHA2-192s (inner) and the house
//! spend-scalar Schnorr (outer) over a domain-separated preimage that
//! binds the signer's classical address segment, the network, and a mode
//! byte (SM-R-3).
//!
//! # Nesting order is load-bearing (SM-R-3)
//!
//! `σ_pq = SLH.Sign(preimage)`, `σ_cl = SpendSchnorr.Sign(preimage ‖ σ_pq)`.
//! Unforgeability is order-independent; separability is not: the inner
//! component remains a standalone-verifiable artifact, the outer does not.
//! With PQ inner, a classical-only verifier **cannot verify at all** — the
//! degenerate implementation fails closed instead of silently verifying
//! classical-only. Do not flip this order; the ruling exists to foreclose
//! exactly that.
//!
//! # The classical half is the house Schnorr, not RFC 8032 (SM-R-3
//! implementation note)
//!
//! The wallet's spend secret is a **raw Ed25519 scalar**
//! (`spend_pk = b·G`, `rederive_account`), and RFC 8032 signing is
//! structurally impossible for a raw-scalar key (`ed25519_dalek` derives
//! its scalar by hashing a seed). This surface therefore signs with
//! [`crate::schnorr`] — the single owner of that construction — under
//! its own challenge domain [`MSG_SIGN_OUTER_DOMAIN`], in the same
//! 64-byte `R ‖ s` wire slot the ruling priced. The nonce is hedged and
//! RNG failure is fail-safe rather than fail-stop; both properties, and
//! why they are not this module's to re-implement, live in that module's
//! docs.
//!
//! # The signing identity (SM-R-4, as amended 2026-08-08)
//!
//! Derived on demand from the wallet master seed — one HKDF-SHA512 expand
//! of **72 bytes**, sliced in order into `SK.seed ‖ SK.prf ‖ PK.seed` at
//! `n = 24` bytes each (SLH-DSA-192s' `n` is 24, not the 32 a category-3
//! reflex suggests), fed to the `fips205` deterministic keygen.
//! Mnemonic-recoverable by construction; never persisted; the secret half
//! zeroizes on drop.
//!
//! The expand is **scoped by `(network, seed_format)`** exactly as every
//! other wallet key is (`account::salt_for`), with
//! [`MSG_SIGN_SEED_DOMAIN`] as the HKDF `info` label. This is the SM-R-4
//! amendment: the ruling as first drafted put the literal domain in the
//! salt and took no network, which would have published **one 48-byte
//! public key across mainnet, testnet and stagenet** for a single seed.
//! Binding `network_id` into the preimage stops cross-network *signature
//! replay*; it does nothing about cross-network *key linkage*, because
//! the public key is published with the attestation and (under fork (ii))
//! inlined into the address. Two different properties, two different
//! mechanisms, both required.
//!
//! # Wire form (SM-R-5)
//!
//! `shekylmsgsig1.<base64url(canonical)>` where `canonical =`
//! `layout_version ‖ scheme ‖ mode ‖ σ_pq ‖ σ_cl ‖ checksum`. The prefix's
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
//! Verification is session-less and pure: message, signature, and address
//! material are all public, caller-supplied inputs. It is constant-time
//! with respect to **nothing** — stated so nobody adds timing hardening
//! where it buys nothing. The FIPS 205 `ctx` parameter is pinned **empty**
//! on both halves (SM-R-3 R3-a); all domain separation lives in the
//! cSHAKE customization strings below.
//!
//! [`verify_message`] takes a [`BoundClassicalSegment`]. The keys and
//! the bound bytes are the same object — there is no constructor that
//! accepts a spend key from one address and an SLH key from another.
//! Accepting the keys as free parameters would mean an adversary who
//! recovered the spend scalar could supply their own SLH keypair and
//! produce an attestation that verifies against a victim's address —
//! the PQ half reduced to decoration, which is precisely the
//! "degenerate verifier" outcome the nesting order was chosen to
//! foreclose. The R6-a type gate lifted by becoming this: every
//! decodable address carries the fourth field, so extraction cannot
//! fail and cannot be unbound.

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use fips205::slh_dsa_sha2_192s;
use fips205::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use shekyl_address::BoundClassicalSegment;

use crate::account::{salt_for, DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use crate::schnorr;
use crate::CryptoError;

/// Preimage domain (SM-R-3): the cSHAKE customization string over the
/// assembled binding input. Doubles as the hybrid binding label — it is
/// what separates this surface from every other signing transcript.
pub const MSG_SIGN_DOMAIN: &[u8] = b"shekyl/msg-sign-v1";

/// Message pre-hash domain (SM-R-3): the message is hashed under its own
/// customization string before entering the preimage.
pub const MSG_HASH_DOMAIN: &[u8] = b"shekyl/msg-hash-v1";

/// Signing-identity derivation label (SM-R-4): the literal, not a
/// template — rule 30's inventory collision-checks literals. If the
/// algorithm ever changes it is a new label and a new address version,
/// since the address commits to the key.
///
/// Used as the HKDF `info`; the salt is `account::salt_for(network,
/// seed_format)`, the same `(network, format)` scoping every other wallet
/// key uses (SM-R-4 as amended — see the module docs).
pub const MSG_SIGN_SEED_DOMAIN: &[u8] = b"shekyl/msg-sign-seed-slh-dsa-192s-v1";

/// Armored-checksum domain (SM-R-5): the 4-byte trailer that lets decode
/// distinguish corruption from mismatch. Not security.
pub const MSG_SIG_CHECKSUM_DOMAIN: &[u8] = b"shekyl/msg-sig-ck-v1";

/// Schnorr challenge domain for the classical half (registered beside
/// the other domains; distinct from every proof domain).
pub const MSG_SIGN_OUTER_DOMAIN: &[u8] = b"shekyl/msg-sign-outer-v1";

/// Payload layout version — the same single value appears as the leading
/// canonical byte and inside the preimage as `sig_format_version`
/// (SM-R-5 R5-c: one value, two appearances; the armored prefix's `1` is
/// the separate envelope version).
pub const MSG_SIG_LAYOUT_VERSION: u8 = 1;

/// Scheme byte: SLH-DSA-SHA2-192s inner + spend-scalar Schnorr outer,
/// nested (SM-R-8). Append-only — the **value** is the genesis-frozen
/// fact; this name exists so no independent implementer reads "Ed25519"
/// and reaches for RFC 8032, which rejects every signature we produce.
pub const MSG_SIG_SCHEME_SLH_192S_SPEND_SCHNORR: u8 = 0x01;

/// Mode byte: spend-tier — the only mode. Future modes append, never
/// renumber (SM-R-3; the view-tier reservation was deliberately deleted).
pub const MSG_SIG_MODE_SPEND: u8 = 0x01;

/// Armored prefix. The trailing `1` is the envelope/armoring version.
pub const MSG_SIG_PREFIX: &str = "shekylmsgsig1.";

/// Canonical header: `layout_version ‖ scheme ‖ mode`. Read and
/// dispatched on **before** any scheme-specific length is enforced, so a
/// future scheme is refused as an unsupported scheme rather than
/// mis-reported as a corrupt shape.
pub const MSG_SIG_HEADER_LEN: usize = 3;

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

/// Classical (spend-Schnorr) signature length: `R ‖ s`.
pub const CLASSICAL_SIG_LEN: usize = schnorr::SIG_LEN;

/// Length of the signing preimage (cSHAKE256-32 output).
pub const MSG_PREIMAGE_LEN: usize = 32;

/// Outer message the classical half signs: `preimage ‖ σ_pq`.
pub const OUTER_MSG_LEN: usize = MSG_PREIMAGE_LEN + SLH_192S_SIG_LEN;

/// Checksum trailer length.
pub const MSG_SIG_CHECKSUM_LEN: usize = 4;

/// Canonical payload length for [`MSG_SIG_SCHEME_SLH_192S_SPEND_SCHNORR`]:
/// fixed by construction (SM-R-5 — every field is fixed-width;
/// reject-don't-truncate means exact-length or refuse).
pub const MSG_SIG_CANONICAL_LEN: usize =
    MSG_SIG_HEADER_LEN + SLH_192S_SIG_LEN + CLASSICAL_SIG_LEN + MSG_SIG_CHECKSUM_LEN;

/// Hard ceiling on the **encoded** armored payload, enforced before any
/// decoding (SM-R-5 R5-b: bounding decoded output after decode would
/// allocate an attacker's bytes from a shorter input — the `shekyl-levin`
/// `decompress_payload` pre-allocation discipline). Covers either
/// parameter set (192s ≈ 21.7 KB, 192f ≈ 47.7 KB encoded) so a pre-freeze
/// s→f flip does not reopen it.
pub const MSG_SIG_MAX_ENCODED_LEN: usize = 64 * 1024;

const _: () = assert!(SLH_192S_PK_LEN == 2 * SLH_192S_N);
const _: () = assert!(slh_dsa_sha2_192s::N == SLH_192S_N);
// 3 + 16224 + 64 + 4 — the ~21.7 KB-encoded blob the round priced.
const _: () = assert!(MSG_SIG_CANONICAL_LEN == 16_295);
const _: () = assert!(OUTER_MSG_LEN == MSG_PREIMAGE_LEN + SLH_192S_SIG_LEN);
const _: () = assert!(MSG_PREIMAGE_LEN == 32);

/// Message-signing errors, split on the SM-R-6 boundary: a *shape* error
/// is the caller's bug; a *verification failure* is an answer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageSigError {
    /// The armored string is not shaped like a signature at all —
    /// wrong prefix, over the ceiling, non-canonical base64url, wrong
    /// decoded length, unknown version/mode bytes.
    #[error("malformed signature string: {0}")]
    Malformed(&'static str),
    /// Well-formed, but produced by a signature scheme this build does
    /// not implement. Distinct from [`Self::Malformed`] on purpose: the
    /// scheme byte is SM-R-5's append-only forward-compatibility field,
    /// and "I don't speak this version" is a different sentence from
    /// "this isn't a signature" (rule 82).
    #[error("unsupported signature scheme {0:#04x} — this wallet is too old to check it")]
    UnsupportedScheme(u8),
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
    /// The operating system's random number generator failed. Not a key
    /// problem and not a corruption problem — kept separate from
    /// [`Self::InvalidKey`] because telling a user their key material is
    /// invalid when the entropy source hiccuped invites them to restore
    /// from mnemonic over an undamaged wallet (rule 82).
    #[error("the system random number generator failed — try again")]
    Rng,
}

/// Derive the wallet-level SLH-DSA-192s signing identity (SM-R-4 as
/// amended): one HKDF-SHA512 expand of 72 bytes salted by
/// `(network, seed_format)` with [`MSG_SIGN_SEED_DOMAIN`] as `info`,
/// sliced in order into `SK.seed ‖ SK.prf ‖ PK.seed`.
///
/// A single expand is ruled explicitly: three separate expands with
/// distinct info strings produce different (equally valid-looking) keys
/// and only one layout can be the spec.
///
/// # Errors
///
/// [`CryptoError::KeyGenerationFailed`] if the HKDF expand rejects the
/// output length — unreachable at 72 bytes, surfaced rather than
/// unwrapped.
pub fn derive_message_signing_identity(
    master_seed: &[u8; MASTER_SEED_BYTES],
    network: DerivationNetwork,
    seed_format: SeedFormat,
) -> Result<(slh_dsa_sha2_192s::PublicKey, slh_dsa_sha2_192s::PrivateKey), CryptoError> {
    let hk = Hkdf::<Sha512>::new(Some(&salt_for(network, seed_format)), master_seed);
    let mut okm = Zeroizing::new([0u8; MSG_SIGN_IDENTITY_SEED_LEN]);
    hk.expand(MSG_SIGN_SEED_DOMAIN, okm.as_mut())
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF expand for SLH identity".into()))?;
    Ok(slh_identity_from_okm(&okm))
}

/// Split a 72-byte identity-seed expansion into the R4-a layout and run
/// the deterministic keygen: `SK.seed ‖ SK.prf ‖ PK.seed` at `n = 24`
/// each. The **one** place the slice order exists (SM-R-4 R4-a — a wrong
/// split silently produces a valid-but-different keypair): the principal
/// identity above and the per-slot archival-P identity
/// (`archival_p::derive_p_msg_sign_pk`) both feed it, under their own
/// HKDF labels.
pub(crate) fn slh_identity_from_okm(
    okm: &Zeroizing<[u8; MSG_SIGN_IDENTITY_SEED_LEN]>,
) -> (slh_dsa_sha2_192s::PublicKey, slh_dsa_sha2_192s::PrivateKey) {
    let mut sk_seed = Zeroizing::new([0u8; SLH_192S_N]);
    let mut sk_prf = Zeroizing::new([0u8; SLH_192S_N]);
    let mut pk_seed = [0u8; SLH_192S_N];
    sk_seed.copy_from_slice(&okm[..SLH_192S_N]);
    sk_prf.copy_from_slice(&okm[SLH_192S_N..2 * SLH_192S_N]);
    pk_seed.copy_from_slice(&okm[2 * SLH_192S_N..]);

    // fips205's deterministic keygen (FIPS 205 Algorithm 18 via
    // KeyGen::keygen_with_seeds). PrivateKey is ZeroizeOnDrop (verified
    // at the crate, SM-R-4 R4-b).
    slh_dsa_sha2_192s::KG::keygen_with_seeds(&sk_seed, &sk_prf, &pk_seed)
}

/// The 48-byte public half of the signing identity — what the v2 address
/// will carry inline (fork (ii)).
///
/// # Errors
///
/// Propagates [`derive_message_signing_identity`].
pub fn derive_message_signing_public_key(
    master_seed: &[u8; MASTER_SEED_BYTES],
    network: DerivationNetwork,
    seed_format: SeedFormat,
) -> Result<[u8; SLH_192S_PK_LEN], CryptoError> {
    let (pk, _sk) = derive_message_signing_identity(master_seed, network, seed_format)?;
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
/// `network_id` is [`DerivationNetwork::as_u8`] rather than the address
/// network's byte: `Fakechain` shares Mainnet's *address* encoding but
/// must never share a signing transcript with it, the same reason it
/// gets its own derivation salt.
///
/// The length prefix makes the framing unambiguous by construction
/// (R3-b): under fork (ii) the segment is variable-length across address
/// versions, and unambiguity must not rest on accidental properties.
#[must_use]
pub fn message_preimage(
    network: DerivationNetwork,
    classical_segment: &[u8],
    message: &[u8],
) -> [u8; MSG_PREIMAGE_LEN] {
    let msg_hash = shekyl_crypto_hash::cshake256_32(MSG_HASH_DOMAIN, message);
    let mut buf = Vec::with_capacity(MSG_SIG_HEADER_LEN + 2 + classical_segment.len() + 32);
    buf.push(MSG_SIG_LAYOUT_VERSION);
    buf.push(network.as_u8());
    buf.push(MSG_SIG_MODE_SPEND);
    // CLIPPY: segment lengths are address-segment-sized, far below u16::MAX.
    #[allow(clippy::cast_possible_truncation)]
    buf.extend_from_slice(&(classical_segment.len() as u16).to_le_bytes());
    buf.extend_from_slice(classical_segment);
    buf.extend_from_slice(&msg_hash);
    shekyl_crypto_hash::cshake256_32(MSG_SIGN_DOMAIN, &buf)
}

/// Sign the outer bytes with the spend **scalar** — see the module-docs
/// implementation note (raw-scalar key ⇒ house Schnorr, not RFC 8032).
///
/// # Errors
///
/// [`MessageSigError::InvalidKey`] if `spend_sk` is not a canonical
/// scalar.
pub fn sign_outer_with_spend_scalar(
    spend_sk: &[u8; 32],
    outer_msg: &[u8],
) -> Result<[u8; CLASSICAL_SIG_LEN], MessageSigError> {
    let secret: Scalar =
        Option::from(Scalar::from_canonical_bytes(*spend_sk)).ok_or(MessageSigError::InvalidKey)?;
    let public = ED25519_BASEPOINT_TABLE * &secret;
    Ok(schnorr::sign(
        MSG_SIGN_OUTER_DOMAIN,
        &secret,
        &public,
        outer_msg,
    ))
}

/// The outer message the classical half signs: `preimage ‖ σ_pq` — the
/// covering that makes stripping the PQ half structurally invalidating.
/// Length is compile-time fixed ([`OUTER_MSG_LEN`]); heap-allocated so the
/// ~16 KB blob does not ride the stack through async boundaries.
#[must_use]
pub fn outer_bytes(
    preimage: &[u8; MSG_PREIMAGE_LEN],
    sig_pq: &[u8; SLH_192S_SIG_LEN],
) -> Box<[u8; OUTER_MSG_LEN]> {
    let mut outer = Box::new([0u8; OUTER_MSG_LEN]);
    outer[..MSG_PREIMAGE_LEN].copy_from_slice(preimage);
    outer[MSG_PREIMAGE_LEN..].copy_from_slice(sig_pq);
    outer
}

/// The PQ half of a signature: preimage + hedged SLH-DSA signature with
/// `ctx = ""`. Split out so the engine can derive this half with the
/// transiently-borrowed master seed while the spend scalar stays inside
/// the key actor (both secret-locality postures preserved).
///
/// **CPU-bound and slow by design** — a full SLH-DSA-192s keygen plus
/// sign, priced at ~4.3 s on the Pi-4 provisioning floor (rule 76).
/// Async callers must not run this on an executor thread.
///
/// # Errors
///
/// * [`MessageSigError::InvalidKey`] — the identity derivation failed.
/// * [`MessageSigError::Rng`] — the OS RNG failed during hedged signing,
///   which `fips205` reports as its only signing failure mode.
pub fn sign_message_pq_half(
    master_seed: &[u8; MASTER_SEED_BYTES],
    network: DerivationNetwork,
    seed_format: SeedFormat,
    segment: &BoundClassicalSegment,
    message: &[u8],
) -> Result<([u8; MSG_PREIMAGE_LEN], Box<[u8; SLH_192S_SIG_LEN]>), MessageSigError> {
    let preimage = message_preimage(network, segment.as_bytes(), message);
    let (_pk, slh_sk) = derive_message_signing_identity(master_seed, network, seed_format)
        .map_err(|_| MessageSigError::InvalidKey)?;
    // Hedged (`true`): fips205 feeds opt_rand on top of SK.prf, so a bad
    // RNG degrades to the deterministic construction, not to catastrophe
    // (SM-R-6). ctx pinned empty (SM-R-3 R3-a). The one documented
    // failure mode of `try_sign` at this ctx length is an RNG failure.
    let sig_pq = slh_sk
        .try_sign(&preimage, b"", true)
        .map_err(|_| MessageSigError::Rng)?;
    Ok((preimage, Box::new(sig_pq)))
}

/// Assemble the armored string from the two halves (SM-R-5 layout).
/// Both halves are fixed-width by type — wrong lengths cannot compile.
#[must_use]
pub fn assemble_armored(
    sig_pq: &[u8; SLH_192S_SIG_LEN],
    sig_cl: &[u8; CLASSICAL_SIG_LEN],
) -> String {
    let mut canonical = Vec::with_capacity(MSG_SIG_CANONICAL_LEN);
    canonical.push(MSG_SIG_LAYOUT_VERSION);
    canonical.push(MSG_SIG_SCHEME_SLH_192S_SPEND_SCHNORR);
    canonical.push(MSG_SIG_MODE_SPEND);
    canonical.extend_from_slice(sig_pq);
    canonical.extend_from_slice(sig_cl);
    let ck = shekyl_crypto_hash::cshake256_32(MSG_SIG_CHECKSUM_DOMAIN, &canonical);
    canonical.extend_from_slice(&ck[..MSG_SIG_CHECKSUM_LEN]);
    debug_assert_eq!(canonical.len(), MSG_SIG_CANONICAL_LEN);

    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&canonical);
    format!("{MSG_SIG_PREFIX}{encoded}")
}

/// Sign a message (SM-R-3/R-6): nested hybrid, hedged, `ctx` empty.
///
/// One-call form for callers holding both secrets; the engine uses the
/// split halves above so each secret stays where it lives. Inherits
/// [`sign_message_pq_half`]'s multi-second cost.
///
/// # Errors
///
/// Propagates [`sign_message_pq_half`] and
/// [`sign_outer_with_spend_scalar`].
pub fn sign_message(
    master_seed: &[u8; MASTER_SEED_BYTES],
    spend_sk: &[u8; 32],
    network: DerivationNetwork,
    seed_format: SeedFormat,
    segment: &BoundClassicalSegment,
    message: &[u8],
) -> Result<String, MessageSigError> {
    let (preimage, sig_pq) =
        sign_message_pq_half(master_seed, network, seed_format, segment, message)?;
    let outer = outer_bytes(&preimage, &sig_pq);
    let sig_cl = sign_outer_with_spend_scalar(spend_sk, outer.as_ref())?;
    Ok(assemble_armored(&sig_pq, &sig_cl))
}

/// A decoded, checksum-intact armored signature of the one scheme this
/// build implements.
///
/// Shape validity is a *type* property here: constructing this proves
/// the prefix, encoding, header bytes, length and checksum all passed,
/// so the verify path below reads fields instead of re-slicing a `Vec`
/// with offsets.
pub struct ArmoredSignature {
    sig_pq: Box<[u8; SLH_192S_SIG_LEN]>,
    sig_cl: [u8; CLASSICAL_SIG_LEN],
}

impl ArmoredSignature {
    /// Decode and shape-check an armored signature string.
    ///
    /// Order is deliberate and *is* the error taxonomy (SM-R-6): the
    /// ceiling applies to the **encoded payload** before any decoding
    /// (R5-b), then canonical-strict base64url, then — see the comment
    /// in the body — a length-conditional split that keeps "your copy is
    /// damaged" distinguishable from "this isn't a scheme I know".
    ///
    /// # Errors
    ///
    /// [`MessageSigError::Malformed`] for shape, [`MessageSigError::
    /// UnsupportedScheme`] for a scheme this build does not implement,
    /// [`MessageSigError::Corrupted`] for a checksum mismatch.
    pub fn decode(armored: &str) -> Result<Self, MessageSigError> {
        let raw = armored
            .trim()
            .strip_prefix(MSG_SIG_PREFIX)
            .ok_or(MessageSigError::Malformed("missing shekylmsgsig1. prefix"))?;
        // Before decoding, and before the only allocation below: a
        // bounded input cannot make us build an attacker-chosen buffer.
        if raw.len() > MSG_SIG_MAX_ENCODED_LEN {
            return Err(MessageSigError::Malformed(
                "over the encoded-length ceiling",
            ));
        }
        // Whitespace tolerance is an *armoring*-layer decision, not a
        // crypto one. SM-R-5's canonical-strict rule governs what we
        // emit — one signature, one spelling, always a single line —
        // but a 21.7 KB line is one every mail client, chat app and
        // issue tracker will hard-wrap, and telling a user who pasted
        // exactly the right signature that it is malformed would be a
        // rule-82 failure with no security content: the bytes are
        // authenticated by the signature itself, not by their spacing.
        let encoded: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        if encoded.contains('=') {
            // Unpadded is pinned (SM-R-5): one signature, one spelling.
            // The decoder would refuse `=` as a non-alphabet byte anyway;
            // this branch exists to say *which* rule was broken.
            return Err(MessageSigError::Malformed("padded base64url"));
        }
        use base64::Engine as _;
        // The general-purpose engine rejects non-alphabet characters and
        // non-zero trailing bits in the final symbol — canonical-form-strict.
        let canonical = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .map_err(|_| MessageSigError::Malformed("non-canonical base64url"))?;

        let header = canonical
            .get(..MSG_SIG_HEADER_LEN)
            .ok_or(MessageSigError::Malformed("shorter than the header"))?;

        // Length decides which question can be answered at all, and the
        // order below is the rule-82 taxonomy rather than a convenience.
        //
        // At OUR canonical length the checksum trailer is locatable, so
        // it runs FIRST: a damaged paste that happens to corrupt a header
        // byte must read as "your copy is damaged", not as "unknown
        // layout version" or — worse — "this wallet is too old to check
        // it", which would send a user to upgrade over a truncated
        // clipboard. Damage is the overwhelmingly likelier cause of a
        // wrong header byte, and it is the one we can actually detect.
        //
        // At any OTHER length the trailer cannot be located, so the
        // scheme byte is all we have: a future scheme carries its own
        // signature size, and reporting it as a corrupt shape would
        // waste the append-only forward-compatibility SM-R-5 assigns to
        // that byte.
        if canonical.len() == MSG_SIG_CANONICAL_LEN {
            let (body, ck) = canonical.split_at(MSG_SIG_CANONICAL_LEN - MSG_SIG_CHECKSUM_LEN);
            let expect = shekyl_crypto_hash::cshake256_32(MSG_SIG_CHECKSUM_DOMAIN, body);
            if ck != &expect[..MSG_SIG_CHECKSUM_LEN] {
                return Err(MessageSigError::Corrupted);
            }
            if header[0] != MSG_SIG_LAYOUT_VERSION {
                return Err(MessageSigError::Malformed("unknown layout version"));
            }
            if header[1] != MSG_SIG_SCHEME_SLH_192S_SPEND_SCHNORR {
                return Err(MessageSigError::UnsupportedScheme(header[1]));
            }
            if header[2] != MSG_SIG_MODE_SPEND {
                return Err(MessageSigError::Malformed("unknown mode"));
            }
        } else if header[1] != MSG_SIG_SCHEME_SLH_192S_SPEND_SCHNORR {
            return Err(MessageSigError::UnsupportedScheme(header[1]));
        } else {
            return Err(MessageSigError::Malformed("wrong canonical length"));
        }

        let pq_end = MSG_SIG_HEADER_LEN + SLH_192S_SIG_LEN;
        let sig_pq: Box<[u8; SLH_192S_SIG_LEN]> = Box::new(
            canonical[MSG_SIG_HEADER_LEN..pq_end]
                .try_into()
                .expect("length fixed by the canonical-length check above"),
        );
        let sig_cl: [u8; CLASSICAL_SIG_LEN] = canonical[pq_end..pq_end + CLASSICAL_SIG_LEN]
            .try_into()
            .expect("length fixed by the canonical-length check above");
        Ok(Self { sig_pq, sig_cl })
    }

    /// The PQ (inner) half, `σ_pq`.
    #[must_use]
    pub fn sig_pq(&self) -> &[u8; SLH_192S_SIG_LEN] {
        &self.sig_pq
    }

    /// The classical (outer) half, `σ_cl` — a house Schnorr over
    /// `preimage ‖ σ_pq` under [`MSG_SIGN_OUTER_DOMAIN`].
    #[must_use]
    pub fn sig_cl(&self) -> &[u8; CLASSICAL_SIG_LEN] {
        &self.sig_cl
    }
}

/// Verify a message signature (SM-R-6): session-less, pure, all inputs
/// public.
///
/// The hybrid is an **AND**: both halves must verify, and the outer half
/// covers the inner one, so a stripped or substituted `σ_pq` invalidates
/// `σ_cl` too. That composition lives here, in one place, so no caller
/// can accidentally implement it as an OR.
///
/// Takes the already-decoded [`ArmoredSignature`], not the armored
/// string: decoding carries the paste taxonomy (SM-R-6) and callers run
/// it *before* judging the address, so accepting the string here would
/// either re-decode the same ~21.7 KB payload (free work for an
/// unauthenticated caller) or move the taxonomy ordering out of the
/// caller's hands. There is exactly one decode, at
/// [`ArmoredSignature::decode`], and exactly one AND, here.
///
/// Keys come from `segment` — the same object whose bytes enter the
/// preimage. There is no parameter that can point them elsewhere.
///
/// # Errors
///
/// [`MessageSigError::VerifyFailed`] if either half does not verify;
/// [`MessageSigError::InvalidKey`] if the segment's SLH key does not
/// parse.
pub fn verify_message(
    segment: &BoundClassicalSegment,
    network: DerivationNetwork,
    message: &[u8],
    sig: &ArmoredSignature,
) -> Result<(), MessageSigError> {
    let preimage = message_preimage(network, segment.as_bytes(), message);

    // Inner half: SLH-DSA over the preimage, ctx empty. The AND is
    // structural — a verifier without this dependency cannot get here.
    let slh_public = slh_dsa_sha2_192s::PublicKey::try_from_bytes(segment.msg_sign_pk())
        .map_err(|_| MessageSigError::InvalidKey)?;
    if !slh_public.verify(&preimage, &sig.sig_pq, b"") {
        return Err(MessageSigError::VerifyFailed);
    }

    // Outer half: the spend-scalar Schnorr over preimage ‖ σ_pq —
    // stripping the PQ half structurally invalidates this one.
    let outer = outer_bytes(&preimage, &sig.sig_pq);
    if !schnorr::verify_compressed(
        MSG_SIGN_OUTER_DOMAIN,
        segment.spend_key(),
        outer.as_ref(),
        &sig.sig_cl,
    ) {
        return Err(MessageSigError::VerifyFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    const SEED: [u8; MASTER_SEED_BYTES] = [0x42u8; MASTER_SEED_BYTES];
    const NET: DerivationNetwork = DerivationNetwork::Testnet;
    const FMT: SeedFormat = SeedFormat::Raw32;
    const VIEW_PK: [u8; 32] = [0x77; 32];
    const TEST_EK: [u8; 1184] = [0xCC; 1184];

    /// A canonical spend scalar (the wallet's spend secret is a raw
    /// scalar, `spend_pk = b·G` — the module-docs implementation note).
    fn spend_sk() -> [u8; 32] {
        Scalar::from_bytes_mod_order([0x24u8; 32]).to_bytes()
    }

    fn spend_pk() -> [u8; 32] {
        let b: Scalar = Option::from(Scalar::from_canonical_bytes(spend_sk())).unwrap();
        (ED25519_BASEPOINT_TABLE * &b).compress().to_bytes()
    }

    fn slh_pk() -> [u8; SLH_192S_PK_LEN] {
        derive_message_signing_public_key(&SEED, NET, FMT).expect("derive")
    }

    /// The fixture wallet's bound classical segment: the REAL layout,
    /// through the version-checked constructor, carrying the fixture's
    /// derived keys — signing and verification see the same bytes an
    /// address encoder would emit.
    fn test_segment() -> BoundClassicalSegment {
        segment_with(&spend_pk(), &slh_pk())
    }

    /// A bound segment with substituted key fields. Since the layout
    /// landed, keys are inseparable from the segment by design, so "a
    /// different key" is expressed as what it really is: a different
    /// address.
    fn segment_with(spend: &[u8; 32], slh: &[u8; SLH_192S_PK_LEN]) -> BoundClassicalSegment {
        let mut classical = Vec::with_capacity(1 + 32 + 32 + SLH_192S_PK_LEN);
        classical.push(shekyl_address::ADDRESS_VERSION_V1);
        classical.extend_from_slice(spend);
        classical.extend_from_slice(&VIEW_PK);
        classical.extend_from_slice(slh);
        BoundClassicalSegment::from_address_parts(&classical, &TEST_EK).expect("fixture segment")
    }

    /// Verify helper: same surface as production — segment in, no
    /// unbound keys.
    fn verify_with(
        segment: &BoundClassicalSegment,
        network: DerivationNetwork,
        message: &[u8],
        armored: &str,
    ) -> Result<(), MessageSigError> {
        let sig = ArmoredSignature::decode(armored)?;
        verify_message(segment, network, message, &sig)
    }

    /// SM-R-4 R4-a KAT: fixed master seed → fixed public key. Pins the
    /// 72-byte single-expand slice order — a wrong split (or an n=32
    /// reflex) produces a valid-but-DIFFERENT keypair, which only this
    /// pin catches. Re-pinned with the SM-R-4 `(network, seed_format)`
    /// amendment.
    #[test]
    fn identity_derivation_is_pinned() {
        let pk = derive_message_signing_public_key(&SEED, NET, FMT).expect("derive");
        let hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "60e1eccf69e1a4ea91f829c477517a2f7510c43a2b712ed5093ed1dbcfe393e7\
             2dac297e6704b20a585f07078c78b8dc",
            "SLH identity derivation moved — seed split, salt or domain changed"
        );
    }

    /// SM-R-4 as amended: the identity is scoped by network **and** by
    /// seed format, exactly like every other wallet key
    /// (`account::same_seed_different_networks_produce_different_scalars`
    /// is the sibling pin). Without this, one seed publishes one 48-byte
    /// public key on mainnet, testnet and stagenet alike — and since that
    /// key is published with every attestation (and inlined into the
    /// address under fork (ii)), it links addresses that were
    /// deliberately made unlinkable.
    #[test]
    fn identity_is_scoped_by_network_and_seed_format() {
        let nets = [
            DerivationNetwork::Mainnet,
            DerivationNetwork::Testnet,
            DerivationNetwork::Stagenet,
            DerivationNetwork::Fakechain,
        ];
        let fmts = [SeedFormat::Bip39, SeedFormat::Raw32];
        // The full cross product — every pair, not a sample.
        let keys: Vec<((DerivationNetwork, SeedFormat), [u8; SLH_192S_PK_LEN])> = nets
            .iter()
            .flat_map(|n| fmts.iter().map(move |f| (*n, *f)))
            .map(|(n, f)| {
                (
                    (n, f),
                    derive_message_signing_public_key(&SEED, n, f).unwrap(),
                )
            })
            .collect();
        assert_eq!(keys.len(), nets.len() * fmts.len());
        for (i, (pair_a, a)) in keys.iter().enumerate() {
            for (pair_b, b) in keys.iter().skip(i + 1) {
                assert_ne!(
                    a, b,
                    "one seed must not yield one message-signing key across \
                     (network, seed_format) pairs: {pair_a:?} vs {pair_b:?}"
                );
            }
        }
    }

    /// The preimage is scoped by network too — replay separation, which
    /// is a *different* property from the key-linkage separation above
    /// and needs its own pin.
    #[test]
    fn preimage_binds_the_network() {
        let seg = test_segment();
        let a = message_preimage(DerivationNetwork::Mainnet, seg.as_bytes(), b"m");
        let b = message_preimage(DerivationNetwork::Testnet, seg.as_bytes(), b"m");
        let c = message_preimage(DerivationNetwork::Fakechain, seg.as_bytes(), b"m");
        assert_ne!(a, b);
        assert_ne!(
            a, c,
            "Fakechain shares Mainnet's address encoding, not its transcript"
        );
    }

    /// End-to-end round trip through the real segment constructor.
    #[test]
    fn sign_verify_round_trips() {
        let seg = test_segment();
        let armored =
            sign_message(&SEED, &spend_sk(), NET, FMT, &seg, b"hello shekyl").expect("sign");
        assert!(armored.starts_with(MSG_SIG_PREFIX));
        assert!(!armored.contains('='), "unpadded is pinned");
        verify_with(&seg, NET, b"hello shekyl", &armored).expect("verify");
    }

    /// Every binding input flips the verdict: message, network, and the
    /// address — where "a different key" now means what it really is, a
    /// different segment, because keys are inseparable from the segment
    /// by construction. (The §4 tamper battery, binding half.)
    #[test]
    fn verification_binds_every_input() {
        let seg = test_segment();
        let armored = sign_message(&SEED, &spend_sk(), NET, FMT, &seg, b"msg").expect("sign");
        assert_eq!(verify_with(&seg, NET, b"msg", &armored), Ok(()));
        assert_eq!(
            verify_with(&seg, NET, b"msh", &armored),
            Err(MessageSigError::VerifyFailed)
        );
        assert_eq!(
            verify_with(&seg, DerivationNetwork::Mainnet, b"msg", &armored),
            Err(MessageSigError::VerifyFailed)
        );
        // A different spend key = a different address.
        let other_b = Scalar::from_bytes_mod_order([9u8; 32]);
        let other_spend = (ED25519_BASEPOINT_TABLE * &other_b).compress().to_bytes();
        assert_eq!(
            verify_with(
                &segment_with(&other_spend, &slh_pk()),
                NET,
                b"msg",
                &armored
            ),
            Err(MessageSigError::VerifyFailed)
        );
        // A different SLH key = a different address.
        let other_slh =
            derive_message_signing_public_key(&[7u8; MASTER_SEED_BYTES], NET, FMT).unwrap();
        assert_eq!(
            verify_with(
                &segment_with(&spend_pk(), &other_slh),
                NET,
                b"msg",
                &armored
            ),
            Err(MessageSigError::VerifyFailed)
        );
    }

    /// The armored-format tamper battery: every canonical field flipped
    /// independently must refuse, with the SM-R-6 error taxonomy —
    /// in-body flips are `Corrupted` (the checksum sees them), header
    /// bytes only reach `Malformed`/`UnsupportedScheme` when
    /// re-checksummed.
    ///
    /// Every assertion names the **exact** discriminant it expects. A
    /// bare `Malformed(_)` would pass even if the branch under test were
    /// deleted and some later check refused the same input for an
    /// unrelated reason.
    #[test]
    fn armored_tamper_battery() {
        use base64::Engine as _;
        let seg = test_segment();
        let armored = sign_message(&SEED, &spend_sk(), NET, FMT, &seg, b"m").expect("sign");
        let verify = |s: &str| verify_with(&seg, NET, b"m", s);

        assert_eq!(
            verify(&armored.replace("shekylmsgsig1.", "shekylmsgsig2.")),
            Err(MessageSigError::Malformed("missing shekylmsgsig1. prefix"))
        );
        assert_eq!(
            verify(&format!("{armored}=")),
            Err(MessageSigError::Malformed("padded base64url"))
        );
        // Over-ceiling input refused *before* decode. Asserting the exact
        // message is what makes this non-vacuous: the same string also
        // fails the canonical-length check, so a bare `Malformed(_)`
        // would stay green with the ceiling guard deleted.
        let huge = format!(
            "{}{}",
            MSG_SIG_PREFIX,
            "A".repeat(MSG_SIG_MAX_ENCODED_LEN + 1)
        );
        assert_eq!(
            verify(&huge),
            Err(MessageSigError::Malformed(
                "over the encoded-length ceiling"
            ))
        );
        // A clipped paste — the commonest real-world damage. Which
        // refusal it earns depends on WHERE the cut lands, and both
        // cases are pinned separately because a cut that leaves a
        // partial 4-character group lands on a data-dependent
        // trailing-bit check. (Signatures are hedged, so σ_pq and σ_cl
        // differ every run: asserting one discriminant for an arbitrary
        // clip is a coin flip, not a test.)
        //
        // Cut to a whole number of base64 groups: always decodes
        // cleanly, always the wrong number of bytes.
        let encoded_len = armored.len() - MSG_SIG_PREFIX.len();
        assert_eq!(
            (encoded_len - 3) % 4,
            0,
            "this case is only deterministic while cutting 3 leaves whole \
             base64 groups — re-derive it if the canonical length moves"
        );
        let group_aligned = &armored[..armored.len() - 3];
        assert_eq!(
            verify(group_aligned),
            Err(MessageSigError::Malformed("wrong canonical length"))
        );
        // Force non-zero trailing bits in the final symbol: the encoded
        // form ends in a 3-character group carrying 16 significant bits
        // of 18, so a last character whose alphabet index is not a
        // multiple of 4 is non-canonical for ANY payload. 'B' is index 1.
        let mut non_canonical = armored.clone();
        non_canonical.pop();
        non_canonical.push('B');
        assert_eq!(
            verify(&non_canonical),
            Err(MessageSigError::Malformed("non-canonical base64url"))
        );

        let engine = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        // A well-formed encoding of the wrong number of bytes: header
        // intact, so this reaches the canonical-length check itself.
        let mut short = engine
            .decode(armored.strip_prefix(MSG_SIG_PREFIX).unwrap())
            .unwrap();
        short.truncate(MSG_SIG_CANONICAL_LEN - 3);
        assert_eq!(
            verify(&format!("{}{}", MSG_SIG_PREFIX, engine.encode(&short))),
            Err(MessageSigError::Malformed("wrong canonical length"))
        );

        // A flipped body byte is CORRUPTION (checksum catches it first).
        let mut canonical = engine
            .decode(armored.strip_prefix(MSG_SIG_PREFIX).unwrap())
            .unwrap();
        canonical[100] ^= 0x01;
        let corrupted = format!("{}{}", MSG_SIG_PREFIX, engine.encode(&canonical));
        assert_eq!(verify(&corrupted), Err(MessageSigError::Corrupted));

        // Header flips with a RECOMPUTED checksum are shape errors — the
        // string is intact, just not ours — and each names its own field.
        let rechecksummed = |idx: usize| {
            let mut c = engine
                .decode(armored.strip_prefix(MSG_SIG_PREFIX).unwrap())
                .unwrap();
            c[idx] ^= 0x01;
            let body_len = MSG_SIG_CANONICAL_LEN - MSG_SIG_CHECKSUM_LEN;
            let ck = shekyl_crypto_hash::cshake256_32(MSG_SIG_CHECKSUM_DOMAIN, &c[..body_len]);
            c[body_len..].copy_from_slice(&ck[..MSG_SIG_CHECKSUM_LEN]);
            format!("{}{}", MSG_SIG_PREFIX, engine.encode(&c))
        };
        assert_eq!(
            verify(&rechecksummed(0)),
            Err(MessageSigError::Malformed("unknown layout version"))
        );
        assert_eq!(
            verify(&rechecksummed(2)),
            Err(MessageSigError::Malformed("unknown mode"))
        );

        // The control that keeps the two assertions above honest: the
        // SAME header bytes flipped WITHOUT recomputing the checksum are
        // damage, and must read as damage. Without this, an
        // implementation that checked the header before the checksum
        // would pass everything above while telling a user whose paste
        // was truncated that their wallet is too old (rule 82).
        let damaged = |idx: usize| {
            let mut c = engine
                .decode(armored.strip_prefix(MSG_SIG_PREFIX).unwrap())
                .unwrap();
            c[idx] ^= 0x01;
            format!("{}{}", MSG_SIG_PREFIX, engine.encode(&c))
        };
        for idx in 0..MSG_SIG_HEADER_LEN {
            assert_eq!(
                verify(&damaged(idx)),
                Err(MessageSigError::Corrupted),
                "a damaged header byte at {idx} is corruption, not an unknown format"
            );
        }
    }

    /// A signature that survived a round trip through something that
    /// wraps long lines still verifies. The armored form is 21,727
    /// characters on one line; email, chat and issue trackers all wrap
    /// it, and "malformed signature" for a correctly-pasted signature is
    /// a rule-82 failure. Emission stays single-line and canonical —
    /// this is decode tolerance only.
    #[test]
    fn wrapped_and_padded_whitespace_still_verifies() {
        let seg = test_segment();
        let armored = sign_message(&SEED, &spend_sk(), NET, FMT, &seg, b"m").expect("sign");
        let wrapped: String = armored
            .as_bytes()
            .chunks(72)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n");
        assert!(wrapped.contains("\r\n"), "fixture must actually wrap");
        for candidate in [
            wrapped,
            format!("  {armored}\n"),
            format!("\n\t{armored}  \n"),
        ] {
            assert_eq!(
                verify_with(&seg, NET, b"m", &candidate),
                Ok(()),
                "whitespace must not change a signature's verdict"
            );
        }
        // Tolerance is whitespace only — a corrupted character is still
        // a refusal, so this is not a blanket "ignore junk".
        let mut damaged = armored.clone();
        damaged.insert(MSG_SIG_PREFIX.len() + 4, '.');
        assert_eq!(
            verify_with(&seg, NET, b"m", &damaged),
            Err(MessageSigError::Malformed("non-canonical base64url"))
        );
    }

    /// SM-R-5's scheme byte is the append-only forward-compat field: an
    /// unknown scheme must be reported *as* an unknown scheme, before any
    /// scheme-specific length is enforced. Otherwise the first future
    /// scheme with a different signature size is misreported as a corrupt
    /// paste and the byte buys nothing.
    #[test]
    fn unknown_scheme_is_reported_as_unsupported_not_malformed() {
        use base64::Engine as _;
        let engine = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let seg = test_segment();
        let armored = sign_message(&SEED, &spend_sk(), NET, FMT, &seg, b"m").expect("sign");
        let mut c = engine
            .decode(armored.strip_prefix(MSG_SIG_PREFIX).unwrap())
            .unwrap();
        c[1] = 0x02;
        // Truncate to a DIFFERENT length as a future scheme would, so
        // this cannot pass by accident through the length check.
        c.truncate(MSG_SIG_HEADER_LEN + 128);
        let s = format!("{}{}", MSG_SIG_PREFIX, engine.encode(&c));
        assert_eq!(
            verify_with(&seg, NET, b"m", &s),
            Err(MessageSigError::UnsupportedScheme(0x02))
        );
    }

    /// Cross-half battery (§4): the hybrid is AND, never OR — a signature
    /// whose PQ half was re-signed by a different identity fails even
    /// though its classical half is honest, and vice versa is unreachable
    /// by construction (σ_cl covers σ_pq).
    #[test]
    fn cross_half_and_never_or() {
        use base64::Engine as _;
        let engine = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let seg = test_segment();
        let armored = sign_message(&SEED, &spend_sk(), NET, FMT, &seg, b"m").expect("sign");
        let mut canonical = engine
            .decode(armored.strip_prefix(MSG_SIG_PREFIX).unwrap())
            .unwrap();

        // Replace σ_pq with a valid signature from a DIFFERENT SLH
        // identity over the same preimage; keep the honest σ_cl.
        let preimage = message_preimage(NET, seg.as_bytes(), b"m");
        let (_pk2, sk2) =
            derive_message_signing_identity(&[9u8; MASTER_SEED_BYTES], NET, FMT).unwrap();
        let sig_pq2 = sk2.try_sign(&preimage, b"", true).unwrap();
        canonical[MSG_SIG_HEADER_LEN..MSG_SIG_HEADER_LEN + SLH_192S_SIG_LEN]
            .copy_from_slice(&sig_pq2);
        let body_len = MSG_SIG_CANONICAL_LEN - MSG_SIG_CHECKSUM_LEN;
        let ck = shekyl_crypto_hash::cshake256_32(MSG_SIG_CHECKSUM_DOMAIN, &canonical[..body_len]);
        canonical[body_len..].copy_from_slice(&ck[..MSG_SIG_CHECKSUM_LEN]);
        let spliced = format!("{}{}", MSG_SIG_PREFIX, engine.encode(&canonical));

        // The inner half fails against the claimed slh_pk; and even
        // against sk2's own pk, the OUTER half now fails because σ_cl
        // covers the original σ_pq — the nesting doing its job.
        assert_eq!(
            verify_with(&seg, NET, b"m", &spliced),
            Err(MessageSigError::VerifyFailed)
        );
        // Even against an address carrying sk2's OWN public key the splice
        // fails: that is a different segment, so the recomputed preimage
        // no longer matches what either half signed — with keys inline in
        // the address, key substitution and address substitution are the
        // same act, and both invalidate everything.
        let pk2 = derive_message_signing_public_key(&[9u8; MASTER_SEED_BYTES], NET, FMT).unwrap();
        assert_eq!(
            verify_with(&segment_with(&spend_pk(), &pk2), NET, b"m", &spliced),
            Err(MessageSigError::VerifyFailed)
        );
    }

    /// SM-R-3 R3-a: the `ctx` pin. A signature produced with a non-empty
    /// FIPS 205 context must NOT verify — proving our verify path passes
    /// `ctx = ""` and that the pin is load-bearing, not decorative.
    #[test]
    fn nonempty_ctx_signature_is_rejected() {
        let seg = test_segment();
        let preimage = message_preimage(NET, seg.as_bytes(), b"m");
        let (_pk, sk) = derive_message_signing_identity(&SEED, NET, FMT).unwrap();
        let sig_pq_bad_ctx = Box::new(
            sk.try_sign(&preimage, MSG_SIGN_DOMAIN, true)
                .expect("sign with wrong ctx"),
        );

        let outer = outer_bytes(&preimage, &sig_pq_bad_ctx);
        let sig_cl = sign_outer_with_spend_scalar(&spend_sk(), outer.as_ref()).unwrap();
        let s = assemble_armored(&sig_pq_bad_ctx, &sig_cl);

        assert_eq!(
            verify_with(&seg, NET, b"m", &s),
            Err(MessageSigError::VerifyFailed),
            "a non-empty ctx must not verify — the empty-ctx pin is load-bearing"
        );
    }

    /// Domain strings are distinct (the collision check the inventory
    /// relies on) and the preimage is length-prefix framed.
    #[test]
    fn domains_distinct_and_framing_unambiguous() {
        let domains: [&[u8]; 5] = [
            MSG_SIGN_DOMAIN,
            MSG_HASH_DOMAIN,
            MSG_SIGN_SEED_DOMAIN,
            MSG_SIG_CHECKSUM_DOMAIN,
            MSG_SIGN_OUTER_DOMAIN,
        ];
        for (i, a) in domains.iter().enumerate() {
            for b in domains.iter().skip(i + 1) {
                assert_ne!(a, b, "domain collision");
            }
        }
        // Length-prefix framing: shifting a byte across the
        // segment/message-hash boundary changes the preimage.
        let p1 = message_preimage(NET, &[0xAA, 0xBB], b"x");
        let p2 = message_preimage(NET, &[0xAA], b"x");
        assert_ne!(p1, p2);
    }

    /// Outer-message construction is exactly preimage ‖ σ_pq at the
    /// compile-time length the actor gate / type boundary relies on.
    #[test]
    fn outer_bytes_length_is_compile_time_fixed() {
        let preimage = [0xABu8; MSG_PREIMAGE_LEN];
        let sig_pq = Box::new([0xCDu8; SLH_192S_SIG_LEN]);
        let outer = outer_bytes(&preimage, &sig_pq);
        assert_eq!(outer.len(), OUTER_MSG_LEN);
        assert_eq!(&outer[..MSG_PREIMAGE_LEN], &preimage);
        assert_eq!(&outer[MSG_PREIMAGE_LEN..], &sig_pq[..]);
    }
}
