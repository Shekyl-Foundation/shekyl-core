// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl wallet-account key derivation: one secret, one derivation, on
//! every network.
//!
//! This module is the **single source of truth** for how a Shekyl wallet's
//! keys are derived from its seed, on every network. Every byte of every
//! address is reproducible by running the inputs through this one file. The
//! derivation is pinned in CI by the `ADDRESS_DERIVATION_V3` KAT suite and
//! its independent oracle (`scripts/kat/address_derivation_v3_oracle.py`).
//!
//! # Pipeline overview
//!
//! ```text
//!                   ┌─────────────────────────────────────┐
//!   The one secret:  │ seed: 32 bytes, every network        │
//!                    │ (shown as BIP-39's 24 words; the     │
//!                    │  words are the 32 bytes' spelling)   │
//!                   └──────────────────┬──────────────────┘
//!                                      │
//!                                      ▼
//!                   ┌─────────────────────────────────────┐
//!                   │ normalize_seed: HKDF-SHA-512         │
//!                   │  salt = "shekyl-seed-normalize-v1"   │
//!                   │  ikm  = seed (32 B)                   │
//!                   │  info = ""                           │
//!                   │  L    = 64                           │
//!                   └──────────────────┬──────────────────┘
//!                                      │
//!                                      ▼
//!                         master_seed_64
//!                                      │
//!         ┌────────────────────────────┼────────────────────────────┐
//!         │                            │                            │
//!         ▼                            ▼                            ▼
//!  HKDF (salt_for(net),         HKDF (salt_for(net),          HKDF (salt_for(net),
//!        ikm=master_seed_64,          ikm=master_seed_64,           ikm=master_seed_64,
//!        info="shekyl-ed25519-        info="shekyl-ed25519-         info="shekyl-ml-kem-
//!              spend",                      view",                         768",
//!        L=64)                         L=64)                         L=64)
//!         │                            │                            │
//!         ▼                            ▼                            ▼
//!  wide_reduce → spend_sk       wide_reduce → view_sk          d_z (feeds ML-KEM)
//!  (Ed25519 Scalar)             (Ed25519 Scalar; also                │
//!                                re-used as Montgomery                ▼
//!                                scalar at ECDH sites)          chacha_seed = SHA3-256(
//!                                                                 "shekyl-mlkem-chacha-seed"
//!                                                                 || d_z)[0..32]
//!                                                                        │
//!                                                                        ▼
//!                                                                SeededRng::from_seed
//!                                                                        │
//!                                                                        ▼
//!                                                                ml_kem_768::KG::
//!                                                                  try_keygen_with_rng
//!                                                                  → (ek, dk)
//! ```
//!
//! That step is `SeededRng::from_seed`. The cipher lives on the heap, and the
//! bytes are what `ChaCha20Rng::from_seed` produces. The SHA3-ChaCha
//! intermediary exists because `fips203 = "=0.4.3"` does not
//! publicly expose `KeyGen_internal(d, z)` per FIPS 203 §7.1; see
//! `upstream-fips203-keygen-internal` in the stabilization plan for the
//! tracking follow-up. The intermediary commits to all 64 bytes of `d_z` via
//! the SHA3-256 hash, so once the upstream API lands we can swap without
//! shifting any consumer-visible bytes (the FIPS `KeyGen_internal` output is
//! already deterministic in `d_z`).
//!
//! # Why 64-byte HKDF expansions even for 32-byte scalars
//!
//! `Scalar::from_bytes_mod_order` on a 32-byte input has non-uniform
//! distribution over the Ed25519 scalar field because the raw integer is
//! `< 2^256` but the field modulus `l ≈ 2^252.5`. The bias is cryptographically
//! negligible (~2^-123) but shows up in careful audits. Expanding to 64 bytes
//! and using `Scalar::from_bytes_mod_order_wide` produces a scalar whose
//! distribution is statistically indistinguishable from uniform; we spend the
//! extra 32 bytes per derivation to eliminate the caveat.
//!
//! # One secret, one derivation (`NETWORK_IDENTITY.md` NI-R7, NI-R10)
//!
//! A wallet's secret is 32 bytes. BIP-39's 24 words and 64 hex digits are
//! two spellings of the same bytes and give the same wallet; there is no
//! passphrase and no PBKDF2 step, so a wallet can always show its words and
//! an import round-trips. The HKDF salt binds the network's **name**, its
//! tag `shekyl/<network>`: the name exists before genesis, and the genesis
//! pays addresses this derivation produces, so the genesis-derived network
//! id cannot be the salt. The same 32 bytes on two networks give unrelated
//! keys.

use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha512;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use fips203::ml_kem_768;
use fips203::traits::{KeyGen, SerDes};

use crate::bip39;
use crate::kem::{ML_KEM_768_DK_LEN, ML_KEM_768_EK_LEN};
use crate::keys::{MlKem768DecapKey, SpendPublicKey, SpendSecret, ViewPublicKey, ViewSecret};
use crate::montgomery;
use crate::CryptoError;

// --- constants ---------------------------------------------------------------

/// Fixed length of the Shekyl master seed, the normalised seed every key
/// is expanded from.
pub const MASTER_SEED_BYTES: usize = 64;

/// Length of a wallet's one secret: 32 bytes, shown as 24 BIP-39 words.
/// The wallet file stores exactly this many bytes.
pub const SEED_BYTES: usize = 32;
const _: () = assert!(SEED_BYTES == bip39::SHEKYL_BIP39_ENTROPY_BYTES);

/// Length of the Shekyl classical-segment address bytes. Owned by
/// `shekyl-address`; this alias exists so the FFI blob and the
/// derivation pipeline name the same width.
pub const CLASSICAL_ADDRESS_BYTES: usize = shekyl_address::CLASSICAL_SEGMENT_LEN;

/// The persisted wallet-envelope field keeps the
/// `version ‖ spend ‖ view` PREFIX of these bytes (see
/// `wallet_envelope::EXPECTED_CLASSICAL_ADDRESS_BYTES`): the prefix
/// detects a seed/file mismatch at full strength — `msg_sign_pk` is
/// deterministic from the same seed and adds no detection power — and
/// keeping the stored bytes unchanged keeps every existing wallet file
/// openable (the field feeds the file-KEK HKDF info).
pub const CLASSICAL_ADDRESS_PREFIX_BYTES: usize =
    CLASSICAL_ADDRESS_BYTES - shekyl_address::MSG_SIGN_PK_LEN;
const _: () = assert!(shekyl_address::MSG_SIGN_PK_LEN == crate::message_signing::SLH_192S_PK_LEN);
const _: () = assert!(
    CLASSICAL_ADDRESS_PREFIX_BYTES == crate::wallet_envelope::EXPECTED_CLASSICAL_ADDRESS_BYTES
);

/// Length of the concatenated PQC public-key buffer stored as
/// `m_pqc_public_key` in C++ `account_public_address`. X25519 32 bytes
/// followed by ML-KEM-768 encap key 1184 bytes.
pub const PQC_PUBLIC_KEY_BYTES: usize = 32 + ML_KEM_768_EK_LEN;
const _: () = {
    assert!(PQC_PUBLIC_KEY_BYTES == 1216);
};

/// HKDF salt for the format-independent seed normalisation step.
pub const SEED_NORMALIZE_SALT: &[u8] = b"shekyl-seed-normalize-v1";

/// HKDF info-label for the Ed25519 spend sub-derivation.
pub const SPEND_INFO: &[u8] = b"shekyl-ed25519-spend";

/// HKDF info-label for the Ed25519 view sub-derivation.
pub const VIEW_INFO: &[u8] = b"shekyl-ed25519-view";

/// HKDF info-label for the ML-KEM-768 sub-derivation (produces 64-byte
/// `d_z` fed into the SHA3-ChaCha intermediary).
pub const KEM_INFO: &[u8] = b"shekyl-ml-kem-768";

/// SHA3-256 prefix committing the full 64-byte `d_z` into a 32-byte
/// ChaCha20 seed. See module doc for why this intermediary exists.
pub const MLKEM_CHACHA_SEED_PREFIX: &[u8] = b"shekyl-mlkem-chacha-seed";

pub use shekyl_address::Network;

// --- salt construction -------------------------------------------------------

/// The HKDF salt's purpose label, after the network's `name_id`.
/// Registered in `CRYPTO_DOMAIN_REGISTRY.tsv`; the label is the salt
/// layout's only version (the signing envelope §2.6: a layout change is a
/// new label, here `-v3` for `name_id ‖ purpose`).
pub const MASTER_DERIVE_PURPOSE: &[u8] = b"shekyl-master-derive-v3";

/// Build the HKDF salt bound to a network's name (NI-R10, Rick's ruling of
/// 2026-11-04 on the signing envelope): the network's 16-byte `name_id` at
/// position 0, then [`MASTER_DERIVE_PURPOSE`], unframed. Keys and addresses
/// exist before any genesis, so derivation binds the name, never the
/// genesis-derived id.
#[must_use]
pub fn salt_for(net: Network) -> Vec<u8> {
    let name_id = net.name_id();
    let mut out = Vec::with_capacity(name_id.as_bytes().len() + MASTER_DERIVE_PURPOSE.len());
    out.extend_from_slice(name_id.as_bytes());
    out.extend_from_slice(MASTER_DERIVE_PURPOSE);
    out
}

// --- normalize_seed ----------------------------------------------------------

/// Normalize an arbitrary-length input into a fixed 64-byte master seed.
///
/// This is HKDF-SHA-512 with salt `shekyl-seed-normalize-v1`, empty info,
/// and output length 64, applied to the 32-byte seed. HKDF-Extract-then-
/// Expand turns the seed's 256 bits into a domain-separated 64-byte value
/// that every key below expands from.
pub fn normalize_seed(ikm: &[u8]) -> Zeroizing<[u8; MASTER_SEED_BYTES]> {
    let hk = Hkdf::<Sha512>::new(Some(SEED_NORMALIZE_SALT), ikm);
    let mut out = [0u8; MASTER_SEED_BYTES];
    hk.expand(b"", &mut out)
        .expect("64 bytes < HKDF-SHA-512 max output");
    Zeroizing::new(out)
}

// --- HKDF sub-derivations ---------------------------------------------------

/// Expand `master_seed` into a 64-byte HKDF output using the supplied info
/// label and the network's salt. Internal helper.
fn hkdf_expand_64(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: Network,
    info: &[u8],
) -> Zeroizing<[u8; 64]> {
    let salt = salt_for(net);
    let hk = Hkdf::<Sha512>::new(Some(&salt), master_seed);
    let mut out = [0u8; 64];
    hk.expand(info, &mut out)
        .expect("64 bytes < HKDF-SHA-512 max output");
    Zeroizing::new(out)
}

/// Expand to the 64-byte intermediate for the Ed25519 spend scalar.
/// Consumers wide-reduce via [`wide_reduce_to_scalar`].
pub fn derive_spend_wide(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: Network,
) -> Zeroizing<[u8; 64]> {
    hkdf_expand_64(master_seed, net, SPEND_INFO)
}

/// Expand to the 64-byte intermediate for the Ed25519 view scalar.
/// Consumers wide-reduce via [`wide_reduce_to_scalar`].
pub fn derive_view_wide(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: Network,
) -> Zeroizing<[u8; 64]> {
    hkdf_expand_64(master_seed, net, VIEW_INFO)
}

/// Expand to the 64-byte `d_z` fed into the ML-KEM SHA3-ChaCha intermediary.
pub fn derive_kem_d_z(master_seed: &[u8; MASTER_SEED_BYTES], net: Network) -> Zeroizing<[u8; 64]> {
    hkdf_expand_64(master_seed, net, KEM_INFO)
}

/// Wide-reduce a 64-byte uniformly-distributed HKDF output into an Ed25519
/// scalar. This is the single point at which 64-byte intermediates collapse
/// to 32-byte scalar material.
#[must_use]
pub fn wide_reduce_to_scalar(input: &[u8; 64]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(input)
}

// --- ML-KEM keygen from d_z --------------------------------------------------

/// Derive the 32-byte ChaCha20 seed that will drive ML-KEM keygen. The
/// input is the 64-byte `d_z` from HKDF-Expand; the output is
/// `SHA3-256(MLKEM_CHACHA_SEED_PREFIX || d_z)`.
///
/// The intermediary commits to all 64 bytes of `d_z`, so when the upstream
/// `fips203` crate exposes `KeyGen_internal(d, z)` directly we can swap
/// this for a one-line call without shifting any observable bytes (the
/// direct API is also deterministic in `d_z` by FIPS 203 §7.1).
///
/// The seed is the whole secret of the ML-KEM key, so it is returned
/// wrapped, and the digest is written straight into the wrapped buffer:
/// there is no separate digest value to wipe, because `finalize` is never
/// asked to return one. The hasher is consumed by that call and wipes its
/// own state (`sha3`'s `zeroize` feature).
#[must_use]
pub fn ml_kem_chacha_seed_from_d_z(d_z: &[u8; 64]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha3_256::new();
    hasher.update(MLKEM_CHACHA_SEED_PREFIX);
    hasher.update(d_z);
    let mut seed = Zeroizing::new([0u8; 32]);
    hasher.finalize_into((&mut *seed).into());
    seed
}

/// Produce an ML-KEM-768 `(ek, dk)` pair deterministically from a
/// 64-byte `d_z`. The output is byte-identical on every run with the
/// same input; this is the property that makes wallet rederivation
/// possible.
///
/// The decap key is returned as the typed [`MlKem768DecapKey`]
/// wrapper. The wrapper carries `Zeroize + ZeroizeOnDrop`; consumers
/// receive the secret already inside the typed-wrapper discipline of
/// `.cursor/rules/18-type-placement.mdc` rather than as raw bytes
/// they must individually wrap. Per `35-secure-memory.mdc`'s hand-off
/// section (a producer returns the typed wrapper, not raw bytes),
/// this keeps the decap-key flow within `Zeroize` coverage from
/// producer to consumer without any call site materialising an
/// untracked `[u8; ML_KEM_768_DK_LEN]` Copy.
///
/// **Known interior temporary (FOLLOWUP, V3.1).** Inside this
/// function, `dk.into_bytes()` is the upstream `fips203` API and
/// returns the 2400-byte representation by value, briefly producing
/// a stack-resident `[u8; ML_KEM_768_DK_LEN]` outside any `Zeroize`
/// wrapper. The subsequent `MlKem768DecapKey::from_zeroizing(...)`
/// move *typically* gets RVO'd to the return-value slot under
/// `--release`, but this is not guaranteed in `--debug` builds.
/// Closing this gap requires either an `encode_into(&mut [u8; N])`
/// API on `fips203`'s `DecapsulationKey` or a Shekyl-side wrapper
/// that constructs the decap key from `fips203`'s typed form
/// without going through `into_bytes`. Tracked in
/// `docs/FOLLOWUPS.md` under V3.1.
pub fn ml_kem_keypair_from_d_z(
    d_z: &[u8; 64],
) -> Result<([u8; ML_KEM_768_EK_LEN], MlKem768DecapKey), CryptoError> {
    let chacha_seed = ml_kem_chacha_seed_from_d_z(d_z);
    let mut rng = crate::seeded_rng::SeededRng::from_seed(&chacha_seed);
    let (ek, dk) = ml_kem_768::KG::try_keygen_with_rng(&mut rng)
        .map_err(|e| CryptoError::KeyGenerationFailed(format!("ML-KEM-768 keygen: {e}")))?;

    let ek_bytes: [u8; ML_KEM_768_EK_LEN] = ek.into_bytes();
    let dk_zeroizing: Zeroizing<[u8; ML_KEM_768_DK_LEN]> = Zeroizing::new(dk.into_bytes());
    Ok((ek_bytes, MlKem768DecapKey::from_zeroizing(dk_zeroizing)))
}

// --- AllKeysBlob: every key of one account, in a fixed layout ---------------

/// Fixed-layout struct carrying every byte needed to construct a wallet
/// account from a master seed. [`rederive_account`] builds it
/// (`AllKeysBlob::zeroed()`, then each field) and returns it by value;
/// on an error the partly filled blob is dropped, which wipes it, and the
/// caller receives only the error. No allocation of it is `mlock`'d or
/// excluded from core dumps: rule 35's OS-level section requires that of
/// the long-lived secret types in this crate, and it is not yet met.
///
/// Layout is frozen at v1. Do not add, remove, or reorder fields without
/// bumping the derivation version and the KAT manifest hash.
///
/// # Wipe-on-drop
///
/// Every field implements `Zeroize`, so per
/// `.cursor/rules/35-secure-memory.mdc` ("`#[derive(ZeroizeOnDrop)]`
/// **only** if every field implements `Zeroize`") the struct derives
/// `Zeroize + ZeroizeOnDrop`. The
/// generated `Drop::drop` calls `self.zeroize()`, which calls
/// `.zeroize()` on every field once. Field-drop-glue then re-invokes
/// each field's destructor independently — for fields that are
/// themselves `ZeroizeOnDrop` (`spend_sk`, `view_sk`, `ml_kem_dk`),
/// that destructor calls `.zeroize()` again on already-zero bytes.
/// The resulting double-wipe is the standard zeroize-crate
/// composition pattern: idempotent, harmless, and the price of
/// uniform field-level wipe coverage. A future grep of
/// `ZeroizeOnDrop`-bearing types will land on this pattern; the
/// inline description above is the locatable record of its
/// intentionality.
///
/// Public-key fields (`spend_pk`, `view_pk`, `ml_kem_ek`, `x25519_pk`,
/// `pqc_public_key`, `classical_address_bytes`) are zeroized for
/// uniform write patterns even though they hold no secret material;
/// this maintains the constant-time-on-error discipline the manual
/// `Drop` previously enforced.
///
/// # Not `Clone`
///
/// `Clone` on a struct that holds the wallet's spend/view/decap
/// secrets requires explicit justification per
/// `.cursor/rules/30-cryptography.mdc` and `35-secure-memory.mdc`
/// ("Never derive `Clone` ... unless there is an explicit, documented
/// reason").
/// The audit performed for `KEY_ENGINE.md` §7.5 surfaced zero
/// production `.clone()` callers workspace-wide (verified across
/// production code and `#[cfg(test)]` blocks via
/// `cargo build --workspace --all-targets`); the trait is not derived.
/// Engine-side ownership flows through `LocalKeys::from_keys_blob`,
/// which moves the blob into the engine's private state — see the
/// `traits/key.rs` doc-comment ("Not Clone — implementors wrap
/// `AllKeysBlob`"). If a future call site needs `Clone`, the
/// disposition reverts to a documented `Clone` retention with
/// explicit justification rather than reflex re-derivation.
#[repr(C)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AllKeysBlob {
    // --- public side (plain-text portion of the wallet) ------------------
    /// Ed25519 spend public key.
    ///
    /// Wrapped in [`SpendPublicKey`] for
    /// type-system protection at sites that distinguish "spend half"
    /// from "view half" of the account identity. Read the
    /// canonical bytes via `spend_pk.as_canonical_bytes()`.
    pub spend_pk: SpendPublicKey,
    /// Ed25519 view public key.
    ///
    /// Wrapped in [`ViewPublicKey`] — see
    /// `spend_pk` for the FFI-layout / accessor contract.
    pub view_pk: ViewPublicKey,
    /// ML-KEM-768 encap (public) key, 1184 bytes.
    pub ml_kem_ek: [u8; ML_KEM_768_EK_LEN],
    /// X25519 public key, derived from `view_pk` via the Edwards-to-Montgomery
    /// birational map `u = (1 + y) / (1 - y) mod p`.
    pub x25519_pk: [u8; 32],
    /// `x25519_pk || ml_kem_ek`, byte-identical to what C++ stores as
    /// `account_public_address::m_pqc_public_key`. 1216 bytes.
    pub pqc_public_key: [u8; PQC_PUBLIC_KEY_BYTES],
    /// `version || spend_pk || view_pk || msg_sign_pk`, the full classical
    /// address payload (113 bytes). The persisted envelope field and C++'s
    /// `m_expected_classical_address_bytes` keep only the 65-byte prefix —
    /// see [`CLASSICAL_ADDRESS_PREFIX_BYTES`].
    pub classical_address_bytes: [u8; CLASSICAL_ADDRESS_BYTES],

    // --- secret side (held by C++ only as opaque bytes) -------------------
    /// Ed25519 spend secret scalar, in canonical 32-byte little-endian form.
    ///
    /// Wrapped in [`SpendSecret`] for
    /// type-system protection and structural wipe-on-drop.
    /// Read the canonical bytes via `spend_sk.as_canonical_bytes()`.
    pub spend_sk: SpendSecret,
    /// Ed25519 view secret scalar, in canonical 32-byte little-endian form.
    /// Also used (unclamped) as the Montgomery scalar at ECDH sites.
    ///
    /// Wrapped in [`ViewSecret`] for type-system
    /// protection and structural wipe-on-drop. Read
    /// the canonical bytes via `view_sk.as_canonical_bytes()`.
    pub view_sk: ViewSecret,
    /// ML-KEM-768 decap (secret) key, 2400 bytes. Rederived on every wallet
    /// open; persisted only via the master seed.
    ///
    /// Wrapped in [`MlKem768DecapKey`] for
    /// type-system protection and structural wipe-on-drop, per the
    /// `35-secure-memory.mdc` "wrap secret scalars and key bytes"
    /// mandate. Read the canonical 2400-byte FIPS 203 representation via
    /// `ml_kem_dk.as_canonical_bytes()`.
    pub ml_kem_dk: MlKem768DecapKey,
}

impl AllKeysBlob {
    /// Byte-for-byte zero. Used at the start of every fill and on every
    /// failure path to guarantee constant-time write patterns.
    pub fn zeroed() -> Self {
        AllKeysBlob {
            spend_pk: SpendPublicKey::from_canonical_bytes([0u8; 32]),
            view_pk: ViewPublicKey::from_canonical_bytes([0u8; 32]),
            ml_kem_ek: [0u8; ML_KEM_768_EK_LEN],
            x25519_pk: [0u8; 32],
            pqc_public_key: [0u8; PQC_PUBLIC_KEY_BYTES],
            classical_address_bytes: [0u8; CLASSICAL_ADDRESS_BYTES],
            spend_sk: SpendSecret::from_bytes([0u8; 32]),
            view_sk: ViewSecret::from_bytes([0u8; 32]),
            ml_kem_dk: MlKem768DecapKey::zero(),
        }
    }

    /// The SLH-DSA-192s message-signing public key — the fourth classical
    /// field, sliced out of `classical_address_bytes` here so no caller
    /// re-learns the layout's offsets.
    #[must_use]
    pub fn msg_sign_pk(&self) -> &[u8; shekyl_address::MSG_SIGN_PK_LEN] {
        shekyl_address::ClassicalFields::parse(&self.classical_address_bytes)
            .expect("blob fill writes a well-formed classical segment")
            .msg_sign_pk
    }

    /// The encoded receive address this blob derives. The one
    /// constructor that knows how the blob's public fields become a
    /// [`shekyl_address::ShekylAddress`] — callers do not re-slice.
    #[must_use]
    pub fn to_address(&self, network: shekyl_address::Network) -> shekyl_address::ShekylAddress {
        shekyl_address::ShekylAddress::from_classical_bytes(
            network,
            &self.classical_address_bytes,
            self.ml_kem_ek.to_vec(),
        )
        .expect("blob fill writes a well-formed classical segment")
    }
}

// --- end-to-end derivation flows --------------------------------------------

/// Rederive every key from a 64-byte master seed. This is the path taken
/// on every wallet-open (through [`account_from_seed`]) and by the freeze
/// tooling when it regenerates addresses for the KAT manifest.
///
/// Returns the filled blob on success. On failure the blob is guaranteed
/// to contain the zero value — any caller that observes a `CryptoError`
/// can safely treat the memory as uninitialised.
pub fn rederive_account(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: Network,
) -> Result<AllKeysBlob, CryptoError> {
    let mut blob = AllKeysBlob::zeroed();

    // Ed25519 spend
    let spend_wide = derive_spend_wide(master_seed, net);
    let spend_scalar = wide_reduce_to_scalar(&spend_wide);
    blob.spend_sk = SpendSecret::from_bytes(*spend_scalar.as_bytes());
    let spend_pub = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &spend_scalar;
    blob.spend_pk = SpendPublicKey::from_canonical_bytes(*spend_pub.compress().as_bytes());

    // Ed25519 view
    let view_wide = derive_view_wide(master_seed, net);
    let view_scalar = wide_reduce_to_scalar(&view_wide);
    blob.view_sk = ViewSecret::from_bytes(*view_scalar.as_bytes());
    let view_pub_edw = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &view_scalar;
    let view_pub_compressed = view_pub_edw.compress();
    blob.view_pk = ViewPublicKey::from_canonical_bytes(*view_pub_compressed.as_bytes());

    // X25519 public via birational. Failure here means the view scalar
    // produced an identity or low-order Ed25519 point; the probability is
    // cryptographically negligible but we surface it cleanly. On error,
    // `blob` is dropped here, which zeroes every field via
    // `AllKeysBlob`'s derived `ZeroizeOnDrop`.
    let x25519_pk = montgomery::ed25519_pk_to_x25519_pk(blob.view_pk.as_canonical_bytes())?;
    blob.x25519_pk.copy_from_slice(&x25519_pk);

    // ML-KEM-768 deterministic keygen. `dk` is already the typed
    // wrapper (`MlKem768DecapKey`); move it directly into the blob
    // field — no `*dk` deref, no untracked `[u8; ML_KEM_768_DK_LEN]`
    // Copy on the stack between producer and consumer.
    let d_z = derive_kem_d_z(master_seed, net);
    let (ek, dk) = ml_kem_keypair_from_d_z(&d_z)?;
    blob.ml_kem_ek.copy_from_slice(&ek);
    blob.ml_kem_dk = dk;

    // Composite fields
    blob.pqc_public_key[..32].copy_from_slice(&blob.x25519_pk);
    blob.pqc_public_key[32..].copy_from_slice(&blob.ml_kem_ek);

    // Fourth classical field: the SLH-DSA-192s message-signing public key
    // (fork (ii), SM-R-8), derived under the same network scoping as
    // every key above (SM-R-4 R4-c — the published key must
    // not link addresses across networks). This is a full SLH keygen
    // (~415 ms on the Pi-4 floor): acceptable because `rederive_account`
    // runs only on the create/open paths, where the Argon2 KDF already
    // dominates — do not add it to any per-request path.
    let msg_sign_pk = crate::message_signing::derive_message_signing_public_key(master_seed, net)?;
    blob.classical_address_bytes = shekyl_address::classical_segment_bytes(
        shekyl_address::ADDRESS_VERSION_V1,
        blob.spend_pk.as_canonical_bytes(),
        blob.view_pk.as_canonical_bytes(),
        &msg_sign_pk,
    );

    Ok(blob)
}

/// Derive an account from its 32-byte seed: the one entry point every
/// network uses (NI-R7). Returns the normalised master seed and the
/// fully-filled blob.
pub fn account_from_seed(
    seed: &[u8; SEED_BYTES],
    net: Network,
) -> Result<(Zeroizing<[u8; MASTER_SEED_BYTES]>, AllKeysBlob), CryptoError> {
    let master_seed = normalize_seed(seed);
    let blob = rederive_account(&master_seed, net)?;
    Ok((master_seed, blob))
}

/// An account derived from its 24 words: the seed the words spell (what
/// the wallet file stores), the master seed and the keys.
pub struct WordsAccount {
    /// The 32 bytes the words spell.
    pub seed: Zeroizing<[u8; SEED_BYTES]>,
    /// `normalize_seed(seed)`.
    pub master_seed: Zeroizing<[u8; MASTER_SEED_BYTES]>,
    /// Every key.
    pub blob: AllKeysBlob,
}

/// Derive an account from its 24 words: the words' 32 bytes, through
/// [`account_from_seed`].
pub fn account_from_words(words: &str, net: Network) -> Result<WordsAccount, CryptoError> {
    let seed = bip39::entropy_from_mnemonic(words)?;
    let (master_seed, blob) = account_from_seed(&seed, net)?;
    Ok(WordsAccount {
        seed,
        master_seed,
        blob,
    })
}

// --- address building / checking --------------------------------------------

/// Validate that a 1216-byte `m_pqc_public_key` is internally consistent
/// with the supplied Ed25519 view public key (i.e., its first 32 bytes are
/// the birational image of `view_pk`).
///
/// The ML-KEM-768 suffix must also be a well-formed encapsulation key
/// ([`crate::kem::check_ml_kem_768_ek`]).
///
/// This is the runtime invariant check C++ runs on every
/// `account_public_address` freshly loaded from the wire or from disk.
/// A mismatch means either corruption or an attacker substituting an
/// alternate X25519 pubkey for the one the view key mandates.
pub fn check_pqc_public_key_matches_view(
    pqc_public_key: &[u8; PQC_PUBLIC_KEY_BYTES],
    view_pk: &[u8; 32],
) -> Result<(), CryptoError> {
    let expected_x25519 = montgomery::ed25519_pk_to_x25519_pk(view_pk)?;
    if pqc_public_key[..32] != expected_x25519 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    crate::kem::check_ml_kem_768_ek(&pqc_public_key[32..])
}

pub use super::coinbase::{coinbase_recipient, RecipientRefused};

#[cfg(test)]
#[path = "coinbase_recipient_tests.rs"]
mod coinbase_recipient_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_for_is_the_name_id_then_the_purpose() {
        for net in [
            Network::Mainnet,
            Network::Testnet,
            Network::Stagenet,
            Network::Regtest,
        ] {
            let salt = salt_for(net);
            assert_eq!(
                salt[..16],
                net.name_id().as_bytes()[..],
                "{net}: name_id at position 0"
            );
            assert_eq!(
                &salt[16..],
                b"shekyl-master-derive-v3",
                "{net}: the purpose"
            );
        }
        assert_ne!(salt_for(Network::Mainnet), salt_for(Network::Regtest));
    }

    #[test]
    fn normalize_seed_is_deterministic_and_64_bytes() {
        let a = normalize_seed(b"hello");
        let b = normalize_seed(b"hello");
        assert_eq!(a.as_slice(), b.as_slice());
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn normalize_seed_differs_on_input_change() {
        let a = normalize_seed(b"input-1");
        let b = normalize_seed(b"input-2");
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn same_seed_different_networks_produce_different_scalars() {
        let seed = Zeroizing::new([0x11u8; MASTER_SEED_BYTES]);
        let a = derive_spend_wide(&seed, Network::Mainnet);
        let b = derive_spend_wide(&seed, Network::Stagenet);
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn spend_view_kem_are_all_distinct() {
        let seed = Zeroizing::new([0x33u8; MASTER_SEED_BYTES]);
        let s = derive_spend_wide(&seed, Network::Mainnet);
        let v = derive_view_wide(&seed, Network::Mainnet);
        let k = derive_kem_d_z(&seed, Network::Mainnet);
        assert_ne!(s.as_slice(), v.as_slice());
        assert_ne!(s.as_slice(), k.as_slice());
        assert_ne!(v.as_slice(), k.as_slice());
    }

    #[test]
    fn ml_kem_keypair_is_deterministic_in_d_z() {
        let d_z = [0x7Au8; 64];
        let (ek1, dk1) = ml_kem_keypair_from_d_z(&d_z).unwrap();
        let (ek2, dk2) = ml_kem_keypair_from_d_z(&d_z).unwrap();
        assert_eq!(ek1, ek2);
        assert_eq!(dk1.as_canonical_bytes(), dk2.as_canonical_bytes());
    }

    #[test]
    fn ml_kem_keypair_changes_on_d_z_change() {
        let mut d_z = [0u8; 64];
        let (ek_a, _) = ml_kem_keypair_from_d_z(&d_z).unwrap();
        d_z[0] = 1;
        let (ek_b, _) = ml_kem_keypair_from_d_z(&d_z).unwrap();
        assert_ne!(ek_a, ek_b);
    }

    #[test]
    fn rederive_account_is_deterministic() {
        let seed = [0x42u8; MASTER_SEED_BYTES];
        let blob1 = rederive_account(&seed, Network::Mainnet).unwrap();
        let blob2 = rederive_account(&seed, Network::Mainnet).unwrap();

        assert_eq!(blob1.spend_pk, blob2.spend_pk);
        assert_eq!(blob1.view_pk, blob2.view_pk);
        assert_eq!(blob1.ml_kem_ek, blob2.ml_kem_ek);
        assert_eq!(blob1.x25519_pk, blob2.x25519_pk);
        assert_eq!(blob1.pqc_public_key, blob2.pqc_public_key);
        assert_eq!(blob1.classical_address_bytes, blob2.classical_address_bytes);
        assert_eq!(
            blob1.spend_sk.as_canonical_bytes(),
            blob2.spend_sk.as_canonical_bytes(),
        );
        assert_eq!(
            blob1.view_sk.as_canonical_bytes(),
            blob2.view_sk.as_canonical_bytes(),
        );
        assert_eq!(
            blob1.ml_kem_dk.as_canonical_bytes(),
            blob2.ml_kem_dk.as_canonical_bytes(),
        );
    }

    /// NI-R7: the same 32 bytes on two networks give unrelated keys.
    #[test]
    fn one_seed_on_every_network_gives_unrelated_accounts() {
        let seed = [0x5Au8; SEED_BYTES];
        let mut spends = std::collections::HashSet::new();
        for net in Network::ALL {
            let (_master, blob) = account_from_seed(&seed, net).unwrap();
            assert!(spends.insert(*blob.spend_pk.as_canonical_bytes()), "{net}");
        }
    }

    /// NI-R7: the words and the bytes are two spellings of one secret.
    #[test]
    fn the_words_and_the_bytes_give_the_same_wallet() {
        let seed = [0xC3u8; SEED_BYTES];
        let words = bip39::mnemonic_from_entropy(&seed).unwrap();
        let WordsAccount {
            seed: from_words_seed,
            master_seed: from_words_master,
            blob: from_words,
        } = account_from_words(&words, Network::Mainnet).unwrap();
        let (from_bytes_master, from_bytes) = account_from_seed(&seed, Network::Mainnet).unwrap();
        assert_eq!(from_words_seed.as_slice(), seed.as_slice());
        assert_eq!(from_words_master.as_slice(), from_bytes_master.as_slice());
        assert_eq!(
            from_words.classical_address_bytes,
            from_bytes.classical_address_bytes
        );
        assert_eq!(from_words.ml_kem_ek, from_bytes.ml_kem_ek);
    }

    #[test]
    fn twelve_words_are_refused() {
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(account_from_words(twelve, Network::Mainnet).is_err());
    }

    #[test]
    fn pqc_public_key_matches_view_roundtrip() {
        let seed = [0x99u8; MASTER_SEED_BYTES];
        let blob = rederive_account(&seed, Network::Mainnet).unwrap();
        check_pqc_public_key_matches_view(&blob.pqc_public_key, blob.view_pk.as_canonical_bytes())
            .unwrap();
    }

    #[test]
    fn pqc_public_key_check_rejects_tampered_x25519() {
        let seed = [0x99u8; MASTER_SEED_BYTES];
        let mut blob = rederive_account(&seed, Network::Mainnet).unwrap();
        blob.pqc_public_key[0] ^= 0x01;
        assert!(check_pqc_public_key_matches_view(
            &blob.pqc_public_key,
            blob.view_pk.as_canonical_bytes()
        )
        .is_err());
    }

    /// An encapsulation key with a coefficient at or above `q` is not an
    /// address's key, whatever its X25519 prefix: all-ones encodes 4095.
    #[test]
    fn pqc_public_key_check_rejects_a_malformed_kem_key() {
        let seed = [0x99u8; MASTER_SEED_BYTES];
        let mut blob = rederive_account(&seed, Network::Mainnet).unwrap();
        blob.pqc_public_key[32..].fill(0xff);
        assert!(check_pqc_public_key_matches_view(
            &blob.pqc_public_key,
            blob.view_pk.as_canonical_bytes()
        )
        .is_err());
    }

    #[test]
    fn mlkem_chacha_seed_is_32_bytes_and_input_sensitive() {
        let a = ml_kem_chacha_seed_from_d_z(&[0u8; 64]);
        let mut d = [0u8; 64];
        d[63] = 1;
        let b = ml_kem_chacha_seed_from_d_z(&d);
        assert_ne!(a, b, "SHA3-256 must commit to every byte of d_z");
        assert_eq!(a.len(), 32);
    }
}
