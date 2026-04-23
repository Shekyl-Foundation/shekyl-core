// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl wallet-account key derivation, stabilized and frozen at v1.
//!
//! This module is the **single source of truth** for how a Shekyl wallet's
//! keys are derived from a user-supplied seed. Every byte of every address
//! ever minted on mainnet or stagenet is reproducible by running the inputs
//! through this one file. The derivation is frozen at release tag `v1` and
//! pinned in CI by the `ADDRESS_DERIVATION_V1` KAT suite.
//!
//! # Pipeline overview
//!
//! ```text
//!                            ┌────────────────────────────────────────┐
//!   User-visible input:      │ BIP-39 24-word mnemonic [+ passphrase] │ (mainnet, stagenet)
//!                            │  OR                                    │
//!                            │ 32-byte raw seed (OsRng or hex)        │ (testnet, fakechain)
//!                            └─────────────────┬──────────────────────┘
//!                                              │
//!                                              ▼
//!                   ┌─────────────────────────────────────┐
//!                   │ BIP-39:  PBKDF2-HMAC-SHA512          │
//!                   │          2048 iters, 64 B out        │
//!                   │ RAW32:   identity (32 B in, 32 B     │
//!                   │          passed as ikm)              │
//!                   └──────────────────┬──────────────────┘
//!                                      │
//!                                      ▼
//!                   ┌─────────────────────────────────────┐
//!                   │ normalize_seed: HKDF-SHA-512         │
//!                   │  salt = "shekyl-seed-normalize-v1"   │
//!                   │  ikm  = previous-step output          │
//!                   │  info = ""                           │
//!                   │  L    = 64                           │
//!                   └──────────────────┬──────────────────┘
//!                                      │
//!                                      ▼
//!                         master_seed_64 (what the wallet file stores)
//!                                      │
//!         ┌────────────────────────────┼────────────────────────────┐
//!         │                            │                            │
//!         ▼                            ▼                            ▼
//!  HKDF (salt_for(net,fmt),     HKDF (salt_for(net,fmt),      HKDF (salt_for(net,fmt),
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
//!                                                                ChaCha20Rng::from_seed
//!                                                                        │
//!                                                                        ▼
//!                                                                ml_kem_768::KG::
//!                                                                  try_keygen_with_rng
//!                                                                  → (ek, dk)
//! ```
//!
//! The SHA3-ChaCha intermediary exists because `fips203 = "=0.4.3"` does not
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
//! extra 32 bytes per derivation to eliminate the caveat. This decision is
//! frozen with the rest of the v1 pipeline.
//!
//! # Why the salt binds both network and format
//!
//! An accidentally-reused seed across networks or formats must not produce
//! overlapping keys. Binding `<network>-<format>` into the HKDF salt makes
//! cross-contamination impossible at the derivation level even if a user
//! imports a mainnet BIP-39 phrase as a testnet raw-seed (they can't, the
//! wallet UI rejects it, but the salt enforces the separation belt-and-
//! braces).

use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha512;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, Zeroizing};

use fips203::ml_kem_768;
use fips203::traits::{KeyGen, SerDes};

use crate::bip39;
use crate::kem::{ML_KEM_768_DK_LEN, ML_KEM_768_EK_LEN};
use crate::montgomery;
use crate::CryptoError;

// --- constants ---------------------------------------------------------------

/// Fixed length of the Shekyl master seed, after normalization. Every wallet
/// file stores exactly this many bytes inside its encrypted envelope.
pub const MASTER_SEED_BYTES: usize = 64;

/// Fixed length of a raw 32-byte seed (testnet and fakechain only).
pub const RAW_SEED_BYTES: usize = 32;

/// Wire byte for `SeedFormat::Bip39`. Part of the wallet-file AAD; changing
/// this value in any future version requires a migration.
pub const SEED_FORMAT_BIP39: u8 = 0x01;

/// Wire byte for `SeedFormat::Raw32`. Part of the wallet-file AAD.
pub const SEED_FORMAT_RAW32: u8 = 0x02;

/// Length of the Shekyl classical-segment address bytes. 1-byte version plus
/// 32-byte spend public key plus 32-byte view public key.
pub const CLASSICAL_ADDRESS_BYTES: usize = 1 + 32 + 32;

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

// --- seed format -------------------------------------------------------------

/// Which input format produced the master seed.
///
/// This value is bound to the wallet-file AAD so that a wallet written in one
/// format cannot be opened as the other — a raw-seed wallet cannot be
/// accidentally re-entered as a BIP-39 mnemonic, and vice versa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedFormat {
    /// BIP-39 24-word English mnemonic; passphrase defaults to empty.
    /// Permitted on `Mainnet` and `Stagenet` only.
    Bip39,
    /// 32-byte raw seed from OsRng (or a `--generate-from-raw-seed-hex` dev
    /// flag). Permitted on `Testnet` and `Fakechain` only.
    Raw32,
}

impl SeedFormat {
    /// Wire byte; included in wallet-file AAD.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            SeedFormat::Bip39 => SEED_FORMAT_BIP39,
            SeedFormat::Raw32 => SEED_FORMAT_RAW32,
        }
    }

    /// Parse the wire byte back to a format. Returns `None` on any unknown
    /// discriminant; wallet-file parsing treats that as a corruption.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            SEED_FORMAT_BIP39 => Some(SeedFormat::Bip39),
            SEED_FORMAT_RAW32 => Some(SeedFormat::Raw32),
            _ => None,
        }
    }

    /// Salt-component label used in `salt_for`.
    fn salt_label(self) -> &'static [u8] {
        match self {
            SeedFormat::Bip39 => b"bip39",
            SeedFormat::Raw32 => b"raw32",
        }
    }
}

// --- derivation network ------------------------------------------------------

/// Shekyl derivation-time network. Distinct from `shekyl_address::Network`
/// because `Fakechain` is a dev-only network that borrows Testnet's address
/// encoding but must not share derivation salts with it — a seed that
/// generated a Fakechain wallet must produce different keys than the same
/// seed entered on Testnet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerivationNetwork {
    Mainnet,
    Testnet,
    Stagenet,
    Fakechain,
}

impl DerivationNetwork {
    /// Wire byte. Not stored anywhere today, but reserved for future
    /// wallet-file extensions that want to bind network into the AAD
    /// independently of the salt.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            DerivationNetwork::Mainnet => 0,
            DerivationNetwork::Testnet => 1,
            DerivationNetwork::Stagenet => 2,
            DerivationNetwork::Fakechain => 3,
        }
    }

    /// Parse the wire byte; `None` on unknown discriminant.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(DerivationNetwork::Mainnet),
            1 => Some(DerivationNetwork::Testnet),
            2 => Some(DerivationNetwork::Stagenet),
            3 => Some(DerivationNetwork::Fakechain),
            _ => None,
        }
    }

    /// Map to the address-layer network. Fakechain addresses reuse the
    /// Testnet HRPs; this is consistent with legacy Monero fakechain
    /// behavior and keeps block-explorer tooling simple.
    #[must_use]
    pub fn to_address_network(self) -> shekyl_address::Network {
        match self {
            DerivationNetwork::Mainnet => shekyl_address::Network::Mainnet,
            DerivationNetwork::Testnet | DerivationNetwork::Fakechain => {
                shekyl_address::Network::Testnet
            }
            DerivationNetwork::Stagenet => shekyl_address::Network::Stagenet,
        }
    }

    /// Salt-component label used in `salt_for`.
    fn salt_label(self) -> &'static [u8] {
        match self {
            DerivationNetwork::Mainnet => b"mainnet",
            DerivationNetwork::Testnet => b"testnet",
            DerivationNetwork::Stagenet => b"stagenet",
            DerivationNetwork::Fakechain => b"fakechain",
        }
    }

    /// Valid seed formats for this network.
    #[must_use]
    pub fn permitted_seed_format(self, fmt: SeedFormat) -> bool {
        matches!(
            (self, fmt),
            (
                DerivationNetwork::Mainnet | DerivationNetwork::Stagenet,
                SeedFormat::Bip39
            ) | (
                DerivationNetwork::Testnet | DerivationNetwork::Fakechain,
                SeedFormat::Raw32
            )
        )
    }
}

// --- salt construction -------------------------------------------------------

/// Build the HKDF salt bound to a (network, format) pair. The value is
/// `b"shekyl-master-derive-v1-" || network || b"-" || format`, concatenated
/// with single hyphens and all ASCII. The result has bounded length and
/// never contains internal NUL bytes.
///
/// Example: `b"shekyl-master-derive-v1-mainnet-bip39"`.
#[must_use]
pub fn salt_for(net: DerivationNetwork, fmt: SeedFormat) -> Vec<u8> {
    let prefix: &[u8] = b"shekyl-master-derive-v1-";
    let mut out = Vec::with_capacity(prefix.len() + 32);
    out.extend_from_slice(prefix);
    out.extend_from_slice(net.salt_label());
    out.push(b'-');
    out.extend_from_slice(fmt.salt_label());
    out
}

// --- normalize_seed ----------------------------------------------------------

/// Normalize an arbitrary-length input into a fixed 64-byte master seed.
///
/// This is HKDF-SHA-512 with salt `shekyl-seed-normalize-v1`, empty info,
/// and output length 64. Applied to **both** the BIP-39 PBKDF2-HMAC-SHA512
/// output (64 B) and the raw 32-byte OsRng seed so that the on-disk
/// `master_seed_64` is format-independent.
///
/// Rationale for the extra HKDF step: a 32-byte raw seed has 256 bits of
/// entropy; a 64-byte PBKDF2 output has ~256 bits too (PBKDF2 doesn't add
/// entropy). Re-expanding to 64 bytes via HKDF-Extract-then-Expand produces
/// a domain-separated 64-byte value that is statistically indistinguishable
/// from uniform and identical in shape regardless of which format it came
/// from. The entire downstream derivation then works with one type.
pub fn normalize_seed(ikm: &[u8]) -> Zeroizing<[u8; MASTER_SEED_BYTES]> {
    let hk = Hkdf::<Sha512>::new(Some(SEED_NORMALIZE_SALT), ikm);
    let mut out = [0u8; MASTER_SEED_BYTES];
    hk.expand(b"", &mut out)
        .expect("64 bytes < HKDF-SHA-512 max output");
    Zeroizing::new(out)
}

// --- HKDF sub-derivations ---------------------------------------------------

/// Expand `master_seed` into a 64-byte HKDF output using the supplied info
/// label and the salt derived from `(network, format)`. Internal helper.
fn hkdf_expand_64(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
    info: &[u8],
) -> Zeroizing<[u8; 64]> {
    let salt = salt_for(net, fmt);
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
    net: DerivationNetwork,
    fmt: SeedFormat,
) -> Zeroizing<[u8; 64]> {
    hkdf_expand_64(master_seed, net, fmt, SPEND_INFO)
}

/// Expand to the 64-byte intermediate for the Ed25519 view scalar.
/// Consumers wide-reduce via [`wide_reduce_to_scalar`].
pub fn derive_view_wide(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
) -> Zeroizing<[u8; 64]> {
    hkdf_expand_64(master_seed, net, fmt, VIEW_INFO)
}

/// Expand to the 64-byte `d_z` fed into the ML-KEM SHA3-ChaCha intermediary.
pub fn derive_kem_d_z(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
) -> Zeroizing<[u8; 64]> {
    hkdf_expand_64(master_seed, net, fmt, KEM_INFO)
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
#[must_use]
pub fn ml_kem_chacha_seed_from_d_z(d_z: &[u8; 64]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(MLKEM_CHACHA_SEED_PREFIX);
    hasher.update(d_z);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    debug_assert_eq!(digest.len(), 32, "SHA3-256 output must be 32 bytes");
    out.copy_from_slice(&digest[..]);
    out
}

/// Produce an ML-KEM-768 `(ek, dk)` pair deterministically from a
/// 64-byte `d_z`. The output is byte-identical on every run with the same
/// input; this is the property that makes wallet rederivation possible.
///
/// On success the decap key is written into the caller-provided
/// `Zeroizing` buffer.
pub fn ml_kem_keypair_from_d_z(
    d_z: &[u8; 64],
) -> Result<([u8; ML_KEM_768_EK_LEN], Zeroizing<[u8; ML_KEM_768_DK_LEN]>), CryptoError> {
    let chacha_seed = ml_kem_chacha_seed_from_d_z(d_z);
    let mut rng = ChaCha20Rng::from_seed(chacha_seed);
    let (ek, dk) = ml_kem_768::KG::try_keygen_with_rng(&mut rng)
        .map_err(|e| CryptoError::KeyGenerationFailed(format!("ML-KEM-768 keygen: {e}")))?;

    let ek_bytes: [u8; ML_KEM_768_EK_LEN] = ek.into_bytes();
    let dk_bytes: [u8; ML_KEM_768_DK_LEN] = dk.into_bytes();
    Ok((ek_bytes, Zeroizing::new(dk_bytes)))
}

// --- AllKeysBlob: the C-layout struct crossed over FFI -----------------------

/// Fixed-layout struct carrying every byte needed to construct a wallet
/// account from a master seed. The C++ side passes a pointer to an
/// `mlock`'d allocation of this size; Rust fills the bytes in place.
/// On any error Rust zeroes the entire struct before returning failure,
/// so the caller never has to distinguish "untouched" from "partially
/// written".
///
/// Layout is frozen at v1. Do not add, remove, or reorder fields without
/// bumping the derivation version and the KAT manifest hash.
#[repr(C)]
#[derive(Clone)]
pub struct AllKeysBlob {
    // --- public side (plain-text portion of the wallet) ------------------
    /// Ed25519 spend public key.
    pub spend_pk: [u8; 32],
    /// Ed25519 view public key.
    pub view_pk: [u8; 32],
    /// ML-KEM-768 encap (public) key, 1184 bytes.
    pub ml_kem_ek: [u8; ML_KEM_768_EK_LEN],
    /// X25519 public key, derived from `view_pk` via the Edwards-to-Montgomery
    /// birational map `u = (1 + y) / (1 - y) mod p`.
    pub x25519_pk: [u8; 32],
    /// `x25519_pk || ml_kem_ek`, byte-identical to what C++ stores as
    /// `account_public_address::m_pqc_public_key`. 1216 bytes.
    pub pqc_public_key: [u8; PQC_PUBLIC_KEY_BYTES],
    /// `version || spend_pk || view_pk`, byte-identical to what C++ stores
    /// as `m_expected_classical_address_bytes`. 65 bytes.
    pub classical_address_bytes: [u8; CLASSICAL_ADDRESS_BYTES],

    // --- secret side (held by C++ only as opaque bytes) -------------------
    /// Ed25519 spend secret scalar, in canonical 32-byte little-endian form.
    pub spend_sk: [u8; 32],
    /// Ed25519 view secret scalar, in canonical 32-byte little-endian form.
    /// Also used (unclamped) as the Montgomery scalar at ECDH sites.
    pub view_sk: [u8; 32],
    /// ML-KEM-768 decap (secret) key, 2400 bytes. Rederived on every wallet
    /// open; persisted only via the master seed.
    pub ml_kem_dk: [u8; ML_KEM_768_DK_LEN],
}

impl AllKeysBlob {
    /// Byte-for-byte zero. Used at the start of every fill and on every
    /// failure path to guarantee constant-time write patterns.
    pub fn zeroed() -> Self {
        AllKeysBlob {
            spend_pk: [0u8; 32],
            view_pk: [0u8; 32],
            ml_kem_ek: [0u8; ML_KEM_768_EK_LEN],
            x25519_pk: [0u8; 32],
            pqc_public_key: [0u8; PQC_PUBLIC_KEY_BYTES],
            classical_address_bytes: [0u8; CLASSICAL_ADDRESS_BYTES],
            spend_sk: [0u8; 32],
            view_sk: [0u8; 32],
            ml_kem_dk: [0u8; ML_KEM_768_DK_LEN],
        }
    }
}

impl Drop for AllKeysBlob {
    fn drop(&mut self) {
        self.spend_sk.zeroize();
        self.view_sk.zeroize();
        self.ml_kem_dk.zeroize();
        // Public fields do not need zeroization but we clear them for
        // uniform write patterns and to avoid accidental reuse of stale
        // public material that the caller may consider authoritative.
        self.spend_pk.zeroize();
        self.view_pk.zeroize();
        self.ml_kem_ek.fill(0);
        self.x25519_pk.zeroize();
        self.pqc_public_key.fill(0);
        self.classical_address_bytes.zeroize();
    }
}

// --- end-to-end derivation flows --------------------------------------------

/// Rederive every key from an existing 64-byte master seed. This is the
/// path taken on every wallet-open and by the freeze tooling when it
/// regenerates addresses for the KAT manifest.
///
/// Returns the filled blob on success. On failure the blob is guaranteed
/// to contain the zero value — any caller that observes a `CryptoError`
/// can safely treat the memory as uninitialised.
pub fn rederive_account(
    master_seed: &[u8; MASTER_SEED_BYTES],
    net: DerivationNetwork,
    fmt: SeedFormat,
) -> Result<AllKeysBlob, CryptoError> {
    if !net.permitted_seed_format(fmt) {
        return Err(CryptoError::InvalidInput(format!(
            "{net:?} does not permit {fmt:?} seed format"
        )));
    }

    let mut blob = AllKeysBlob::zeroed();

    // Ed25519 spend
    let spend_wide = derive_spend_wide(master_seed, net, fmt);
    let spend_scalar = wide_reduce_to_scalar(&spend_wide);
    blob.spend_sk.copy_from_slice(spend_scalar.as_bytes());
    let spend_pub = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &spend_scalar;
    blob.spend_pk
        .copy_from_slice(spend_pub.compress().as_bytes());

    // Ed25519 view
    let view_wide = derive_view_wide(master_seed, net, fmt);
    let view_scalar = wide_reduce_to_scalar(&view_wide);
    blob.view_sk.copy_from_slice(view_scalar.as_bytes());
    let view_pub_edw = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &view_scalar;
    let view_pub_compressed = view_pub_edw.compress();
    blob.view_pk.copy_from_slice(view_pub_compressed.as_bytes());

    // X25519 public via birational. Failure here means the view scalar
    // produced an identity or low-order Ed25519 point; the probability is
    // cryptographically negligible but we surface it cleanly. On error,
    // `blob` is dropped here, which zeroes its secret fields via
    // `AllKeysBlob::drop`.
    let x25519_pk = montgomery::ed25519_pk_to_x25519_pk(&blob.view_pk)?;
    blob.x25519_pk.copy_from_slice(&x25519_pk);

    // ML-KEM-768 deterministic keygen
    let d_z = derive_kem_d_z(master_seed, net, fmt);
    let (ek, dk) = ml_kem_keypair_from_d_z(&d_z)?;
    blob.ml_kem_ek.copy_from_slice(&ek);
    blob.ml_kem_dk.copy_from_slice(dk.as_slice());

    // Composite fields
    blob.pqc_public_key[..32].copy_from_slice(&blob.x25519_pk);
    blob.pqc_public_key[32..].copy_from_slice(&blob.ml_kem_ek);

    blob.classical_address_bytes[0] = shekyl_address::ADDRESS_VERSION_V1;
    blob.classical_address_bytes[1..33].copy_from_slice(&blob.spend_pk);
    blob.classical_address_bytes[33..65].copy_from_slice(&blob.view_pk);

    Ok(blob)
}

/// Generate a new account from a BIP-39 24-word mnemonic plus optional
/// passphrase. Returns both the normalised master seed (for wallet-file
/// persistence) and the fully-filled blob.
///
/// Only permitted on `Mainnet` and `Stagenet`. On any other network the
/// call returns `InvalidInput`.
pub fn generate_account_from_bip39(
    mnemonic: &str,
    passphrase: &str,
    net: DerivationNetwork,
) -> Result<(Zeroizing<[u8; MASTER_SEED_BYTES]>, AllKeysBlob), CryptoError> {
    if !net.permitted_seed_format(SeedFormat::Bip39) {
        return Err(CryptoError::InvalidInput(format!(
            "{net:?} does not permit BIP-39 seed format"
        )));
    }

    let pbkdf2_seed = bip39::mnemonic_to_pbkdf2_seed(mnemonic, passphrase)?;
    let master_seed = normalize_seed(pbkdf2_seed.as_slice());
    let blob = rederive_account(&master_seed, net, SeedFormat::Bip39)?;
    Ok((master_seed, blob))
}

/// Generate a new account from a 32-byte raw seed (testnet, fakechain).
/// The raw seed is typically produced by the wallet's own OsRng call
/// immediately before this function runs.
///
/// Returns both the normalised master seed (for wallet-file persistence)
/// and the fully-filled blob. Only permitted on `Testnet` and `Fakechain`.
pub fn generate_account_from_raw_seed(
    raw_seed: &[u8; RAW_SEED_BYTES],
    net: DerivationNetwork,
) -> Result<(Zeroizing<[u8; MASTER_SEED_BYTES]>, AllKeysBlob), CryptoError> {
    if !net.permitted_seed_format(SeedFormat::Raw32) {
        return Err(CryptoError::InvalidInput(format!(
            "{net:?} does not permit raw-seed format"
        )));
    }

    let master_seed = normalize_seed(raw_seed);
    let blob = rederive_account(&master_seed, net, SeedFormat::Raw32)?;
    Ok((master_seed, blob))
}

// --- address building / checking --------------------------------------------

/// Assemble the 1216-byte `m_pqc_public_key` from its two parts. Used by
/// the FFI surface that rebuilds an `account_public_address` from raw
/// components post-rederive.
#[must_use]
pub fn build_pqc_public_key(
    x25519_pk: &[u8; 32],
    ml_kem_ek: &[u8; ML_KEM_768_EK_LEN],
) -> [u8; PQC_PUBLIC_KEY_BYTES] {
    let mut out = [0u8; PQC_PUBLIC_KEY_BYTES];
    out[..32].copy_from_slice(x25519_pk);
    out[32..].copy_from_slice(ml_kem_ek);
    out
}

/// Validate that a 1216-byte `m_pqc_public_key` is internally consistent
/// with the supplied Ed25519 view public key (i.e., its first 32 bytes are
/// the birational image of `view_pk`).
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_for_produces_expected_strings() {
        assert_eq!(
            salt_for(DerivationNetwork::Mainnet, SeedFormat::Bip39),
            b"shekyl-master-derive-v1-mainnet-bip39"
        );
        assert_eq!(
            salt_for(DerivationNetwork::Stagenet, SeedFormat::Bip39),
            b"shekyl-master-derive-v1-stagenet-bip39"
        );
        assert_eq!(
            salt_for(DerivationNetwork::Testnet, SeedFormat::Raw32),
            b"shekyl-master-derive-v1-testnet-raw32"
        );
        assert_eq!(
            salt_for(DerivationNetwork::Fakechain, SeedFormat::Raw32),
            b"shekyl-master-derive-v1-fakechain-raw32"
        );
    }

    #[test]
    fn permitted_seed_formats_mainnet_stagenet_bip39_only() {
        assert!(DerivationNetwork::Mainnet.permitted_seed_format(SeedFormat::Bip39));
        assert!(!DerivationNetwork::Mainnet.permitted_seed_format(SeedFormat::Raw32));
        assert!(DerivationNetwork::Stagenet.permitted_seed_format(SeedFormat::Bip39));
        assert!(!DerivationNetwork::Stagenet.permitted_seed_format(SeedFormat::Raw32));
    }

    #[test]
    fn permitted_seed_formats_testnet_fakechain_raw32_only() {
        assert!(DerivationNetwork::Testnet.permitted_seed_format(SeedFormat::Raw32));
        assert!(!DerivationNetwork::Testnet.permitted_seed_format(SeedFormat::Bip39));
        assert!(DerivationNetwork::Fakechain.permitted_seed_format(SeedFormat::Raw32));
        assert!(!DerivationNetwork::Fakechain.permitted_seed_format(SeedFormat::Bip39));
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
        let a = derive_spend_wide(&seed, DerivationNetwork::Mainnet, SeedFormat::Bip39);
        let b = derive_spend_wide(&seed, DerivationNetwork::Stagenet, SeedFormat::Bip39);
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn same_seed_different_formats_produce_different_scalars() {
        let seed = Zeroizing::new([0x22u8; MASTER_SEED_BYTES]);
        let a = derive_spend_wide(&seed, DerivationNetwork::Testnet, SeedFormat::Raw32);
        let b = derive_spend_wide(&seed, DerivationNetwork::Mainnet, SeedFormat::Bip39);
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn spend_view_kem_are_all_distinct() {
        let seed = Zeroizing::new([0x33u8; MASTER_SEED_BYTES]);
        let s = derive_spend_wide(&seed, DerivationNetwork::Mainnet, SeedFormat::Bip39);
        let v = derive_view_wide(&seed, DerivationNetwork::Mainnet, SeedFormat::Bip39);
        let k = derive_kem_d_z(&seed, DerivationNetwork::Mainnet, SeedFormat::Bip39);
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
        assert_eq!(dk1.as_slice(), dk2.as_slice());
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
        let blob1 = rederive_account(&seed, DerivationNetwork::Mainnet, SeedFormat::Bip39).unwrap();
        let blob2 = rederive_account(&seed, DerivationNetwork::Mainnet, SeedFormat::Bip39).unwrap();

        assert_eq!(blob1.spend_pk, blob2.spend_pk);
        assert_eq!(blob1.view_pk, blob2.view_pk);
        assert_eq!(blob1.ml_kem_ek, blob2.ml_kem_ek);
        assert_eq!(blob1.x25519_pk, blob2.x25519_pk);
        assert_eq!(blob1.pqc_public_key, blob2.pqc_public_key);
        assert_eq!(blob1.classical_address_bytes, blob2.classical_address_bytes);
        assert_eq!(blob1.spend_sk, blob2.spend_sk);
        assert_eq!(blob1.view_sk, blob2.view_sk);
        assert_eq!(blob1.ml_kem_dk, blob2.ml_kem_dk);
    }

    #[test]
    fn rederive_rejects_network_format_mismatch() {
        let seed = [0x42u8; MASTER_SEED_BYTES];
        // Mainnet + Raw32 is not permitted.
        assert!(rederive_account(&seed, DerivationNetwork::Mainnet, SeedFormat::Raw32).is_err());
        // Testnet + Bip39 is not permitted.
        assert!(rederive_account(&seed, DerivationNetwork::Testnet, SeedFormat::Bip39).is_err());
    }

    #[test]
    fn generate_from_bip39_mainnet_roundtrips_to_rederive() {
        let entropy = [0u8; 32];
        let words = bip39::mnemonic_from_entropy(&entropy).unwrap();

        let (seed, blob_a) =
            generate_account_from_bip39(&words, "", DerivationNetwork::Mainnet).unwrap();
        let blob_b =
            rederive_account(&seed, DerivationNetwork::Mainnet, SeedFormat::Bip39).unwrap();

        assert_eq!(blob_a.spend_pk, blob_b.spend_pk);
        assert_eq!(blob_a.view_pk, blob_b.view_pk);
        assert_eq!(blob_a.ml_kem_ek, blob_b.ml_kem_ek);
        assert_eq!(blob_a.pqc_public_key, blob_b.pqc_public_key);
        assert_eq!(
            blob_a.classical_address_bytes,
            blob_b.classical_address_bytes
        );
    }

    #[test]
    fn generate_from_raw_seed_testnet_roundtrips_to_rederive() {
        let raw = [0xAAu8; 32];
        let (seed, blob_a) =
            generate_account_from_raw_seed(&raw, DerivationNetwork::Testnet).unwrap();
        let blob_b =
            rederive_account(&seed, DerivationNetwork::Testnet, SeedFormat::Raw32).unwrap();

        assert_eq!(blob_a.spend_pk, blob_b.spend_pk);
        assert_eq!(blob_a.view_pk, blob_b.view_pk);
        assert_eq!(blob_a.pqc_public_key, blob_b.pqc_public_key);
    }

    #[test]
    fn generate_from_bip39_rejects_non_mainnet_stagenet() {
        let entropy = [0u8; 32];
        let words = bip39::mnemonic_from_entropy(&entropy).unwrap();
        assert!(generate_account_from_bip39(&words, "", DerivationNetwork::Testnet).is_err());
        assert!(generate_account_from_bip39(&words, "", DerivationNetwork::Fakechain).is_err());
    }

    #[test]
    fn generate_from_raw_seed_rejects_mainnet_stagenet() {
        let raw = [0u8; 32];
        assert!(generate_account_from_raw_seed(&raw, DerivationNetwork::Mainnet).is_err());
        assert!(generate_account_from_raw_seed(&raw, DerivationNetwork::Stagenet).is_err());
    }

    #[test]
    fn different_passphrases_yield_different_accounts() {
        let entropy = [0x55u8; 32];
        let words = bip39::mnemonic_from_entropy(&entropy).unwrap();

        let (_, a) = generate_account_from_bip39(&words, "", DerivationNetwork::Mainnet).unwrap();
        let (_, b) =
            generate_account_from_bip39(&words, "TREZOR", DerivationNetwork::Mainnet).unwrap();

        assert_ne!(a.spend_pk, b.spend_pk);
        assert_ne!(a.view_pk, b.view_pk);
    }

    #[test]
    fn pqc_public_key_matches_view_roundtrip() {
        let seed = [0x99u8; MASTER_SEED_BYTES];
        let blob = rederive_account(&seed, DerivationNetwork::Mainnet, SeedFormat::Bip39).unwrap();
        check_pqc_public_key_matches_view(&blob.pqc_public_key, &blob.view_pk).unwrap();
    }

    #[test]
    fn pqc_public_key_check_rejects_tampered_x25519() {
        let seed = [0x99u8; MASTER_SEED_BYTES];
        let mut blob =
            rederive_account(&seed, DerivationNetwork::Mainnet, SeedFormat::Bip39).unwrap();
        blob.pqc_public_key[0] ^= 0x01;
        assert!(check_pqc_public_key_matches_view(&blob.pqc_public_key, &blob.view_pk).is_err());
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
