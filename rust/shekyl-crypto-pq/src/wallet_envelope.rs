// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl wallet file format v1 — two-file, two-level-KEK, capability-mode
//! envelope with Stance Minimum-Leak AAD.
//!
//! # On-disk layout
//!
//! ## `<name>.wallet.keys`
//!
//! Contains the seed / capability block. Written once at wallet creation and
//! re-written only on password rotation thereafter. Auto-save never touches
//! this file.
//!
//! ```text
//!   offset  size  contents
//!   ------  ----  --------
//!   [0..8)   8   magic = "SHEKYLWT"                       ┐
//!   [8..9)   1   file_version = 0x01                      │ AAD, every AEAD
//!   [9..10)  1   kdf_algo = 0x01 (Argon2id)               │       ┐
//!   [10..11) 1   kdf_m_log2                               │       │ AAD,
//!   [11..12) 1   kdf_t                                    │       │ wrap AEAD
//!   [12..13) 1   kdf_p                                    │       │
//!   [13..29) 16  wrap_salt (rotates on password change)   ┘       ┘
//!   [29..30) 1   wrap_count (u8 = 1 in V3.0)
//!   [30..54) 24  wrap_nonce
//!   [54..102) 48 wrap_ct_with_tag = AEAD(file_kek, tag)    under wrap_key
//!                                   wrap_key = Argon2id(password, wrap_salt, …)
//!                                   nonce    = wrap_nonce
//!                                   aad      = bytes [0..29)
//!   [102..126) 24 region1_nonce
//!   [126..N)   _  region1_ct_with_tag = AEAD(plaintext, tag)  under file_kek
//!                                       nonce = region1_nonce
//!                                       aad   = bytes [0..9)
//!
//!   region 1 plaintext (length = 82 + cap_content_len):
//!     [0..1)     mode_byte
//!     [1..2)     network
//!     [2..3)     seed_format
//!     [3..68)    expected_classical_address[65]
//!     [68..70)   cap_content_len (u16 LE)
//!     [70..70+L) cap_content
//!     [70+L..78+L)  creation_timestamp (u64 LE)
//!     [78+L..82+L)  restore_height_hint (u32 LE)
//! ```
//!
//! ## `<name>.wallet`
//!
//! Contains the state block (transfers, tx keys, subaddresses, address book,
//! UI preferences — whatever the caller passes in as an opaque byte blob).
//! Rewritten on every auto-save.
//!
//! ```text
//!   offset  size  contents
//!   ------  ----  --------
//!   [0..8)   8   magic = "SHEKYLWS"                        ┐
//!   [8..9)   1   state_version = 0x01                      │ AAD
//!   [9..33)  24  region2_nonce (fresh per save)
//!   [33..M)  _   region2_ct_with_tag = AEAD(state, tag)    under file_kek
//!                                       nonce = region2_nonce
//!                                       aad   = bytes [0..9)
//!                                               || state_tag_of_seed_block[16]
//! ```
//!
//! Where `state_tag_of_seed_block` is the 16-byte Poly1305 tag of region 1
//! from the `.wallet.keys` file (i.e. the last 16 bytes of its
//! `region1_ct_with_tag`). The tag is not stored in `.wallet`; the opener
//! recovers it by re-reading the keys file. This binding:
//! - catches any attempt to swap one wallet's `.wallet.keys` onto another's
//!   `.wallet` (the swapped tag won't match the binding);
//! - survives password rotation, because rotation changes only the wrap layer;
//!   region 1 ciphertext + its Poly1305 tag are byte-identical for the life of
//!   the wallet.
//!
//! # Design principles
//!
//! - **Stance Minimum-Leak**: AAD carries only what a reader needs before
//!   attempting decryption (magic, version, KDF parameters). Everything else
//!   — capability mode, network, seed format, address — is encrypted.
//!   Poly1305 over the ciphertext catches any tampering; no integrity is
//!   lost by encrypting fields that are read after decrypt. See
//!   `.cursor/rules/36-secret-locality.mdc` for the secret-material policy.
//! - **Two-level KEK**: password → Argon2id → wrap_key → unwraps
//!   file_kek → decrypts region 1 and region 2. Password rotation only
//!   rewrites the wrapped_kek section; region 1 bytes stay byte-identical.
//! - **Pinned sizes + length-prefixed capability content**: Poly1305 prevents
//!   malformed content from surviving, but defensive `cap_content_len`
//!   parsing gives typed errors rather than buffer-overrun risk on any
//!   future format migration.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::kem::{ML_KEM_768_DK_LEN, ML_KEM_768_EK_LEN};

// ---------------------------------------------------------------------------
// Format constants. Every byte offset / length in this module refers to these.
// Any change to any of these values is a format break and must bump
// `WALLET_FILE_FORMAT_VERSION`.
// ---------------------------------------------------------------------------

/// ASCII magic for `.wallet.keys`. Eight bytes so it aligns cleanly and so
/// `file(1)` can detect it. "WT" = Wallet Keys.
pub const KEYS_FILE_MAGIC: &[u8; 8] = b"SHEKYLWT";

/// ASCII magic for `.wallet`. "WS" = Wallet State.
pub const STATE_FILE_MAGIC: &[u8; 8] = b"SHEKYLWS";

/// Version of the file format emitted by this implementation. Bumps on any
/// layout change; the parser refuses files whose `file_version` is greater.
pub const WALLET_FILE_FORMAT_VERSION: u8 = 0x01;
pub const STATE_FILE_FORMAT_VERSION: u8 = 0x01;

/// KDF algorithm identifier. Only Argon2id is defined; `kdf_algo` is a byte
/// so we can introduce alternatives in future versions without breaking the
/// AAD layout.
pub const KDF_ALGO_ARGON2ID: u8 = 0x01;

/// Default Argon2id cost parameters. OWASP 2024 memory-constrained profile
/// (64 MiB, t=3, p=1) — tuned so GPU cracking is not meaningfully faster than
/// CPU while staying under ~500 ms on a commodity desktop.
pub const DEFAULT_KDF_M_LOG2: u8 = 0x10; // 2^16 KiB = 64 MiB
pub const DEFAULT_KDF_T: u8 = 0x03;
pub const DEFAULT_KDF_P: u8 = 0x01;

/// Capability mode discriminators. Match the `SHEKYL_CAPABILITY_*` constants
/// in `src/shekyl/shekyl_ffi.h`.
pub const CAPABILITY_FULL: u8 = 0x01;
pub const CAPABILITY_VIEW_ONLY: u8 = 0x02;
pub const CAPABILITY_HARDWARE_OFFLOAD: u8 = 0x03;
pub const CAPABILITY_RESERVED_MULTISIG: u8 = 0x04;

/// Canonical 65-byte classical address body (version || spend_pk || view_pk)
/// used by the address invariant check in region 1.
pub const EXPECTED_CLASSICAL_ADDRESS_BYTES: usize = 65;

/// File-kek length, matching XChaCha20-Poly1305 key size.
const FILE_KEK_BYTES: usize = 32;
/// Argon2id-derived wrap_key length, matching XChaCha20-Poly1305 key size.
const WRAP_KEY_BYTES: usize = 32;
/// Argon2id salt length. 16 bytes is above the birthday bound for any
/// realistic wallet population.
const WRAP_SALT_BYTES: usize = 16;
/// XChaCha20-Poly1305 nonce length (24 B extended nonce).
const AEAD_NONCE_BYTES: usize = 24;
/// XChaCha20-Poly1305 Poly1305 tag length.
const AEAD_TAG_BYTES: usize = 16;

// Offsets in the `.wallet.keys` header (plaintext + AAD regions only).
const OFF_MAGIC: usize = 0;
const OFF_FILE_VERSION: usize = 8;
const OFF_KDF_ALGO: usize = 9;
const OFF_KDF_M_LOG2: usize = 10;
const OFF_KDF_T: usize = 11;
const OFF_KDF_P: usize = 12;
const OFF_WRAP_SALT: usize = 13;
const OFF_WRAP_COUNT: usize = 29;
const OFF_WRAP_NONCE: usize = 30;
const OFF_WRAP_CT: usize = 54;
const OFF_WRAP_CT_END: usize = OFF_WRAP_CT + FILE_KEK_BYTES + AEAD_TAG_BYTES; // 102
const OFF_REGION1_NONCE: usize = OFF_WRAP_CT_END;
const OFF_REGION1_CT: usize = OFF_REGION1_NONCE + AEAD_NONCE_BYTES; // 126

// Region 1 plaintext internal offsets (within the decrypted plaintext, not
// the on-disk file).
const R1_OFF_MODE: usize = 0;
const R1_OFF_NETWORK: usize = 1;
const R1_OFF_SEED_FORMAT: usize = 2;
const R1_OFF_EXPECTED_ADDR: usize = 3;
const R1_OFF_CAP_LEN: usize = R1_OFF_EXPECTED_ADDR + EXPECTED_CLASSICAL_ADDRESS_BYTES; // 68
const R1_OFF_CAP: usize = R1_OFF_CAP_LEN + 2; // 70
const R1_FIXED_HEAD_BYTES: usize = R1_OFF_CAP; // 70
const R1_TRAILER_BYTES: usize = 8 + 4; // creation_timestamp + restore_height_hint
const R1_MIN_PLAINTEXT_BYTES: usize = R1_FIXED_HEAD_BYTES + R1_TRAILER_BYTES; // 82

// `.wallet` file offsets.
const S_OFF_MAGIC: usize = 0;
const S_OFF_VERSION: usize = 8;
const S_OFF_NONCE: usize = 9;
const S_OFF_CT: usize = S_OFF_NONCE + AEAD_NONCE_BYTES; // 33

const STATE_AEAD_AAD_BYTES: usize = 9 + AEAD_TAG_BYTES; // magic||version||seed_block_tag

/// FIPS 203 layout offset inside a 2400-byte ML-KEM-768 decapsulation key:
/// `dk = dk_PKE(1152) || ek(1184) || H(ek)(32) || z(32)`.
const ML_KEM_768_DK_EK_OFFSET: usize = 384 * 3; // 1152 = k * 384 for k=3

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors surfaced by the wallet-file envelope. Mapped 1:1 onto FFI booleans
/// plus a last-error channel; the taxonomy is kept narrow so C++ can do
/// localized error messages without string matching.
#[derive(Debug, Error)]
pub enum WalletEnvelopeError {
    #[error("input buffer is too short to be a Shekyl wallet file")]
    TooShort,

    #[error("magic mismatch: not a Shekyl wallet file of the expected type")]
    BadMagic,

    #[error("format version {got:#x} is newer than this build supports (max {max:#x})")]
    FormatVersionTooNew { got: u8, max: u8 },

    #[error("unsupported KDF algorithm {0:#x}")]
    UnsupportedKdfAlgo(u8),

    #[error("KDF parameters out of range (m_log2={m_log2}, t={t}, p={p})")]
    KdfParamsOutOfRange { m_log2: u8, t: u8, p: u8 },

    #[error("wrapped_kek count {0} not supported in this version (expected 1)")]
    UnsupportedWrapCount(u8),

    #[error("cap_content_len {len} does not match capability mode {mode:#x}")]
    CapContentLenMismatch { mode: u8, len: u16 },

    #[error("unknown capability mode {0:#x}")]
    UnknownCapabilityMode(u8),

    #[error("this wallet requires Shekyl V3.1 or later (multisig mode)")]
    RequiresMultisigSupport,

    #[error("invalid password or corrupted wallet file")]
    InvalidPasswordOrCorrupt,

    #[error("wallet state file does not belong to this keys file (seed block tag mismatch)")]
    StateSeedBlockMismatch,

    #[error("internal error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Argon2id cost parameters. Values are stored in the wallet file and
/// therefore become part of the address-freeze / compat story.
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    /// Log2 of memory cost in KiB. `m_log2 = 0x10` ⇒ 64 MiB.
    pub m_log2: u8,
    /// Iteration (time) cost.
    pub t: u8,
    /// Parallelism (lanes).
    pub p: u8,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { m_log2: DEFAULT_KDF_M_LOG2, t: DEFAULT_KDF_T, p: DEFAULT_KDF_P }
    }
}

impl KdfParams {
    /// Validate that the parameters are within ranges accepted by the
    /// `argon2` crate. We allow m_log2 ∈ [8, 22] (256 KiB to 4 GiB),
    /// t ∈ [1, 64], p ∈ [1, 16]. The lower bound on m_log2 is intentionally
    /// loose so KAT fixtures can use a fast-stretching profile.
    fn validate(&self) -> Result<(), WalletEnvelopeError> {
        if !(8..=22).contains(&self.m_log2)
            || !(1..=64).contains(&self.t)
            || !(1..=16).contains(&self.p)
        {
            return Err(WalletEnvelopeError::KdfParamsOutOfRange {
                m_log2: self.m_log2,
                t: self.t,
                p: self.p,
            });
        }
        Ok(())
    }
}

/// Capability-mode content, borrowed. Callers own the storage; we only read
/// during seal. Contents match `SHEKYL_CAPABILITY_*` modes in the FFI header.
pub enum CapabilityContent<'a> {
    /// FULL wallet: can spend. Contains the 64-byte master seed; everything
    /// else (spend_sk, view_sk, ml_kem_dk) is rederived on every open via
    /// `shekyl_account_rederive`.
    Full { master_seed_64: &'a [u8; 64] },

    /// VIEW_ONLY wallet: can scan, cannot spend. Holds the classical view
    /// secret (also the X25519 scan secret, by RFC 7748 birational map), the
    /// ML-KEM-768 decapsulation key, and the spend public key required by
    /// the scanner's `O = h_o·G + B + y·T` check.
    ViewOnly {
        view_sk: &'a [u8; 32],
        ml_kem_dk: &'a [u8; ML_KEM_768_DK_LEN],
        spend_pk: &'a [u8; 32],
    },

    /// HARDWARE_OFFLOAD wallet: same as VIEW_ONLY plus an opaque device
    /// descriptor that wallet2 uses to reopen the signer channel. The
    /// descriptor is length-prefixed; its contents are not interpreted here.
    HardwareOffload {
        view_sk: &'a [u8; 32],
        ml_kem_dk: &'a [u8; ML_KEM_768_DK_LEN],
        spend_pk: &'a [u8; 32],
        device_desc: &'a [u8],
    },
}

impl CapabilityContent<'_> {
    fn mode_byte(&self) -> u8 {
        match self {
            Self::Full { .. } => CAPABILITY_FULL,
            Self::ViewOnly { .. } => CAPABILITY_VIEW_ONLY,
            Self::HardwareOffload { .. } => CAPABILITY_HARDWARE_OFFLOAD,
        }
    }

    fn serialized_len(&self) -> usize {
        match self {
            Self::Full { .. } => 64,
            Self::ViewOnly { .. } => 32 + ML_KEM_768_DK_LEN + 32,
            Self::HardwareOffload { device_desc, .. } => {
                32 + ML_KEM_768_DK_LEN + 32 + 2 + device_desc.len()
            }
        }
    }

    fn write_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Full { master_seed_64 } => out.extend_from_slice(master_seed_64.as_slice()),
            Self::ViewOnly { view_sk, ml_kem_dk, spend_pk } => {
                out.extend_from_slice(view_sk.as_slice());
                out.extend_from_slice(ml_kem_dk.as_slice());
                out.extend_from_slice(spend_pk.as_slice());
            }
            Self::HardwareOffload { view_sk, ml_kem_dk, spend_pk, device_desc } => {
                out.extend_from_slice(view_sk.as_slice());
                out.extend_from_slice(ml_kem_dk.as_slice());
                out.extend_from_slice(spend_pk.as_slice());
                let dev_len: u16 = device_desc
                    .len()
                    .try_into()
                    .expect("device_desc exceeds u16::MAX; rejected earlier");
                out.extend_from_slice(&dev_len.to_le_bytes());
                out.extend_from_slice(device_desc);
            }
        }
    }
}

/// AAD-only view of a `.wallet.keys` file. Returned by
/// [`inspect_keys_file`] and contains exactly the fields that are readable
/// without the password.
#[derive(Debug, Clone)]
pub struct KeysFileHeaderView {
    pub format_version: u8,
    pub kdf: KdfParams,
    pub wrap_salt: [u8; WRAP_SALT_BYTES],
    pub wrap_count: u8,
}

/// Full decrypted contents of a `.wallet.keys` file. Secret-bearing fields
/// live in `Zeroizing` containers; `Drop` wipes them. The custom
/// `Debug` impl redacts `cap_content` so test output and panic messages
/// never surface secret bytes.
pub struct OpenedKeysFile {
    pub capability_mode: u8,
    pub network: u8,
    pub seed_format: u8,
    pub expected_classical_address: [u8; EXPECTED_CLASSICAL_ADDRESS_BYTES],
    pub creation_timestamp: u64,
    pub restore_height_hint: u32,
    /// Raw capability-content bytes (length per `capability_mode`).
    pub cap_content: Zeroizing<Vec<u8>>,
    /// Poly1305 tag of region 1 — used as AAD when sealing / opening
    /// `.wallet`. Stable across password rotation.
    pub seed_block_tag: [u8; AEAD_TAG_BYTES],
}

impl std::fmt::Debug for OpenedKeysFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedKeysFile")
            .field("capability_mode", &self.capability_mode)
            .field("network", &self.network)
            .field("seed_format", &self.seed_format)
            .field("expected_classical_address", &"[..65 bytes..]")
            .field("creation_timestamp", &self.creation_timestamp)
            .field("restore_height_hint", &self.restore_height_hint)
            .field("cap_content", &"[REDACTED]")
            .field("seed_block_tag", &"[..16 bytes..]")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte wrap_key from the password under the given KDF
/// parameters. Always uses Argon2id v1.3 (current recommended version).
fn derive_wrap_key(
    password: &[u8],
    wrap_salt: &[u8; WRAP_SALT_BYTES],
    kdf: KdfParams,
) -> Result<Zeroizing<[u8; WRAP_KEY_BYTES]>, WalletEnvelopeError> {
    kdf.validate()?;
    let m_cost_kib: u32 = 1u32
        .checked_shl(u32::from(kdf.m_log2))
        .ok_or(WalletEnvelopeError::KdfParamsOutOfRange {
            m_log2: kdf.m_log2,
            t: kdf.t,
            p: kdf.p,
        })?;
    let params = Params::new(m_cost_kib, u32::from(kdf.t), u32::from(kdf.p), Some(WRAP_KEY_BYTES))
        .map_err(|e| WalletEnvelopeError::Internal(format!("Argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; WRAP_KEY_BYTES]);
    argon2
        .hash_password_into(password, wrap_salt, out.as_mut_slice())
        .map_err(|e| WalletEnvelopeError::Internal(format!("Argon2 hash: {e}")))?;
    Ok(out)
}

fn fresh_random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

/// Encrypt `plaintext` in place under `key` with XChaCha20-Poly1305; appends
/// the 16-byte Poly1305 tag and returns it. Destructive on `plaintext`.
fn aead_encrypt(
    key: &[u8; 32],
    nonce: &[u8; AEAD_NONCE_BYTES],
    aad: &[u8],
    plaintext: &mut Vec<u8>,
) -> Result<[u8; AEAD_TAG_BYTES], WalletEnvelopeError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_ga = XNonce::from(*nonce);
    let tag = cipher
        .encrypt_in_place_detached(&nonce_ga, aad, plaintext.as_mut_slice())
        .map_err(|e| WalletEnvelopeError::Internal(format!("XChaCha20-Poly1305 seal: {e}")))?;
    let mut tag_bytes = [0u8; AEAD_TAG_BYTES];
    tag_bytes.copy_from_slice(&tag);
    Ok(tag_bytes)
}

/// Decrypt `ciphertext` in place; `tag` is the detached Poly1305 tag.
/// Returns the authentication result as `InvalidPasswordOrCorrupt` so
/// callers cannot use the failure path as an oracle distinguishing
/// tampered AAD from tampered ciphertext from wrong key.
fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; AEAD_NONCE_BYTES],
    aad: &[u8],
    ciphertext: &mut [u8],
    tag: &[u8; AEAD_TAG_BYTES],
) -> Result<(), WalletEnvelopeError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_ga = XNonce::from(*nonce);
    let tag_ga = chacha20poly1305::Tag::from(*tag);
    cipher
        .decrypt_in_place_detached(&nonce_ga, aad, ciphertext, &tag_ga)
        .map_err(|_| WalletEnvelopeError::InvalidPasswordOrCorrupt)
}

/// Extract the FIPS 203 `ek` sub-slice from an ML-KEM-768 decapsulation
/// key serialization. See §7.1: `dk = dk_PKE || ek || H(ek) || z` with
/// `ek` starting at `offset = 384·K` (K=3 for ML-KEM-768) and spanning
/// `384·K + 32` bytes.
pub fn ek_from_dk(dk: &[u8; ML_KEM_768_DK_LEN]) -> [u8; ML_KEM_768_EK_LEN] {
    let mut ek = [0u8; ML_KEM_768_EK_LEN];
    ek.copy_from_slice(&dk[ML_KEM_768_DK_EK_OFFSET..ML_KEM_768_DK_EK_OFFSET + ML_KEM_768_EK_LEN]);
    ek
}

fn expect_at_least(bytes: &[u8], need: usize) -> Result<(), WalletEnvelopeError> {
    if bytes.len() < need {
        Err(WalletEnvelopeError::TooShort)
    } else {
        Ok(())
    }
}

fn parse_header_view(bytes: &[u8]) -> Result<KeysFileHeaderView, WalletEnvelopeError> {
    expect_at_least(bytes, OFF_REGION1_CT)?;
    if &bytes[OFF_MAGIC..OFF_MAGIC + 8] != KEYS_FILE_MAGIC {
        return Err(WalletEnvelopeError::BadMagic);
    }
    let ver = bytes[OFF_FILE_VERSION];
    if ver > WALLET_FILE_FORMAT_VERSION {
        return Err(WalletEnvelopeError::FormatVersionTooNew {
            got: ver,
            max: WALLET_FILE_FORMAT_VERSION,
        });
    }
    let algo = bytes[OFF_KDF_ALGO];
    if algo != KDF_ALGO_ARGON2ID {
        return Err(WalletEnvelopeError::UnsupportedKdfAlgo(algo));
    }
    let kdf = KdfParams {
        m_log2: bytes[OFF_KDF_M_LOG2],
        t: bytes[OFF_KDF_T],
        p: bytes[OFF_KDF_P],
    };
    kdf.validate()?;
    let wrap_count = bytes[OFF_WRAP_COUNT];
    if wrap_count != 1 {
        return Err(WalletEnvelopeError::UnsupportedWrapCount(wrap_count));
    }
    let mut wrap_salt = [0u8; WRAP_SALT_BYTES];
    wrap_salt.copy_from_slice(&bytes[OFF_WRAP_SALT..OFF_WRAP_COUNT]);
    Ok(KeysFileHeaderView { format_version: ver, kdf, wrap_salt, wrap_count })
}

fn write_keys_file_header(
    out: &mut Vec<u8>,
    kdf: KdfParams,
    wrap_salt: &[u8; WRAP_SALT_BYTES],
) {
    out.extend_from_slice(KEYS_FILE_MAGIC);
    out.push(WALLET_FILE_FORMAT_VERSION);
    out.push(KDF_ALGO_ARGON2ID);
    out.push(kdf.m_log2);
    out.push(kdf.t);
    out.push(kdf.p);
    out.extend_from_slice(wrap_salt);
    out.push(1u8); // wrap_count
    debug_assert_eq!(out.len(), OFF_WRAP_NONCE);
}

/// Validate capability-mode / cap_content_len pair on open. Separate from
/// the Poly1305 check because we want a typed error for "my seal code
/// wrote a wrong-length cap_content" rather than generic AEAD failure.
fn validate_cap_content(mode: u8, cap_len: u16) -> Result<(), WalletEnvelopeError> {
    let expected_min: usize = match mode {
        CAPABILITY_FULL => 64,
        CAPABILITY_VIEW_ONLY => 32 + ML_KEM_768_DK_LEN + 32,
        CAPABILITY_HARDWARE_OFFLOAD => 32 + ML_KEM_768_DK_LEN + 32 + 2, // u16 device_len prefix
        CAPABILITY_RESERVED_MULTISIG => {
            return Err(WalletEnvelopeError::RequiresMultisigSupport)
        }
        other => return Err(WalletEnvelopeError::UnknownCapabilityMode(other)),
    };
    let cap_len_usize = usize::from(cap_len);
    let ok = match mode {
        CAPABILITY_FULL | CAPABILITY_VIEW_ONLY => cap_len_usize == expected_min,
        CAPABILITY_HARDWARE_OFFLOAD => cap_len_usize >= expected_min,
        _ => false,
    };
    if !ok {
        return Err(WalletEnvelopeError::CapContentLenMismatch { mode, len: cap_len });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API — keys file
// ---------------------------------------------------------------------------

/// Seal a fresh `.wallet.keys` file. Called at wallet creation only.
/// The returned bytes are suitable for atomic `tmp → fsync → rename` save.
#[allow(clippy::too_many_arguments)]
pub fn seal_keys_file(
    password: &[u8],
    network: u8,
    seed_format: u8,
    capability: &CapabilityContent<'_>,
    creation_timestamp: u64,
    restore_height_hint: u32,
    expected_classical_address: &[u8; EXPECTED_CLASSICAL_ADDRESS_BYTES],
    kdf: KdfParams,
) -> Result<Vec<u8>, WalletEnvelopeError> {
    let wrap_salt: [u8; WRAP_SALT_BYTES] = fresh_random_bytes();
    let wrap_nonce: [u8; AEAD_NONCE_BYTES] = fresh_random_bytes();
    let region1_nonce: [u8; AEAD_NONCE_BYTES] = fresh_random_bytes();
    let file_kek_seed: [u8; FILE_KEK_BYTES] = fresh_random_bytes();
    seal_keys_file_with_entropy(
        password,
        network,
        seed_format,
        capability,
        creation_timestamp,
        restore_height_hint,
        expected_classical_address,
        kdf,
        &wrap_salt,
        &wrap_nonce,
        &region1_nonce,
        &file_kek_seed,
    )
}

/// Deterministic seal helper. Used by:
///
/// - [`seal_keys_file`] (with `OsRng`-derived entropy);
/// - Tier-3 KAT fixtures that need byte-identical sealed blobs across
///   runs (same password + same entropy → same bytes).
///
/// `file_kek_seed` is the 32-byte plaintext of `wrap_ct` — i.e. the
/// `file_kek` that the wrap layer will protect. It is treated as a
/// secret by the caller (`Zeroizing` recommended).
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_keys_file_with_entropy(
    password: &[u8],
    network: u8,
    seed_format: u8,
    capability: &CapabilityContent<'_>,
    creation_timestamp: u64,
    restore_height_hint: u32,
    expected_classical_address: &[u8; EXPECTED_CLASSICAL_ADDRESS_BYTES],
    kdf: KdfParams,
    wrap_salt: &[u8; WRAP_SALT_BYTES],
    wrap_nonce: &[u8; AEAD_NONCE_BYTES],
    region1_nonce: &[u8; AEAD_NONCE_BYTES],
    file_kek_seed: &[u8; FILE_KEK_BYTES],
) -> Result<Vec<u8>, WalletEnvelopeError> {
    kdf.validate()?;

    let cap_len: u16 = capability
        .serialized_len()
        .try_into()
        .map_err(|_| WalletEnvelopeError::Internal("cap_content exceeds u16::MAX".into()))?;

    let mut out = Vec::with_capacity(
        OFF_REGION1_CT
            + R1_MIN_PLAINTEXT_BYTES
            + usize::from(cap_len)
            + AEAD_TAG_BYTES,
    );
    write_keys_file_header(&mut out, kdf, wrap_salt);
    out.extend_from_slice(wrap_nonce);

    let wrap_aad: &[u8] = &out[OFF_MAGIC..OFF_WRAP_COUNT]; // magic||ver||kdf||salt

    let wrap_key = derive_wrap_key(password, wrap_salt, kdf)?;
    let file_kek_z: Zeroizing<[u8; FILE_KEK_BYTES]> = Zeroizing::new(*file_kek_seed);
    let mut file_kek_ct: Vec<u8> = file_kek_z.as_slice().to_vec();
    let wrap_tag = aead_encrypt(&wrap_key, wrap_nonce, wrap_aad, &mut file_kek_ct)?;
    out.extend_from_slice(&file_kek_ct);
    out.extend_from_slice(&wrap_tag);
    debug_assert_eq!(out.len(), OFF_REGION1_NONCE);

    out.extend_from_slice(region1_nonce);

    let mut region1_plain: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(R1_MIN_PLAINTEXT_BYTES + usize::from(cap_len)));
    region1_plain.push(capability.mode_byte());
    region1_plain.push(network);
    region1_plain.push(seed_format);
    region1_plain.extend_from_slice(expected_classical_address);
    region1_plain.extend_from_slice(&cap_len.to_le_bytes());
    capability.write_into(&mut region1_plain);
    region1_plain.extend_from_slice(&creation_timestamp.to_le_bytes());
    region1_plain.extend_from_slice(&restore_height_hint.to_le_bytes());

    let region1_aad: &[u8] = &out[OFF_MAGIC..OFF_KDF_ALGO]; // magic||ver
    let mut region1_ct: Vec<u8> = region1_plain.as_slice().to_vec();
    let region1_tag = aead_encrypt(&file_kek_z, region1_nonce, region1_aad, &mut region1_ct)?;
    out.extend_from_slice(&region1_ct);
    out.extend_from_slice(&region1_tag);

    Ok(out)
}

/// Parse only the AAD-readable header of a `.wallet.keys` file without
/// attempting decryption. Fails with `BadMagic` on pre-v1 files, letting
/// the C++ side show the dedicated upgrade message.
pub fn inspect_keys_file(bytes: &[u8]) -> Result<KeysFileHeaderView, WalletEnvelopeError> {
    parse_header_view(bytes)
}

/// Decrypt and return the full `OpenedKeysFile`. On wrong password or any
/// tampering, fails with `InvalidPasswordOrCorrupt` — the specific failure
/// point (wrap vs region 1 vs malformed plaintext) is deliberately not
/// exposed.
pub fn open_keys_file(
    password: &[u8],
    bytes: &[u8],
) -> Result<OpenedKeysFile, WalletEnvelopeError> {
    let view = parse_header_view(bytes)?;
    expect_at_least(bytes, OFF_REGION1_CT + AEAD_TAG_BYTES)?;

    // Recover file_kek.
    let wrap_key = derive_wrap_key(password, &view.wrap_salt, view.kdf)?;
    let wrap_nonce: [u8; AEAD_NONCE_BYTES] = bytes[OFF_WRAP_NONCE..OFF_WRAP_CT]
        .try_into()
        .expect("slice length pinned by constants");
    let mut file_kek_buf: Zeroizing<Vec<u8>> =
        Zeroizing::new(bytes[OFF_WRAP_CT..OFF_WRAP_CT + FILE_KEK_BYTES].to_vec());
    let wrap_tag: [u8; AEAD_TAG_BYTES] = bytes
        [OFF_WRAP_CT + FILE_KEK_BYTES..OFF_WRAP_CT_END]
        .try_into()
        .expect("slice length pinned by constants");
    let wrap_aad: &[u8] = &bytes[OFF_MAGIC..OFF_WRAP_COUNT];
    aead_decrypt(
        &wrap_key,
        &wrap_nonce,
        wrap_aad,
        file_kek_buf.as_mut_slice(),
        &wrap_tag,
    )?;
    let mut file_kek = [0u8; FILE_KEK_BYTES];
    file_kek.copy_from_slice(&file_kek_buf);
    let file_kek_z = Zeroizing::new(file_kek);

    // Decrypt region 1.
    let region1_nonce: [u8; AEAD_NONCE_BYTES] = bytes[OFF_REGION1_NONCE..OFF_REGION1_CT]
        .try_into()
        .expect("slice length pinned by constants");
    let region1_total_len = bytes.len() - OFF_REGION1_CT;
    if region1_total_len < AEAD_TAG_BYTES + R1_MIN_PLAINTEXT_BYTES {
        return Err(WalletEnvelopeError::TooShort);
    }
    let region1_ct_end = bytes.len() - AEAD_TAG_BYTES;
    let mut region1_plain: Zeroizing<Vec<u8>> =
        Zeroizing::new(bytes[OFF_REGION1_CT..region1_ct_end].to_vec());
    let region1_tag: [u8; AEAD_TAG_BYTES] = bytes[region1_ct_end..]
        .try_into()
        .expect("slice length pinned above");
    let region1_aad: &[u8] = &bytes[OFF_MAGIC..OFF_KDF_ALGO];
    aead_decrypt(
        &file_kek_z,
        &region1_nonce,
        region1_aad,
        region1_plain.as_mut_slice(),
        &region1_tag,
    )?;

    // Parse plaintext. Any arithmetic here that could overflow is bounded
    // by u16 cap_len; buffer length is already authenticated.
    if region1_plain.len() < R1_MIN_PLAINTEXT_BYTES {
        return Err(WalletEnvelopeError::InvalidPasswordOrCorrupt);
    }
    let mode = region1_plain[R1_OFF_MODE];
    let network = region1_plain[R1_OFF_NETWORK];
    let seed_format = region1_plain[R1_OFF_SEED_FORMAT];
    let mut expected_addr = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
    expected_addr.copy_from_slice(
        &region1_plain[R1_OFF_EXPECTED_ADDR..R1_OFF_EXPECTED_ADDR + EXPECTED_CLASSICAL_ADDRESS_BYTES],
    );
    let cap_len = u16::from_le_bytes(
        region1_plain[R1_OFF_CAP_LEN..R1_OFF_CAP_LEN + 2]
            .try_into()
            .expect("2 bytes"),
    );
    validate_cap_content(mode, cap_len)?;

    let cap_end = R1_OFF_CAP + usize::from(cap_len);
    if region1_plain.len() < cap_end + R1_TRAILER_BYTES {
        return Err(WalletEnvelopeError::InvalidPasswordOrCorrupt);
    }
    let cap_content_buf: Zeroizing<Vec<u8>> =
        Zeroizing::new(region1_plain[R1_OFF_CAP..cap_end].to_vec());
    let creation_timestamp = u64::from_le_bytes(
        region1_plain[cap_end..cap_end + 8]
            .try_into()
            .expect("8 bytes"),
    );
    let restore_height_hint = u32::from_le_bytes(
        region1_plain[cap_end + 8..cap_end + 12]
            .try_into()
            .expect("4 bytes"),
    );

    Ok(OpenedKeysFile {
        capability_mode: mode,
        network,
        seed_format,
        expected_classical_address: expected_addr,
        creation_timestamp,
        restore_height_hint,
        cap_content: cap_content_buf,
        seed_block_tag: region1_tag,
    })
}

/// Rewrite a `.wallet.keys` file with a new password. Only the wrap layer
/// (wrap_salt, wrap_nonce, wrap_ct, wrap_tag) changes; region 1 bytes are
/// byte-identical in the output. Optionally bumps `kdf` parameters; pass
/// `None` to preserve the existing parameters.
pub fn rewrap_keys_file_password(
    old_password: &[u8],
    new_password: &[u8],
    bytes: &[u8],
    new_kdf: Option<KdfParams>,
) -> Result<Vec<u8>, WalletEnvelopeError> {
    let view = parse_header_view(bytes)?;
    expect_at_least(bytes, OFF_REGION1_CT + AEAD_TAG_BYTES + R1_MIN_PLAINTEXT_BYTES)?;

    // Recover file_kek under the old password, identically to open_keys_file.
    let old_wrap_key = derive_wrap_key(old_password, &view.wrap_salt, view.kdf)?;
    let wrap_nonce_old: [u8; AEAD_NONCE_BYTES] =
        bytes[OFF_WRAP_NONCE..OFF_WRAP_CT].try_into().expect("pinned");
    let mut file_kek_buf: Zeroizing<Vec<u8>> =
        Zeroizing::new(bytes[OFF_WRAP_CT..OFF_WRAP_CT + FILE_KEK_BYTES].to_vec());
    let wrap_tag_old: [u8; AEAD_TAG_BYTES] = bytes
        [OFF_WRAP_CT + FILE_KEK_BYTES..OFF_WRAP_CT_END]
        .try_into()
        .expect("pinned");
    let wrap_aad_old: &[u8] = &bytes[OFF_MAGIC..OFF_WRAP_COUNT];
    aead_decrypt(
        &old_wrap_key,
        &wrap_nonce_old,
        wrap_aad_old,
        file_kek_buf.as_mut_slice(),
        &wrap_tag_old,
    )?;

    // Fresh wrap_salt and wrap_nonce — defense-in-depth against any
    // precomputed brute-force the attacker may have done against the old
    // wrap_salt / wrap_ct combination.
    let new_kdf = new_kdf.unwrap_or(view.kdf);
    new_kdf.validate()?;
    let wrap_salt_new: [u8; WRAP_SALT_BYTES] = fresh_random_bytes();
    let wrap_nonce_new: [u8; AEAD_NONCE_BYTES] = fresh_random_bytes();

    let mut out = Vec::with_capacity(bytes.len());
    write_keys_file_header(&mut out, new_kdf, &wrap_salt_new);
    out.extend_from_slice(&wrap_nonce_new);

    let wrap_aad_new: &[u8] = &out[OFF_MAGIC..OFF_WRAP_COUNT];
    let new_wrap_key = derive_wrap_key(new_password, &wrap_salt_new, new_kdf)?;
    let mut file_kek_ct_new: Vec<u8> = file_kek_buf.to_vec();
    let wrap_tag_new =
        aead_encrypt(&new_wrap_key, &wrap_nonce_new, wrap_aad_new, &mut file_kek_ct_new)?;
    out.extend_from_slice(&file_kek_ct_new);
    out.extend_from_slice(&wrap_tag_new);

    // Splice region 1 bytes verbatim from the input. This is the
    // byte-identical-seed-region invariant: password rotation must not touch
    // any byte of the seed block.
    out.extend_from_slice(&bytes[OFF_REGION1_NONCE..]);

    debug_assert_eq!(
        &out[OFF_REGION1_NONCE..],
        &bytes[OFF_REGION1_NONCE..],
        "seed-region-immutability invariant violated by rewrap"
    );

    Ok(out)
}

// ---------------------------------------------------------------------------
// Public API — state file
// ---------------------------------------------------------------------------

fn state_aad(magic_version: &[u8], seed_block_tag: &[u8; AEAD_TAG_BYTES]) -> Vec<u8> {
    debug_assert_eq!(magic_version.len(), 9);
    let mut aad = Vec::with_capacity(STATE_AEAD_AAD_BYTES);
    aad.extend_from_slice(magic_version);
    aad.extend_from_slice(seed_block_tag);
    aad
}

fn write_state_header(out: &mut Vec<u8>) {
    out.extend_from_slice(STATE_FILE_MAGIC);
    out.push(STATE_FILE_FORMAT_VERSION);
    debug_assert_eq!(out.len(), S_OFF_NONCE);
}

/// Seal a `.wallet` state file. `keys_file_bytes` is the current on-disk
/// `.wallet.keys`; the Argon2id derivation runs once per save (≈ KDF-cost
/// latency). Callers that need throughput can fold multiple saves into one,
/// but the design accepts the per-save cost in exchange for never caching
/// `file_kek` or the password in Rust-owned memory across calls.
pub fn seal_state_file(
    password: &[u8],
    keys_file_bytes: &[u8],
    state_plaintext: &[u8],
) -> Result<Vec<u8>, WalletEnvelopeError> {
    let region2_nonce: [u8; AEAD_NONCE_BYTES] = fresh_random_bytes();
    seal_state_file_with_entropy(
        password,
        keys_file_bytes,
        state_plaintext,
        &region2_nonce,
    )
}

/// Deterministic state-seal helper. Used by [`seal_state_file`] (with
/// an `OsRng`-drawn nonce) and Tier-3 KAT fixtures that need
/// byte-identical sealed blobs.
pub(crate) fn seal_state_file_with_entropy(
    password: &[u8],
    keys_file_bytes: &[u8],
    state_plaintext: &[u8],
    region2_nonce: &[u8; AEAD_NONCE_BYTES],
) -> Result<Vec<u8>, WalletEnvelopeError> {
    // open_keys_file gives us file_kek implicitly (we need to re-derive to
    // seal state); easier to re-run the wrap unwrap here directly.
    let view = parse_header_view(keys_file_bytes)?;
    expect_at_least(keys_file_bytes, OFF_REGION1_CT + AEAD_TAG_BYTES)?;

    let wrap_key = derive_wrap_key(password, &view.wrap_salt, view.kdf)?;
    let wrap_nonce: [u8; AEAD_NONCE_BYTES] =
        keys_file_bytes[OFF_WRAP_NONCE..OFF_WRAP_CT].try_into().expect("pinned");
    let mut file_kek_buf: Zeroizing<Vec<u8>> =
        Zeroizing::new(keys_file_bytes[OFF_WRAP_CT..OFF_WRAP_CT + FILE_KEK_BYTES].to_vec());
    let wrap_tag: [u8; AEAD_TAG_BYTES] =
        keys_file_bytes[OFF_WRAP_CT + FILE_KEK_BYTES..OFF_WRAP_CT_END]
            .try_into()
            .expect("pinned");
    let wrap_aad: &[u8] = &keys_file_bytes[OFF_MAGIC..OFF_WRAP_COUNT];
    aead_decrypt(
        &wrap_key,
        &wrap_nonce,
        wrap_aad,
        file_kek_buf.as_mut_slice(),
        &wrap_tag,
    )?;
    let mut file_kek = [0u8; FILE_KEK_BYTES];
    file_kek.copy_from_slice(&file_kek_buf);
    let file_kek_z = Zeroizing::new(file_kek);

    // seed_block_tag = last 16 bytes of keys_file_bytes.
    let mut seed_block_tag = [0u8; AEAD_TAG_BYTES];
    seed_block_tag.copy_from_slice(&keys_file_bytes[keys_file_bytes.len() - AEAD_TAG_BYTES..]);

    let mut out = Vec::with_capacity(S_OFF_CT + state_plaintext.len() + AEAD_TAG_BYTES);
    write_state_header(&mut out);
    out.extend_from_slice(region2_nonce);

    let magic_version = &out[S_OFF_MAGIC..S_OFF_NONCE];
    let aad = state_aad(magic_version, &seed_block_tag);

    let mut region2_ct = state_plaintext.to_vec();
    let region2_tag = aead_encrypt(&file_kek_z, region2_nonce, &aad, &mut region2_ct)?;
    out.extend_from_slice(&region2_ct);
    out.extend_from_slice(&region2_tag);
    Ok(out)
}

/// Open a `.wallet` state file. Cross-checks `seed_block_tag` against the
/// companion `.wallet.keys`; fails with `StateSeedBlockMismatch` if the two
/// do not belong together.
pub fn open_state_file(
    password: &[u8],
    keys_file_bytes: &[u8],
    state_file_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, WalletEnvelopeError> {
    // Validate the .wallet header.
    expect_at_least(state_file_bytes, S_OFF_CT + AEAD_TAG_BYTES)?;
    if &state_file_bytes[S_OFF_MAGIC..S_OFF_MAGIC + 8] != STATE_FILE_MAGIC {
        return Err(WalletEnvelopeError::BadMagic);
    }
    let sv = state_file_bytes[S_OFF_VERSION];
    if sv > STATE_FILE_FORMAT_VERSION {
        return Err(WalletEnvelopeError::FormatVersionTooNew {
            got: sv,
            max: STATE_FILE_FORMAT_VERSION,
        });
    }

    // Recover file_kek via the same path as open_keys_file.
    let view = parse_header_view(keys_file_bytes)?;
    expect_at_least(keys_file_bytes, OFF_REGION1_CT + AEAD_TAG_BYTES)?;
    let wrap_key = derive_wrap_key(password, &view.wrap_salt, view.kdf)?;
    let wrap_nonce: [u8; AEAD_NONCE_BYTES] =
        keys_file_bytes[OFF_WRAP_NONCE..OFF_WRAP_CT].try_into().expect("pinned");
    let mut file_kek_buf: Zeroizing<Vec<u8>> =
        Zeroizing::new(keys_file_bytes[OFF_WRAP_CT..OFF_WRAP_CT + FILE_KEK_BYTES].to_vec());
    let wrap_tag: [u8; AEAD_TAG_BYTES] =
        keys_file_bytes[OFF_WRAP_CT + FILE_KEK_BYTES..OFF_WRAP_CT_END]
            .try_into()
            .expect("pinned");
    let wrap_aad: &[u8] = &keys_file_bytes[OFF_MAGIC..OFF_WRAP_COUNT];
    aead_decrypt(
        &wrap_key,
        &wrap_nonce,
        wrap_aad,
        file_kek_buf.as_mut_slice(),
        &wrap_tag,
    )?;
    let mut file_kek = [0u8; FILE_KEK_BYTES];
    file_kek.copy_from_slice(&file_kek_buf);
    let file_kek_z = Zeroizing::new(file_kek);

    // Compute seed_block_tag from the keys file bytes.
    let mut seed_block_tag = [0u8; AEAD_TAG_BYTES];
    seed_block_tag.copy_from_slice(&keys_file_bytes[keys_file_bytes.len() - AEAD_TAG_BYTES..]);

    let region2_nonce: [u8; AEAD_NONCE_BYTES] =
        state_file_bytes[S_OFF_NONCE..S_OFF_CT].try_into().expect("pinned");
    let region2_ct_end = state_file_bytes.len() - AEAD_TAG_BYTES;
    let mut region2_plain: Zeroizing<Vec<u8>> =
        Zeroizing::new(state_file_bytes[S_OFF_CT..region2_ct_end].to_vec());
    let region2_tag: [u8; AEAD_TAG_BYTES] = state_file_bytes[region2_ct_end..]
        .try_into()
        .expect("pinned");
    let magic_version = &state_file_bytes[S_OFF_MAGIC..S_OFF_NONCE];
    let aad = state_aad(magic_version, &seed_block_tag);
    // AEAD failure at this point is either wrong password (wrap succeeded
    // only because we did not check there) or mismatched seed_block_tag. We
    // map both to a specific error once we've distinguished them: if the
    // wallet state file's region2 AEAD fails under the *correct* file_kek and
    // we authenticated it elsewhere (wrap succeeded), the most likely cause
    // is a seed_block swap. But we cannot distinguish without running both
    // checks. Prefer a generic error here.
    if aead_decrypt(
        &file_kek_z,
        &region2_nonce,
        &aad,
        region2_plain.as_mut_slice(),
        &region2_tag,
    )
    .is_err()
    {
        return Err(WalletEnvelopeError::StateSeedBlockMismatch);
    }
    Ok(region2_plain)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use fips203::ml_kem_768;
    use fips203::traits::{KeyGen, SerDes};

    // KAT profile: Argon2id clamped to m_log2=8 (256 KiB), t=1, p=1 so the
    // test suite runs in seconds on a commodity laptop. Production wallets
    // use DEFAULT_KDF_* (64 MiB, t=3, p=1).
    fn kat_kdf() -> KdfParams {
        KdfParams { m_log2: 8, t: 1, p: 1 }
    }

    fn dummy_address() -> [u8; EXPECTED_CLASSICAL_ADDRESS_BYTES] {
        let mut a = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
        for (i, b) in a.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).expect("i masked to u8 range");
        }
        a
    }

    #[test]
    fn roundtrip_full_mainnet() {
        let seed = [0x11u8; 64];
        let pw = b"correct horse battery staple";
        let cap = CapabilityContent::Full { master_seed_64: &seed };
        let addr = dummy_address();
        let bytes = seal_keys_file(pw, 0, 0, &cap, 1_700_000_000, 2_500_000, &addr, kat_kdf())
            .expect("seal");
        let opened = open_keys_file(pw, &bytes).expect("open");
        assert_eq!(opened.capability_mode, CAPABILITY_FULL);
        assert_eq!(opened.network, 0);
        assert_eq!(opened.seed_format, 0);
        assert_eq!(&opened.expected_classical_address, &addr);
        assert_eq!(opened.creation_timestamp, 1_700_000_000);
        assert_eq!(opened.restore_height_hint, 2_500_000);
        assert_eq!(opened.cap_content.as_slice(), &seed);
    }

    #[test]
    fn roundtrip_view_only() {
        let view_sk = [0x22u8; 32];
        let mut dk = [0u8; ML_KEM_768_DK_LEN];
        for (i, b) in dk.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).expect("i masked to u8 range");
        }
        let spend_pk = [0x33u8; 32];
        let cap = CapabilityContent::ViewOnly {
            view_sk: &view_sk,
            ml_kem_dk: &dk,
            spend_pk: &spend_pk,
        };
        let pw = b"viewonly pw";
        let addr = dummy_address();
        let bytes = seal_keys_file(pw, 1, 1, &cap, 42, 0, &addr, kat_kdf()).expect("seal");
        let opened = open_keys_file(pw, &bytes).expect("open");
        assert_eq!(opened.capability_mode, CAPABILITY_VIEW_ONLY);
        assert_eq!(opened.cap_content.len(), 32 + ML_KEM_768_DK_LEN + 32);
        assert_eq!(&opened.cap_content[..32], &view_sk);
        assert_eq!(&opened.cap_content[32..32 + ML_KEM_768_DK_LEN], &dk[..]);
        assert_eq!(&opened.cap_content[32 + ML_KEM_768_DK_LEN..], &spend_pk);
    }

    #[test]
    fn roundtrip_hardware_offload() {
        let view_sk = [0x44u8; 32];
        let dk = [0x55u8; ML_KEM_768_DK_LEN];
        let spend_pk = [0x66u8; 32];
        let device_desc = b"ledger:12345:foo";
        let cap = CapabilityContent::HardwareOffload {
            view_sk: &view_sk,
            ml_kem_dk: &dk,
            spend_pk: &spend_pk,
            device_desc,
        };
        let pw = b"hw pw";
        let addr = dummy_address();
        let bytes = seal_keys_file(pw, 2, 1, &cap, 0, 0, &addr, kat_kdf()).expect("seal");
        let opened = open_keys_file(pw, &bytes).expect("open");
        assert_eq!(opened.capability_mode, CAPABILITY_HARDWARE_OFFLOAD);
        // Skip over the fixed prefix and check device descriptor.
        let dd_off = 32 + ML_KEM_768_DK_LEN + 32;
        let dev_len = u16::from_le_bytes([opened.cap_content[dd_off], opened.cap_content[dd_off + 1]]);
        assert_eq!(usize::from(dev_len), device_desc.len());
        assert_eq!(&opened.cap_content[dd_off + 2..dd_off + 2 + device_desc.len()], device_desc);
    }

    #[test]
    fn password_rotation_preserves_seed_region_bytes() {
        let seed = [0x77u8; 64];
        let pw_old = b"old pw";
        let pw_new = b"new pw";
        let cap = CapabilityContent::Full { master_seed_64: &seed };
        let addr = dummy_address();
        let bytes_before =
            seal_keys_file(pw_old, 0, 0, &cap, 0, 0, &addr, kat_kdf()).expect("seal");
        let bytes_after = rewrap_keys_file_password(pw_old, pw_new, &bytes_before, None)
            .expect("rewrap");

        // Seed region runs from OFF_REGION1_NONCE to end of file.
        assert_eq!(
            &bytes_before[OFF_REGION1_NONCE..],
            &bytes_after[OFF_REGION1_NONCE..],
            "region 1 bytes changed under password rotation"
        );
        // Wrap salt and nonce differ (defense-in-depth).
        assert_ne!(
            &bytes_before[OFF_WRAP_SALT..OFF_WRAP_COUNT],
            &bytes_after[OFF_WRAP_SALT..OFF_WRAP_COUNT]
        );
        assert_ne!(
            &bytes_before[OFF_WRAP_NONCE..OFF_WRAP_CT],
            &bytes_after[OFF_WRAP_NONCE..OFF_WRAP_CT]
        );
        // Opens under the new password, gives the same seed material.
        let opened = open_keys_file(pw_new, &bytes_after).expect("open-post");
        assert_eq!(opened.cap_content.as_slice(), &seed);
        // Does not open under the old password.
        assert!(open_keys_file(pw_old, &bytes_after).is_err());
    }

    #[test]
    fn wrong_password_rejected() {
        let seed = [0u8; 64];
        let cap = CapabilityContent::Full { master_seed_64: &seed };
        let bytes =
            seal_keys_file(b"right", 0, 0, &cap, 0, 0, &dummy_address(), kat_kdf()).unwrap();
        let err = open_keys_file(b"wrong", &bytes).unwrap_err();
        assert!(matches!(err, WalletEnvelopeError::InvalidPasswordOrCorrupt));
    }

    #[test]
    fn tamper_magic_fails() {
        let cap = CapabilityContent::Full { master_seed_64: &[0u8; 64] };
        let mut bytes =
            seal_keys_file(b"pw", 0, 0, &cap, 0, 0, &dummy_address(), kat_kdf()).unwrap();
        bytes[0] ^= 0x80;
        assert!(matches!(inspect_keys_file(&bytes), Err(WalletEnvelopeError::BadMagic)));
    }

    #[test]
    fn tamper_kdf_params_fails_authentication() {
        let cap = CapabilityContent::Full { master_seed_64: &[0u8; 64] };
        let mut bytes =
            seal_keys_file(b"pw", 0, 0, &cap, 0, 0, &dummy_address(), kat_kdf()).unwrap();
        bytes[OFF_KDF_T] = 0x05; // legitimate value, but not the one sealed with
        // parse_header_view now uses the wrong kdf_t; Argon2id derives a
        // different wrap_key; wrap AEAD fails; we see InvalidPasswordOrCorrupt.
        let err = open_keys_file(b"pw", &bytes).unwrap_err();
        assert!(matches!(err, WalletEnvelopeError::InvalidPasswordOrCorrupt));
    }

    #[test]
    fn tamper_region1_ciphertext_fails() {
        let cap = CapabilityContent::Full { master_seed_64: &[0u8; 64] };
        let mut bytes =
            seal_keys_file(b"pw", 0, 0, &cap, 0, 0, &dummy_address(), kat_kdf()).unwrap();
        // Flip a bit somewhere inside region 1 ciphertext.
        let mid = OFF_REGION1_CT + 5;
        bytes[mid] ^= 1;
        assert!(matches!(
            open_keys_file(b"pw", &bytes),
            Err(WalletEnvelopeError::InvalidPasswordOrCorrupt)
        ));
    }

    #[test]
    fn reject_reserved_multisig_mode() {
        // Build a valid FULL envelope, then flip the encrypted mode byte ...
        // we can't do that cheaply without the key, so instead: test the
        // validate_cap_content gate directly with the reserved mode.
        let err = validate_cap_content(CAPABILITY_RESERVED_MULTISIG, 0).unwrap_err();
        assert!(matches!(err, WalletEnvelopeError::RequiresMultisigSupport));
    }

    #[test]
    fn reject_unknown_capability_mode() {
        let err = validate_cap_content(0x07, 0).unwrap_err();
        assert!(matches!(err, WalletEnvelopeError::UnknownCapabilityMode(0x07)));
    }

    #[test]
    fn reject_format_version_too_new() {
        let cap = CapabilityContent::Full { master_seed_64: &[0u8; 64] };
        let mut bytes =
            seal_keys_file(b"pw", 0, 0, &cap, 0, 0, &dummy_address(), kat_kdf()).unwrap();
        bytes[OFF_FILE_VERSION] = 0xFF;
        assert!(matches!(
            inspect_keys_file(&bytes),
            Err(WalletEnvelopeError::FormatVersionTooNew { got: 0xFF, max: 0x01 })
        ));
    }

    #[test]
    fn state_file_roundtrip_and_swap_detection() {
        let seed_a = [0xAAu8; 64];
        let seed_b = [0xBBu8; 64];
        let pw = b"shared pw";
        let cap_a = CapabilityContent::Full { master_seed_64: &seed_a };
        let cap_b = CapabilityContent::Full { master_seed_64: &seed_b };
        let addr = dummy_address();
        let keys_a = seal_keys_file(pw, 0, 0, &cap_a, 0, 0, &addr, kat_kdf()).unwrap();
        let keys_b = seal_keys_file(pw, 0, 0, &cap_b, 0, 0, &addr, kat_kdf()).unwrap();

        let state_a_plain = b"state payload A";
        let state_a = seal_state_file(pw, &keys_a, state_a_plain).unwrap();
        let opened = open_state_file(pw, &keys_a, &state_a).unwrap();
        assert_eq!(opened.as_slice(), state_a_plain);

        // Swap: use keys_b to open state_a — must fail because seed_block_tag
        // differs between keys_a and keys_b.
        assert!(matches!(
            open_state_file(pw, &keys_b, &state_a),
            Err(WalletEnvelopeError::StateSeedBlockMismatch)
        ));
    }

    #[test]
    fn state_file_survives_password_rotation() {
        let seed = [0xCCu8; 64];
        let pw_old = b"old";
        let pw_new = b"new";
        let cap = CapabilityContent::Full { master_seed_64: &seed };
        let addr = dummy_address();
        let keys_v1 = seal_keys_file(pw_old, 0, 0, &cap, 0, 0, &addr, kat_kdf()).unwrap();
        let state_plain = b"state across rotation";
        let state_v1 = seal_state_file(pw_old, &keys_v1, state_plain).unwrap();

        let keys_v2 = rewrap_keys_file_password(pw_old, pw_new, &keys_v1, None).unwrap();
        // State file sealed against keys_v1 must still open against keys_v2.
        let opened = open_state_file(pw_new, &keys_v2, &state_v1).unwrap();
        assert_eq!(opened.as_slice(), state_plain);
    }

    #[test]
    fn ek_from_dk_matches_fresh_keygen() {
        let (ek, dk) = ml_kem_768::KG::try_keygen().expect("keygen");
        let ek_direct: [u8; ML_KEM_768_EK_LEN] = ek.into_bytes();
        let dk_bytes: [u8; ML_KEM_768_DK_LEN] = dk.into_bytes();
        let ek_extracted = ek_from_dk(&dk_bytes);
        assert_eq!(ek_extracted, ek_direct, "FIPS 203 ek offset in dk layout drifted");
    }

    #[test]
    fn auto_save_state_file_has_fresh_nonce() {
        let seed = [0xDDu8; 64];
        let pw = b"pw";
        let cap = CapabilityContent::Full { master_seed_64: &seed };
        let keys = seal_keys_file(pw, 0, 0, &cap, 0, 0, &dummy_address(), kat_kdf()).unwrap();
        let s1 = seal_state_file(pw, &keys, b"payload").unwrap();
        let s2 = seal_state_file(pw, &keys, b"payload").unwrap();
        // Same plaintext, same key, different nonce ⇒ different ciphertext.
        assert_ne!(s1, s2, "state file nonces did not refresh across saves");
    }

    #[test]
    fn inspect_bails_on_pre_v1_file() {
        // Old Monero-lineage keys_file_data layout is {chacha_iv:24, string account_data}.
        // A byte stream that begins with something that isn't SHEKYLWT must
        // produce BadMagic so wallet2.cpp can show the "restore from seed"
        // message.
        let fake = [0u8; 200];
        assert!(matches!(inspect_keys_file(&fake), Err(WalletEnvelopeError::BadMagic)));
    }

    #[test]
    fn tamper_every_section_fails_loudly() {
        // Parametrized bit-flip: walk through every byte of a sealed envelope
        // and confirm the opener rejects loudly. We exhaustively flip the low
        // bit of every byte outside the bytes we explicitly expect to be
        // AAD-unbound (there are none in this layout — even the wrap-only AAD
        // bytes invalidate the wrap AEAD).
        let seed = [0x99u8; 64];
        let pw: &[u8] = b"tamper-pw";
        let cap = CapabilityContent::Full { master_seed_64: &seed };
        let bytes = seal_keys_file(pw, 0, 0, &cap, 1, 2, &dummy_address(), kat_kdf()).unwrap();

        // Check a representative byte in each region rather than every byte
        // (would bloat test time with many Argon2 calls). One byte per region
        // is enough to pin down "every section is authenticated".
        let offsets = [
            OFF_MAGIC,              // magic
            OFF_FILE_VERSION,       // file_version
            OFF_KDF_ALGO,           // wrap-AAD kdf
            OFF_WRAP_SALT,          // wrap_salt
            OFF_WRAP_NONCE,         // wrap_nonce
            OFF_WRAP_CT,            // wrap ciphertext
            OFF_WRAP_CT + FILE_KEK_BYTES, // wrap tag
            OFF_REGION1_NONCE,      // region1 nonce
            OFF_REGION1_CT,         // region1 ciphertext
            bytes.len() - 1,        // region1 tag trailing byte
        ];
        for off in offsets {
            let mut b = bytes.clone();
            b[off] ^= 0x01;
            // inspect_keys_file catches magic/version tampering early;
            // open_keys_file catches the rest. Union must never be Ok.
            let inspect_ok = inspect_keys_file(&b).is_ok();
            let open_ok = open_keys_file(pw, &b).is_ok();
            assert!(
                !(inspect_ok && open_ok),
                "tampering at offset {off} did not trigger rejection"
            );
        }
    }

    #[test]
    fn expected_address_matches_full_mode_derivation() {
        // The envelope stores expected_classical_address byte-for-byte; this
        // test pins the invariant that a FULL-mode open returns the exact
        // 65 bytes the caller sealed in. Deriving the real address bytes
        // from master_seed is the caller's job (wallet2.cpp cross-checks
        // against the derivation pipeline in shekyl_crypto_pq::account).
        let seed = [0xEEu8; 64];
        let expected_addr = {
            let mut a = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
            a[0] = 0x01; // version byte
            a[1..33].copy_from_slice(&[0xAA; 32]); // spend_pk
            a[33..65].copy_from_slice(&[0xBB; 32]); // view_pk
            a
        };
        let cap = CapabilityContent::Full { master_seed_64: &seed };
        let bytes =
            seal_keys_file(b"pw", 0, 0, &cap, 0, 0, &expected_addr, kat_kdf()).unwrap();
        let opened = open_keys_file(b"pw", &bytes).unwrap();
        assert_eq!(opened.expected_classical_address, expected_addr);
        assert_eq!(opened.cap_content.as_slice(), &seed);
    }

    #[test]
    fn expected_address_matches_view_only_reconstruction() {
        // VIEW_ONLY reconstruction: the loader recovers view_sk + ml_kem_dk
        // from cap_content, and expected_classical_address pins the
        // spend_pk+view_pk pair the wallet claims. This test pins the
        // byte-for-byte preservation of both halves through the envelope.
        let view_sk = [0xAAu8; 32];
        let dk = [0xBBu8; ML_KEM_768_DK_LEN];
        let spend_pk = [0xCCu8; 32];
        let view_pk_expected = [0xDDu8; 32];
        let mut expected_addr = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
        expected_addr[0] = 0x02; // reserved for stagenet in the classical header
        expected_addr[1..33].copy_from_slice(&spend_pk);
        expected_addr[33..65].copy_from_slice(&view_pk_expected);
        let cap = CapabilityContent::ViewOnly {
            view_sk: &view_sk,
            ml_kem_dk: &dk,
            spend_pk: &spend_pk,
        };
        let bytes =
            seal_keys_file(b"pw", 1, 0, &cap, 0, 0, &expected_addr, kat_kdf()).unwrap();
        let opened = open_keys_file(b"pw", &bytes).unwrap();
        assert_eq!(opened.capability_mode, CAPABILITY_VIEW_ONLY);
        assert_eq!(opened.expected_classical_address, expected_addr);
        assert_eq!(&opened.cap_content[..32], &view_sk);
        assert_eq!(&opened.cap_content[32..32 + ML_KEM_768_DK_LEN], &dk[..]);
        assert_eq!(&opened.cap_content[32 + ML_KEM_768_DK_LEN..], &spend_pk);
    }

    // ------------------------------------------------------------------
    // Tier-3 KAT fixtures
    //
    // The fixtures under docs/test_vectors/WALLET_FILE_FORMAT_V1/ are
    // frozen sealed blobs produced with fixed entropy by the `seal_*_
    // with_entropy` helpers. Two invariants are pinned:
    //
    //   1. Re-running the same seal with the same entropy reproduces the
    //      fixture bytes exactly (format stability across commits).
    //   2. Opening the fixture under the fixed password recovers the
    //      documented plaintext (decryption stability).
    //
    // The KAT profile clamps Argon2id to m_log2=8 (256 KiB) so the test
    // cycle runs in < 1 s per blob. Production wallets always use
    // DEFAULT_KDF_M_LOG2 (64 MiB).
    // ------------------------------------------------------------------

    const KAT_WRAP_SALT_FULL: [u8; WRAP_SALT_BYTES] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    ];
    const KAT_WRAP_NONCE_FULL: [u8; AEAD_NONCE_BYTES] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    ];
    const KAT_REGION1_NONCE_FULL: [u8; AEAD_NONCE_BYTES] = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    const KAT_FILE_KEK_SEED: [u8; FILE_KEK_BYTES] = [
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    ];
    const KAT_PASSWORD: &[u8] = b"shekyl-kat-pw-v1";
    const KAT_EXPECTED_ADDRESS: [u8; EXPECTED_CLASSICAL_ADDRESS_BYTES] = {
        let mut a = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
        a[0] = 0x01;
        let mut i = 1;
        while i < 33 {
            a[i] = 0xAA;
            i += 1;
        }
        while i < 65 {
            a[i] = 0xBB;
            i += 1;
        }
        a
    };
    const KAT_CREATION_TIMESTAMP: u64 = 1_700_000_000;
    const KAT_RESTORE_HEIGHT: u32 = 2_500_000;
    const KAT_STATE_NONCE: [u8; AEAD_NONCE_BYTES] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    ];
    const KAT_STATE_PAYLOAD: &[u8] = b"shekyl-kat-state-v1";

    fn kat_full_seed() -> [u8; 64] {
        let mut s = [0u8; 64];
        for (i, b) in s.iter_mut().enumerate() {
            *b = 0x80 | u8::try_from(i & 0x7f).expect("masked");
        }
        s
    }

    fn kat_view_only_cap() -> ([u8; 32], [u8; ML_KEM_768_DK_LEN], [u8; 32]) {
        let view_sk = [0x11u8; 32];
        let mut dk = [0u8; ML_KEM_768_DK_LEN];
        for (i, b) in dk.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).expect("masked");
        }
        let spend_pk = [0x22u8; 32];
        (view_sk, dk, spend_pk)
    }

    fn seal_kat_full() -> Vec<u8> {
        let seed = kat_full_seed();
        let cap = CapabilityContent::Full { master_seed_64: &seed };
        seal_keys_file_with_entropy(
            KAT_PASSWORD,
            0, 0,
            &cap,
            KAT_CREATION_TIMESTAMP,
            KAT_RESTORE_HEIGHT,
            &KAT_EXPECTED_ADDRESS,
            kat_kdf(),
            &KAT_WRAP_SALT_FULL,
            &KAT_WRAP_NONCE_FULL,
            &KAT_REGION1_NONCE_FULL,
            &KAT_FILE_KEK_SEED,
        )
        .expect("KAT seal")
    }

    fn seal_kat_view_only() -> Vec<u8> {
        let (view_sk, dk, spend_pk) = kat_view_only_cap();
        let cap = CapabilityContent::ViewOnly {
            view_sk: &view_sk,
            ml_kem_dk: &dk,
            spend_pk: &spend_pk,
        };
        seal_keys_file_with_entropy(
            KAT_PASSWORD,
            1, 0,
            &cap,
            KAT_CREATION_TIMESTAMP,
            KAT_RESTORE_HEIGHT,
            &KAT_EXPECTED_ADDRESS,
            kat_kdf(),
            &KAT_WRAP_SALT_FULL,
            &KAT_WRAP_NONCE_FULL,
            &KAT_REGION1_NONCE_FULL,
            &KAT_FILE_KEK_SEED,
        )
        .expect("KAT seal")
    }

    fn seal_kat_hardware_offload() -> Vec<u8> {
        let (view_sk, dk, spend_pk) = kat_view_only_cap();
        let device_desc = b"ledger-nano-s:kat-serial-001";
        let cap = CapabilityContent::HardwareOffload {
            view_sk: &view_sk,
            ml_kem_dk: &dk,
            spend_pk: &spend_pk,
            device_desc,
        };
        seal_keys_file_with_entropy(
            KAT_PASSWORD,
            2, 0,
            &cap,
            KAT_CREATION_TIMESTAMP,
            KAT_RESTORE_HEIGHT,
            &KAT_EXPECTED_ADDRESS,
            kat_kdf(),
            &KAT_WRAP_SALT_FULL,
            &KAT_WRAP_NONCE_FULL,
            &KAT_REGION1_NONCE_FULL,
            &KAT_FILE_KEK_SEED,
        )
        .expect("KAT seal")
    }

    fn seal_kat_state(keys_bytes: &[u8]) -> Vec<u8> {
        seal_state_file_with_entropy(KAT_PASSWORD, keys_bytes, KAT_STATE_PAYLOAD, &KAT_STATE_NONCE)
            .expect("KAT state seal")
    }

    // Frozen fixture bytes. See docs/test_vectors/WALLET_FILE_FORMAT_V1/.
    // The bytes are checked in alongside this test module; any drift in
    // seal_keys_file_with_entropy vs. these fixtures constitutes a
    // wire-format break and must land as an explicit format-version bump.
    const KAT_FULL_HEX: &str =
        include_str!("../../../docs/test_vectors/WALLET_FILE_FORMAT_V1/full.hex");
    const KAT_VIEW_ONLY_HEX: &str =
        include_str!("../../../docs/test_vectors/WALLET_FILE_FORMAT_V1/view_only.hex");
    const KAT_HARDWARE_OFFLOAD_HEX: &str =
        include_str!("../../../docs/test_vectors/WALLET_FILE_FORMAT_V1/hardware_offload.hex");
    const KAT_STATE_HEX: &str =
        include_str!("../../../docs/test_vectors/WALLET_FILE_FORMAT_V1/state_for_full.hex");

    fn decode_hex_fixture(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        hex::decode(cleaned).expect("fixture hex must be valid")
    }

    #[test]
    fn kat_full_roundtrip() {
        let bytes = seal_kat_full();
        assert_eq!(
            bytes,
            decode_hex_fixture(KAT_FULL_HEX),
            "FULL-mode seal output diverged from fixture (format break?)"
        );
        let opened = open_keys_file(KAT_PASSWORD, &bytes).expect("open KAT");
        assert_eq!(opened.capability_mode, CAPABILITY_FULL);
        assert_eq!(opened.network, 0);
        assert_eq!(opened.seed_format, 0);
        assert_eq!(opened.creation_timestamp, KAT_CREATION_TIMESTAMP);
        assert_eq!(opened.restore_height_hint, KAT_RESTORE_HEIGHT);
        assert_eq!(opened.expected_classical_address, KAT_EXPECTED_ADDRESS);
        assert_eq!(opened.cap_content.as_slice(), &kat_full_seed());
    }

    #[test]
    fn kat_view_only_roundtrip() {
        let bytes = seal_kat_view_only();
        assert_eq!(bytes, decode_hex_fixture(KAT_VIEW_ONLY_HEX));
        let opened = open_keys_file(KAT_PASSWORD, &bytes).expect("open KAT");
        assert_eq!(opened.capability_mode, CAPABILITY_VIEW_ONLY);
        let (view_sk, dk, spend_pk) = kat_view_only_cap();
        assert_eq!(&opened.cap_content[..32], &view_sk);
        assert_eq!(&opened.cap_content[32..32 + ML_KEM_768_DK_LEN], &dk[..]);
        assert_eq!(&opened.cap_content[32 + ML_KEM_768_DK_LEN..], &spend_pk);
    }

    #[test]
    fn kat_hardware_offload_roundtrip() {
        let bytes = seal_kat_hardware_offload();
        assert_eq!(bytes, decode_hex_fixture(KAT_HARDWARE_OFFLOAD_HEX));
        let opened = open_keys_file(KAT_PASSWORD, &bytes).expect("open KAT");
        assert_eq!(opened.capability_mode, CAPABILITY_HARDWARE_OFFLOAD);
        // Device descriptor follows view_sk || dk || spend_pk.
        let dd_off = 32 + ML_KEM_768_DK_LEN + 32;
        let dev_len =
            u16::from_le_bytes([opened.cap_content[dd_off], opened.cap_content[dd_off + 1]]);
        let dev_desc = &opened.cap_content[dd_off + 2..dd_off + 2 + usize::from(dev_len)];
        assert_eq!(dev_desc, b"ledger-nano-s:kat-serial-001");
    }

    #[test]
    fn kat_state_roundtrip_against_full() {
        let keys = seal_kat_full();
        let state = seal_kat_state(&keys);
        assert_eq!(state, decode_hex_fixture(KAT_STATE_HEX));
        let opened = open_state_file(KAT_PASSWORD, &keys, &state).expect("open state KAT");
        assert_eq!(opened.as_slice(), KAT_STATE_PAYLOAD);
    }

    /// Regenerates the KAT fixtures on disk. Run manually with
    /// `cargo test -p shekyl-crypto-pq kat_regenerate_fixtures -- --ignored --nocapture`
    /// whenever a deliberate, documented format change requires rotating
    /// the on-disk vectors. Commit the resulting `.hex` files.
    #[test]
    #[ignore = "fixture regenerator; run manually after format changes"]
    fn kat_regenerate_fixtures() {
        use std::fs;
        use std::path::PathBuf;
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/test_vectors/WALLET_FILE_FORMAT_V1");
        fs::create_dir_all(&dir).expect("mkdir -p");
        let write = |name: &str, bytes: &[u8]| {
            let path = dir.join(name);
            let mut text = String::new();
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 && i % 32 == 0 {
                    text.push('\n');
                }
                text.push_str(&format!("{b:02x}"));
            }
            text.push('\n');
            fs::write(&path, text).expect("write fixture");
            eprintln!("wrote {}: {} bytes", path.display(), bytes.len());
        };
        let full = seal_kat_full();
        let view_only = seal_kat_view_only();
        let hardware_offload = seal_kat_hardware_offload();
        let state_for_full = seal_kat_state(&full);
        write("full.hex", &full);
        write("view_only.hex", &view_only);
        write("hardware_offload.hex", &hardware_offload);
        write("state_for_full.hex", &state_for_full);
    }
}
