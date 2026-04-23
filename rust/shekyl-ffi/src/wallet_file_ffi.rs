// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the high-level wallet-file orchestrator.
//!
//! Where [`crate::wallet_envelope_ffi`] exposes the raw envelope primitives
//! (seal/open/rewrap/inspect/state-seal/state-open) so callers can compose
//! their own on-disk orchestration, this module exposes a **single opaque
//! handle** (`ShekylWallet`) that wraps a [`WalletFileHandle`] plus the
//! [`WalletLedger`] loaded at open time. The C++ core calls into this
//! surface for every wallet lifecycle operation (create / open /
//! save-state / rotate-password / close) and for read-only metadata
//! ("network", "capability", "timestamp", "restore height hint", "classical
//! address"). It never touches raw envelope bytes, per Rule 40.
//!
//! # Why one more FFI module?
//!
//! The envelope primitives are AAD-aware but path-unaware: they know how
//! to seal bytes, not where those bytes should live on disk, how to
//! fsync the parent directory, or how to refuse a second opener. The
//! orchestrator in `shekyl-wallet-file` owns all of that. Before this
//! module, `wallet2.cpp` reimplemented companion-path derivation,
//! atomic writes, advisory locking, and write-once enforcement in C++.
//! This module deletes that duplication: the orchestrator lives in
//! Rust and the FFI exposes only the operations a consumer actually
//! needs.
//!
//! # Handle lifecycle
//!
//! ```text
//! create(base, pw, …) ─┐
//!                      ├─► ShekylWallet*    (owns WalletFileHandle + WalletLedger)
//! open(base, pw, net) ─┘                     (advisory lock held for lifetime)
//!
//! save_state(h, pw, new_ledger_postcard)
//! rotate_password(h, old_pw, new_pw)
//! export_ledger_postcard(h, buf, cap, len_required)
//! get_metadata(h, out)
//!
//! free(h)  ───► drops WalletFileHandle (releases lock) and zeroes
//!               the owned WalletLedger (TxSecretKey fields wipe on drop).
//! ```
//!
//! # Ownership & safety
//!
//! `shekyl_wallet_create` / `shekyl_wallet_open` return a heap-allocated
//! `*mut ShekylWallet` via `Box::into_raw`. The ONLY legal way to
//! destroy such a pointer is through `shekyl_wallet_free`, which
//! reconstitutes the `Box` and drops it. Calling `free(nullptr)` is a
//! no-op (mirrors the C idiom and lets RAII wrappers on the C++ side be
//! branchless).
//!
//! All other functions take `*mut ShekylWallet` as their first argument
//! and dereference it under `&mut *h` with the handle's aliasing rules
//! enforced by C++ (i.e. C++ must not concurrently call two mutating
//! functions on the same handle; read-only getters may overlap with
//! each other but not with writers).
//!
//! # Variable-length output discipline
//!
//! Matches [`crate::wallet_envelope_ffi`]: every variable-length output
//! (the ledger postcard blob) takes `(out_buf, out_cap, out_len_required)`.
//! On every return the function writes the size it *would* have needed
//! into `out_len_required`, so the caller can probe with `out_buf =
//! null` and allocate precisely, then retry.
//!
//! # Error taxonomy
//!
//! See [`map_wallet_file_err`] for the crosswalk from
//! [`WalletFileError`] into the wire-stable `SHEKYL_WALLET_ERR_*` codes.
//! Envelope failures reuse the existing codes from `wallet_envelope_ffi`
//! so the C++ side has one taxonomy to render.

use std::os::raw::c_char;
use std::path::PathBuf;

use shekyl_address::Network;
use shekyl_wallet_file::{
    Capability, CreateParams, OpenOutcome, SafetyOverrides, WalletFileError, WalletFileHandle,
};
use shekyl_wallet_state::WalletLedger;
use zeroize::Zeroizing;

use crate::wallet_envelope_ffi::{
    map_err as map_envelope_err, SHEKYL_WALLET_CAPABILITY_FULL,
    SHEKYL_WALLET_CAPABILITY_HARDWARE_OFFLOAD, SHEKYL_WALLET_CAPABILITY_RESERVED_MULTISIG,
    SHEKYL_WALLET_CAPABILITY_VIEW_ONLY, SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL,
    SHEKYL_WALLET_ERR_NULL_POINTER, SHEKYL_WALLET_ERR_OK, SHEKYL_WALLET_ERR_REQUIRES_MULTISIG,
    SHEKYL_WALLET_ERR_UNKNOWN_CAPABILITY_MODE, SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES,
};

// ---------------------------------------------------------------------------
// Error codes added by this module (wire-stable, appended after the
// envelope-ffi codes; never reused).
// ---------------------------------------------------------------------------

/// Filesystem I/O failure (read/write/rename not otherwise categorised).
pub const SHEKYL_WALLET_ERR_IO: u32 = 15;

/// SWSP payload framing failure (bad payload magic, unknown payload
/// kind, body-length mismatch). Envelope AEAD succeeded but the
/// plaintext did not conform to the framed payload schema.
pub const SHEKYL_WALLET_ERR_PAYLOAD: u32 = 16;

/// Inner-ledger postcard failure or bundle/block version mismatch.
pub const SHEKYL_WALLET_ERR_LEDGER: u32 = 17;

/// Refused to overwrite an existing `.wallet.keys` at create time.
pub const SHEKYL_WALLET_ERR_KEYS_FILE_ALREADY_EXISTS: u32 = 18;

/// Advisory lock on `.wallet.keys` is held by another process (or an
/// in-process second opener that reached the same file description).
pub const SHEKYL_WALLET_ERR_ALREADY_LOCKED: u32 = 19;

/// `rename(2)` of a newly-written temp file into its final location
/// failed. The original target (if any) is untouched.
pub const SHEKYL_WALLET_ERR_ATOMIC_WRITE_RENAME: u32 = 20;

/// Keys file decoded cleanly but declared an unknown network byte.
pub const SHEKYL_WALLET_ERR_UNKNOWN_NETWORK: u32 = 21;

/// Keys file is bound to a different network than the caller
/// requested. Refuses loudly to prevent cross-chain confusion.
pub const SHEKYL_WALLET_ERR_NETWORK_MISMATCH: u32 = 22;

/// Internal bug: a non-rotation save path attempted to rewrite
/// `.wallet.keys`. Should be unreachable by construction. Surfaces as
/// [`SHEKYL_WALLET_ERR_INTERNAL`] plus a tracing log entry.
pub const SHEKYL_WALLET_ERR_KEYS_FILE_WRITE_ONCE_VIOLATION: u32 = 23;

// ---------------------------------------------------------------------------
// Metadata view struct
// ---------------------------------------------------------------------------

/// Read-only snapshot of every non-secret field the orchestrator knows
/// about. Populated by [`shekyl_wallet_get_metadata`]; all getters on
/// the handle would collapse into this one struct on the C++ side.
///
/// Layout is `#[repr(C)]` and pinned by a `const _ = assert!(size_of…)`
/// so any future field addition that would shift existing offsets fails
/// at compile time.
#[repr(C)]
pub struct ShekylWalletMetadata {
    /// 0 = Mainnet, 1 = Testnet, 2 = Stagenet. Wire-stable; matches
    /// `shekyl_address::Network::as_u8()`.
    pub network: u8,
    /// Capability discriminant matching `SHEKYL_WALLET_CAPABILITY_*`.
    pub capability_mode: u8,
    /// Seed format (0x00 = BIP-39 mnemonic, 0x01 = raw hex) as
    /// declared at creation. Persisted for UX.
    pub seed_format: u8,
    /// Padding to 8-byte alignment for the u64 below. Keeps the
    /// layout byte-stable across compilers without depending on
    /// implicit padding rules.
    pub _reserved: [u8; 5],
    /// Unix-epoch seconds at wallet creation. Persisted in the AAD.
    pub creation_timestamp: u64,
    /// Block-height floor for full-history rescans. Also the value
    /// seeded into the sync-state block on the lost-`.wallet`
    /// recovery path.
    pub restore_height_hint: u32,
    /// Explicit alignment padding for the fixed-size array below.
    /// Unused; always zero.
    pub _reserved_align: [u8; 4],
    /// Canonical 65-byte classical address committed in the AAD:
    /// `version(1) || spend_pk(32) || view_pk(32)`.
    pub expected_classical_address: [u8; SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES],
    /// Trailing pad so the struct's byte size is a multiple of its
    /// natural 8-byte alignment (driven by the u64 above). Without
    /// this, `sizeof` returns 96 but the field enumeration sums to
    /// 89, which is easy to misread on the C++ side.
    pub _tail_pad: [u8; 7],
}

// Pin the layout contract; mirrors the C++ static_assert in
// `src/shekyl/shekyl_ffi.h`. 1+1+1+5 + 8 + 4+4 + 65 + 7 = 96.
const _: () = assert!(
    core::mem::size_of::<ShekylWalletMetadata>()
        == 8 + 8 + 4 + 4 + SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES + 7,
    "ShekylWalletMetadata layout must match the C++ static_assert in shekyl_ffi.h",
);

// ---------------------------------------------------------------------------
// Safety overrides (2k.2)
// ---------------------------------------------------------------------------

/// CLI-ephemeral safety overrides in their C-ABI form.
///
/// Implements the "CLI-ephemeral overrides" layer of the three-layer
/// preference model (see `docs/WALLET_PREFS.md` §2.3, §3.3). Each field is
/// an explicit `(has_<name>, <name>)` pair so there is no sentinel-value
/// accident where a legitimate u64 happens to mean "no override". The
/// `_pad*` fields exist to anchor the `u64` members on their natural
/// 8-byte alignment without relying on implicit padding rules.
///
/// Pass `*const ShekylSafetyOverrides = null` to
/// [`shekyl_wallet_open`] to mean "no overrides" (the GUI path).
#[repr(C)]
pub struct ShekylSafetyOverrides {
    pub has_max_reorg_depth: u8,
    pub _pad0: [u8; 7],
    pub max_reorg_depth: u64,
    pub has_skip_to_height: u8,
    pub _pad1: [u8; 7],
    pub skip_to_height: u64,
    pub has_refresh_from_block_height: u8,
    pub _pad2: [u8; 7],
    pub refresh_from_block_height: u64,
}

// Pin the layout: three `(u8 + [u8; 7] + u64)` tuples = 3 * 16 = 48 bytes.
// Mirrors the C++ `static_assert` in `src/shekyl/shekyl_ffi.h`.
const _: () = assert!(
    core::mem::size_of::<ShekylSafetyOverrides>() == 48,
    "ShekylSafetyOverrides layout must match the C++ static_assert in shekyl_ffi.h",
);

impl ShekylSafetyOverrides {
    /// Decode a caller-supplied C struct into the typed Rust
    /// [`SafetyOverrides`]. A null pointer means "no overrides", which
    /// maps to [`SafetyOverrides::none`]. The `_pad*` fields are not
    /// validated: they are present purely to pin alignment, and any
    /// future tampering-protection check would go here.
    ///
    /// # Safety
    ///
    /// `ptr` must either be null or point to a valid, aligned, fully
    /// initialised [`ShekylSafetyOverrides`] for the duration of this
    /// call.
    unsafe fn decode(ptr: *const Self) -> SafetyOverrides {
        if ptr.is_null() {
            return SafetyOverrides::none();
        }
        let s = &*ptr;
        SafetyOverrides {
            max_reorg_depth: (s.has_max_reorg_depth != 0).then_some(s.max_reorg_depth),
            skip_to_height: (s.has_skip_to_height != 0).then_some(s.skip_to_height),
            refresh_from_block_height: (s.has_refresh_from_block_height != 0)
                .then_some(s.refresh_from_block_height),
        }
    }
}

// ---------------------------------------------------------------------------
// Opaque handle
// ---------------------------------------------------------------------------

/// Opaque wallet handle. The C side only ever sees `*mut ShekylWallet`
/// and must dispose of it exclusively via [`shekyl_wallet_free`].
///
/// Internally, this owns:
///
/// - the orchestrator [`WalletFileHandle`] (which holds the advisory
///   lock, cached keys-file bytes, and decoded non-secret metadata), and
/// - a [`WalletLedger`] loaded from `.wallet` (or synthesized on the
///   state-lost recovery path).
///
/// The ledger is stored on the handle so the caller does not need to
/// round-trip postcard bytes on every get/set; a single
/// [`shekyl_wallet_export_ledger_postcard`] call produces the on-disk
/// image on demand, and [`shekyl_wallet_save_state`] takes fresh bytes
/// and both seals them AND replaces the in-memory ledger so subsequent
/// exports reflect the save.
///
/// # Dropping
///
/// Drop order is the same as any other Rust struct: `ledger` first,
/// then `inner`. The ledger's secret-bearing fields (TxSecretKey,
/// Zeroizing master seed, etc.) zero on drop; the handle releases the
/// advisory lock on drop.
pub struct ShekylWallet {
    inner: WalletFileHandle,
    ledger: WalletLedger,
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Crosswalk [`WalletFileError`] into the wire-stable error codes.
///
/// Envelope errors route through [`crate::wallet_envelope_ffi::map_err`]
/// so both FFI surfaces share one taxonomy — the C++ side only ever
/// learns one set of `SHEKYL_WALLET_ERR_*` constants.
fn map_wallet_file_err(e: &WalletFileError) -> u32 {
    match e {
        WalletFileError::Envelope(inner) => map_envelope_err(inner),
        WalletFileError::Payload(_) => SHEKYL_WALLET_ERR_PAYLOAD,
        WalletFileError::Ledger(_) => SHEKYL_WALLET_ERR_LEDGER,
        WalletFileError::Io(_) => SHEKYL_WALLET_ERR_IO,
        WalletFileError::KeysFileAlreadyExists { .. } => SHEKYL_WALLET_ERR_KEYS_FILE_ALREADY_EXISTS,
        WalletFileError::KeysFileWriteOnceViolation { .. } => {
            SHEKYL_WALLET_ERR_KEYS_FILE_WRITE_ONCE_VIOLATION
        }
        WalletFileError::AlreadyLocked { .. } => SHEKYL_WALLET_ERR_ALREADY_LOCKED,
        WalletFileError::AtomicWriteRename { .. } => SHEKYL_WALLET_ERR_ATOMIC_WRITE_RENAME,
        WalletFileError::UnknownNetwork(_) => SHEKYL_WALLET_ERR_UNKNOWN_NETWORK,
        WalletFileError::NetworkMismatch { .. } => SHEKYL_WALLET_ERR_NETWORK_MISMATCH,
        WalletFileError::UnknownCapability(_) => SHEKYL_WALLET_ERR_UNKNOWN_CAPABILITY_MODE,
        WalletFileError::MultisigNotSupported => SHEKYL_WALLET_ERR_REQUIRES_MULTISIG,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers (local variants of the wallet_envelope_ffi helpers so
// this module has no cross-module private coupling).
// ---------------------------------------------------------------------------

unsafe fn make_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

unsafe fn set_err(out: *mut u32, code: u32) {
    if !out.is_null() {
        *out = code;
    }
}

unsafe fn set_len(out: *mut usize, v: usize) {
    if !out.is_null() {
        *out = v;
    }
}

unsafe fn set_bool(out: *mut bool, v: bool) {
    if !out.is_null() {
        *out = v;
    }
}

unsafe fn set_u64(out: *mut u64, v: u64) {
    if !out.is_null() {
        *out = v;
    }
}

/// Decode a UTF-8 path from (ptr, len). Paths are utf-8 on every target
/// we support (Linux, macOS, Windows via Rust's `OsStr` conversion).
unsafe fn path_from_utf8(ptr: *const c_char, len: usize) -> Option<PathBuf> {
    if len == 0 || ptr.is_null() {
        return None;
    }
    let bytes = std::slice::from_raw_parts(ptr.cast::<u8>(), len);
    let s = std::str::from_utf8(bytes).ok()?;
    Some(PathBuf::from(s))
}

/// Decode a capability discriminant byte into a borrowed-content
/// variant. `cap_content` layout is dictated by `mode` exactly as the
/// envelope's own tests describe; this function does not re-validate
/// lengths (the envelope's `seal_keys_file` does that and returns a
/// precise error code).
unsafe fn capability_from_parts<'a>(
    mode: u8,
    cap_content: &'a [u8],
) -> Option<shekyl_crypto_pq::wallet_envelope::CapabilityContent<'a>> {
    use shekyl_crypto_pq::wallet_envelope::CapabilityContent;
    match mode {
        SHEKYL_WALLET_CAPABILITY_FULL => {
            let master_seed_64: &[u8; 64] = cap_content.get(..64)?.try_into().ok()?;
            Some(CapabilityContent::Full { master_seed_64 })
        }
        SHEKYL_WALLET_CAPABILITY_VIEW_ONLY => {
            use shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN;
            let view_sk: &[u8; 32] = cap_content.get(..32)?.try_into().ok()?;
            let dk_end = 32 + ML_KEM_768_DK_LEN;
            let ml_kem_dk: &[u8; ML_KEM_768_DK_LEN] =
                cap_content.get(32..dk_end)?.try_into().ok()?;
            let spend_pk: &[u8; 32] = cap_content.get(dk_end..dk_end + 32)?.try_into().ok()?;
            Some(CapabilityContent::ViewOnly {
                view_sk,
                ml_kem_dk,
                spend_pk,
            })
        }
        SHEKYL_WALLET_CAPABILITY_HARDWARE_OFFLOAD => {
            use shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN;
            let view_sk: &[u8; 32] = cap_content.get(..32)?.try_into().ok()?;
            let dk_end = 32 + ML_KEM_768_DK_LEN;
            let ml_kem_dk: &[u8; ML_KEM_768_DK_LEN] =
                cap_content.get(32..dk_end)?.try_into().ok()?;
            let spend_pk: &[u8; 32] = cap_content.get(dk_end..dk_end + 32)?.try_into().ok()?;
            let desc_len_off = dk_end + 32;
            let dev_desc_len = u16::from_le_bytes(
                cap_content
                    .get(desc_len_off..desc_len_off + 2)?
                    .try_into()
                    .ok()?,
            ) as usize;
            let desc_start = desc_len_off + 2;
            let device_desc = cap_content.get(desc_start..desc_start + dev_desc_len)?;
            Some(CapabilityContent::HardwareOffload {
                view_sk,
                ml_kem_dk,
                spend_pk,
                device_desc,
            })
        }
        _ => None,
    }
}

fn capability_to_byte(c: Capability) -> u8 {
    match c {
        Capability::Full => SHEKYL_WALLET_CAPABILITY_FULL,
        Capability::ViewOnly => SHEKYL_WALLET_CAPABILITY_VIEW_ONLY,
        Capability::HardwareOffload => SHEKYL_WALLET_CAPABILITY_HARDWARE_OFFLOAD,
    }
}

// ---------------------------------------------------------------------------
// Lifecycle: create
// ---------------------------------------------------------------------------

/// Create a fresh wallet pair (`.wallet.keys` + `.wallet`) on disk and
/// return an owning handle.
///
/// Ownership: on success, `*out_handle` is set to a pointer the caller
/// must eventually pass to [`shekyl_wallet_free`]. On failure, the
/// pointer is left unchanged and the caller must not dereference it.
///
/// `initial_ledger_postcard` may be zero-length; the orchestrator will
/// seal an empty [`WalletLedger`]. Non-empty bytes must parse as a
/// valid [`WalletLedger`] via `from_postcard_bytes`, otherwise this
/// function returns [`SHEKYL_WALLET_ERR_LEDGER`] without touching disk.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_wallet_create(
    base_path_ptr: *const c_char,
    base_path_len: usize,
    password_ptr: *const u8,
    password_len: usize,
    network: u8,
    seed_format: u8,
    capability_mode: u8,
    cap_content_ptr: *const u8,
    cap_content_len: usize,
    creation_timestamp: u64,
    restore_height_hint: u32,
    expected_classical_address_ptr: *const u8,
    kdf_m_log2: u8,
    kdf_t: u8,
    kdf_p: u8,
    initial_ledger_postcard_ptr: *const u8,
    initial_ledger_postcard_len: usize,
    out_handle: *mut *mut ShekylWallet,
    out_error: *mut u32,
) -> bool {
    if out_handle.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    *out_handle = std::ptr::null_mut();

    let base_path = match path_from_utf8(base_path_ptr, base_path_len) {
        Some(p) => p,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };
    let password = match make_slice(password_ptr, password_len) {
        Some(s) => s,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };
    let cap_content = match make_slice(cap_content_ptr, cap_content_len) {
        Some(s) => s,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };
    let initial_postcard =
        match make_slice(initial_ledger_postcard_ptr, initial_ledger_postcard_len) {
            Some(s) => s,
            None => {
                set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
                return false;
            }
        };
    if expected_classical_address_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let expected_addr: &[u8; SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES] =
        std::slice::from_raw_parts(
            expected_classical_address_ptr,
            SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES,
        )
        .try_into()
        .unwrap();

    // Reject reserved/unknown capability bytes up-front so the C++
    // error message can reference the same code the envelope would
    // have emitted internally.
    if capability_mode == SHEKYL_WALLET_CAPABILITY_RESERVED_MULTISIG {
        set_err(out_error, SHEKYL_WALLET_ERR_REQUIRES_MULTISIG);
        return false;
    }
    let capability = match capability_from_parts(capability_mode, cap_content) {
        Some(c) => c,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_UNKNOWN_CAPABILITY_MODE);
            return false;
        }
    };

    let network = match Network::from_u8(network) {
        Some(n) => n,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_UNKNOWN_NETWORK);
            return false;
        }
    };

    // Parse the initial ledger (empty bytes → empty ledger) before
    // touching disk so a malformed buffer never produces a half-
    // created wallet.
    let initial_ledger = if initial_postcard.is_empty() {
        WalletLedger::empty()
    } else {
        match WalletLedger::from_postcard_bytes(initial_postcard) {
            Ok(l) => l,
            Err(_) => {
                set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
                return false;
            }
        }
    };

    let kdf = shekyl_crypto_pq::wallet_envelope::KdfParams {
        m_log2: kdf_m_log2,
        t: kdf_t,
        p: kdf_p,
    };

    let params = CreateParams {
        base_path: &base_path,
        password,
        network,
        seed_format,
        capability: &capability,
        creation_timestamp,
        restore_height_hint,
        expected_classical_address: expected_addr,
        kdf,
        initial_ledger: &initial_ledger,
    };

    match WalletFileHandle::create(&params) {
        Ok(inner) => {
            let boxed = Box::new(ShekylWallet {
                inner,
                ledger: initial_ledger,
            });
            *out_handle = Box::into_raw(boxed);
            set_err(out_error, SHEKYL_WALLET_ERR_OK);
            true
        }
        Err(e) => {
            set_err(out_error, map_wallet_file_err(&e));
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle: open
// ---------------------------------------------------------------------------

/// Open an existing wallet pair. On success, populates `*out_handle`
/// with an owning pointer the caller must dispose via
/// [`shekyl_wallet_free`], sets `*out_state_lost` according to the
/// orchestrator's recovery-path signal, and writes the rescan floor
/// into `*out_restore_from_height`.
///
/// `overrides` may be NULL, meaning "no CLI overrides active" — the
/// GUI path. A non-NULL pointer passes the CLI-ephemeral safety layer
/// through to the orchestrator, which stores it on the handle and
/// emits `tracing::warn!` lines for each active field.
///
/// When `*out_state_lost` is `true`, the caller MUST drive a rescan
/// starting at `*out_restore_from_height` and then call
/// [`shekyl_wallet_save_state`] with the rebuilt ledger before
/// closing. Closing without saving leaves the `.wallet` absent on
/// disk, and the next open will again see `state_lost = true`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_wallet_open(
    base_path_ptr: *const c_char,
    base_path_len: usize,
    password_ptr: *const u8,
    password_len: usize,
    expected_network: u8,
    overrides: *const ShekylSafetyOverrides,
    out_handle: *mut *mut ShekylWallet,
    out_state_lost: *mut bool,
    out_restore_from_height: *mut u64,
    out_error: *mut u32,
) -> bool {
    if out_handle.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    *out_handle = std::ptr::null_mut();
    set_bool(out_state_lost, false);
    set_u64(out_restore_from_height, 0);

    let base_path = match path_from_utf8(base_path_ptr, base_path_len) {
        Some(p) => p,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };
    let password = match make_slice(password_ptr, password_len) {
        Some(s) => s,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };
    let expected_network = match Network::from_u8(expected_network) {
        Some(n) => n,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_UNKNOWN_NETWORK);
            return false;
        }
    };
    let overrides = ShekylSafetyOverrides::decode(overrides);

    match WalletFileHandle::open(&base_path, password, expected_network, overrides) {
        Ok((inner, outcome)) => {
            let (ledger, state_lost, restore_from_height) = match outcome {
                OpenOutcome::StateLoaded(l) => (l, false, 0u64),
                OpenOutcome::StateLost {
                    ledger,
                    restore_from_height,
                } => (ledger, true, restore_from_height),
            };
            let boxed = Box::new(ShekylWallet { inner, ledger });
            *out_handle = Box::into_raw(boxed);
            set_bool(out_state_lost, state_lost);
            set_u64(out_restore_from_height, restore_from_height);
            set_err(out_error, SHEKYL_WALLET_ERR_OK);
            true
        }
        Err(e) => {
            set_err(out_error, map_wallet_file_err(&e));
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle: free
// ---------------------------------------------------------------------------

/// Destroy a handle returned by [`shekyl_wallet_create`] or
/// [`shekyl_wallet_open`]. Calling with `NULL` is a no-op so C++ RAII
/// wrappers can be branchless.
///
/// # Safety
///
/// `h` must have been produced by one of this module's constructors and
/// must not have been freed already. Passing the same non-null pointer
/// twice is undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_free(h: *mut ShekylWallet) {
    if h.is_null() {
        return;
    }
    // Reconstitute the Box and drop. The `Box` drop runs
    // `WalletFileHandle`'s Drop (releases the advisory lock) and the
    // `WalletLedger`'s drop (zeroes TxSecretKey fields).
    drop(Box::from_raw(h));
}

// ---------------------------------------------------------------------------
// Metadata getter
// ---------------------------------------------------------------------------

/// Populate `*out` with the non-secret wallet metadata the
/// orchestrator tracks. Returns `false` only on null-pointer arguments;
/// the metadata itself cannot fail to read because it was fully
/// decoded at create/open time.
#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_metadata(
    h: *mut ShekylWallet,
    out: *mut ShekylWalletMetadata,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    std::ptr::write_bytes(out, 0u8, 1);
    let w = &*h;
    let meta = ShekylWalletMetadata {
        network: w.inner.network().as_u8(),
        capability_mode: capability_to_byte(w.inner.capability()),
        seed_format: w.inner.opened_keys().seed_format,
        _reserved: [0; 5],
        creation_timestamp: w.inner.creation_timestamp(),
        restore_height_hint: w.inner.restore_height_hint(),
        _reserved_align: [0; 4],
        expected_classical_address: *w.inner.expected_classical_address(),
        _tail_pad: [0; 7],
    };
    *out = meta;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

// ---------------------------------------------------------------------------
// Ledger export (two-call sizing)
// ---------------------------------------------------------------------------

/// Serialize the handle's in-memory [`WalletLedger`] to postcard bytes
/// and copy them into `out_buf`. Follows the two-call sizing
/// convention: on every return `*out_len_required` is set to the size
/// the ledger would serialize to; on buffer-too-small, `out_error` is
/// `SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL` and `out_buf` is not written.
///
/// # Secret exposure
///
/// The postcard bytes contain `TxSecretKey` fields from the tx-meta
/// block, so the caller MUST treat the buffer as secret (zeroize
/// before free, never log). This module does not retain the serialized
/// bytes; each call re-serializes from the in-memory ledger.
#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_export_ledger_postcard(
    h: *mut ShekylWallet,
    out_buf: *mut u8,
    out_cap: usize,
    out_len_required: *mut usize,
    out_error: *mut u32,
) -> bool {
    set_len(out_len_required, 0);
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let bytes: Zeroizing<Vec<u8>> = match w.ledger.to_postcard_bytes() {
        Ok(b) => Zeroizing::new(b),
        Err(_) => {
            set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
            return false;
        }
    };
    set_len(out_len_required, bytes.len());
    if out_buf.is_null() || out_cap < bytes.len() {
        set_err(out_error, SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL);
        return false;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

// ---------------------------------------------------------------------------
// State save
// ---------------------------------------------------------------------------

/// Seal a new `.wallet` from the given ledger postcard bytes.
///
/// The bytes are parsed as a [`WalletLedger`] first (so malformed input
/// is rejected before Argon2id runs), then sealed via the
/// orchestrator's `save_state`. On success the handle's in-memory
/// ledger is replaced with the fresh one so subsequent
/// [`shekyl_wallet_export_ledger_postcard`] calls reflect the save.
///
/// # Password discipline
///
/// The password is required on every call because the envelope's
/// `seal_state_file` must re-derive `file_kek` via Argon2id (no
/// caching — see spec §4.3).
#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_save_state(
    h: *mut ShekylWallet,
    password_ptr: *const u8,
    password_len: usize,
    ledger_postcard_ptr: *const u8,
    ledger_postcard_len: usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let password = match make_slice(password_ptr, password_len) {
        Some(s) => s,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };
    let ledger_bytes = match make_slice(ledger_postcard_ptr, ledger_postcard_len) {
        Some(s) => s,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };

    let new_ledger = match WalletLedger::from_postcard_bytes(ledger_bytes) {
        Ok(l) => l,
        Err(_) => {
            set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
            return false;
        }
    };

    let w = &mut *h;
    if let Err(e) = w.inner.save_state(password, &new_ledger) {
        set_err(out_error, map_wallet_file_err(&e));
        return false;
    }
    // Save succeeded; replace in-memory copy. Clear the state-lost
    // flag: we've just persisted the caller's rebuilt ledger, so
    // future opens will take the StateLoaded path and
    // export_ledger_postcard will see the saved state.
    w.ledger = new_ledger;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

// ---------------------------------------------------------------------------
// Password rotation
// ---------------------------------------------------------------------------

/// Rotate the wallet password. `new_kdf_*` fields are used only when
/// `use_new_kdf` is non-zero; otherwise the existing KDF parameters are
/// retained (matching the Rust-side `Option::None`).
///
/// Region 1 of `.wallet.keys` and every byte of `.wallet` are
/// byte-identical after the rotation: only the wrap layer changes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_wallet_rotate_password(
    h: *mut ShekylWallet,
    old_password_ptr: *const u8,
    old_password_len: usize,
    new_password_ptr: *const u8,
    new_password_len: usize,
    use_new_kdf: u8,
    new_kdf_m_log2: u8,
    new_kdf_t: u8,
    new_kdf_p: u8,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let old_password = match make_slice(old_password_ptr, old_password_len) {
        Some(s) => s,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };
    let new_password = match make_slice(new_password_ptr, new_password_len) {
        Some(s) => s,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };
    let new_kdf = if use_new_kdf != 0 {
        Some(shekyl_crypto_pq::wallet_envelope::KdfParams {
            m_log2: new_kdf_m_log2,
            t: new_kdf_t,
            p: new_kdf_p,
        })
    } else {
        None
    };

    let w = &mut *h;
    match w.inner.rotate_password(old_password, new_password, new_kdf) {
        Ok(()) => {
            set_err(out_error, SHEKYL_WALLET_ERR_OK);
            true
        }
        Err(e) => {
            set_err(out_error, map_wallet_file_err(&e));
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! In-Rust tests for the opaque-handle FFI. These exercise the
    //! full lifecycle (create → open → export → save → reopen) plus
    //! the metadata getter and error paths. They cannot substitute
    //! for a C++ integration test — they're the Rust-side confidence
    //! that the FFI layer itself doesn't regress. The C++-consumer
    //! wiring lands in 2k/2l.

    use super::*;
    use shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN;
    use shekyl_crypto_pq::wallet_envelope::EXPECTED_CLASSICAL_ADDRESS_BYTES;

    /// Fast KDF profile identical to the one used in
    /// `shekyl-wallet-file`'s own tests.
    const KDF_M_LOG2: u8 = 0x08;
    const KDF_T: u8 = 1;
    const KDF_P: u8 = 1;

    fn fixture_view_only_cap_content() -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + ML_KEM_768_DK_LEN + 32);
        v.extend_from_slice(&[0x11u8; 32]);
        v.extend_from_slice(&[0x22u8; ML_KEM_768_DK_LEN]);
        v.extend_from_slice(&[0x33u8; 32]);
        v
    }

    fn fixture_address() -> [u8; EXPECTED_CLASSICAL_ADDRESS_BYTES] {
        let mut a = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
        a[0] = 0x01;
        a
    }

    fn create_with_path(base: &std::path::Path) -> *mut ShekylWallet {
        let cap = fixture_view_only_cap_content();
        let addr = fixture_address();
        let base_str = base.to_str().unwrap();
        let mut h: *mut ShekylWallet = std::ptr::null_mut();
        let mut err: u32 = 0;
        unsafe {
            let ok = shekyl_wallet_create(
                base_str.as_ptr().cast(),
                base_str.len(),
                b"pw".as_ptr(),
                2,
                Network::Testnet.as_u8(),
                0x00,
                SHEKYL_WALLET_CAPABILITY_VIEW_ONLY,
                cap.as_ptr(),
                cap.len(),
                0x6000_0000,
                0,
                addr.as_ptr(),
                KDF_M_LOG2,
                KDF_T,
                KDF_P,
                std::ptr::null(),
                0,
                &raw mut h,
                &raw mut err,
            );
            assert!(ok, "create failed: code={err}");
            assert!(!h.is_null());
            assert_eq!(err, SHEKYL_WALLET_ERR_OK);
        }
        h
    }

    #[test]
    fn create_open_metadata_export_save_reopen_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let h = create_with_path(&base);

        // Metadata getter.
        unsafe {
            let mut meta: ShekylWalletMetadata = std::mem::zeroed();
            let mut err = 0u32;
            assert!(shekyl_wallet_get_metadata(h, &raw mut meta, &raw mut err));
            assert_eq!(err, SHEKYL_WALLET_ERR_OK);
            assert_eq!(meta.network, Network::Testnet.as_u8());
            assert_eq!(meta.capability_mode, SHEKYL_WALLET_CAPABILITY_VIEW_ONLY);
            assert_eq!(meta.seed_format, 0x00);
            assert_eq!(meta.creation_timestamp, 0x6000_0000);
            assert_eq!(meta.restore_height_hint, 0);
            assert_eq!(meta.expected_classical_address[0], 0x01);
        }

        // Export ledger bytes (two-call sizing: probe first).
        let exported = unsafe {
            let mut need = 0usize;
            let mut err = 0u32;
            assert!(!shekyl_wallet_export_ledger_postcard(
                h,
                std::ptr::null_mut(),
                0,
                &raw mut need,
                &raw mut err,
            ));
            assert_eq!(err, SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL);
            assert!(need > 0, "empty ledger should still have >0 bytes postcard");
            let mut buf = vec![0u8; need];
            let mut got = 0usize;
            let mut err = 0u32;
            assert!(shekyl_wallet_export_ledger_postcard(
                h,
                buf.as_mut_ptr(),
                buf.len(),
                &raw mut got,
                &raw mut err,
            ));
            assert_eq!(err, SHEKYL_WALLET_ERR_OK);
            assert_eq!(got, need);
            buf
        };

        // Save a (byte-identical) round-trip of the ledger.
        unsafe {
            let mut err = 0u32;
            assert!(shekyl_wallet_save_state(
                h,
                b"pw".as_ptr(),
                2,
                exported.as_ptr(),
                exported.len(),
                &raw mut err,
            ));
            assert_eq!(err, SHEKYL_WALLET_ERR_OK);
        }

        // Free, then reopen.
        unsafe {
            shekyl_wallet_free(h);
        }
        let base_str = base.to_str().unwrap();
        unsafe {
            let mut h2: *mut ShekylWallet = std::ptr::null_mut();
            let mut lost: bool = true;
            let mut floor: u64 = 0;
            let mut err = 0u32;
            assert!(shekyl_wallet_open(
                base_str.as_ptr().cast(),
                base_str.len(),
                b"pw".as_ptr(),
                2,
                Network::Testnet.as_u8(),
                std::ptr::null(),
                &raw mut h2,
                &raw mut lost,
                &raw mut floor,
                &raw mut err,
            ));
            assert_eq!(err, SHEKYL_WALLET_ERR_OK);
            assert!(!h2.is_null());
            assert!(!lost, "freshly-saved wallet must not report state_lost");
            shekyl_wallet_free(h2);
        }
    }

    #[test]
    fn open_with_missing_state_reports_state_lost() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let h = create_with_path(&base);
        unsafe {
            shekyl_wallet_free(h);
        }
        // Delete the `.wallet` state file to simulate cache loss.
        std::fs::remove_file(&base).expect("remove .wallet");

        let base_str = base.to_str().unwrap();
        unsafe {
            let mut h2: *mut ShekylWallet = std::ptr::null_mut();
            let mut lost: bool = false;
            let mut floor: u64 = 0xdead_beef;
            let mut err = 0u32;
            assert!(shekyl_wallet_open(
                base_str.as_ptr().cast(),
                base_str.len(),
                b"pw".as_ptr(),
                2,
                Network::Testnet.as_u8(),
                std::ptr::null(),
                &raw mut h2,
                &raw mut lost,
                &raw mut floor,
                &raw mut err,
            ));
            assert_eq!(err, SHEKYL_WALLET_ERR_OK);
            assert!(lost, "missing .wallet must surface as state_lost=true");
            assert_eq!(floor, 0, "restore_from_height hint defaults to 0 here");
            shekyl_wallet_free(h2);
        }
    }

    #[test]
    fn open_with_wrong_network_returns_network_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let h = create_with_path(&base); // Testnet
        unsafe {
            shekyl_wallet_free(h);
        }
        let base_str = base.to_str().unwrap();
        unsafe {
            let mut h2: *mut ShekylWallet = std::ptr::null_mut();
            let mut lost = false;
            let mut floor = 0u64;
            let mut err = 0u32;
            assert!(!shekyl_wallet_open(
                base_str.as_ptr().cast(),
                base_str.len(),
                b"pw".as_ptr(),
                2,
                Network::Mainnet.as_u8(),
                std::ptr::null(),
                &raw mut h2,
                &raw mut lost,
                &raw mut floor,
                &raw mut err,
            ));
            assert_eq!(err, SHEKYL_WALLET_ERR_NETWORK_MISMATCH);
            assert!(h2.is_null(), "handle must stay null on refusal");
        }
    }

    #[test]
    fn create_refuses_duplicate_on_existing_keys_file() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let h = create_with_path(&base);
        unsafe {
            shekyl_wallet_free(h);
        }
        // Second create at the same base path must refuse.
        let cap = fixture_view_only_cap_content();
        let addr = fixture_address();
        let base_str = base.to_str().unwrap();
        unsafe {
            let mut h2: *mut ShekylWallet = std::ptr::null_mut();
            let mut err = 0u32;
            assert!(!shekyl_wallet_create(
                base_str.as_ptr().cast(),
                base_str.len(),
                b"pw".as_ptr(),
                2,
                Network::Testnet.as_u8(),
                0x00,
                SHEKYL_WALLET_CAPABILITY_VIEW_ONLY,
                cap.as_ptr(),
                cap.len(),
                0,
                0,
                addr.as_ptr(),
                KDF_M_LOG2,
                KDF_T,
                KDF_P,
                std::ptr::null(),
                0,
                &raw mut h2,
                &raw mut err,
            ));
            assert_eq!(err, SHEKYL_WALLET_ERR_KEYS_FILE_ALREADY_EXISTS);
            assert!(h2.is_null());
        }
    }

    #[test]
    fn free_nullptr_is_noop() {
        unsafe {
            shekyl_wallet_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn unknown_network_byte_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let h = create_with_path(&base);
        unsafe {
            shekyl_wallet_free(h);
        }
        let base_str = base.to_str().unwrap();
        unsafe {
            let mut h2: *mut ShekylWallet = std::ptr::null_mut();
            let mut lost = false;
            let mut floor = 0u64;
            let mut err = 0u32;
            assert!(!shekyl_wallet_open(
                base_str.as_ptr().cast(),
                base_str.len(),
                b"pw".as_ptr(),
                2,
                0xEF, // not a valid Network discriminant
                std::ptr::null(),
                &raw mut h2,
                &raw mut lost,
                &raw mut floor,
                &raw mut err,
            ));
            assert_eq!(err, SHEKYL_WALLET_ERR_UNKNOWN_NETWORK);
            assert!(h2.is_null());
        }
    }

    /// 2k.2: passing a non-NULL `ShekylSafetyOverrides` must produce a
    /// successful open with identical observable behavior to the NULL
    /// path. This pins the FFI contract: the C struct is the transport,
    /// and once it has been decoded into [`SafetyOverrides`] the
    /// orchestrator handles it exactly as any Rust caller would.
    ///
    /// We cannot easily observe the `tracing::warn!` emission from an
    /// FFI test (no subscriber is attached), but the `effective_*`
    /// path is covered in `shekyl-wallet-file`'s own tests, and here
    /// we confirm that the FFI boundary does not itself corrupt the
    /// override values.
    #[test]
    fn open_with_non_null_overrides_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let h = create_with_path(&base);
        unsafe {
            shekyl_wallet_free(h);
        }
        let base_str = base.to_str().unwrap();
        let overrides = ShekylSafetyOverrides {
            has_max_reorg_depth: 1,
            _pad0: [0; 7],
            max_reorg_depth: 0,
            has_skip_to_height: 1,
            _pad1: [0; 7],
            skip_to_height: 42,
            has_refresh_from_block_height: 0,
            _pad2: [0; 7],
            refresh_from_block_height: 0,
        };
        unsafe {
            let mut h2: *mut ShekylWallet = std::ptr::null_mut();
            let mut lost = false;
            let mut floor = 0u64;
            let mut err = 0u32;
            assert!(shekyl_wallet_open(
                base_str.as_ptr().cast(),
                base_str.len(),
                b"pw".as_ptr(),
                2,
                Network::Testnet.as_u8(),
                &raw const overrides,
                &raw mut h2,
                &raw mut lost,
                &raw mut floor,
                &raw mut err,
            ));
            assert_eq!(err, SHEKYL_WALLET_ERR_OK);
            assert!(!h2.is_null(), "open with overrides must succeed");
            shekyl_wallet_free(h2);
        }
    }

    /// 2k.2: the NULL overrides pointer decodes to
    /// [`SafetyOverrides::none`]. Kept as a focused Rust test so a
    /// future regression in [`ShekylSafetyOverrides::decode`] fails
    /// loudly at unit-test time rather than silently behind the
    /// envelope layer.
    #[test]
    fn decode_null_overrides_is_none() {
        unsafe {
            let o = ShekylSafetyOverrides::decode(std::ptr::null());
            assert_eq!(o, SafetyOverrides::none());
        }
    }

    /// 2k.2: a populated `ShekylSafetyOverrides` round-trips through
    /// `decode` to a matching Rust [`SafetyOverrides`].
    #[test]
    fn decode_populated_overrides_matches() {
        let c_struct = ShekylSafetyOverrides {
            has_max_reorg_depth: 1,
            _pad0: [0; 7],
            max_reorg_depth: 7,
            has_skip_to_height: 0,
            _pad1: [0; 7],
            skip_to_height: u64::MAX,
            has_refresh_from_block_height: 1,
            _pad2: [0; 7],
            refresh_from_block_height: 99,
        };
        let decoded = unsafe { ShekylSafetyOverrides::decode(&raw const c_struct) };
        assert_eq!(
            decoded,
            SafetyOverrides {
                max_reorg_depth: Some(7),
                skip_to_height: None,
                refresh_from_block_height: Some(99),
            }
        );
    }
}
