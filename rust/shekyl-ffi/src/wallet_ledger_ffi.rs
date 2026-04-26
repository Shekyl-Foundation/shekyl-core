// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed per-block FFI for the `WalletLedger` on the
//! [`crate::wallet_file_ffi::ShekylWallet`] handle.
//!
//! # Why this module exists (2l.a, design pin #2 — Option α-Shape-2)
//!
//! The 2k phase promoted `.wallet.keys` handling into the Rust handle
//! with classical-secret extraction FFI. 2l completes the rewire by
//! moving the `.wallet` (cache) state onto the handle too. Rather than
//! crossing the FFI with raw postcard bytes and asking the C++ side
//! to grow a hand-rolled postcard reader (*that* would be a second
//! implementation of the format tracked against every postcard-crate
//! update), this module exposes **typed** per-block views: each
//! element is a `#[repr(C)]` struct with `static_assert`-pinned
//! layout, and C++ accesses them through RAII wrappers landed in
//! `src/wallet/wallet2_handle_views.h/.cpp` (added in 2l.b).
//!
//! # Shape-2 layout contract
//!
//! Every `#[repr(C)]` leaf struct in this module follows the same
//! layout discipline:
//!
//! * **Fixed-width scalars** (`u64`, `u32`, `bool`, …) are direct
//!   fields. Alignment is anchored by explicit `_padN` fields where
//!   necessary so layout is stable across compilers.
//! * **Fixed-size byte arrays that C++ reads hot** (`tx_hash[32]`,
//!   `key_image[32]`, `output_public_key[32]`, …) are promoted to
//!   direct fields so the render / display paths do not have to
//!   decode an opaque blob on every access.
//! * **Option-of-scalar** uses a `(has_value: u8, value: T)`
//!   convention with padding to preserve natural alignment. `0` =
//!   absent, `1` = present; any other value is malformed and
//!   surfaces as `SHEKYL_WALLET_ERR_LEDGER`.
//! * **Variable-length fields** (strings, `Vec<T>` nested inside a
//!   leaf element) use `(ptr: *mut u8, len: usize)` pairs with
//!   Rust-owned memory. Ownership transfers to C++ on read;
//!   C++ releases via the paired `shekyl_wallet_free_*` function.
//! * **Sensitive variable-length parts** (Phase-6 `combined_shared_secret`,
//!   `ho/y/z/k_amount` HKDF scalars, tx secret-key scalars, FCMP
//!   precomputed path) live inside an `opaque_blob` that is
//!   postcard-serialized by Rust and passed through by C++
//!   unchanged on save. This keeps Phase-6 secrets on a zero-copy
//!   Rust-owned path — C++ never touches plaintext scalar bytes.
//!
//! # Memory ownership
//!
//! All pointers returned by a `shekyl_wallet_get_*` function are
//! Rust-allocated and owned by the FFI caller until the paired
//! `shekyl_wallet_free_*` runs. Calling any `free_*` function with a
//! null pointer or zero count is a no-op (branchless RAII friendly).
//!
//! All pointers passed into a `shekyl_wallet_set_*` function are
//! *borrowed* for the duration of the call: the FFI copies every
//! scalar, every array, and every heap byte into a fresh Rust-owned
//! representation before returning. Callers may free their input
//! buffers immediately after the setter returns.
//!
//! # Scope of this commit (2l.a)
//!
//! Pure-additive. No existing C++ call site uses the functions in
//! this module yet — 2l.b wires the open path (hydrate), 2l.c wires
//! the save path (emit), 2l.d wires `save_as` and `change_password`.

use std::os::raw::c_char;

use shekyl_primitives::Commitment;
use zeroize::Zeroizing;

use shekyl_wallet_state::{
    bookkeeping_block::{
        AddressBookEntry, BookkeepingBlock, SubaddressLabels, BOOKKEEPING_BLOCK_VERSION,
    },
    ledger_block::{BlockchainTip, LedgerBlock, ReorgBlocks, LEDGER_BLOCK_VERSION},
    payment_id::PaymentId,
    subaddress::SubaddressIndex,
    sync_state_block::{SyncStateBlock, SYNC_STATE_BLOCK_VERSION},
    transfer::{FcmpPrecomputedPath, TransferDetails, SPENDABLE_AGE},
    tx_meta_block::{ScannedPoolTx, TxMetaBlock, TxSecretKey, TxSecretKeys, TX_META_BLOCK_VERSION},
};

use crate::wallet_envelope_ffi::{SHEKYL_WALLET_ERR_NULL_POINTER, SHEKYL_WALLET_ERR_OK};
use crate::wallet_file_ffi::{ShekylWallet, SHEKYL_WALLET_ERR_LEDGER};

// ---------------------------------------------------------------------------
// Internal helpers: Rust-owned heap allocation for (ptr, len) wire pairs
// ---------------------------------------------------------------------------

/// Allocate a fresh `Box<[T]>` from the given `Vec<T>` and return a
/// raw `(ptr, count)` pair that the caller owns and must free via
/// [`drop_boxed_slice`]. An empty vec returns `(NonNull::dangling,
/// 0)` per Rust's empty-slice convention.
fn boxed_slice_into_raw<T>(v: Vec<T>) -> (*mut T, usize) {
    let count = v.len();
    let boxed: Box<[T]> = v.into_boxed_slice();
    let ptr = Box::into_raw(boxed) as *mut T;
    (ptr, count)
}

/// Reconstitute and drop a `Box<[T]>` previously handed out by
/// [`boxed_slice_into_raw`]. No-op on null or zero-count.
///
/// # Safety
///
/// `ptr` must either be null, or point to a slice of exactly `count`
/// `T`s previously produced by [`boxed_slice_into_raw`] and not yet
/// freed. Callers must not retain any alias to the pointed-to memory
/// after this call returns.
unsafe fn drop_boxed_slice<T>(ptr: *mut T, count: usize) {
    if ptr.is_null() || count == 0 {
        return;
    }
    let slice = std::slice::from_raw_parts_mut(ptr, count);
    let _ = Box::from_raw(slice as *mut [T]);
}

/// Allocate a Rust-owned UTF-8 buffer for `s` and return `(ptr, len)`.
/// An empty string returns `(NonNull::dangling, 0)` to avoid a null
/// ptr that C++ RAII wrappers would have to special-case.
fn string_into_raw(s: &str) -> (*mut u8, usize) {
    let bytes: Box<[u8]> = s.as_bytes().to_vec().into_boxed_slice();
    let len = bytes.len();
    let ptr = Box::into_raw(bytes) as *mut u8;
    (ptr, len)
}

/// Free a UTF-8 buffer previously allocated by [`string_into_raw`].
/// No-op on null / zero len.
///
/// # Safety
///
/// Mirrors [`drop_boxed_slice`]'s safety contract for `T = u8`.
unsafe fn drop_string(ptr: *mut u8, len: usize) {
    drop_boxed_slice::<u8>(ptr, len);
}

/// Read a borrowed `&[u8]` from a `(ptr, len)` pair supplied by the
/// C++ caller. Zero-length is always `Some(&[])` regardless of ptr
/// (mirrors the envelope FFI's convention).
///
/// # Safety
///
/// `ptr` must either be null (with `len == 0`) or point to `len`
/// valid bytes for the duration of the call.
unsafe fn borrow_bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

/// Same as [`borrow_bytes`] but validates UTF-8 and returns a
/// `&str`. Used by setters that accept caller-supplied strings.
unsafe fn borrow_str<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    let bytes = borrow_bytes(ptr, len)?;
    std::str::from_utf8(bytes).ok()
}

unsafe fn set_err(out: *mut u32, code: u32) {
    if !out.is_null() {
        *out = code;
    }
}

unsafe fn set_usize(out: *mut usize, v: usize) {
    if !out.is_null() {
        *out = v;
    }
}

// ---------------------------------------------------------------------------
// Shape-2 leaf structs — LedgerBlock
// ---------------------------------------------------------------------------

/// Shape-2 view of a [`TransferDetails`]. All hot-path scalars and
/// 32-byte arrays are promoted out of the opaque blob; variable-length
/// and Phase-6-sensitive fields
/// (`subaddress`, `payment_id`, `spent_height`, `combined_shared_secret`,
/// `ho`, `y`, `z`, `k_amount`, `fcmp_precomputed_path`) are
/// postcard-serialized into `opaque_blob`. `key` and `key_offset` are
/// promoted as their 32-byte canonical byte forms; see
/// [`shekyl_wallet_state::serde_helpers`] for the encoding the Rust
/// source uses on the wire.
///
/// Layout is pinned by `const _: () = assert!(size_of…)` below so a
/// future field addition that would shift existing offsets fails at
/// compile time — the C header must be updated in lockstep.
#[repr(C)]
pub struct ShekylTransferDetailsC {
    // Identity
    pub tx_hash: [u8; 32],
    pub internal_output_index: u64,
    pub global_output_index: u64,
    pub block_height: u64,
    // Output
    pub key_compressed: [u8; 32],
    pub key_offset: [u8; 32],
    pub commitment_mask: [u8; 32],
    pub commitment_amount: u64,
    // Spend tracking — spent is promoted; spent_height/Option fields go
    // in the opaque blob.
    pub spent: u8,
    pub has_key_image: u8,
    pub _pad0: [u8; 6],
    pub key_image: [u8; 32],
    // Staking
    pub staked: u8,
    pub stake_tier: u8,
    pub _pad1: [u8; 6],
    pub stake_lock_until: u64,
    pub last_claimed_height: u64,
    pub eligible_height: u64,
    pub frozen: u8,
    pub _pad2: [u8; 7],
    // Opaque blob: postcard-encoded tuple of
    //   (subaddress: Option<SubaddressIndex>,
    //    payment_id: Option<PaymentId>,
    //    spent_height: Option<u64>,
    //    combined_shared_secret: Option<Zeroizing<[u8;64]>>,
    //    ho/y/z/k_amount: Option<Zeroizing<[u8;32]>>,
    //    fcmp_precomputed_path: Option<FcmpPrecomputedPath>)
    pub opaque_blob: *mut u8,
    pub opaque_blob_len: usize,
}

const _: () = assert!(
    core::mem::size_of::<ShekylTransferDetailsC>() == 256,
    "ShekylTransferDetailsC layout must match the C++ static_assert in shekyl_ffi.h"
);

/// Shape-2 view of [`BlockchainTip`]. `has_hash = 0` ↔ `tip_hash =
/// None` in Rust; when absent, `tip_hash` contents are undefined
/// (zero-filled by convention but not observable).
#[repr(C)]
pub struct ShekylBlockchainTipC {
    pub synced_height: u64,
    pub has_hash: u8,
    pub _pad0: [u8; 7],
    pub tip_hash: [u8; 32],
}

const _: () = assert!(
    core::mem::size_of::<ShekylBlockchainTipC>() == 48,
    "ShekylBlockchainTipC layout must match the C++ static_assert in shekyl_ffi.h"
);

/// One `(height, hash)` pair in the scanner's reorg-detection window.
#[repr(C)]
pub struct ShekylReorgBlockEntryC {
    pub height: u64,
    pub hash: [u8; 32],
}

const _: () = assert!(
    core::mem::size_of::<ShekylReorgBlockEntryC>() == 40,
    "ShekylReorgBlockEntryC layout must match the C++ static_assert in shekyl_ffi.h"
);

// ---------------------------------------------------------------------------
// Shape-2 leaf structs — BookkeepingBlock
// ---------------------------------------------------------------------------

/// Entry in the reverse lookup from compressed-Edwards public spend
/// key to subaddress index. Scanner produces one of these per
/// subaddress the user has materialized.
///
/// The `index` field is the flat 32-bit [`SubaddressIndex`]. There
/// is no trailing pad: with zero `.cpp` callers in the tree at the
/// time of the flat-namespace migration, preserving the legacy
/// 40-byte stride for hypothetical future callers would be a
/// defensive measure for nobody. If a new C++ caller ever appears
/// it matches whatever the struct says at that point.
#[repr(C)]
pub struct ShekylSubaddressRegistryEntryC {
    pub spend_pk_bytes: [u8; 32],
    pub index: u32,
}

const _: () = assert!(
    core::mem::size_of::<ShekylSubaddressRegistryEntryC>() == 36,
    "ShekylSubaddressRegistryEntryC layout must match the C++ static_assert in shekyl_ffi.h"
);

/// One `(subaddress_index, label)` entry from
/// [`SubaddressLabels::per_index`]. Covers every labeled address —
/// the primary slot (`SubaddressIndex(0)`) and every derived index —
/// since the flat-namespace decision removed the carved-out primary
/// label field.
///
/// As with [`ShekylSubaddressRegistryEntryC`], no padding: the only
/// declarer of this struct is `src/shekyl/shekyl_ffi.h` and there
/// are zero `.cpp` callers. Stride compatibility with the
/// pre-flat-namespace `(major, minor, label_ptr, label_len)` layout
/// would defend an empty caller set.
#[repr(C)]
pub struct ShekylSubaddressLabelEntryC {
    pub index: u32,
    pub label_ptr: *mut u8,
    pub label_len: usize,
}

const _: () = assert!(
    core::mem::size_of::<ShekylSubaddressLabelEntryC>() == 24,
    "ShekylSubaddressLabelEntryC layout must match the C++ static_assert in shekyl_ffi.h"
);

/// One contact / recurring payee in the external address book.
/// `payment_id_bytes` is the encrypted 8-byte form;
/// `has_payment_id == 0` ↔ `None`. `is_subaddress` is cached so the
/// render path does not need a parse round-trip.
#[repr(C)]
pub struct ShekylAddressBookEntryC {
    pub address_ptr: *mut u8,
    pub address_len: usize,
    pub description_ptr: *mut u8,
    pub description_len: usize,
    pub has_payment_id: u8,
    pub is_subaddress: u8,
    pub _pad0: [u8; 6],
    pub payment_id_bytes: [u8; 8],
}

const _: () = assert!(
    core::mem::size_of::<ShekylAddressBookEntryC>() == 48,
    "ShekylAddressBookEntryC layout must match the C++ static_assert in shekyl_ffi.h"
);

// ---------------------------------------------------------------------------
// Shape-2 leaf structs — TxMetaBlock
// ---------------------------------------------------------------------------

/// One `(txid, TxSecretKeys)` entry. The actual scalar bytes live in
/// the `opaque_blob` (postcard-encoded `TxSecretKeys`) so Phase-6
/// secret discipline is preserved: C++ never sees plaintext scalar
/// bytes. `additional_count` is a diagnostic hint readable without
/// parsing the blob — useful for the scenario tests in 2l.c.
#[repr(C)]
pub struct ShekylTxKeyEntryC {
    pub txid: [u8; 32],
    pub additional_count: u32,
    pub _pad0: [u8; 4],
    pub opaque_blob: *mut u8,
    pub opaque_blob_len: usize,
}

const _: () = assert!(
    core::mem::size_of::<ShekylTxKeyEntryC>() == 56,
    "ShekylTxKeyEntryC layout must match the C++ static_assert in shekyl_ffi.h"
);

/// One `(txid, note)` entry from [`TxMetaBlock::tx_notes`].
#[repr(C)]
pub struct ShekylTxNoteEntryC {
    pub txid: [u8; 32],
    pub note_ptr: *mut u8,
    pub note_len: usize,
}

const _: () = assert!(
    core::mem::size_of::<ShekylTxNoteEntryC>() == 48,
    "ShekylTxNoteEntryC layout must match the C++ static_assert in shekyl_ffi.h"
);

/// One `(key, value)` string pair from
/// [`TxMetaBlock::attributes`]. Used as a forward-compatible extension
/// point for UX settings that do not yet have a dedicated field.
#[repr(C)]
pub struct ShekylTxAttributeEntryC {
    pub key_ptr: *mut u8,
    pub key_len: usize,
    pub value_ptr: *mut u8,
    pub value_len: usize,
}

const _: () = assert!(
    core::mem::size_of::<ShekylTxAttributeEntryC>() == 32,
    "ShekylTxAttributeEntryC layout must match the C++ static_assert in shekyl_ffi.h"
);

/// One `(txid, ScannedPoolTx)` entry from
/// [`TxMetaBlock::scanned_pool_txs`].
#[repr(C)]
pub struct ShekylScannedPoolTxEntryC {
    pub txid: [u8; 32],
    pub first_seen_unix_secs: u64,
    pub double_spend_seen: u8,
    pub _pad0: [u8; 7],
}

const _: () = assert!(
    core::mem::size_of::<ShekylScannedPoolTxEntryC>() == 48,
    "ShekylScannedPoolTxEntryC layout must match the C++ static_assert in shekyl_ffi.h"
);

// ---------------------------------------------------------------------------
// Shape-2 leaf structs — SyncStateBlock
// ---------------------------------------------------------------------------

/// Shape-2 view of the scalar portion of [`SyncStateBlock`]. The
/// variable-length `pending_tx_hashes` is accessed through a separate
/// array trio (`shekyl_wallet_get_pending_tx_hashes` / `_set_` / `_free_`)
/// so the fixed-shape struct stays branchless for the hot-path getters
/// (`scan_completed`, `restore_from_height`, `confirmations_required`).
#[repr(C)]
pub struct ShekylSyncStateScalarsC {
    pub block_version: u32,
    pub confirmations_required: u32,
    pub restore_from_height: u64,
    pub has_creation_anchor: u8,
    pub scan_completed: u8,
    pub trusted_daemon: u8,
    pub _pad0: [u8; 5],
    pub creation_anchor_hash: [u8; 32],
}

const _: () = assert!(
    core::mem::size_of::<ShekylSyncStateScalarsC>() == 56,
    "ShekylSyncStateScalarsC layout must match the C++ static_assert in shekyl_ffi.h"
);

// ---------------------------------------------------------------------------
// Helper: convert Option-bearing fields for TransferDetails opaque blob
// ---------------------------------------------------------------------------

/// Private portion of [`TransferDetails`] that does not fit
/// comfortably into a `#[repr(C)]` struct — strings, option-bearing
/// secrets, and the FCMP precomputed path. Serialized via postcard
/// into `ShekylTransferDetailsC::opaque_blob` and reconstructed by
/// [`shekyl_wallet_set_transfers`]. The Rust side owns this type
/// exclusively; C++ treats the blob as opaque bytes.
#[derive(serde::Serialize, serde::Deserialize)]
struct TransferDetailsOpaque {
    subaddress: Option<SubaddressIndex>,
    payment_id: Option<PaymentId>,
    spent_height: Option<u64>,
    /// HKDF-derived secrets are stored using the same wire helpers as
    /// `TransferDetails` itself so the opaque blob's encoding matches
    /// what `TransferDetails`'s own postcard form would produce — a
    /// reviewer comparing the blob to a fully-postcard-encoded
    /// transfer sees byte-for-byte identical secret regions.
    #[serde(
        with = "shekyl_wallet_state::serde_helpers::opt_zeroizing_bytes_64",
        default
    )]
    combined_shared_secret: Option<Zeroizing<[u8; 64]>>,
    #[serde(
        with = "shekyl_wallet_state::serde_helpers::opt_zeroizing_bytes_32",
        default
    )]
    ho: Option<Zeroizing<[u8; 32]>>,
    #[serde(
        with = "shekyl_wallet_state::serde_helpers::opt_zeroizing_bytes_32",
        default
    )]
    y: Option<Zeroizing<[u8; 32]>>,
    #[serde(
        with = "shekyl_wallet_state::serde_helpers::opt_zeroizing_bytes_32",
        default
    )]
    z: Option<Zeroizing<[u8; 32]>>,
    #[serde(
        with = "shekyl_wallet_state::serde_helpers::opt_zeroizing_bytes_32",
        default
    )]
    k_amount: Option<Zeroizing<[u8; 32]>>,
    fcmp_precomputed_path: Option<FcmpPrecomputedPath>,
}

impl TransferDetailsOpaque {
    fn from_transfer(t: &TransferDetails) -> Self {
        Self {
            subaddress: t.subaddress,
            payment_id: t.payment_id,
            spent_height: t.spent_height,
            combined_shared_secret: t
                .combined_shared_secret
                .as_ref()
                .map(|z| Zeroizing::new(**z)),
            ho: t.ho.as_ref().map(|z| Zeroizing::new(**z)),
            y: t.y.as_ref().map(|z| Zeroizing::new(**z)),
            z: t.z.as_ref().map(|z| Zeroizing::new(**z)),
            k_amount: t.k_amount.as_ref().map(|z| Zeroizing::new(**z)),
            fcmp_precomputed_path: t.fcmp_precomputed_path.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// LedgerBlock — transfers (get / set / free)
// ---------------------------------------------------------------------------

/// Populate `out_ptr` with a Rust-allocated array of
/// [`ShekylTransferDetailsC`] mirroring the handle's current
/// `LedgerBlock::transfers`. `out_count` receives the array length.
///
/// # Safety
///
/// `h`, `out_ptr`, `out_count`, and `out_error` must point to valid
/// memory for the duration of the call. On success, the caller owns
/// the returned array and must release it with
/// [`shekyl_wallet_free_transfers`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_transfers(
    h: *mut ShekylWallet,
    out_ptr: *mut *mut ShekylTransferDetailsC,
    out_count: *mut usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out_ptr.is_null() || out_count.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let transfers = &w.ledger.ledger.transfers;
    let mut out = Vec::with_capacity(transfers.len());
    for t in transfers {
        let opaque = TransferDetailsOpaque::from_transfer(t);
        let blob_bytes = match postcard::to_allocvec(&opaque) {
            Ok(b) => b,
            Err(_) => {
                // Roll back what we've built so far.
                for e in out {
                    free_transfer_details(&e);
                }
                set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
                return false;
            }
        };
        let (blob_ptr, blob_len) = boxed_slice_into_raw(blob_bytes);
        let key_compressed = t.key.compress().to_bytes();
        let commitment_mask = t.commitment.mask.to_bytes();
        let key_offset = t.key_offset.to_bytes();
        out.push(ShekylTransferDetailsC {
            tx_hash: t.tx_hash,
            internal_output_index: t.internal_output_index,
            global_output_index: t.global_output_index,
            block_height: t.block_height,
            key_compressed,
            key_offset,
            commitment_mask,
            commitment_amount: t.commitment.amount,
            spent: t.spent as u8,
            has_key_image: t.key_image.is_some() as u8,
            _pad0: [0; 6],
            key_image: t.key_image.unwrap_or([0; 32]),
            staked: t.staked as u8,
            stake_tier: t.stake_tier,
            _pad1: [0; 6],
            stake_lock_until: t.stake_lock_until,
            last_claimed_height: t.last_claimed_height,
            eligible_height: t.eligible_height,
            frozen: t.frozen as u8,
            _pad2: [0; 7],
            opaque_blob: blob_ptr,
            opaque_blob_len: blob_len,
        });
    }
    let (ptr, count) = boxed_slice_into_raw(out);
    *out_ptr = ptr;
    set_usize(out_count, count);
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

/// Replace the handle's `LedgerBlock::transfers` with the values
/// decoded from `in_ptr[..in_count]`. Each element's `opaque_blob` is
/// postcard-decoded into the secret-bearing fields; a malformed blob
/// surfaces as [`SHEKYL_WALLET_ERR_LEDGER`].
///
/// # Safety
///
/// `in_ptr[..in_count]` must be valid, aligned, and fully initialised
/// for the duration of the call. The FFI copies every scalar and
/// re-deserializes every opaque blob into Rust-owned state; callers
/// may free their input immediately after this function returns.
#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_transfers(
    h: *mut ShekylWallet,
    in_ptr: *const ShekylTransferDetailsC,
    in_count: usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if in_count != 0 && in_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let mut out: Vec<TransferDetails> = Vec::with_capacity(in_count);
    let slice = std::slice::from_raw_parts(in_ptr, in_count);
    for c in slice {
        let blob = match borrow_bytes(c.opaque_blob, c.opaque_blob_len) {
            Some(b) => b,
            None => {
                set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
                return false;
            }
        };
        let op: TransferDetailsOpaque = match postcard::from_bytes(blob) {
            Ok(o) => o,
            Err(_) => {
                set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
                return false;
            }
        };
        let key = match curve25519_dalek::edwards::CompressedEdwardsY(c.key_compressed).decompress()
        {
            Some(p) => p,
            None => {
                set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
                return false;
            }
        };
        let key_offset = match option_scalar_from_bytes(c.key_offset) {
            Some(s) => s,
            None => {
                set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
                return false;
            }
        };
        let commitment_mask = match option_scalar_from_bytes(c.commitment_mask) {
            Some(s) => s,
            None => {
                set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
                return false;
            }
        };
        let commitment = Commitment::new(commitment_mask, c.commitment_amount);
        let key_image = (c.has_key_image != 0).then_some(c.key_image);
        out.push(TransferDetails {
            tx_hash: c.tx_hash,
            internal_output_index: c.internal_output_index,
            global_output_index: c.global_output_index,
            block_height: c.block_height,
            key,
            key_offset,
            commitment,
            subaddress: op.subaddress,
            payment_id: op.payment_id,
            spent: c.spent != 0,
            spent_height: op.spent_height,
            key_image,
            staked: c.staked != 0,
            stake_tier: c.stake_tier,
            stake_lock_until: c.stake_lock_until,
            last_claimed_height: c.last_claimed_height,
            combined_shared_secret: op.combined_shared_secret,
            ho: op.ho,
            y: op.y,
            z: op.z,
            k_amount: op.k_amount,
            eligible_height: c.eligible_height,
            frozen: c.frozen != 0,
            fcmp_precomputed_path: op.fcmp_precomputed_path,
        });
    }
    let _ = SPENDABLE_AGE; // reserved for future invariant checks
    let w = &mut *h;
    w.ledger.ledger.transfers = out;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

/// Release an array previously produced by
/// [`shekyl_wallet_get_transfers`]. No-op on null / zero count.
///
/// # Safety
///
/// `ptr[..count]` must be exactly the buffer returned by
/// `shekyl_wallet_get_transfers` and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_free_transfers(
    ptr: *mut ShekylTransferDetailsC,
    count: usize,
) {
    if ptr.is_null() || count == 0 {
        return;
    }
    let slice = std::slice::from_raw_parts(ptr, count);
    for e in slice {
        free_transfer_details(e);
    }
    drop_boxed_slice(ptr, count);
}

/// Free the nested allocations inside a single transfer entry.
/// Invoked during both full-array `shekyl_wallet_free_transfers` and
/// the rollback path in `shekyl_wallet_get_transfers`.
unsafe fn free_transfer_details(e: &ShekylTransferDetailsC) {
    drop_boxed_slice::<u8>(e.opaque_blob, e.opaque_blob_len);
}

/// Reconstruct a `curve25519_dalek::Scalar` from its 32-byte canonical
/// encoding. Returns `None` for non-canonical inputs.
fn option_scalar_from_bytes(bytes: [u8; 32]) -> Option<curve25519_dalek::Scalar> {
    curve25519_dalek::Scalar::from_canonical_bytes(bytes).into_option()
}

// ---------------------------------------------------------------------------
// LedgerBlock — blockchain tip (get / set; no free — fixed struct)
// ---------------------------------------------------------------------------

/// Write the handle's current [`BlockchainTip`] into `*out`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_blockchain_tip(
    h: *mut ShekylWallet,
    out: *mut ShekylBlockchainTipC,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let tip = &w.ledger.ledger.tip;
    let (has_hash, tip_hash) = match tip.tip_hash {
        Some(h) => (1u8, h),
        None => (0u8, [0u8; 32]),
    };
    *out = ShekylBlockchainTipC {
        synced_height: tip.synced_height,
        has_hash,
        _pad0: [0; 7],
        tip_hash,
    };
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

/// Replace the handle's [`BlockchainTip`] with the value described by
/// `in_ptr`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_blockchain_tip(
    h: *mut ShekylWallet,
    in_ptr: *const ShekylBlockchainTipC,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || in_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let c = &*in_ptr;
    let tip = BlockchainTip {
        synced_height: c.synced_height,
        tip_hash: (c.has_hash != 0).then_some(c.tip_hash),
    };
    let w = &mut *h;
    w.ledger.ledger.tip = tip;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

// ---------------------------------------------------------------------------
// LedgerBlock — reorg window (get / set / free)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_reorg_blocks(
    h: *mut ShekylWallet,
    out_ptr: *mut *mut ShekylReorgBlockEntryC,
    out_count: *mut usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out_ptr.is_null() || out_count.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let entries: Vec<ShekylReorgBlockEntryC> = w
        .ledger
        .ledger
        .reorg_blocks
        .blocks
        .iter()
        .map(|(height, hash)| ShekylReorgBlockEntryC {
            height: *height,
            hash: *hash,
        })
        .collect();
    let (ptr, count) = boxed_slice_into_raw(entries);
    *out_ptr = ptr;
    set_usize(out_count, count);
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_reorg_blocks(
    h: *mut ShekylWallet,
    in_ptr: *const ShekylReorgBlockEntryC,
    in_count: usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if in_count != 0 && in_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let slice = std::slice::from_raw_parts(in_ptr, in_count);
    let blocks: Vec<(u64, [u8; 32])> = slice.iter().map(|e| (e.height, e.hash)).collect();
    let w = &mut *h;
    w.ledger.ledger.reorg_blocks = ReorgBlocks { blocks };
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_free_reorg_blocks(
    ptr: *mut ShekylReorgBlockEntryC,
    count: usize,
) {
    drop_boxed_slice(ptr, count);
}

// ---------------------------------------------------------------------------
// LedgerBlock — version accessor (scalar; no allocation)
// ---------------------------------------------------------------------------

/// Emit / accept the ledger-block's schema version. Exposed so the
/// typed FFI fully owns block versioning; C++ never constructs an
/// out-of-band version number.
#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_ledger_block_version(
    h: *mut ShekylWallet,
    out: *mut u32,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    *out = w.ledger.ledger.block_version;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_ledger_block_version(
    h: *mut ShekylWallet,
    version: u32,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if version != LEDGER_BLOCK_VERSION {
        set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
        return false;
    }
    let w = &mut *h;
    w.ledger.ledger.block_version = version;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

// ---------------------------------------------------------------------------
// BookkeepingBlock — subaddress registry (get / set / free)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_subaddress_registry(
    h: *mut ShekylWallet,
    out_ptr: *mut *mut ShekylSubaddressRegistryEntryC,
    out_count: *mut usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out_ptr.is_null() || out_count.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let entries: Vec<ShekylSubaddressRegistryEntryC> = w
        .ledger
        .bookkeeping
        .subaddress_registry
        .iter()
        .map(
            |(pk_bytes, idx): (&[u8; 32], &SubaddressIndex)| ShekylSubaddressRegistryEntryC {
                spend_pk_bytes: *pk_bytes,
                index: idx.get(),
            },
        )
        .collect();
    let (ptr, count) = boxed_slice_into_raw(entries);
    *out_ptr = ptr;
    set_usize(out_count, count);
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_subaddress_registry(
    h: *mut ShekylWallet,
    in_ptr: *const ShekylSubaddressRegistryEntryC,
    in_count: usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if in_count != 0 && in_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let slice = std::slice::from_raw_parts(in_ptr, in_count);
    let mut registry = std::collections::BTreeMap::new();
    for e in slice {
        if e.index == 0 {
            // The registry exists for non-primary subaddresses; the
            // primary address (`SubaddressIndex(0)`) is reconstructed
            // from the wallet keys, not stored. If C++ ever tries to
            // insert index 0 it is a bug.
            set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
            return false;
        }
        registry.insert(e.spend_pk_bytes, SubaddressIndex::new(e.index));
    }
    let w = &mut *h;
    w.ledger.bookkeeping.subaddress_registry = registry;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_free_subaddress_registry(
    ptr: *mut ShekylSubaddressRegistryEntryC,
    count: usize,
) {
    drop_boxed_slice(ptr, count);
}

// ---------------------------------------------------------------------------
// BookkeepingBlock — subaddress labels (per-index trio)
// ---------------------------------------------------------------------------
//
// Under the flat `SubaddressIndex(u32)` namespace the "primary" label is
// just the entry at index 0; there is no separate primary-label slot,
// and consumers wanting the primary label read/write index 0 through
// the per-index FFI below.

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_subaddress_labels(
    h: *mut ShekylWallet,
    out_ptr: *mut *mut ShekylSubaddressLabelEntryC,
    out_count: *mut usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out_ptr.is_null() || out_count.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let labels = &w.ledger.bookkeeping.subaddress_labels.per_index;
    let mut out = Vec::with_capacity(labels.len());
    for (idx, label) in labels {
        let (label_ptr, label_len) = string_into_raw(label);
        out.push(ShekylSubaddressLabelEntryC {
            index: idx.get(),
            label_ptr,
            label_len,
        });
    }
    let (ptr, count) = boxed_slice_into_raw(out);
    *out_ptr = ptr;
    set_usize(out_count, count);
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_subaddress_labels(
    h: *mut ShekylWallet,
    in_ptr: *const ShekylSubaddressLabelEntryC,
    in_count: usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if in_count != 0 && in_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let slice = std::slice::from_raw_parts(in_ptr, in_count);
    let mut map = std::collections::BTreeMap::new();
    for e in slice {
        let s = match borrow_str(e.label_ptr, e.label_len) {
            Some(s) => s,
            None => {
                set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
                return false;
            }
        };
        map.insert(SubaddressIndex::new(e.index), s.to_owned());
    }
    let w = &mut *h;
    w.ledger.bookkeeping.subaddress_labels.per_index = map;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_free_subaddress_labels(
    ptr: *mut ShekylSubaddressLabelEntryC,
    count: usize,
) {
    if ptr.is_null() || count == 0 {
        return;
    }
    let slice = std::slice::from_raw_parts(ptr, count);
    for e in slice {
        drop_string(e.label_ptr, e.label_len);
    }
    drop_boxed_slice(ptr, count);
}

// ---------------------------------------------------------------------------
// BookkeepingBlock — address book (get / set / free)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_address_book(
    h: *mut ShekylWallet,
    out_ptr: *mut *mut ShekylAddressBookEntryC,
    out_count: *mut usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out_ptr.is_null() || out_count.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let book = &w.ledger.bookkeeping.address_book;
    let mut out = Vec::with_capacity(book.len());
    for e in book {
        let (addr_ptr, addr_len) = string_into_raw(&e.address);
        let (desc_ptr, desc_len) = string_into_raw(&e.description);
        let (has_pid, pid_bytes) = match e.payment_id {
            Some(PaymentId(b)) => (1u8, b),
            None => (0u8, [0u8; 8]),
        };
        out.push(ShekylAddressBookEntryC {
            address_ptr: addr_ptr,
            address_len: addr_len,
            description_ptr: desc_ptr,
            description_len: desc_len,
            has_payment_id: has_pid,
            is_subaddress: e.is_subaddress as u8,
            _pad0: [0; 6],
            payment_id_bytes: pid_bytes,
        });
    }
    let (ptr, count) = boxed_slice_into_raw(out);
    *out_ptr = ptr;
    set_usize(out_count, count);
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_address_book(
    h: *mut ShekylWallet,
    in_ptr: *const ShekylAddressBookEntryC,
    in_count: usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if in_count != 0 && in_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let slice = std::slice::from_raw_parts(in_ptr, in_count);
    let mut out = Vec::with_capacity(in_count);
    for e in slice {
        let addr = match borrow_str(e.address_ptr, e.address_len) {
            Some(s) => s.to_owned(),
            None => {
                set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
                return false;
            }
        };
        let desc = match borrow_str(e.description_ptr, e.description_len) {
            Some(s) => s.to_owned(),
            None => {
                set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
                return false;
            }
        };
        let pid = (e.has_payment_id != 0).then(|| PaymentId(e.payment_id_bytes));
        out.push(AddressBookEntry {
            address: addr,
            description: desc,
            payment_id: pid,
            is_subaddress: e.is_subaddress != 0,
        });
    }
    let w = &mut *h;
    w.ledger.bookkeeping.address_book = out;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_free_address_book(
    ptr: *mut ShekylAddressBookEntryC,
    count: usize,
) {
    if ptr.is_null() || count == 0 {
        return;
    }
    let slice = std::slice::from_raw_parts(ptr, count);
    for e in slice {
        drop_string(e.address_ptr, e.address_len);
        drop_string(e.description_ptr, e.description_len);
    }
    drop_boxed_slice(ptr, count);
}

// ---------------------------------------------------------------------------
// BookkeepingBlock — version accessor
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_bookkeeping_block_version(
    h: *mut ShekylWallet,
    out: *mut u32,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    *out = w.ledger.bookkeeping.block_version;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_bookkeeping_block_version(
    h: *mut ShekylWallet,
    version: u32,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if version != BOOKKEEPING_BLOCK_VERSION {
        set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
        return false;
    }
    let w = &mut *h;
    w.ledger.bookkeeping.block_version = version;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

// ---------------------------------------------------------------------------
// TxMetaBlock — tx keys (get / set / free) — secret-bearing via opaque blob
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_tx_keys(
    h: *mut ShekylWallet,
    out_ptr: *mut *mut ShekylTxKeyEntryC,
    out_count: *mut usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out_ptr.is_null() || out_count.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let map = &w.ledger.tx_meta.tx_keys;
    let mut out: Vec<ShekylTxKeyEntryC> = Vec::with_capacity(map.len());
    for (txid, keys) in map {
        let additional_count = keys.additional.len() as u32;
        let blob_bytes = match postcard::to_allocvec(keys) {
            Ok(b) => b,
            Err(_) => {
                for e in out.iter() {
                    drop_boxed_slice::<u8>(e.opaque_blob, e.opaque_blob_len);
                }
                set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
                return false;
            }
        };
        let (blob_ptr, blob_len) = boxed_slice_into_raw(blob_bytes);
        out.push(ShekylTxKeyEntryC {
            txid: *txid,
            additional_count,
            _pad0: [0; 4],
            opaque_blob: blob_ptr,
            opaque_blob_len: blob_len,
        });
    }
    let (ptr, count) = boxed_slice_into_raw(out);
    *out_ptr = ptr;
    set_usize(out_count, count);
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_tx_keys(
    h: *mut ShekylWallet,
    in_ptr: *const ShekylTxKeyEntryC,
    in_count: usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if in_count != 0 && in_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let slice = std::slice::from_raw_parts(in_ptr, in_count);
    let mut map = std::collections::BTreeMap::new();
    for e in slice {
        let blob = match borrow_bytes(e.opaque_blob, e.opaque_blob_len) {
            Some(b) => b,
            None => {
                set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
                return false;
            }
        };
        let keys: TxSecretKeys = match postcard::from_bytes(blob) {
            Ok(k) => k,
            Err(_) => {
                set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
                return false;
            }
        };
        if keys.additional.len() as u32 != e.additional_count {
            set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
            return false;
        }
        map.insert(e.txid, keys);
    }
    let _ = TxSecretKey::new; // retain import for blob typing
    let w = &mut *h;
    w.ledger.tx_meta.tx_keys = map;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_free_tx_keys(ptr: *mut ShekylTxKeyEntryC, count: usize) {
    if ptr.is_null() || count == 0 {
        return;
    }
    let slice = std::slice::from_raw_parts(ptr, count);
    for e in slice {
        drop_boxed_slice::<u8>(e.opaque_blob, e.opaque_blob_len);
    }
    drop_boxed_slice(ptr, count);
}

// ---------------------------------------------------------------------------
// TxMetaBlock — tx notes (get / set / free)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_tx_notes(
    h: *mut ShekylWallet,
    out_ptr: *mut *mut ShekylTxNoteEntryC,
    out_count: *mut usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out_ptr.is_null() || out_count.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let map = &w.ledger.tx_meta.tx_notes;
    let mut out = Vec::with_capacity(map.len());
    for (txid, note) in map {
        let (np, nl) = string_into_raw(note);
        out.push(ShekylTxNoteEntryC {
            txid: *txid,
            note_ptr: np,
            note_len: nl,
        });
    }
    let (ptr, count) = boxed_slice_into_raw(out);
    *out_ptr = ptr;
    set_usize(out_count, count);
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_tx_notes(
    h: *mut ShekylWallet,
    in_ptr: *const ShekylTxNoteEntryC,
    in_count: usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if in_count != 0 && in_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let slice = std::slice::from_raw_parts(in_ptr, in_count);
    let mut map = std::collections::BTreeMap::new();
    for e in slice {
        let note = match borrow_str(e.note_ptr, e.note_len) {
            Some(s) => s.to_owned(),
            None => {
                set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
                return false;
            }
        };
        map.insert(e.txid, note);
    }
    let w = &mut *h;
    w.ledger.tx_meta.tx_notes = map;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_free_tx_notes(ptr: *mut ShekylTxNoteEntryC, count: usize) {
    if ptr.is_null() || count == 0 {
        return;
    }
    let slice = std::slice::from_raw_parts(ptr, count);
    for e in slice {
        drop_string(e.note_ptr, e.note_len);
    }
    drop_boxed_slice(ptr, count);
}

// ---------------------------------------------------------------------------
// TxMetaBlock — attributes (get / set / free)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_tx_attributes(
    h: *mut ShekylWallet,
    out_ptr: *mut *mut ShekylTxAttributeEntryC,
    out_count: *mut usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out_ptr.is_null() || out_count.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let map = &w.ledger.tx_meta.attributes;
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let (kp, kl) = string_into_raw(k);
        let (vp, vl) = string_into_raw(v);
        out.push(ShekylTxAttributeEntryC {
            key_ptr: kp,
            key_len: kl,
            value_ptr: vp,
            value_len: vl,
        });
    }
    let (ptr, count) = boxed_slice_into_raw(out);
    *out_ptr = ptr;
    set_usize(out_count, count);
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_tx_attributes(
    h: *mut ShekylWallet,
    in_ptr: *const ShekylTxAttributeEntryC,
    in_count: usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if in_count != 0 && in_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let slice = std::slice::from_raw_parts(in_ptr, in_count);
    let mut map = std::collections::BTreeMap::new();
    for e in slice {
        let k = match borrow_str(e.key_ptr, e.key_len) {
            Some(s) => s.to_owned(),
            None => {
                set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
                return false;
            }
        };
        let v = match borrow_str(e.value_ptr, e.value_len) {
            Some(s) => s.to_owned(),
            None => {
                set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
                return false;
            }
        };
        map.insert(k, v);
    }
    let w = &mut *h;
    w.ledger.tx_meta.attributes = map;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_free_tx_attributes(
    ptr: *mut ShekylTxAttributeEntryC,
    count: usize,
) {
    if ptr.is_null() || count == 0 {
        return;
    }
    let slice = std::slice::from_raw_parts(ptr, count);
    for e in slice {
        drop_string(e.key_ptr, e.key_len);
        drop_string(e.value_ptr, e.value_len);
    }
    drop_boxed_slice(ptr, count);
}

// ---------------------------------------------------------------------------
// TxMetaBlock — scanned pool txs (get / set / free)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_scanned_pool_txs(
    h: *mut ShekylWallet,
    out_ptr: *mut *mut ShekylScannedPoolTxEntryC,
    out_count: *mut usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out_ptr.is_null() || out_count.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let map = &w.ledger.tx_meta.scanned_pool_txs;
    let out: Vec<ShekylScannedPoolTxEntryC> = map
        .iter()
        .map(|(txid, pool)| ShekylScannedPoolTxEntryC {
            txid: *txid,
            first_seen_unix_secs: pool.first_seen_unix_secs,
            double_spend_seen: pool.double_spend_seen as u8,
            _pad0: [0; 7],
        })
        .collect();
    let (ptr, count) = boxed_slice_into_raw(out);
    *out_ptr = ptr;
    set_usize(out_count, count);
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_scanned_pool_txs(
    h: *mut ShekylWallet,
    in_ptr: *const ShekylScannedPoolTxEntryC,
    in_count: usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if in_count != 0 && in_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let slice = std::slice::from_raw_parts(in_ptr, in_count);
    let mut map = std::collections::BTreeMap::new();
    for e in slice {
        map.insert(
            e.txid,
            ScannedPoolTx {
                first_seen_unix_secs: e.first_seen_unix_secs,
                double_spend_seen: e.double_spend_seen != 0,
            },
        );
    }
    let w = &mut *h;
    w.ledger.tx_meta.scanned_pool_txs = map;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_free_scanned_pool_txs(
    ptr: *mut ShekylScannedPoolTxEntryC,
    count: usize,
) {
    drop_boxed_slice(ptr, count);
}

// ---------------------------------------------------------------------------
// TxMetaBlock — version accessor
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_tx_meta_block_version(
    h: *mut ShekylWallet,
    out: *mut u32,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    *out = w.ledger.tx_meta.block_version;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_tx_meta_block_version(
    h: *mut ShekylWallet,
    version: u32,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if version != TX_META_BLOCK_VERSION {
        set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
        return false;
    }
    let w = &mut *h;
    w.ledger.tx_meta.block_version = version;
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

// ---------------------------------------------------------------------------
// SyncStateBlock — scalar block (get / set; no array)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_sync_state_scalars(
    h: *mut ShekylWallet,
    out: *mut ShekylSyncStateScalarsC,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let s = &w.ledger.sync_state;
    let (has_anchor, anchor) = match s.creation_anchor_hash {
        Some(h) => (1u8, h),
        None => (0u8, [0u8; 32]),
    };
    *out = ShekylSyncStateScalarsC {
        block_version: s.block_version,
        confirmations_required: s.confirmations_required,
        restore_from_height: s.restore_from_height,
        has_creation_anchor: has_anchor,
        scan_completed: s.scan_completed as u8,
        trusted_daemon: s.trusted_daemon as u8,
        _pad0: [0; 5],
        creation_anchor_hash: anchor,
    };
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_sync_state_scalars(
    h: *mut ShekylWallet,
    in_ptr: *const ShekylSyncStateScalarsC,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || in_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let c = &*in_ptr;
    if c.block_version != SYNC_STATE_BLOCK_VERSION {
        set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
        return false;
    }
    let w = &mut *h;
    // Preserve the existing pending_tx_hashes vector; this setter only
    // touches the scalar portion. C++ calls set_pending_tx_hashes
    // separately when it needs to replace that list.
    let pending = std::mem::take(&mut w.ledger.sync_state.pending_tx_hashes);
    w.ledger.sync_state = SyncStateBlock {
        block_version: c.block_version,
        restore_from_height: c.restore_from_height,
        creation_anchor_hash: (c.has_creation_anchor != 0).then_some(c.creation_anchor_hash),
        scan_completed: c.scan_completed != 0,
        pending_tx_hashes: pending,
        confirmations_required: c.confirmations_required,
        trusted_daemon: c.trusted_daemon != 0,
    };
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

// ---------------------------------------------------------------------------
// SyncStateBlock — pending tx hashes (get / set / free)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_get_pending_tx_hashes(
    h: *mut ShekylWallet,
    out_ptr: *mut *mut [u8; 32],
    out_count: *mut usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() || out_ptr.is_null() || out_count.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    let v: Vec<[u8; 32]> = w.ledger.sync_state.pending_tx_hashes.clone();
    let (ptr, count) = boxed_slice_into_raw(v);
    *out_ptr = ptr;
    set_usize(out_count, count);
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_set_pending_tx_hashes(
    h: *mut ShekylWallet,
    in_ptr: *const [u8; 32],
    in_count: usize,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    if in_count != 0 && in_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let slice = std::slice::from_raw_parts(in_ptr, in_count);
    let w = &mut *h;
    w.ledger.sync_state.pending_tx_hashes = slice.to_vec();
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_free_pending_tx_hashes(ptr: *mut [u8; 32], count: usize) {
    drop_boxed_slice(ptr, count);
}

// ---------------------------------------------------------------------------
// Cross-block: entire-ledger preflight
// ---------------------------------------------------------------------------

/// Invoke `WalletLedger::preflight_save()` on the handle's in-memory
/// ledger. 2l.c uses this before calling `save_state` so the C++ save
/// path fails fast on schema-invariant violations rather than after
/// the AEAD seal.
#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_ledger_preflight(
    h: *mut ShekylWallet,
    out_error: *mut u32,
) -> bool {
    if h.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let w = &*h;
    match w.ledger.preflight_save() {
        Ok(()) => {
            set_err(out_error, SHEKYL_WALLET_ERR_OK);
            true
        }
        Err(_) => {
            set_err(out_error, SHEKYL_WALLET_ERR_LEDGER);
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Stub: retain imports we may need later and silence unused warnings.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn _keep_imports(
    _: LedgerBlock,
    _: BookkeepingBlock,
    _: TxMetaBlock,
    _: SyncStateBlock,
    _: SubaddressLabels,
    _: AddressBookEntry,
    _: ScannedPoolTx,
    _: ReorgBlocks,
    _: BlockchainTip,
    _: c_char,
) {
}

#[cfg(test)]
mod tests {
    //! Behavioral tests for the typed-ledger FFI surface.
    //!
    //! These currently focus on flat-namespace invariants that are
    //! easy to express without standing up a full opaque-handle
    //! fixture; lifecycle and round-trip coverage lives next to the
    //! wallet-file FFI in `wallet_file_ffi::tests`.
    use super::*;
    use crate::wallet_envelope_ffi::{SHEKYL_WALLET_CAPABILITY_VIEW_ONLY, SHEKYL_WALLET_ERR_OK};
    use crate::wallet_file_ffi::{shekyl_wallet_create, ShekylWallet, SHEKYL_WALLET_ERR_LEDGER};
    use shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN;
    use shekyl_crypto_pq::wallet_envelope::EXPECTED_CLASSICAL_ADDRESS_BYTES;
    use shekyl_wallet_file::Network;

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

    fn make_test_wallet(base: &std::path::Path) -> *mut ShekylWallet {
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
                0x08,
                1,
                1,
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

    /// The flat subaddress namespace has no separate "primary" slot:
    /// `SubaddressIndex(0)` is the primary address, derived from the
    /// wallet keys at every load. The registry is therefore strictly
    /// for *non-primary* subaddresses, and an attempt to insert
    /// `index == 0` is a structural error rather than a benign
    /// overwrite. wallet2 silently accepted such inserts; the V3 FFI
    /// returns `SHEKYL_WALLET_ERR_LEDGER` so the bug surfaces at
    /// the call site instead of producing inconsistent ledger state.
    #[test]
    fn registry_set_rejects_index_zero() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let h = make_test_wallet(&base);

        let entries = [ShekylSubaddressRegistryEntryC {
            spend_pk_bytes: [0x44u8; 32],
            index: 0,
        }];
        let mut err: u32 = 0;
        unsafe {
            let ok = shekyl_wallet_set_subaddress_registry(
                h,
                entries.as_ptr(),
                entries.len(),
                &raw mut err,
            );
            assert!(!ok, "set with index==0 must fail");
            assert_eq!(
                err, SHEKYL_WALLET_ERR_LEDGER,
                "primary address is reconstructed from keys, not registered"
            );
            // Registry must be untouched on rejection — no partial write.
            let w = &*h;
            assert!(w.ledger.bookkeeping.subaddress_registry.is_empty());
        }
        unsafe { crate::wallet_file_ffi::shekyl_wallet_free(h) };
    }

    /// Counterpart to `registry_set_rejects_index_zero`: a valid
    /// non-primary insert succeeds and round-trips through the
    /// getter with the flat-namespace `index` field intact.
    #[test]
    fn registry_set_accepts_nonzero_index_and_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("y.wallet");
        let h = make_test_wallet(&base);

        let entries = [ShekylSubaddressRegistryEntryC {
            spend_pk_bytes: [0x55u8; 32],
            index: 7,
        }];
        let mut err: u32 = 0;
        unsafe {
            assert!(shekyl_wallet_set_subaddress_registry(
                h,
                entries.as_ptr(),
                entries.len(),
                &raw mut err,
            ));
            assert_eq!(err, SHEKYL_WALLET_ERR_OK);

            let mut out_ptr: *mut ShekylSubaddressRegistryEntryC = std::ptr::null_mut();
            let mut out_count: usize = 0;
            assert!(shekyl_wallet_get_subaddress_registry(
                h,
                &raw mut out_ptr,
                &raw mut out_count,
                &raw mut err,
            ));
            assert_eq!(err, SHEKYL_WALLET_ERR_OK);
            assert_eq!(out_count, 1);
            let got = &*out_ptr;
            assert_eq!(got.spend_pk_bytes, [0x55u8; 32]);
            assert_eq!(got.index, 7);
            shekyl_wallet_free_subaddress_registry(out_ptr, out_count);
            crate::wallet_file_ffi::shekyl_wallet_free(h);
        }
    }
}
