// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! On-disk orchestrator for the Shekyl v1 two-file wallet envelope.
//!
//! This crate is the glue between three layers:
//!
//! 1. [`shekyl_crypto_pq::wallet_envelope`] — the cryptographic envelope
//!    that owns `file_kek` derivation, AEAD sealing of the seed block
//!    (region 1) and state block (region 2), and the anti-swap AAD
//!    binding between `.wallet.keys` and `.wallet`.
//! 2. [`shekyl_wallet_state`] — the canonical wallet ledger types: the
//!    postcard-serialized `WalletLedger` (ledger + bookkeeping +
//!    tx-meta + sync-state blocks).
//! 3. The filesystem: atomic `tmp → fsync → rename → fsync(parent)`
//!    writes, advisory locking, companion-path discipline, and
//!    write-once enforcement on `.wallet.keys`.
//!
//! The public surface is deliberately small: one struct
//! ([`WalletFileHandle`]), four methods (`create`, `open`, `save_state`,
//! `rotate_password`), and a dedicated error type
//! ([`WalletFileError`]).
//!
//! # What lives where
//!
//! | Concern                                      | Module                     |
//! |----------------------------------------------|----------------------------|
//! | SWSP payload framing (`SWSP` magic, kind, len) | [`payload`]              |
//! | Atomic write with parent-dir fsync             | [`atomic`] (private)      |
//! | Advisory lock (`flock` / `LockFileEx`)         | [`lock`] (private)        |
//! | Companion-path rules (`.wallet` ↔ `.wallet.keys`) | [`paths`]              |
//! | `WalletFileHandle` lifecycle                   | [`handle`]                |
//! | Error type & `From` impls                      | [`error`]                 |
//!
//! # Rule compliance
//!
//! - **[rule 30 — cryptography](../../../.cursor/rules/30-cryptography.mdc):**
//!   this crate does not implement any crypto; every AEAD call lives
//!   in `shekyl-crypto-pq::wallet_envelope`.
//! - **[rule 35 — secure memory](../../../.cursor/rules/35-secure-memory.mdc):**
//!   [`OpenedKeysFile`] stays in a [`Zeroizing`] container for the
//!   handle's lifetime; passwords are borrowed, never cached.
//! - **[rule 40 — FFI discipline](../../../.cursor/rules/40-ffi-discipline.mdc):**
//!   this crate exposes only a Rust-native API. The FFI surface is
//!   added in 2j as a thin wrapper on top.
//!
//! [`OpenedKeysFile`]: shekyl_crypto_pq::wallet_envelope::OpenedKeysFile
//! [`Zeroizing`]: zeroize::Zeroizing

mod atomic;
pub mod capability;
pub mod error;
mod handle;
mod lock;
pub mod overrides;
pub mod paths;
pub mod payload;
pub mod secrets_transitional;

pub use capability::Capability;
pub use error::WalletFileError;
pub use handle::{CreateParams, OpenOutcome, WalletFileHandle};
pub use overrides::SafetyOverrides;
pub use secrets_transitional::{ClassicalSecretKeys, ExtractClassicalSecretsError};
pub use payload::{
    decode_payload, encode_payload, DecodedPayload, PayloadError, PayloadKind,
    CURRENT_PAYLOAD_VERSION, PAYLOAD_BODY_MAX, PAYLOAD_HEADER_LEN, PAYLOAD_MAGIC,
};

// Re-export `Network` so consumers do not have to depend on
// `shekyl-address` directly just to satisfy `open`'s signature.
pub use shekyl_address::Network;
