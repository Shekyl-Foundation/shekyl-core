// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Error type for the wallet-file orchestrator.
//!
//! The orchestrator sits between three distinct error surfaces:
//!
//! 1. [`shekyl_crypto_pq::wallet_envelope::WalletEnvelopeError`] — envelope
//!    seal/open failures (truncation, bad magic, wrong password, companion-
//!    file mismatch, …). The envelope deliberately collapses "wrong password"
//!    and "ciphertext tampered" into one code so this layer cannot grow a
//!    password oracle.
//! 2. [`std::io::Error`] — filesystem I/O: missing directory, permission
//!    denied, disk full, rename failures, advisory-lock contention.
//! 3. [`PayloadError`] — SWSP (Shekyl Wallet State Payload) framing errors:
//!    bad magic, unsupported version, unknown payload kind, body-length
//!    mismatch. See [`crate::payload`].
//!
//! Surface rules:
//!
//! - `WalletFileError` wraps each source but never widens it. Envelope
//!   errors are surfaced verbatim so the C++ FFI can map them one-to-one to
//!   the user-facing error taxonomy documented in
//!   [`docs/WALLET_FILE_FORMAT_V1.md`](../../../../docs/WALLET_FILE_FORMAT_V1.md)
//!   §5.
//! - Write-once enforcement on `.wallet.keys` is modelled as a dedicated
//!   variant ([`WalletFileError::KeysFileAlreadyExists`]). This is
//!   deliberately not an `io::Error(AlreadyExists)` because the orchestrator
//!   also refuses in-process second-writes against a handle that was opened
//!   without an explicit rotation or restore opt-in — a file-system check
//!   alone is insufficient (rule 35: secrets must not be re-written on every
//!   autosave path).
//! - [`WalletFileError::AtomicWriteRename`] carries the `io::Error` from the
//!   `rename(2)` step specifically, so callers can distinguish "wrote the
//!   tmp OK but could not atomically swap it in" from generic I/O.

use shekyl_address::Network;
use shekyl_crypto_pq::wallet_envelope::WalletEnvelopeError;
use shekyl_wallet_prefs::PrefsError;
use shekyl_wallet_state::WalletLedgerError;
use std::io;
use std::path::PathBuf;

use crate::payload::PayloadError;

/// Unified error type for every public entry point on the wallet-file
/// orchestrator. Tier-1 variants (envelope, payload, I/O) wrap their
/// upstream error types verbatim; tier-2 variants carry orchestrator-
/// specific semantics that no upstream layer can produce on its own.
#[derive(Debug, thiserror::Error)]
pub enum WalletFileError {
    /// Envelope-layer failure (bad magic, wrong password/corrupt, seed-block
    /// mismatch, …). Forwarded unchanged so the FFI error taxonomy stays
    /// stable.
    #[error("envelope error: {0}")]
    Envelope(#[from] WalletEnvelopeError),

    /// Region-2 payload framing failure (SWSP). Distinct from `Envelope`
    /// because the envelope's AEAD succeeded — the bytes it revealed simply
    /// did not conform to the framed payload schema (wrong magic, unknown
    /// kind, unsupported version, body-length mismatch).
    #[error("payload framing error: {0}")]
    Payload(#[from] PayloadError),

    /// Inner-ledger encode/decode failure: postcard corruption or a
    /// bundle/block version mismatch that survived the SWSP frame.
    /// These errors indicate either on-disk corruption that the AEAD
    /// happened to authenticate (real but rare) or a refusal-to-migrate
    /// across a version boundary (the common case in a mixed-version
    /// deployment).
    #[error("wallet ledger error: {0}")]
    Ledger(#[from] WalletLedgerError),

    /// Generic filesystem I/O failure. Callers should treat this as
    /// "transient, retriable" unless paired with a specific file-state
    /// error below.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The orchestrator refused to create a wallet whose `.wallet.keys`
    /// path already exists on disk. The seed file is write-once; replacing
    /// an existing one must go through an explicit rotation or restore
    /// path, not through the creation constructor.
    #[error("refusing to overwrite existing keys file at {path}")]
    KeysFileAlreadyExists { path: PathBuf },

    /// A `save_state` / autosave path attempted to write `.wallet.keys`.
    /// This should be unreachable by construction; the variant exists so
    /// the bug surfaces loudly in tests rather than silently corrupting
    /// seed material.
    #[error("internal bug: non-rotation save path attempted to rewrite {path}")]
    KeysFileWriteOnceViolation { path: PathBuf },

    /// Another process (or another handle in this process) holds the
    /// advisory lock on the keys file. We do not block — the wallet UI
    /// should surface this as "the wallet is already open elsewhere".
    #[error("wallet is already open by another process (lock held on {path})")]
    AlreadyLocked { path: PathBuf },

    /// The atomic-write sequence wrote a fresh temp file successfully but
    /// could not `rename(2)` it into place. The original target (if any)
    /// is untouched and the temp file has been removed.
    #[error("atomic rename into {target} failed: {source}")]
    AtomicWriteRename {
        target: PathBuf,
        #[source]
        source: io::Error,
    },

    /// The keys file decoded cleanly but declared a `network` byte that
    /// does not map to any known [`Network`]. Envelope-level validation
    /// does not currently vet this field, so the orchestrator is the
    /// first layer to notice. Treated as corruption rather than a
    /// caller bug.
    #[error("unknown network discriminant {0:#04x} in keys file")]
    UnknownNetwork(u8),

    /// The keys file opened cleanly but is bound to a different network
    /// than the caller requested. Refusing loudly here prevents the
    /// scanner, RPC wiring, or address-rendering layer from silently
    /// talking to the wrong chain — a confusion that would otherwise
    /// only surface as "no transactions ever show up" or, worse, as a
    /// mainnet address rendered with testnet HRPs.
    #[error("network mismatch: keys file is {found}, but {expected} was requested")]
    NetworkMismatch { expected: Network, found: Network },

    /// The keys file's `capability_mode` byte is neither FULL /
    /// VIEW_ONLY / HARDWARE_OFFLOAD nor the RESERVED_MULTISIG
    /// placeholder. The envelope layer already rejects unknown bytes at
    /// seal/open time, so this variant is a belt-and-braces guard for
    /// test helpers or future refactors that synthesize an
    /// `OpenedKeysFile` outside the envelope's validation path.
    #[error("unknown capability-mode discriminant {0:#04x} in keys file")]
    UnknownCapability(u8),

    /// The keys file carries the reserved multisig placeholder
    /// (`CAPABILITY_RESERVED_MULTISIG`). Multisig is scoped out of the
    /// v1 envelope on purpose (see `PQC_MULTISIG.md`), and silently
    /// treating such a file as one of the three supported capabilities
    /// would be unsafe.
    #[error("multisig wallets are not supported by this envelope version")]
    MultisigNotSupported,

    /// A preferences-layer operation failed (HMAC mismatch on save,
    /// Bucket-3 field slipped through a save path, oversize body,
    /// TOML serialization failure, …). Surfaces
    /// [`PrefsError`](shekyl_wallet_prefs::PrefsError) verbatim so
    /// the FFI can map each variant to an actionable user message
    /// without this crate having to mirror the prefs taxonomy.
    ///
    /// Note: tamper events on **load** do not surface here; they are
    /// signalled via [`shekyl_wallet_prefs::LoadOutcome::Tampered`]
    /// and folded into defaults per the advisory-failure-mode policy
    /// in `docs/WALLET_PREFS.md §5`. This variant only fires on
    /// paths that must refuse (save failures and hard errors).
    #[error("preferences error: {0}")]
    Prefs(#[from] PrefsError),
}

impl WalletFileError {
    /// Convenience: wraps an `io::Error` from a `rename(2)` call into the
    /// dedicated variant. Centralizing the wrap here keeps the orchestrator
    /// free of ad-hoc `Err(WalletFileError::AtomicWriteRename { … })`
    /// construction at every call site.
    pub(crate) fn rename(target: PathBuf, source: io::Error) -> Self {
        Self::AtomicWriteRename { target, source }
    }
}
