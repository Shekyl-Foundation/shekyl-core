// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Plaintext-with-HMAC user preferences — layer 2 of the three-layer
//! wallet-preference model defined in
//! [`docs/WALLET_PREFS.md`](../../docs/WALLET_PREFS.md).
//!
//! # Contract
//!
//! Every wallet cluster shares a base name `P` and carries **two**
//! prefs artifacts:
//!
//! ```text
//! <P>.prefs.toml        — TOML body, ≤ 64 KiB, strict schema
//! <P>.prefs.toml.hmac   — exactly 32 bytes, HMAC-SHA256 of the body
//! ```
//!
//! The HMAC key is not a password stretch; it is derived from the
//! wallet's `file_kek` and `expected_classical_address` per §2.2 of the
//! spec:
//!
//! ```text
//! prefs_hmac_key = HKDF-Expand(
//!     prk  = file_kek,
//!     info = b"shekyl-prefs-hmac-v1" || expected_classical_address,
//!     L    = 32
//! )
//! ```
//!
//! That means only a fully-unlocked wallet can validate, write, or
//! rotate the prefs files. Tampering while the wallet is locked is
//! **detected on the next open** (the HMAC is verified before the
//! schema is parsed).
//!
//! # Failure policy: advisory, not refuse-to-load
//!
//! Ledger data refuses to load on schema drift or integrity failure
//! because a silent migration there is a funds-threatening attack
//! surface. Prefs data is cosmetic / operational — every field the
//! TOML carries has a safe hardcoded default, and refusing to open a
//! wallet over tampered cosmetics is user-hostile. So:
//!
//! * Missing files → silent defaults, no log.
//! * Missing one of the pair → quarantine the orphan + `WARN`.
//! * HMAC mismatch or parse failure → quarantine both + `WARN`,
//!   return defaults.
//!
//! Quarantine filenames follow `…tampered-<unix_seconds>[.N]` where
//! `.N` is a monotonic counter that prevents collisions within a
//! single wall-clock second. Forensic files are **never** clobbered;
//! they accumulate until the user deletes them.
//!
//! # Bucket-3 rejection
//!
//! The TOML parser is locked down hard: `#[serde(deny_unknown_fields)]`
//! on every nested struct, a 64 KiB file-size cap, and per-field
//! rejection messages for any name that collides with a Bucket-3
//! CLI-only override (`max_reorg_depth`, `skip_to_height`,
//! `refresh_from_block_height`). The messages quote the flag equivalent
//! and the spec section so a user who pastes a forum snippet into
//! `prefs.toml` gets a precise redirect instead of "unknown field".
//! See [`errors::PrefsError`] and rule `82-failure-mode-ux.mdc`.
//!
//! # Module layout
//!
//! | Module          | Responsibility                                                        |
//! |-----------------|-----------------------------------------------------------------------|
//! | [`errors`]      | `PrefsError`, including Bucket-3 collision variants.                  |
//! | [`hmac_key`]    | HKDF-Expand derivation + `PrefsHmacKey` newtype with `Zeroize`.       |
//! | [`paths`]       | `<base>.prefs.toml` / `<base>.prefs.toml.hmac` derivation.            |
//! | [`schema`]      | `WalletPrefs` and nested structs (Buckets 1/2/4/5/6 from §3.2).      |
//! | [`io`]          | `load_prefs` / `save_prefs` with HMAC verify, atomic write, quarantine. |
//!
//! # What this crate does not do
//!
//! * It does **not** derive `file_kek`. Callers obtain `file_kek` from
//!   the envelope layer (`shekyl-crypto-pq`) and pass it into
//!   [`hmac_key::PrefsHmacKey::derive`] once, cache the returned key
//!   for the session, and drop it with `Zeroize` when the handle is
//!   released.
//! * It does **not** persist Bucket-3 fields. Those are
//!   [`shekyl_engine_file::SafetyOverrides`]; this crate's only
//!   relationship to them is to reject any attempt to write them to
//!   `prefs.toml`.
//! * It does **not** open wallets. Callers integrate load/save into the
//!   `WalletFile::open` and `save_state` sequences in 2k.4 and
//!   2k.5; this crate is a leaf.
//!
//! [`shekyl_engine_file::SafetyOverrides`]: https://docs.rs/shekyl-engine-file

pub mod errors;
pub mod hmac_key;
pub mod io;
pub mod paths;
pub mod schema;

pub use errors::PrefsError;
pub use hmac_key::PrefsHmacKey;
pub use io::{load_prefs, save_prefs, LoadOutcome, MAX_PREFS_TOML_BYTES};
pub use paths::{prefs_hmac_path_from, prefs_toml_path_from};
pub use schema::{
    CosmeticPrefs, DevicePrefs, OperationalPrefs, RpcPrefs, SubaddressLookahead, WalletPrefs,
};
