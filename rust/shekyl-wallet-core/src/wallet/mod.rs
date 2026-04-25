// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl wallet domain orchestrator.
//!
//! `shekyl-wallet-core::wallet` is the home of the [`Wallet`](Wallet) type
//! that composes the file envelope ([`shekyl_wallet_file::WalletFile`]),
//! identity material ([`shekyl_crypto_pq::account::AllKeysBlob`]), the
//! ledger ([`shekyl_wallet_state::WalletLedger`]), preferences
//! ([`shekyl_wallet_prefs::WalletPrefs`]), the daemon RPC client, and
//! the per-process scanning surface into a single audited domain
//! orchestrator. The CLI ([`shekyl-cli`]) and the JSON-RPC server
//! ([`shekyl-wallet-rpc`]) sit on top of this surface, never reaching
//! around it.
//!
//! # What this module rejects on purpose
//!
//! The Phase 1 design log
//! ([`docs/V3_WALLET_DECISION_LOG.md`]) names every monero-era pattern
//! that is *not* being carried forward; the briefest summary, kept here
//! so the rejection survives "while we're here" temptations:
//!
//! - **Integrated addresses and `payment_id`s.** Subaddresses provide
//!   per-recipient tracking with strictly stronger privacy properties.
//!   `TxRequest` carries no `payment_id` field and the `IntegratedAddress`
//!   type is not modeled.
//! - **The two-level account / subaddress hierarchy.** Shekyl ships a
//!   single flat [`SubaddressIndex`](shekyl_wallet_state::SubaddressIndex)
//!   namespace; index 0 is the primary address. Exchanges that need
//!   stronger isolation use multiple wallet files (separate keys are a
//!   strictly stronger boundary than wallet2's account-shared keys).
//! - **The `export_outputs` / `import_outputs` / `export_key_images` /
//!   `import_key_images` four-call dance.** Air-gapped flows use two
//!   typed bundle types (`UnsignedTxBundle`, `SignedTxBundle`) — see
//!   Phase 2d.
//! - **A god-object `Wallet` with hundreds of public members.** Every
//!   [`Wallet`] member's mutability and locking discipline is explicit;
//!   the type is *composition*, not *inheritance*.
//! - **Background-sync as a wallet-internal feature.** Refresh is
//!   `tokio::spawn`'d by the caller; cancellation is RAII via
//!   `RefreshHandle` (lands in a follow-up commit).
//!
//! # Cross-cutting locks honored
//!
//! Every lock in the rewrite plan
//! ([`/home/torvaldsl/.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md`])
//! is enforced at the type layer in this module:
//!
//! 1. **Async runtime** — caller-provided multi-threaded `tokio`. IO-bound
//!    methods are `async`; pure compute stays sync.
//! 2. **Error types** — per-domain enums in [`error`], unified at the
//!    RPC boundary by [`shekyl-wallet-rpc`].
//! 3. **Locking discipline** — `&self` queries / `&mut self` mutations.
//!    The RPC binary wraps in [`Arc<RwLock<Wallet>>`].
//! 4. **`PendingTx` lifetime** — process-local, chain-state-tagged,
//!    reservation-bearing. Lands with the build/submit/discard methods.
//! 5. **`Network`** — closed enum re-exported as [`Network`] from
//!    [`shekyl_address`]; daemon mismatch is `OpenError::NetworkMismatch`.
//! 6. **Subaddress hierarchy** — flat
//!    [`SubaddressIndex`](shekyl_wallet_state::SubaddressIndex). No
//!    account level.
//! 7. **`RefreshHandle`** — cancel-on-drop RAII, single-flight via
//!    `&mut self`. Lands with `Wallet::refresh`.
//! 8. **Fee priority** — `FeePriority { Economy | Standard | Priority |
//!    Custom(NonZeroU64) }` over daemon `get_fee_estimates`. Lands with
//!    `build_pending_tx`.
//! 9. **Logging** — `tracing` spans throughout, two-layer secret
//!    redaction via [`shekyl_wallet_state::LocalLabel`] (type layer) and
//!    a redacting subscriber field formatter (subscriber layer). Lands
//!    with the `tracing` wiring commit.
//! 10. **KAT regression** — plain `cargo test --workspace`,
//!     [`docs/test_vectors/`] under `CODEOWNERS`.
//! 11. **Decision Log** — every binding sub-decision in this module
//!     ships an entry in [`docs/V3_WALLET_DECISION_LOG.md`].
//!
//! # Status (as of this commit)
//!
//! This commit lands the type-layer foundations only:
//!
//! - Per-domain error enums in [`error`].
//! - [`Network`] (re-exported from `shekyl-address`) and [`Capability`]
//!   (re-exported from `shekyl-wallet-file`).
//! - The sealed [`WalletSignerKind`] trait + [`SoloSigner`] marker.
//!
//! The `Wallet<S>` struct, the lifecycle methods (`create`,
//! `open_full`, `open_view_only`, `open_hardware_offload`,
//! `change_password`, `close`), `RefreshHandle`, `PendingTx`,
//! `ScanResult`, and the daemon-RPC thin wrapper all land in
//! follow-up commits on the same Phase 1 branch.

pub mod capability;
pub mod error;
pub mod network;
pub mod signer;

pub use capability::Capability;
pub use error::{IoError, KeyError, OpenError, PendingTxError, RefreshError, SendError, TxError};
pub use network::Network;
pub use signer::{SoloSigner, WalletSignerKind};
