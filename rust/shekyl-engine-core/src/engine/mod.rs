// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl engine domain orchestrator.
//!
//! `shekyl-engine-core::engine` is the home of the [`Engine`](Engine) type
//! that composes the file envelope ([`shekyl_engine_file::WalletFile`]),
//! identity material ([`shekyl_crypto_pq::account::AllKeysBlob`]), the
//! ledger ([`crate::engine::local_ledger::LocalLedger`] aggregating
//! [`shekyl_engine_state::WalletLedger`] and
//! [`shekyl_engine_state::LedgerIndexes`] under interior-mutability
//! `RwLock` per the `LedgerEngine` trait contract — the trait itself
//! is `pub(crate)` per `V3_ENGINE_TRAIT_BOUNDARIES.md` §1.4),
//! preferences ([`shekyl_engine_prefs::WalletPrefs`]), the daemon RPC
//! client (via the `DaemonEngine` trait, default `D = DaemonClient`,
//! also `pub(crate)` per §1.4), and the per-process scanning
//! surface into a single audited domain orchestrator. `Engine<S, D, L>`
//! is generic over signer / daemon / ledger trait implementors, with
//! defaults that preserve the existing concrete-typed shape for
//! production callers — the CLI ([`shekyl-cli`]) and the JSON-RPC
//! server ([`shekyl-wallet-rpc`]) sit on top of this surface, never
//! reaching around it.
//!
//! # What this module rejects on purpose
//!
//! The Phase 1 design log
//! ([`docs/V3_WALLET_DECISION_LOG.md`]) names every monero-era pattern
//! that is *not* being carried forward; the briefest summary, kept here
//! so the rejection survives "while we're here" temptations:
//!
//! - **Integrated addresses and legacy unencrypted `payment_id`s on wire.**
//!   Shekyl supports encrypted 8-byte [`shekyl_engine_state::PaymentId`]
//!   only; unencrypted IDs
//!   are rejected. Receive attribution uses payment requests (FA-8), not
//!   address rotation. `TxRequest` carries no standalone `payment_id` field
//!   and the `IntegratedAddress` type is not modeled.
//! - **Subaddresses and flat index namespaces.** End-state 5 (FA-2): one
//!   primary address per account; signing uses `output_claim` offset `m₀`
//!   at index 0. Exchanges that need stronger isolation use multiple wallet
//!   files (separate keys are a strictly stronger boundary than shared keys).
//! - **The `export_outputs` / `import_outputs` / `export_key_images` /
//!   `import_key_images` four-call dance.** Air-gapped flows use two
//!   typed bundle types (`UnsignedTxBundle`, `SignedTxBundle`) — see
//!   Phase 2d.
//! - **A god-object `Engine` with hundreds of public members.** Every
//!   [`Engine`] member's mutability and locking discipline is explicit;
//!   the type is *composition*, not *inheritance*. Staking product API is [`Engine::stake`] / [`stake_facade::StakeFacade`].
//! - **Background-sync as a wallet-internal feature.** Refresh is
//!   `tokio::spawn`'d by the caller; cancellation is RAII via
//!   `RefreshHandle` (lands in a follow-up commit).
//!
//! # Cross-cutting locks honored
//!
//! Every cross-cutting lock recorded in the in-tree decision log
//! ([`docs/V3_WALLET_DECISION_LOG.md`]) is enforced at the type layer
//! in this module:
//!
//! 1. **Async runtime** — caller-provided multi-threaded `tokio`. IO-bound
//!    methods are `async`; pure compute stays sync.
//! 2. **Error types** — per-domain enums in [`error`], unified at the
//!    RPC boundary by [`shekyl-wallet-rpc`].
//! 3. **Locking discipline** — `&self` queries / `&mut self` mutations.
//!    The RPC binary wraps in [`Arc<RwLock<Engine>>`].
//! 4. **`PendingTx` lifetime** — process-local, chain-state-tagged,
//!    reservation-bearing. Lands with the build/submit/discard methods.
//! 5. **`Network`** — closed enum re-exported as [`Network`] from
//!    [`shekyl_address`]; daemon mismatch is `OpenError::NetworkMismatch`.
//! 6. **Receive addressing** — one primary address per account (End-state 5);
//!    payment requests for merchant attribution (FA-8). No subaddress surface.
//! 7. **`RefreshHandle`** — cancel-on-drop RAII, single-flight via
//!    `&mut self`. Lands with `Engine::refresh`.
//! 8. **Fee priority** — `FeePriority { Economy | Standard | Priority |
//!    Custom(NonZeroU64) }` over daemon `get_fee_estimates`. Lands with
//!    `build_pending_tx`.
//! 9. **Logging** — `tracing` spans throughout, two-layer secret
//!    redaction via [`shekyl_engine_state::LocalLabel`] (type layer) and
//!    a redacting subscriber field formatter (subscriber layer). Lands
//!    with the `tracing` wiring commit.
//! 10. **KAT regression** — plain `cargo test --workspace`,
//!     [`docs/test_vectors/`] under `CODEOWNERS`.
//! 11. **Decision Log** — every binding sub-decision in this module
//!     ships an entry in [`docs/V3_WALLET_DECISION_LOG.md`].
//!
//! # Status (as of this commit)
//!
//! Type-layer foundations + the [`Engine<S>`](Engine) struct itself with
//! its accessor surface, the [`DaemonClient`] thin wrapper, and the
//! lifecycle methods on `Engine<SoloSigner>`. [`Engine::create`] and
//! [`Engine::open_full`] ship end-to-end against the
//! [`shekyl_engine_file::WalletFile`] envelope and the
//! [`shekyl_crypto_pq::account::AllKeysBlob`] re-derivation path;
//! [`Engine::open_view_only`] and [`Engine::open_hardware_offload`]
//! ship as signature stubs that return
//! [`OpenError::CapabilityNotYetImplemented`](error::OpenError::CapabilityNotYetImplemented)
//! pending the matching `shekyl-crypto-pq` constructors.
//! [`Engine::change_password`] and [`Engine::close`] ship for every
//! signer kind. The struct is composition over field type — every
//! member's purpose, mutability discipline, and ownership are
//! explicit:
//!
//! | Field                 | Type                                                 | Provenance                              |
//! | --------------------- | ---------------------------------------------------- | --------------------------------------- |
//! | `file`                | [`shekyl_engine_file::WalletFile`]                   | `.wallet.keys` envelope IO              |
//! | `keys`                | [`shekyl_crypto_pq::account::AllKeysBlob`]           | rederived from master seed              |
//! | `ledger`              | [`shekyl_engine_state::WalletLedger`]                | aggregator over the four blocks         |
//! | `indexes`             | [`shekyl_engine_state::LedgerIndexes`]               | rebuilt at open from `ledger`           |
//! | `reservations`        | `BTreeMap<ReservationId, Reservation>`               | runtime-only `PendingTx` tracker        |
//! | `next_reservation_id` | `u64`                                                | process-local monotonic counter         |
//! | `prefs`               | [`shekyl_engine_prefs::WalletPrefs`]                 | plaintext-with-HMAC layer 2             |
//! | `daemon`              | [`DaemonClient`]                                     | thin wrapper around `HttpRpc`  |
//! | `network`             | [`Network`]                                          | cached from `file.network()`            |
//! | `capability`          | [`Capability`]                                       | cached from `file.capability()`         |
//! | `_signer`             | `PhantomData<S>`                                     | compile-time signer dispatch            |
//!
//! `network` and `capability` are cached on the struct so the hot
//! `Engine::network()` / `Engine::capability()` accessors are infallible
//! and O(1). The cache is established at construction and never drifts:
//! `WalletFile`'s region 1 is write-once after `create`, and region 1 is
//! the only place either field is sourced from.
//!
//! # Runtime-only state on `Engine`
//!
//! Two fields on `Engine<S>` are deliberately runtime-only and are
//! never serialized to disk:
//!
//! - [`indexes`](Engine) (`LedgerIndexes`): key-image / pubkey lookup
//!   maps and the staker-pool aggregate. Rebuilt at every
//!   `Engine::open*` from `self.ledger.ledger`.
//! - [`reservations`](Engine) (`BTreeMap<ReservationId, Reservation>`):
//!   the in-flight transaction reservation tracker. Cross-cutting
//!   lock 4 binds the *behavioral* shape (build reserves, discard
//!   releases, submit consumes, close errors with outstanding); the
//!   2026-04-26 follow-up Decision Log entry refines the storage
//!   location to a runtime field rather than the persisted
//!   bookkeeping block. See [`pending`] for the full rationale.
//!
//! Per cross-cutting lock 7, the cancel-on-drop refresh handle is
//! **not** a `Engine` field; it is *returned* by `Engine::refresh`
//! and held by the caller, so its `Drop` implementation drives the
//! cancellation token. A `Engine`-internal handle would defeat the
//! single-flight `&mut self` borrow that enforces no concurrent
//! refresh.
//!
//! # Query surface (Phase 1 disposition)
//!
//! Phase 1 deliberately ships a *thin* public query surface; rich
//! filtered queries (`transfers(filter)`, history pagination, balance
//! breakdowns) are Phase 2 operations per
//! `docs/design/WALLET_REWRITE_PLAN.md` §Phase 2 (History / Balance).
//! Until those land, binaries query through three stable patterns:
//!
//! - **Address** — [`Engine::primary_address`] returns the wallet's
//!   one reusable [`ShekylAddress`] (End-state 5; no subaddresses).
//!   Render with `.encode()` / `.encode_classical_display()`.
//! - **Balance** — borrow the wallet and project it through the
//!   scanner's extension trait — whole-wallet by design (PR-SJ-1b),
//!   because balance needs the journal's F14 locks too:
//!
//!   ```ignore
//!   use shekyl_scanner::WalletLedgerExt;
//!   let guard = engine.ledger(); // derefs to &WalletLedger
//!   let balance = guard.balance();
//!   drop(guard);
//!   ```
//!
//! - **Transfers** — the same borrow exposes the persisted transfer
//!   slice directly: `engine.ledger().ledger.transfers()`.
//!
//! [`Engine::ledger`] returns a [`LedgerReadGuard`] (an RAII read
//! guard that derefs to [`shekyl_engine_state::WalletLedger`]); hold
//! it for the minimum span and never across an `.await` — writers
//! (refresh merge, pending-tx mutators) block while any reader is
//! live. The guard-based pattern is the documented Phase 1 answer to
//! "where is `Engine::balance()`?": a thin wrapper would freeze a
//! signature before the Phase 2 filtered-query design settles, so the
//! pattern is documented instead (reopen at Phase 2 ops).
pub mod capability;
pub mod local_ledger_ops;
// CT-5 curve-tree actor + handle (`docs/design/CT5_ENGINE_WIRING.md` §3.1).
// Mirrors `key_actor`: a `kameo` actor owns the wallet's `CurveTreeClient`
// (redb single-writer), and `Engine` holds a `Clone` `CurveTreeHandle`.
pub(crate) mod curve_tree_actor;
// `ScannableBlock` -> per-block leaf set decode (CT-5 §3.2, R1-Q3): reproduces
// the daemon's consensus drain order so the producer can materialize the full
// leaf set the merge feeds to `curve_tree_actor`.
pub(crate) mod curve_tree_decode;
// Native `ScannableBlock` fetch over the `shekyl-wire` parse — the engine-side
// replacement for the legacy `shekyl_rpc_client::Rpc::get_scannable_block_by_*` path.
// Backs `DaemonEngine::fetch_scannable_block`'s default impl.
/// GF-4b (`ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.4, §5 item 1): the
/// `BackingSet` constructor-mint gate — the sole enforcement layer for
/// backing-lineage eligibility (consensus is lineage-blind and spend-blind
/// for backing) — and the C-1 designated-backing selector
/// (`designate_backing`, most-recent-eligible, arity-1), which consumes
/// candidates exclusively through it and owns the Q11 fee-exclusion
/// (`DesignatedBacking::fee_sweep`).
pub(crate) mod backing_set;
pub(crate) mod block_fetch;
/// WI-2 (`ARCHIVAL_BOND_WI2_ASSEMBLY.md`): production bond assembly — the
/// `PBoundBytes` P-1 provenance boundary (single private mint site), the D-A2
/// funding-sweep policy over the sealed `PFundingOutputRecord` set (GF-4b
/// sweep semantics), and the assemble path's typed failure surface.
pub(crate) mod bond_assembly;
/// WI-2 §3.3 Engine-side `assemble_bond_post` orchestrator (public halves +
/// persist-before-return via an independent `PendingPostStore`).
pub(crate) mod bond_orchestrator;
/// SA-R-6 bond watch: shared `Input::BondPost` lift + merge sighting adoption.
pub(crate) mod bond_watch;
/// PR-4's CB-3 dispatch seam (`EMISSION_CLAIM_BUILDER.md` §8): the Engine-side
/// emission-claim **request path** — activate the claimant slot, assemble via
/// `claim_orchestrator`, dispatch through the audited posture→submitter choke
/// point. Scheduling policy stays external (the GF-4 seam).
pub(crate) mod claim_dispatch;
/// PR-3's Engine-side emission-claim orchestration (`EMISSION_CLAIM_BUILDER.md`
/// §8): the fetch → designate → fee-sweep → path-assembly →
/// `AssembleEmissionClaim` pipeline that prepares the operands the
/// `StakeEngine` handler validates and signs against. Returns the reply
/// unbroadcast (CB-3: dispatch is the `claim_dispatch` seam).
pub(crate) mod claim_orchestrator;
pub mod daemon;
pub(crate) mod diagnostics;
/// F-D1 amount stage (`ARCHIVAL_FIREWALL_GATE6.md` §12.3): the drain amount
/// is chosen from `{user target, cadence, RNG}` and an aggregate-scalar
/// affordability check only — a guarded module the M1 import-check arm keeps
/// blind to the per-output reward vector.
pub(crate) mod drain_amount;
/// F-D2 drain assembly (`ARCHIVAL_P_DRAIN.md` §DS-PR-1): the `P`→principal
/// value-out transaction builder. Produces a **transfer-shaped** tx (two
/// confidential outputs — principal payment + `P`-space change) byte-identical
/// to a modal 2-out transfer (T-DS-6 ∧ T-DS-7), by reusing the transfer path's
/// output primitive (`sign_bridge::build_output`), the bond/claim fee-sweep
/// spend leg (`stake_engine::prepare_funding_inputs`), and the plain-transfer
/// prefix/prove/PQC-auth calls with empty `extra_inputs` and spend-only auths.
pub(crate) mod drain_assembly;
/// DS-PR-2's CB-3 dispatch seam (`ARCHIVAL_DRAIN_SEND_FD2.md` §6, the
/// `claim_dispatch` sibling): the Engine-side drain **request path** — resolve
/// the principal destination, assemble via `drain_orchestrator`, persist the
/// `PendingDrain` before any send, dispatch through the persona-transport
/// choke point (T-DS-2). Scheduling stays external.
pub(crate) mod drain_dispatch;
/// WI-RPC-5: the **public** drain façade over the CB-3 dispatch seam — one
/// embedder-callable `drain_to_principal(payment)` with no slot / fee /
/// destination parameters (type-level active-persona restriction; the
/// canonical P-lane floor fee and the SP-R0 witness are quoted/minted
/// internally). The wallet-RPC `drain` handler is the production caller.
pub(crate) mod drain_facade;
/// F-D1 projection / drain trust boundary (`ARCHIVAL_FIREWALL_GATE6.md`
/// §12.3): the sole drain-path site holding the funding records, projecting
/// them into the aggregate scalar + stripped candidate operands the guarded
/// stages consume, and composing the three stages ([`drain_orchestrator::plan_drain`]).
/// Carries the F-D2 core-side aggregate-only balance surface
/// ([`drain_orchestrator::DrainBalance`]). Public: the drain planner is the
/// API the eventual drain command/actor calls.
pub mod drain_orchestrator;
/// F-D2 aggregate drain-balance read (`ARCHIVAL_DRAIN_SEND_FD2.md`): the
/// engine-side "how much is drainable?" accessor a UI polls. Lifts the sealed
/// `P` funding set, anchors the canonical send-path reference
/// ([`bond_orchestrator::anchored_reference_block`], the same helper the drain
/// itself anchors through), and returns the aggregate spendable scalar. Its
/// [`drain_read::DrainBalanceReadError`] is two-armed by design (transient
/// "syncing" vs. non-transient state fault) so the read never renders a
/// misleading zero.
pub(crate) mod drain_read;
/// F-D1 select stage (`ARCHIVAL_FIREWALL_GATE6.md` §12.3): lineage-blind coin
/// selection over the stripped `{output_id, amount, spendable_height}`
/// vector — a guarded module the M1 import-check arm keeps blind to the
/// lineage tag and the persisted funding record.
pub(crate) mod drain_select;
/// SP-T2 (DQ-T2.3): daemon-posture selection — the no-silent-③ invariant (a
/// posture is named, never defaulted; no-choice + local-unreachable *refuses*,
/// never falls back to a remote/third-party node). §2b build invariant 3.
pub(crate) mod posture;
/// SP-T2 (DQ-T2.2): the per-`P` RPC-over-Tor transport (`PRpc`) — an `Rpc` impl
/// over `shekyl-p-transport`'s `PTorClient`. Confines the async/sync bridge; all
/// `ureq`/agent construction stays in `shekyl-p-transport` (§2b invariant 1).
pub(crate) mod prpc;
// C4 engine-vs-sim `EconomicsEngine` differential (§5.4 / §7.1); replays
// the sim-recorded `RecordedChainFixture` through the real
// `LocalEconomics` path. Test-substrate only.
/// SP-T2 daemon-observability measurement harness (Round-0): quantifies the
/// enumeration and cross-persona timing residuals of serving N per-`P` block
/// fetches from one daemon, against a live `shekyld --regtest`. `#[ignore]`d,
/// requires `SHEKYLD_BIN`. See `docs/design/ARCHIVAL_BOND_2D2_SP_T2_FETCH.md`.
#[cfg(test)]
mod daemon_observability;
#[cfg(test)]
mod economics_differential;
pub(crate) mod economics_snapshot;
/// Emission claim assembly (`EMISSION_CLAIM_BUILDER.md` §2, PR 2): the pure,
/// KAT-able derivation/assembly core the PR-3 `StakeEngine` handler drives.
pub(crate) mod emission_claim;
/// Emission claim-source RPC decode (`EMISSION_CLAIM_BUILDER.md` §7, PR 1):
/// the wallet-side twin of the daemon's claim-source serializer, producing
/// the verify-side `EmissionEpochSource`/`ClaimantBondRecord` views the
/// PR-2 assembly consumes.
pub(crate) mod emission_source;
pub mod error;
#[cfg(any(test, feature = "test-helpers"))]
pub(crate) mod fault_injecting_pending_tx;
#[cfg(any(test, feature = "test-helpers"))]
pub(crate) mod fault_injecting_refresh;
pub mod fee_estimator;
pub(crate) mod fee_policy;
// WI-RPC-1: read-only fee/weight query projection for the wallet-RPC surface.
pub mod fee_query;
pub(crate) mod fee_snapshot;
/// GF-7 leg-(b) sealing re-run harness (`ARCHIVAL_BOND_WI4_MEASUREMENT.md`
/// §19.8): drives the **production** P-scan task + dispatch driver
/// (`start_pscan_sealing_run`, production config/cadence, real sleeps)
/// against a live `shekyld --regtest` and writes the receipts artifact that
/// `shekyl-staking-sim --gf7-seal` grades. `#[ignore]`d; requires
/// `SHEKYLD_BIN` and the non-default `gf7-hooks` feature; multi-hour by
/// design (§19.8.2 wall-clock budget).
#[cfg(all(test, feature = "gf7-hooks"))]
mod gf7_sealing_run;
pub(crate) mod key_actor;
/// §5.3 B9 dispatch-overhead bench support. Gated behind
/// `bench-internals`; re-exported through [`crate::__bench_internals`]
/// for the external Criterion / gungraun targets.
#[cfg(feature = "bench-internals")]
pub(crate) mod key_dispatch_bench;
pub mod lifecycle;
pub(crate) mod local_economics;
pub(crate) mod local_keys;
pub(crate) mod local_ledger;
pub mod local_pending_tx;
pub(crate) mod local_persistence;
pub(crate) mod local_refresh;
pub mod merge;
pub mod message_signing;
pub mod network;
pub mod output_selector;
pub mod payment_requests;
pub mod pending;
pub(crate) mod principal_stake;
/// WI-RPC-3 proof-generation bridge: the crypto bodies behind the
/// [`key_actor::KeyActor`]'s inbound-tx-proof and reserve-proof messages.
pub(crate) mod proof_bridge;
pub mod proofs;
pub(crate) mod proofs_chain_facts;
pub(crate) mod pscan;
pub mod refresh;
/// Per-engine single-flight slot shared by `start_refresh` / `start_rescan`.
pub(crate) mod refresh_slot;
/// Track-2 end-to-end FAKECHAIN regtest (C++↔Rust FCMP++ verify parity). Spawns
/// a real `shekyld --regtest` and drives the production [`Engine`] against it;
/// all tests are `#[ignore]`d and require `SHEKYLD_BIN`.
#[cfg(test)]
mod regtest_e2e;
/// Full-wallet rescan: reset scan-derived ledger state (Phase 4c).
pub(crate) mod rescan;
#[cfg(test)]
mod retire_walk;
pub(crate) mod scan_floor;
pub(crate) mod sealing_keys;
pub(crate) mod sign_bridge;
pub mod signer;
pub(crate) mod signing_assembly;
/// PR 2b/2c-2a (`docs/design/ARCHIVAL_BOND_CONSTRUCTION.md` §10.2): the
/// archival staking actor that owns the pre-derived archival personas `P` (the
/// Model D derive-forward set), not the seed. Landed inert — exercised by tests
/// only; the `assemble()` spawn and the JoinMarket request path (2c-2b) wire it
/// into the lifecycle.
pub(crate) mod stake_engine;
pub mod stake_facade;
/// PR 2c-2a (`ARCHIVAL_BOND_CONSTRUCTION.md` §10.2, typed contract #1): the
/// `PersistedBondTicket` persist-before-use typestate and its sole producer
/// `Engine::persist_bond_record`. Inert until 2c-2b's `plan_bond_post` consumes the
/// ticket; produced here so the cross-split contract is an unforgeable type.
pub(crate) mod stake_persist;
/// Bond-PR 2c-2b (Round 2): typed timing-seam newtypes — `BlockSpan`, `SebSpan`,
/// `NetworkGap`, `EconomicSpacing`, and their named default constants. Prevents
/// cross-applying the block-level standoff window with the economic SEB spacing
/// (distinct inner types → compile error on cross-apply). Design-now; real checks
/// wire in cold-start / 2d wiring.
pub(crate) mod stake_timing;
/// Transfer / pending-tx workflow (extracted from the former monofile
/// `local_pending_tx.rs` — see `docs/design/ENGINE_COMPOSITION_DECOMPOSITION.md`).
pub mod transfer;
/// PR-C: the composed `unstake` — two named actions on `StakeFacade`.
pub mod unstake_facade;
// WI-RPC-1: read-only staked-balance/staked-output aggregation over the
// authoritative sealed pscan/pending records, for the wallet-RPC surface.
pub mod staking_read;
/// `docs/design/DAEMON_SUBMIT_VERDICT.md` §5.3: the submit lifecycle
/// driver — the wallet-side actor that lifts the [`submit_watchdog`]
/// kernel (projection → escape ladder → resubmit-same-bytes probe →
/// outcome) and executes the F40 targeted re-scan with its R2
/// fruitless-rescan breaker. Thin scheduler around audited kernel
/// decisions; cadence is owned by the embedding runtime (`tick()`).
pub(crate) mod submit_lifecycle;
/// PR-4 (`docs/design/DAEMON_SUBMIT_VERDICT.md` §5.3): the submit
/// watchdog's pure decision kernel — F14-lock-keyed held tracking, the
/// privacy-tiered escape ladder with presence branching, health-context
/// gating, and the F35 horizon bound. Driven by [`submit_lifecycle`].
pub(crate) mod submit_watchdog;
/// CT-5c: production no longer uses synthetic membership vectors — the signer
/// folds the real paths the curve-tree client assembled (`assemble_path`).
/// Retained `#[cfg(test)]` for the two non-daemon test surfaces that genuinely
/// need synthetic, depth-controlled fixtures: the tx-weight KAT
/// ([`tx_weight_kat`], which measures FCMP++ proof size across tree depths) and
/// the [`local_keys`] signing KATs. This is the A4 reversion clause of
/// `docs/design/CT5C_ASSEMBLER_CUTOVER.md` firing (the doc had recorded "none
/// identified"; two were).
#[cfg(test)]
pub(crate) mod synthetic_tree;
#[cfg(test)]
pub(crate) mod test_support;
pub(crate) mod traits;
pub(crate) mod transaction_submitter;
pub(crate) mod tx_counts;
pub(crate) mod tx_fee_model;
#[cfg(test)]
mod tx_weight_kat;
/// The `submit_unbond` dispatch seam (PR-P4): seal a `PendingUnbond`, then
/// the persona-transport choke point; driven by `StakeFacade::unstake` (PR-C).
pub(crate) mod unbond_dispatch;
pub mod view_material;

pub use capability::Capability;
pub use daemon::DaemonClient;
pub use diagnostics::{
    BuildErrorKind, BuildRequestSummary, DaemonOp, DiagnosticSink, DiscardReason, MalformedKind,
    NoopDiagnosticSink, PendingTxDiagnostic, ProtocolErrorKind, RefreshDiagnostic, SuppressedClass,
    TracingDiagnosticSink, WatchdogAlarmReason, WatchdogProbeOutcome,
};
pub use error::{
    ChangePasswordError, IoError, KeyError, OpenError, PendingTxError, PersistenceError,
    RefreshError, SendError, SubmitError, TxError,
};
pub use fee_estimator::{DaemonFeeEstimator, FeeEstimationContext, FeeEstimator};
// `ValidatedFeeEstimates` is the type of `FeeEstimationContext`'s public
// `fee_snapshot` field, and `absolute_fee_rate_cap()` is the `bound` an
// RPC consumer reads out of a `-29109` payload: both were reachable
// through public API while unnameable, so neither could be documented.
pub use fee_policy::{absolute_fee_rate_cap, ValidatedFeeEstimates};
pub use fee_query::{FeeTierQuote, TxShapeEstimate};
pub use lifecycle::{CapabilityInput, Credentials, EngineCreateParams, OpenedEngine};
pub use local_economics::LocalEconomics;
pub use local_ledger::LocalLedger;
pub use local_pending_tx::LocalPendingTx;
pub use local_refresh::LocalRefresh;
pub use network::Network;
pub use tx_counts::{InputCount, OutputCount};
// Re-exported so binary-layer consumers of [`Engine::primary_address`]
// can name the return type without a direct `shekyl-address` dependency,
// mirroring the `Network` re-export above.
pub use shekyl_address::ShekylAddress;
// Re-exported so consumers of [`DaemonClient::fetch_scannable_block`] can
// name the return type without a direct `shekyl-scanner` dependency —
// same shape as `ShekylAddress` above. Canonical definition stays in
// `shekyl-scanner`; do not wrap or redefine (type-placement).
pub use shekyl_scanner::ScannableBlock;

pub use output_selector::{
    OutputCandidate, OutputSelector, SelectedOutputs, WalletGreedyOutputSelector,
};
pub use pending::{
    FeePriority, PendingTx, ReservationExtension, ReservationId, ReservationTTLConfig, SnapshotId,
    SubmitOutcome, TxHash, TxRecipient, TxRecipientSummary, TxRequest, DEFAULT_RESERVATION_TTL,
};
// The P-scan lifecycle surface (WI-1): handle + start error + cadence default,
// re-exported so embedders holding the `PScanHandle` (the module keeps the
// handle embedder-held, not engine-held — see `pscan::start`'s docs) can name
// the types without reaching into the `pub(crate)` pscan internals.
pub use bond_orchestrator::{FirstStakeError, FirstStakeOutcome, StakePosture};
// F-D2 aggregate drain-balance read error: two-armed (transient "syncing" vs.
// non-transient state fault), re-exported flat so the wallet/GUI can match on
// the arm across the command boundary without reaching into the `pub(crate)`
// drain-read module (mirrors the `FirstStakeError` re-export just above).
pub use drain_read::DrainBalanceReadError;
// WI-RPC-5 archival principal staking actions, re-exported flat for the
// wallet-RPC layer (the same shape as `FirstStakeError` above): the public
// drain façade's outcome/error pair and the `stake_in` error the handler
// matches on for its refusal codes.
pub use drain_facade::{DrainOutcome, DrainToPrincipalError};
pub use principal_stake::StakeInError;
pub use pscan::start::{PScanHandle, PScanStartError, DEFAULT_PSCAN_CADENCE};
pub use refresh::{
    RefreshHandle, RefreshOptions, RefreshPhase, RefreshProgress, RefreshReorgEvent, RefreshSummary,
};
pub use sealing_keys::StateWrapKey;
/// The MS-5 multisig signer marker — only present under `--features multisig`.
#[cfg(feature = "multisig")]
pub use signer::MultisigSignerV2;
pub use signer::{
    EngineSignerKind, LocalSigner, SignedTransfer, Signer, SoloSigner, TransferSigningContext,
};
pub use staking_read::{StakedBalance, StakedOutput, StakingReadError, StakingReadView};
pub use unstake_facade::{CollectOutcome, CollectUnstakedError, UnstakeError, UnstakeOutcome};
pub use view_material::ViewMaterial;

use std::marker::PhantomData;
use std::sync::Arc;

use shekyl_engine_file::WalletFile;
use shekyl_engine_prefs::WalletPrefs;
use shekyl_engine_state::WalletLedger;

use crate::engine::curve_tree_actor::CurveTreeHandle;
use crate::engine::key_actor::{HandleDerivationViewSecret, KeyEngineHandle};
use crate::engine::local_ledger::LedgerState;
use crate::engine::stake_engine::StakeEngineHandle;
use crate::engine::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, PersistenceEngine, RefreshEngine,
};

/// The Shekyl V3 wallet domain orchestrator.
///
/// `Engine<S>` composes the file envelope, identity material, persistent
/// ledger, user preferences, and daemon RPC connection into a single
/// audited surface. The CLI and JSON-RPC server both sit on top of
/// this type; neither reaches around it to the underlying crates.
///
/// # Type parameter `S`
///
/// `S: EngineSignerKind` selects between the V3.0
/// [`SoloSigner`] (in-process signing, single spend secret) and the
/// V3.1 multisig path (`MultisigSigner<N, K>`, lands behind the
/// existing `multisig` Cargo feature). V3.0 only constructs
/// `Engine<SoloSigner>`. The trait is sealed; see [`signer`].
///
/// # Lifecycle
///
/// Construction goes through one of the lifecycle methods:
///
/// - [`Engine::create`] — fresh wallet (BIP-39 seed for mainnet/stagenet,
///   raw 32-byte seed for testnet/fakechain).
/// - [`Engine::open_full`] — open an existing `Capability::Full`
///   wallet with the user's password.
/// - [`Engine::open_view_only`] — open an existing `Capability::ViewOnly`
///   wallet (no spend material).
/// - [`Engine::open_hardware_offload`] — open an existing
///   `Capability::HardwareOffload` wallet (signing happens out-of-band).
/// - [`Engine::change_password`] — rotate the user-supplied password
///   without rederiving the master seed.
/// - [`Engine::close`] — flush state to disk and release the advisory
///   lock; refuses if any [`PendingTx`] is in flight.
///
/// All six methods land in the lifecycle commit; this commit defines
/// the struct shape and the read-only accessor surface that those
/// methods produce.
///
/// # Locking discipline
///
/// Per cross-cutting lock 3, this type's methods follow the
/// `&self` for queries / `&mut self` for mutations split. The
/// JSON-RPC server binary wraps a `Engine<S>` in
/// `std::sync::Arc<tokio::sync::RwLock<Engine<S>>>`; the lock is the
/// caller's responsibility, not `Engine`'s. CLI and tests can hold a
/// `Engine<S>` directly without any lock.
///
/// # Drop semantics
///
/// `Engine<S>` does not implement `Drop`. The secret-bearing field
/// [`AllKeysBlob`](shekyl_crypto_pq::account::AllKeysBlob) has its own `Drop` impl that zeroizes spend / view /
/// ML-KEM-DK material; [`WalletFile`] has its own `Drop` for the file
/// KEK and lock release. Composing types that already wipe correctly
/// is sound; adding a wrapper `Drop` here would risk shadowing the
/// inner ones at compile time without changing behavior at run time.
///
/// [`PendingTx`]: error::PendingTxError
// `D: DaemonEngine` and `L: LedgerEngine` are more private than this
// `pub` item: per `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §2 preamble,
// Stage 1 traits ship `pub(crate)`. JSON-RPC cutover (the original
// promotion trigger) landed; traits stay crate-local until a second
// in-tree production crate must construct a workflow without `Engine`
// (rule 21). External callers use inherent methods on `Engine<S>`
// (defaults `D = DaemonClient`, `L = LocalLedger`); they cannot name
// `D` or `L`. Trait-`pub` (if that reopen fires) deletes this allow
// together with the sibling annotations (mod.rs inherent impls;
// lifecycle.rs's `OpenedEngine` / its inherent impl / signer-agnostic
// `Engine` impl; merge.rs / pending.rs / refresh.rs inherent impls)
// in a single sweep — same architectural relationship at each `pub`
// site.
#[allow(private_bounds)]
pub struct Engine<
    S: EngineSignerKind,
    D: DaemonEngine = DaemonClient,
    L: LedgerEngine = LocalLedger,
    E: EconomicsEngine = LocalEconomics,
    R: RefreshEngine = LocalRefresh,
    P: PendingTxEngine = LocalPendingTx<
        LocalSigner,
        WalletGreedyOutputSelector,
        DaemonFeeEstimator,
        fee_snapshot::DaemonFeeSnapshotSource<DaemonClient>,
        transaction_submitter::DaemonTransactionSubmitter<DaemonClient>,
        LocalLedger,
    >,
    F: PersistenceEngine = WalletFile,
> {
    /// On-disk persistence: `.wallet.keys` (region 1) + `.wallet` (region 2).
    /// Stage 1 implementor: [`WalletFile`]; Stage 4: actor-backed `F`.
    persistence: F,

    /// HKDF-derived `wrap_key_region_2` for steady-state ledger seals (F5(b)).
    state_wrap_key: StateWrapKey,

    /// HKDF-derived prefs integrity key; copied from the open path before
    /// [`WalletFile::zeroize_transient_file_kek`].
    prefs_hmac_key: shekyl_engine_prefs::PrefsHmacKey,

    /// Handle to the wallet's [`KeyActor`](super::key_actor::KeyActor), which
    /// owns the full [`AllKeysBlob`](shekyl_crypto_pq::account::AllKeysBlob) inside its own task (Stage 2,
    /// `docs/design/STAGE_2_KEY_ENGINE_ACTOR.md`). No `&AllKeysBlob` is
    /// reachable from the orchestrator after `assemble`: secret-touching key
    /// operations route through the actor's message protocol; public reads
    /// (`account_public_address`) resolve from the
    /// handle's construction-time projections. The blob is wiped when the last
    /// handle clone drops (which stops the actor — `KeyActor::on_stop` plus
    /// `AllKeysBlob`'s own `ZeroizeOnDrop`).
    ///
    /// Named `key` (singular), not `keys`: it is a single handle, not the
    /// key *blob* the old `keys: Arc<AllKeysBlob>` field held. The rename is
    /// the type-system signal that the orchestrator no longer owns key
    /// material (§6 step 3(c)).
    //
    // The field is read on the production path now, so it carries no
    // suppression. Its other load-bearing role is ownership: its `Drop` stops
    // the actor and zeroizes the blob (`LocalSigner` carries a clone).
    key: KeyEngineHandle,

    /// Handle to the wallet's [`CurveTreeActor`](super::curve_tree_actor::CurveTreeActor),
    /// which owns the FCMP++ [`CurveTreeClient`](shekyl_curve_tree::CurveTreeClient)
    /// — the `redb`-backed leaf store living beside the wallet files (CT-5,
    /// `docs/design/CT5_ENGINE_WIRING.md` §3.1). Opened and spawned in
    /// [`assemble`](Self::assemble); its `Drop` (last handle clone going away)
    /// stops the actor and closes the store on engine close. Unlike `key` the
    /// curve tree carries **no secret** (public on-chain material only), so the
    /// actor has no `on_stop` zeroization; durability is per-ingest, not
    /// at-close, so the async actor shutdown loses nothing.
    //
    // The handle is read on the merge ingest path (`handle.ingest` /
    // `rollback_to_fork`, CT-5a commits 4–5) and the spend-gate cursor read, so
    // the prior `#[allow(dead_code)]` (held-but-not-read at commit 2) has been
    // deleted now that its read sites landed, per
    // `21-reversion-clause-discipline.mdc`.
    curve_tree: CurveTreeHandle,

    /// Construction-time view-secret projection for the merge post-pass
    /// ([`Engine::apply_scan_result`]), per `STAGE_2_KEY_ENGINE_ACTOR.md` §6
    /// option 6-i. That path is synchronous and runs under the ledger
    /// `RwLock` write guard, so it cannot `ask` the actor (6-ii is foreclosed
    /// until the Ledger actor lands, §8.1); it derives the per-output
    /// `OutputHandle` from the view secret carried here instead. This is the
    /// *second* construction-time view-secret holder — the first is
    /// [`ViewMaterial`](super::view_material::ViewMaterial), moved into
    /// [`LocalRefresh`](super::local_refresh::LocalRefresh) for scanning. The
    /// two are deliberately distinct types so neither is mistaken for a clone
    /// of the other; both are Stage-2-minimal pending the 6-ii re-route.
    merge_view_secret: HandleDerivationViewSecret,

    /// Persistent wallet state plus its runtime-only index projection,
    /// aggregated under a single [`std::sync::RwLock`] by [`LocalLedger`].
    ///
    /// The aggregate carries:
    ///
    /// - The [`shekyl_engine_state::WalletLedger`] — scanner-derived
    ///   transfers, bookkeeping (primary label and address book), tx
    ///   metadata (`tx_keys`, scanned pool
    ///   txs), and the sync-state block. **Reservations do not live
    ///   here** — see [`local_pending_tx`](crate::engine::local_pending_tx)
    ///   below (reservations live in `LocalPendingTx`, not in the ledger).
    /// - The [`shekyl_engine_state::LedgerIndexes`] — runtime-only
    ///   indexes derived from chain replay (key-image / pubkey lookup
    ///   maps, staker-pool accrual aggregate). Per the
    ///   `RuntimeWalletState audit` Decision Log entry (2026-04-25),
    ///   these fields are reconstructible from the [`WalletLedger`]
    ///   plus daemon block replay and are never persisted; they are
    ///   rebuilt at every `Engine::open*` and mutated together with
    ///   the `WalletLedger` by `apply_scan_result`.
    ///
    /// Stage 1 PR 2 promotes this aggregate from two `&mut self`-gated
    /// fields to a single `RwLock`-gated [`LocalLedger`] so the
    /// in-process orchestration can call into [`LedgerEngine`] methods
    /// through `&self`. The trait surface (commit 1) and the field
    /// shape (this commit) are co-aligned: [`LocalLedger`] is the
    /// Stage 1 implementor.
    ///
    /// [`LedgerEngine`]: traits::LedgerEngine
    ledger: Arc<L>,

    /// **Transfer workflow handle** — the production default is
    /// [`LocalPendingTx`](local_pending_tx::LocalPendingTx) in
    /// [`transfer`](transfer). Multi-step send (build / submit / discard /
    /// re-anchor) is owned by that implementor, not by inherent methods on
    /// `Engine`. Prefer `self.pending.…` / `PendingTxEngine` over growing
    /// send bodies here (`ENGINE_COMPOSITION_DECOMPOSITION.md` §Transfer
    /// workflow ownership).
    ///
    /// Shares the same [`Arc`] ledger handle as [`Engine::ledger`] at
    /// assembly time (C6). `Engine::close` consults
    /// `outstanding_pending_txs()` and refuses with
    /// [`OpenError::OutstandingPendingTx`](error::OpenError::OutstandingPendingTx)
    /// when any reservation is in flight.
    pub(crate) pending: P,

    /// The §5.3 submit lifecycle driver's persistent overlay state
    /// (`docs/design/DAEMON_SUBMIT_VERDICT.md`): the escape-ladder wait
    /// epochs, alarm latches, and F40 targeted-re-scan / R2-breaker
    /// counters that must survive across driver ticks. Not generic in
    /// `P`/`D` — the wallet surface and the daemon are lent to the driver
    /// per tick ([`SubmitLifecycleDriver::tick`]), not owned by it.
    ///
    /// Wrapped in a [`tokio::sync::Mutex`] so the tick entry point
    /// ([`Engine::run_submit_lifecycle_tick`]) can hold the driver's
    /// `&mut` across the daemon round-trips inside one tick while the
    /// entry point itself takes `&self`. The guard is the *driver's*
    /// lock, independent of the ledger `RwLock`, so a tick never blocks
    /// the merge write-lock.
    submit_driver: tokio::sync::Mutex<submit_lifecycle::SubmitLifecycleDriver>,

    /// User preferences per the layer-2 plaintext+HMAC contract in
    /// [`docs/WALLET_PREFS.md`]. Loaded at open, saved on
    /// [`Engine::change_password`] / [`Engine::close`].
    prefs: WalletPrefs,

    /// Engine → daemon connection. Cloneable; shared by clone with the
    /// scanner and the tx-submission paths so each can issue daemon
    /// RPCs without touching the wallet's state.
    ///
    /// Generic over `D: DaemonEngine`. Production code defaults `D` to
    /// [`DaemonClient`] (a thin wrapper over
    /// `shekyl_rpc_transport::HttpRpc`); crate-internal
    /// tests substitute `TestDaemon` to drive failure-injection and
    /// deduplication scenarios against the same orchestration logic.
    /// See `crate::engine::traits::daemon` for the trait contract.
    daemon: D,

    /// Cached from `file.network()` for O(1) accessor speed. The
    /// wallet-file region 1 is the source of truth and never changes
    /// after `create`; this cache is therefore stable for the life of
    /// the open `Engine<S>`.
    network: Network,

    /// Cached from `file.capability()` for O(1) accessor speed. Same
    /// stability argument as `network`. Used by the lifecycle
    /// constructors to decide which `open_*` is appropriate (mismatched
    /// capability surfaces as
    /// [`OpenError::CapabilityMismatch`](error::OpenError::CapabilityMismatch))
    /// and by call sites that gate spend operations on
    /// [`Capability::can_spend_locally`].
    capability: Capability,

    /// Single-flight slot for [`Engine::start_refresh`]. Held by the
    /// engine for the lifetime of the open wallet; claimed (and
    /// guarded) by the producer task `run_refresh_task` for the
    /// duration of one refresh. A racing `start_refresh` finds the
    /// flag set and returns
    /// [`RefreshError::AlreadyRunning`](error::RefreshError::AlreadyRunning).
    ///
    /// Independent of the cross-cutting RwLock around `Engine<S>`:
    /// the slot is its own `Arc<AtomicBool>` so the slot-claim path
    /// only needs a brief shared read of the engine to clone the
    /// flag, not a write borrow. The producer task holds a
    /// [`SlotGuard`](refresh::SlotGuard) that releases the flag on
    /// task exit (RAII).
    refresh_slot: refresh::RefreshSlot,

    /// Single-flight slots for the embedder-held open-span tasks (P-scan +
    /// serving). One field so a third task does not spend a `FIELDS_CEILING`
    /// slot; the two flags are independent. Serving reuses [`RefreshSlot`]
    /// rather than a third copy of the same primitive.
    open_slots: refresh_slot::OpenTaskSlots,

    /// Per-wallet write lock over the `.wallet.pending` sibling seal (WI-3
    /// §3.3 writer discipline). The pending seal legitimately has **two**
    /// writers — the WI-2 assemble path (append) and the WI-3 dispatch driver
    /// (transition/remove) — on two cadences; a shared async mutex around
    /// load→modify→seal is what makes them safe against read-modify-seal
    /// races. Held here (not inside the ephemeral dispatch driver) so both
    /// writers serialize against **one** mutex per wallet: the driver clones
    /// it into its [`PendingPostStore`](pscan::dispatch::PendingPostStore) at
    /// spawn, and the assemble path takes the same clone. A bare `Arc<Mutex>`
    /// (no back-reference to the engine), so — unlike the running task's
    /// engine-arc — it introduces no ownership cycle.
    pending_write_lock: std::sync::Arc<tokio::sync::Mutex<()>>,

    /// Producer-side [`RefreshEngine`] implementor.
    ///
    /// Per [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §7.X C5,
    /// the engine owns one
    /// `R: RefreshEngine` for the lifetime of the open wallet; the
    /// orchestrator's refresh paths (`Engine::start_refresh` /
    /// `Engine::refresh`) dispatch the per-attempt producer body
    /// through the trait surface. Production callers default
    /// `R = LocalRefresh`, constructed at every `Engine::create` /
    /// `Engine::open_*` site by moving a freshly-derived
    /// [`ViewMaterial`](view_material::ViewMaterial) into
    /// `LocalRefresh::new`.
    ///
    /// # Why `Arc<R>` rather than `R`
    ///
    /// `run_refresh_task` takes an `Arc<RwLock<Engine<...>>>` because
    /// the orchestrator and the merge path share the same engine
    /// instance. The producer body (`produce_scan_result`) is long-
    /// running — network round-trips plus per-block scan — and must
    /// **not** hold any engine borrow across its `.await` boundary:
    /// the merge path needs the write half of the `RwLock` to land
    /// the scan result, and a read-borrow held through the scan
    /// would deadlock the merge.
    ///
    /// Holding the implementor as `Arc<R>` lets the orchestrator
    /// `Arc::clone` it out of the read-lock in a single brief borrow
    /// and then dispatch the trait call lock-free. The `&self`
    /// receiver on the trait method composes naturally: the cloned
    /// `Arc<R>` keeps `R` alive for the future's lifetime, the trait
    /// implementor's interior state is accessed through `&*arc` (free
    /// of borrow-on-Engine). `LocalRefresh`'s `ViewMaterial` remains
    /// owned-and-non-Clone at the implementor level; the Arc wraps
    /// the implementor, not the secret.
    ///
    /// # Visibility for trait-dispatch (Stage 4)
    ///
    /// Holding the implementor by-Arc on `Engine` makes the producer
    /// wipe-on-drop chain run when the last `Arc<R>` reference drops
    /// — typically at wallet close (today: `Engine::close`; Stage 4:
    /// actor shutdown). The Arc's strong count is exactly 1 in
    /// steady state (engine owns the only handle); the producer
    /// briefly bumps it to 2 for the duration of one
    /// `produce_scan_result` call, then drops back to 1 when the
    /// future settles. The Stage 4 actor cutover replaces this field
    /// with an actor handle; the trait surface stays the same.
    ///
    /// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
    pub(crate) refresh: std::sync::Arc<R>,

    /// Canonical economic-derivation implementor
    /// ([`EconomicsEngine`]).
    ///
    /// Production callers default `E = LocalEconomics`
    /// ([`LocalEconomics`](local_economics::LocalEconomics)), constructed
    /// at every `Engine::create` / `Engine::open_*` site (a pure
    /// constants rulebook — the claim-era chain-read seam was retired
    /// with the confidential-staking sweep).
    ///
    /// # Not yet consumed (PR 7 R6)
    ///
    /// The slot is **added, not wired**: no V3.0 production path invokes
    /// the [`EconomicsEngine`] trait through this field. The base-subsidy
    /// consensus cutover already landed (`7-cutover` / C2c, #93), but it
    /// routes `cryptonote::get_block_reward` to the Rust *primitive*
    /// (`shekyl_base_block_reward`) directly — **not** through this trait
    /// — and the burn / release-multiplier paths stay in C++. So this
    /// engine field remains unconsumed regardless of #93. Carrying it now
    /// keeps the struct shape stable for the eventual orchestrator-side
    /// adoption of the trait and for the Stage 4 `EconomicsActor` handle
    /// that replaces it behind the same trait surface.
    ///
    /// `LocalEconomics` is stateless at V3.0, so this is a value field
    /// (not `Arc<E>` like [`Engine::refresh`]); the V3.x adaptive-burn
    /// `Mutex<AdaptiveBurnState>` lives *inside* the implementor, and
    /// the Stage 4 cutover swaps the field type to an actor handle.
    // R6: carried for struct-shape stability, no V3.0 reader (§5.5);
    // reopens when an orchestrator path consumes the trait through this
    // field (not C2c/#93, which cut consensus over to the Rust primitive,
    // not this trait).
    #[allow(dead_code)]
    pub(crate) economics: E,

    /// Handle to the wallet's [`StakeEngine`](super::stake_engine::StakeEngine),
    /// the archival-staking actor that holds the Model-D pre-derived persona
    /// bundles (`ARCHIVAL_BOND_CONSTRUCTION.md` §10.2). `Some` only for a wallet
    /// that has staked (`StakingBlock::staking_enabled`); `None` for the
    /// overwhelming majority of wallets, which derive and hold no personas.
    ///
    /// Homonym: `self.stake` is this field; [`Engine::stake`](Self::stake) is
    /// the product façade (always a view — [`Self::has_stake_engine`] is the
    /// handle predicate).
    ///
    /// Spawned in [`assemble`](Self::assemble) over the derive-forward set —
    /// `{persisted bonded slots} ∪ {p_slot ..= p_slot + lookahead}` — derived
    /// there while the master seed is transiently borrowed, so the seed never
    /// reaches the actor and is dropped at the caller exactly as in the
    /// non-staker path. The actor's `Drop` (last handle clone) stops it and
    /// wipes the held bundles (`ZeroizeOnDrop`), mirroring `key`.
    // Ownership: spawn-at-open / wipe-at-close. JoinMarket PersonaHandle +
    // PersistedBondTicket still lands in 2c-2b.
    pub(crate) stake: Option<StakeEngineHandle>,

    /// Compile-time signer-kind dispatch. The actual key material lives
    /// in [`Engine::keys`] (for `SoloSigner`); this marker exists so
    /// the V3.1 multisig type can name distinct method signatures via
    /// associated items on [`EngineSignerKind`] without the V3.0 build
    /// paying a runtime branch on every send.
    _signer: PhantomData<S>,
}

impl<
        S: EngineSignerKind,
        D: DaemonEngine + std::fmt::Debug,
        L: LedgerEngine,
        E: EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
    > std::fmt::Debug for Engine<S, D, L, E, R, P>
{
    /// Redacted debug output. Specific reasons each field is or is not
    /// printed:
    ///
    /// - `file` — passes through to [`WalletFile`]'s own `Debug`, which
    ///   already redacts sealed material and prints only filesystem
    ///   paths and the public `network` / `capability`.
    /// - `key` — never printed. The [`KeyEngineHandle`] transitively
    ///   reaches the [`AllKeysBlob`](shekyl_crypto_pq::account::AllKeysBlob) (in the actor) and a view-secret
    ///   projection; neither implements `Debug` and we do not want a
    ///   stringly-typed leak path here.
    /// - `merge_view_secret` — never printed. Carries a raw view scalar
    ///   ([`HandleDerivationViewSecret`]); redacted for the same reason.
    /// - `ledger`, `prefs` — printed as opaque `<…>` markers. The
    ///   `ledger` field is the [`LocalLedger`] aggregate (the
    ///   [`shekyl_engine_state::WalletLedger`] plus the rebuilt-on-open
    ///   [`shekyl_engine_state::LedgerIndexes`]); both halves contain
    ///   user labels (already typed as
    ///   [`shekyl_engine_state::LocalLabel`] with redacting `Debug`,
    ///   per cross-cutting lock 9), but a wallet-level dump would be
    ///   noisy and add nothing not already available via the per-block
    ///   accessors.
    /// - `daemon` — passes through to [`DaemonClient`]'s `Debug`, which
    ///   includes the daemon URL but no auth credentials (see
    ///   [`shekyl_rpc_transport::HttpRpc`]).
    /// - `network`, `capability` — printed verbatim; these are cached
    ///   public values from region 1 of the wallet file.
    /// - `pending` — printed as an outstanding-count via
    ///   [`PendingTxEngine::outstanding`], not reservation contents.
    /// - `refresh` — printed as an opaque `<redacted: RefreshEngine>`
    ///   marker. The producer holds view-and-spend material per
    ///   §5.4.7 R4; surfacing the implementor's `Debug` would risk
    ///   leaking that material through a downstream sink. The
    ///   producer's identity type is also printed for diagnostic
    ///   purposes (e.g., distinguishing `LocalRefresh` from a future
    ///   actor-backed implementor at Stage 4); `type_name` is
    ///   secret-free.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("persistence", &"<redacted>")
            .field("state_wrap_key", &self.state_wrap_key)
            .field("prefs_hmac_key", &self.prefs_hmac_key)
            .field("key", &"<redacted: KeyEngineHandle>")
            .field("curve_tree", &"<opaque: CurveTreeHandle>")
            .field("merge_view_secret", &"<redacted: view secret>")
            .field("ledger", &"<…>")
            .field("outstanding_pending_txs", &self.pending.outstanding())
            .field("prefs", &"<…>")
            .field("daemon", &self.daemon)
            .field("network", &self.network)
            .field("capability", &self.capability)
            .field("refresh_running", &self.refresh_slot.is_claimed())
            .field("pscan_running", &self.open_slots.pscan.is_claimed())
            .field("serving_running", &self.open_slots.serving.is_claimed())
            .field("refresh", &"<redacted: RefreshEngine>")
            .field("refresh_kind", &std::any::type_name::<R>())
            .field("economics_kind", &std::any::type_name::<E>())
            .field("staking", &self.stake.is_some())
            .field("signer_kind", &std::any::type_name::<S>())
            .finish()
    }
}

/// RAII guard returned by [`Engine::ledger`]: holds a read lock on
/// the wallet's [`LocalLedger`] and derefs transparently to
/// [`WalletLedger`].
///
/// The guard is opaque: external callers cannot observe the
/// crate-private `LedgerState` aggregate or the `LedgerIndexes`
/// half — the [`Deref`] impl projects to `WalletLedger`, the only
/// type the public surface exposes. The `inner` field is private,
/// so even though its type names the `pub(crate)` `LedgerState`,
/// the `private_interfaces` lint does not fire (the type only
/// appears in private positions). The lint *would* fire if the
/// field were `pub`; it is deliberately not. Source compatibility
/// with the pre-Stage-1 `&WalletLedger` accessor is preserved by
/// the [`Deref`] impl, so calls of the form
/// `engine.ledger().some_wallet_ledger_method()` continue to compile
/// and behave identically.
///
/// A future refactor may project directly to `WalletLedger` via
/// `std::sync::RwLockReadGuard::map` (currently
/// `mapped_lock_guards`-feature-gated) or `parking_lot::RwLock`,
/// which would remove `LedgerState` from the field type entirely
/// and eliminate the rustdoc "private item" warning on the doc
/// comment below. Tracked under V3.x in `docs/FOLLOWUPS.md` →
/// "`LedgerReadGuard` field type leaks crate-private `LedgerState`".
///
/// Hold the guard for the minimum span necessary; concurrent writers
/// (`apply_scan_result` and the [`pending`]-module mutators) cannot
/// acquire the write lock while any reader is live.
///
/// [`Deref`]: std::ops::Deref
pub struct LedgerReadGuard<'a> {
    inner: std::sync::RwLockReadGuard<'a, LedgerState>,
}

impl std::ops::Deref for LedgerReadGuard<'_> {
    type Target = WalletLedger;

    fn deref(&self) -> &WalletLedger {
        &self.inner.ledger
    }
}

// `D: DaemonEngine` and `L: LedgerEngine` private-bound: see the
// rationale on the `pub struct Engine` definition in this file.
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        L: LedgerEngine,
        E: EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
        F: PersistenceEngine,
    > Engine<S, D, L, E, R, P, F>
{
    /// Network this wallet is bound to. Cached from
    /// [`WalletFile`]'s region 1 at construction; stable for the life
    /// of the open wallet.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Capability mode of this wallet (full / view-only /
    /// hardware-offload). Cached from [`WalletFile`]'s region 1 at
    /// construction; stable for the life of the open wallet.
    pub fn capability(&self) -> Capability {
        self.capability
    }

    /// The wallet's primary receive address (End-state 5: one reusable
    /// primary address per account; no subaddresses at V3.0 — see
    /// `docs/design/SUBADDRESS_UNDER_PQC.md` §5.7).
    ///
    /// Assembled from the `KeyActor`'s cached public projection
    /// (`KeyEngine::account_public_address` — sync, no actor
    /// round-trip, no secret material) and the engine's cached
    /// [`Network`]. Infallible and O(1) apart from the byte copies;
    /// render with [`ShekylAddress::encode`] (full three-segment form)
    /// or [`ShekylAddress::encode_classical_display`] (short display
    /// form).
    ///
    /// Phase 2c expands the receive surface with payment requests
    /// (`create_payment_request` / `list_payment_requests`); this
    /// accessor is the Phase 1 substrate that binaries need to show
    /// the wallet address at all.
    pub fn primary_address(&self) -> ShekylAddress {
        use crate::engine::traits::key::KeyEngine;

        self.key
            .account_public_address()
            .to_shekyl_address(self.network)
            .expect("key-actor projection is a well-formed classical segment + ek")
    }

    /// Borrow the [`PersistenceEngine`] implementor.
    pub fn persistence(&self) -> &F {
        &self.persistence
    }

    /// Steady-state region-2 sealing key for this session.
    pub(crate) fn state_wrap_key(&self) -> &StateWrapKey {
        &self.state_wrap_key
    }

    /// Session prefs HMAC key (orchestrator copy; see [`WalletFile`] for the
    /// handle's cached copy used by inherent prefs I/O).
    pub(crate) fn prefs_hmac_key(&self) -> &shekyl_engine_prefs::PrefsHmacKey {
        &self.prefs_hmac_key
    }

    /// Borrow user preferences. Read-only; preference rotation goes
    /// through dedicated methods that re-HMAC the body and atomic-write
    /// both files together.
    pub fn prefs(&self) -> &WalletPrefs {
        &self.prefs
    }

    /// Test-only: mutate in-memory prefs before `change_password` flush tests.
    #[cfg(test)]
    pub(crate) fn prefs_mut(&mut self) -> &mut WalletPrefs {
        &mut self.prefs
    }

    /// Borrow the daemon RPC client. Cloneable for handing to the
    /// scanner / tx-submission paths.
    ///
    /// The return type is `&D`, the type-parameter slot for the
    /// daemon. The production default `D = DaemonClient` resolves
    /// this to `&DaemonClient`; crate-internal tests substitute
    /// `TestDaemon` and observe the same accessor shape.
    pub fn daemon(&self) -> &D {
        &self.daemon
    }

    /// Whether a StakeEngine actor is resident (a staker open, or an
    /// open-with-first-stake-intent). Embedder-facing handle predicate
    /// (SA-R1-a intent reopen); [`Self::stake`] is a view either way.
    /// Deliberately a bool — the handle itself stays crate-private.
    pub fn has_stake_engine(&self) -> bool {
        self.stake.is_some()
    }

    /// Clone the archival-bond [`StakeEngineHandle`], or `None` if no stake
    /// engine is running. The handle is the `view_sk`-vault actor's address; the
    /// 2d-1 P-scan task ([`start_pscan`](Self::start_pscan)) clones it to offload
    /// each scan-step. Cloning the handle clones an `ActorRef`, not the vault.
    pub(crate) fn stake_handle(&self) -> Option<StakeEngineHandle> {
        self.stake.clone()
    }

    /// Test-only constructor: rebuild the engine with `refresh`
    /// substituted in place of the existing
    /// [`RefreshEngine`](super::traits::RefreshEngine) implementor,
    /// leaving every other field unchanged.
    ///
    /// Mirrors [`super::Engine::replace_daemon`] for the
    /// `R: RefreshEngine` slot added in PR 4 C5a. Hybrid tests that
    /// need a fully-constructed `Engine<SoloSigner>` but want to wrap
    /// the production [`super::local_refresh::LocalRefresh`] in a
    /// [`super::fault_injecting_refresh::FaultInjecting`] failure-
    /// injection wrapper compose this with `replace_daemon`:
    ///
    /// ```ignore
    /// let real = Engine::<SoloSigner>::create(params, dummy_daemon())?;
    /// // Post Stage 2 the engine no longer exposes its keys (the blob lives
    /// // in the KeyActor), so re-derive ViewMaterial from the same seed +
    /// // derivation params the engine was created with:
    /// let vm = ViewMaterial::try_from_keys(&rederive_test_blob())?;
    /// let refresh = FaultInjecting::new(LocalRefresh::new(vm, 0));
    /// let hybrid: Engine<
    ///     SoloSigner, TestDaemon, LocalLedger, LocalEconomics, FaultInjecting<LocalRefresh>,
    /// > = real
    ///         .replace_daemon(test_daemon)
    ///         .replace_refresh(refresh);
    /// ```
    ///
    /// The original `R1` refresh implementor is dropped (its
    /// `Arc<R1>` strong count goes to zero, firing the wipe-on-drop
    /// chain on any view material the implementor held); the
    /// returned engine's `refresh` field is a fresh `Arc<R2>` over
    /// the supplied implementor. Per the C6α "Arc replacement
    /// semantics" rationale, tests must not call this method while
    /// a refresh is in flight — the engine's single-flight slot
    /// guards against concurrent `start_refresh` but not against
    /// setter-during-refresh races.
    ///
    /// # Visibility
    ///
    /// `pub(crate)` and gated by `#[cfg(any(test, feature =
    /// "test-helpers"))]` per the C6α F-Mock-1 symmetry pin (asymmetric
    /// with sibling `replace_daemon`, which is
    /// `#[cfg(test)]`-only: that method predates the `test-helpers`
    /// feature and exist purely for crate-internal tests, while
    /// `replace_refresh` lands alongside the `FaultInjecting<R>`
    /// wrapper that is itself `test-helpers`-feature-callable for
    /// downstream consumers). Production builds do not compile this
    /// method.
    ///
    /// # API shape change from C6α
    ///
    /// C6α introduced `replace_refresh` as a `&mut self` setter that
    /// could only swap one `R` for another `R` of the same type. C7's
    /// hybrid test requires changing the type parameter from
    /// `LocalRefresh` to `FaultInjecting<LocalRefresh>`, which the
    /// `&mut self` shape cannot express. The consume-and-rebuild
    /// signature here matches the precedent set by `replace_daemon`
    /// and lets the `Engine` orchestrator compose cleanly across the
    /// daemon and refresh slot substitutions. Per the C6α docstring's "Phase 1 author
    /// commitment note", `replace_refresh` had no consumers in
    /// C6α/C6β/C6γ, so the signature change is non-breaking; C7 is
    /// the first consumer.
    #[cfg(any(test, feature = "test-helpers"))]
    #[allow(dead_code)]
    pub(crate) fn replace_refresh<R2: RefreshEngine>(
        self,
        refresh: R2,
    ) -> Engine<S, D, L, E, R2, P, F> {
        let Engine {
            persistence,
            state_wrap_key,
            prefs_hmac_key,
            key,
            curve_tree,
            merge_view_secret,
            ledger,
            pending,
            submit_driver,
            prefs,
            daemon,
            network,
            capability,
            refresh_slot,
            open_slots,
            pending_write_lock,
            refresh: _old,
            economics,
            stake,
            _signer,
        } = self;
        Engine {
            persistence,
            state_wrap_key,
            prefs_hmac_key,
            key,
            curve_tree,
            merge_view_secret,
            ledger,
            pending,
            submit_driver,
            prefs,
            daemon,
            network,
            capability,
            refresh_slot,
            open_slots,
            pending_write_lock,
            refresh: std::sync::Arc::new(refresh),
            economics,
            stake,
            _signer,
        }
    }

    /// Test-only constructor: rebuild the engine with `pending`
    /// substituted, leaving every other field unchanged.
    ///
    /// Mirrors [`Self::replace_refresh`] for the `P: PendingTxEngine`
    /// slot (PR 5 C6). Hybrid tests that need a
    /// [`super::fault_injecting_pending::FaultInjecting`] wrapper
    /// (C7) compose this with the other `replace_*` helpers.
    #[cfg(any(test, feature = "test-helpers"))]
    #[allow(dead_code)]
    pub(crate) fn replace_pending_tx<P2: PendingTxEngine>(
        self,
        pending: P2,
    ) -> Engine<S, D, L, E, R, P2, F> {
        let Engine {
            persistence,
            state_wrap_key,
            prefs_hmac_key,
            key,
            curve_tree,
            merge_view_secret,
            ledger,
            pending: _old,
            submit_driver,
            prefs,
            daemon,
            network,
            capability,
            refresh_slot,
            open_slots,
            pending_write_lock,
            refresh,
            economics,
            stake,
            _signer,
        } = self;
        Engine {
            persistence,
            state_wrap_key,
            prefs_hmac_key,
            key,
            curve_tree,
            merge_view_secret,
            ledger,
            pending,
            submit_driver,
            prefs,
            daemon,
            network,
            capability,
            refresh_slot,
            open_slots,
            pending_write_lock,
            refresh,
            economics,
            stake,
            _signer,
        }
    }
}

#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        L: LedgerEngine,
        E: EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine + submit_lifecycle::WatchdogHost,
        F: PersistenceEngine,
    > Engine<S, D, L, E, R, P, F>
{
    /// Run one submit lifecycle driver cadence step
    /// (`docs/design/DAEMON_SUBMIT_VERDICT.md` §5.3): the F40 targeted
    /// re-scan verification (with its R2 breaker) and the escape ladder
    /// (projection → health → resubmit-same-bytes probe → outcome) over
    /// every held tx. Lends the pending-tx engine (as the
    /// [`WatchdogHost`](submit_lifecycle::WatchdogHost)) and the daemon
    /// to the driver for the duration of the tick.
    ///
    /// # Cadence is the embedding runtime's, not the Engine's (§5.3)
    ///
    /// "Cadence is role policy; termination is not." This method is the
    /// **entry point**, not a scheduler — the owner of the `Engine`
    /// (the wallet binary / RPC server; Stage 4: the actor runtime)
    /// decides *when* to call it. The natural call site is after each
    /// completed refresh cycle, since the held projection and
    /// `synced_height` only move on refresh / ledger writes; it must
    /// **not** be called while a merge write-lock is held, because the
    /// tick issues daemon round-trips and holding the ledger lock across
    /// them would block the merge it depends on.
    ///
    /// Available only when the pending-tx engine is the production
    /// [`LocalPendingTx`](local_pending_tx::LocalPendingTx) (the
    /// `WatchdogHost` implementor); fault-injection test wrappers that do
    /// not implement the host contract do not expose this entry point.
    pub async fn run_submit_lifecycle_tick(&self) {
        let mut driver = self.submit_driver.lock().await;
        driver.tick(&self.pending, &self.daemon).await;
    }
}

#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        L: LedgerEngine,
        E: EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
    > Engine<S, D, L, E, R, P, WalletFile>
{
    /// Borrow the Stage 1 [`WalletFile`] implementor. Prefer
    /// [`Self::persistence`] for trait-shaped save/rotate paths.
    pub fn file(&self) -> &WalletFile {
        &self.persistence
    }
}

// `D: DaemonEngine` private-bound: see the rationale on the `pub
// struct Engine` definition in this file. The `L = LocalLedger`
// specialization is intentional: [`Engine::ledger`] returns a
// [`LedgerReadGuard`] tied to the in-process [`LocalLedger`]'s
// [`std::sync::RwLockReadGuard`]; once Stage 4 promotes the trait
// `LedgerEngine` to a richer surface (or replaces this accessor
// with a trait-level read-state method), this block dissolves.
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
    > Engine<S, D, LocalLedger, E, R, P>
{
    /// Borrow the persistent ledger for read-only queries (transfers,
    /// bookkeeping entries, tx metadata, sync cursor). Mutation goes
    /// through the methods on [`Engine`] that the lifecycle / refresh /
    /// send commits add — never through this borrow.
    ///
    /// The return value is a [`LedgerReadGuard`] that holds a
    /// [`std::sync::RwLockReadGuard`] over [`LocalLedger`]'s state
    /// for the borrow's lifetime; the guard derefs transparently to
    /// `&WalletLedger` so existing call sites that read through this
    /// accessor are source-compatible. Drop the guard to release the
    /// read lock and allow concurrent writers to acquire it.
    ///
    /// # Public-API signature change vs. pre-Stage-1
    ///
    /// Pre-Stage-1 this method returned `&WalletLedger`; Stage 1 PR 2
    /// changes the return type to `LedgerReadGuard<'_>` so the borrow
    /// is tied to a [`std::sync::RwLock`] read guard rather than a
    /// flat field. Source-compatible upgrade paths:
    ///
    /// - **Call-style read access** (`engine.ledger().balance()`,
    ///   `engine.ledger().transfers()`, …) keeps working unchanged
    ///   via the [`std::ops::Deref`] impl on [`LedgerReadGuard`].
    /// - **Code that named the old return type explicitly** — e.g.
    ///   `let l: &WalletLedger = engine.ledger();` or `fn(&WalletLedger)
    ///   = Engine::ledger;` — must change either to bind the guard
    ///   (`let l = engine.ledger(); let l: &WalletLedger = &*l;`) or
    ///   accept `LedgerReadGuard<'_>` as the named type.
    /// - **Long-lived borrows held across `.await`** are no longer
    ///   sound: holding the guard across an await blocks writers, so
    ///   refactor such call sites to drop the guard before awaiting.
    ///
    /// Specialized to `L = LocalLedger` because the guard is tied
    /// to that implementor's lock; mocked-`L` tests (commit 6) do
    /// not exercise this accessor.
    pub fn ledger(&self) -> LedgerReadGuard<'_> {
        LedgerReadGuard {
            inner: self.ledger.read(),
        }
    }
}

/// Bench-internals helpers (gated) — split from this file per the
/// decomposition ratchet; re-exported so `crate::__bench_internals` paths hold.
#[cfg(feature = "bench-internals")]
pub(crate) mod bench_support;
#[cfg(feature = "bench-internals")]
pub use bench_support::*;
