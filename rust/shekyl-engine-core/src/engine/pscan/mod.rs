// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! 2d-1 — the firewalled per-`P` scan layer (read-side only).
//!
//! This subsystem is the archival-bond persona (`P`) scan: a `P.view_sk` sweep
//! isolated from the principal's ledger scan at the key, state, fetch, and
//! execution layers. The design and its per-SP breakdown live in
//! [`docs/design/ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`](../../../../../docs/design/ARCHIVAL_BOND_2D1_PSCAN_PLAN.md).
//!
//! Build order: **SP-0** ([`block_source`]) — the per-`P` fetch-everything block
//! source the isolation boundary (DQ1) rests on; **SP-1** ([`persona_scanner`]) —
//! the `ArchivalPKeys` → `GuaranteedViewPair` adapter that builds a persona's
//! burning-bug-immune scanner; **SP-3/SP-5** ([`scan_step`]) — the dual extractor
//! (view-key funding + cleartext bond-post) run offloaded behind the actor's
//! `ScanStep` boundary; **SP-4/SP-5** ([`accrual`]) — the accumulate-side scan
//! accrual (`PScanAccrual`) + the finalized per-epoch funding signal
//! (`PFundingInflow`, the finalization guard) `C_min` consumes; **SP-5** the
//! [`cadence`] (injectable fixed-rate schedule), the driving [`task`]
//! (`run_pscan_task`), and [`start`] (`Engine::start_pscan`, the wiring to the
//! daemon + the `.wallet.pscan` seal). All read-side: they produce no on-chain
//! event and broadcast/GC nothing.
//!
//! The full SP-3/SP-5 layer — extractor, accrual, cadence, driving task, and the
//! `Engine::start_pscan` wiring — landed with PR-B. WI-1 then made the chain
//! live **from the embedder**: the P-scan handle is embedder-held (there is no
//! in-`engine` call site), so `shekyl-wallet-rpc`'s wallet lifecycle is the
//! production caller — it auto-starts `Engine::start_pscan_if_staker` on a
//! staker open and `PScanHandle::shutdown`s the task on close (before the
//! `Arc::try_unwrap` that `Engine::close` needs). Remaining transient
//! `#[allow(dead_code)]` marks items whose consumer is a *later* slice (2d-2
//! posture selector, SP-7 `C_min` sizing, SP-R0 reconcile GC, cold-start cover
//! discovery), each annotated with its named consumer.

pub(crate) mod accrual;
// SP-R0 arm #1 DQ-F fire harness. `not(test)` is load-bearing: it guarantees
// every compilation containing the harness has no `#[cfg(test)]` constructors
// (Guard 1 — no `for_test()` on the path under test — as a compile-time fact).
#[cfg(all(feature = "test-helpers", not(test)))]
pub(crate) mod arm1_fire;
pub(crate) mod block_source;
pub(crate) mod cadence;
pub(crate) mod cover_discovery;
pub(crate) mod dispatch;
pub(crate) mod exhaustiveness;
pub(crate) mod persona_scanner;
pub(crate) mod reconcile;
pub(crate) mod scan_step;
pub(crate) mod seal_basis;
pub(crate) mod start;
pub(crate) mod task;
