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
//! `Engine::start_pscan` wiring — lands in this PR (PR-B). The lifecycle layer that
//! *calls* `start_pscan` is the only remaining consumer, so the modules carry
//! transient `#[allow(dead_code)]` on the items it will reach until it lands.

pub(crate) mod accrual;
pub(crate) mod block_source;
pub(crate) mod cadence;
pub(crate) mod exhaustiveness;
pub(crate) mod persona_scanner;
pub(crate) mod reconcile;
pub(crate) mod scan_step;
pub(crate) mod start;
pub(crate) mod task;
