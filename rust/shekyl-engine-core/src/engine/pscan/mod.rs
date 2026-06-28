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
//! (`PFundingInflow`, the finalization guard) `C_min` consumes. All read-side:
//! they produce no on-chain event and broadcast/GC nothing.
//!
//! [`scan_step`] (SP-3 + the SP-5 actor scan-step) and [`accrual`] (the accumulate
//! model + persisted-state mirror) land here; the **driving task** that wires them
//! to the [`block_source`] + the `.wallet.pscan` seal follows in PR-B's later
//! commits. [`block_source`] and [`accrual`] are exercised only by their own tests
//! until that task lands, so they keep a transient `#[allow(dead_code)]`.

pub(crate) mod accrual;
pub(crate) mod block_source;
pub(crate) mod cadence;
pub(crate) mod persona_scanner;
pub(crate) mod scan_step;
pub(crate) mod task;
