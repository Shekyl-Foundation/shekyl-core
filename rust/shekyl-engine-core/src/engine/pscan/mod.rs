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
//! `ScanStep` boundary; **SP-4** ([`inflow`]) — the idempotent per-epoch
//! funding-inflow signal `C_min` consumes (paired with SP-2's `PScanCursor` in
//! `shekyl-engine-state` as the one crash-recovery decision). All read-side: they
//! produce no on-chain event and broadcast/GC nothing.
//!
//! [`scan_step`] (SP-3 + the SP-5 actor scan-step) lands here; the **driving
//! task** + the sealed P-isolated cursor/inflow persistence (the rest of SP-5)
//! follow in PR-B. [`block_source`] and [`inflow`] are exercised only by their own
//! tests until that task wires them, so they keep a transient `#[allow(dead_code)]`.

pub(crate) mod block_source;
pub(crate) mod inflow;
pub(crate) mod persona_scanner;
pub(crate) mod scan_step;
