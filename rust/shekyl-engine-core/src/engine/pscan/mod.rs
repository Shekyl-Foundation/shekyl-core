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
//! burning-bug-immune scanner; **SP-4** ([`inflow`]) — the idempotent per-epoch
//! funding-inflow signal `C_min` consumes (paired with SP-2's `PScanCursor` in
//! `shekyl-engine-state` as the one crash-recovery decision). All read-side: they
//! produce no on-chain event and broadcast/GC nothing. Their non-test consumer is
//! the SP-5 scan loop (not yet built), so they carry transient `#[allow(dead_code)]`.

pub(crate) mod block_source;
pub(crate) mod inflow;
pub(crate) mod persona_scanner;
