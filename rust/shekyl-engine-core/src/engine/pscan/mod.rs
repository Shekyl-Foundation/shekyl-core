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
//! Build order: **SP-0** ([`block_source`]) lands first — the per-`P`
//! fetch-everything block source that the isolation boundary (DQ1) rests on.
//! It produces no on-chain event; it broadcasts and garbage-collects nothing.

pub(crate) mod block_source;
