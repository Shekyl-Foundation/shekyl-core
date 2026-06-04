// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Frozen sub-root (`R_k`) store and segment caching (CT-1 hot path).
//!
//! Home for the content-addressed frozen sub-root cache that turns the
//! Round-1 rebuild-from-leaves oracle ([`crate::recon::root_from_scalars`]
//! via `shekyl_fcmp::tree::build_layers`) into the steady-state cached
//! path (`shekyl_fcmp::tree::build_upper_layers` over cached `R_k`
//! nodes). Correctness-first: this is intentionally empty until the
//! reconstruct-root baseline (CT-2 KAT) is green, at which point that
//! same KAT becomes the regression gate for the `build_upper_layers`
//! factor.
//!
//! See `docs/design/CURVE_TREE_CLIENT.md` §3.2 (components) and
//! `docs/design/CT2_DRAIN_ORDER.md` §8 (the KAT this is gated behind).
