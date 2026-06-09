// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Frozen sub-root (`R_k`) store and segment caching (CT-1 hot path).
//!
//! Persists drained leaves and frozen segment metadata in **redb**
//! (`docs/design/CT1_ROUND1_PINS.md`). The steady-state root path composes
//! cached `R_k` nodes with `shekyl_fcmp::tree::build_upper_layers`.

mod ops;
mod redb_backend;

pub use ops::{mixed_composition_root, MixedRootError};
pub use redb_backend::{FrozenSegmentRecord, LeafStore, StoreError};
