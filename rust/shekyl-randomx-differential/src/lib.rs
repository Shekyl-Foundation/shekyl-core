// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Phase 2g Rust/C differential test harness library surface.
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §5.1.2 + §5.1.4, this
//! `[lib]` target exists **solely** so integration tests under
//! `tests/` can call into the harness's `pub(crate)` modules at C6+;
//! it is not a public-API crate. The crate-level `#![doc(hidden)]`
//! attribute hides the entire surface from rustdoc per §5.1.2's
//! `#[doc(hidden)]` annotation, so consumers reading
//! `cargo doc --workspace` output do not see the harness's internals
//! as a documented surface.
//!
//! ## C4 skeleton scope
//!
//! At C4 (per §8.1), the module surface enumerated in §5.1.5–§5.1.14
//! + §5.1.17 + §5.1.18 does not yet exist; the file is intentionally
//! empty beyond this header. Module re-exports land alongside the
//! corresponding modules at C5–C9 per §8.1.
//!
//! ## §5.7 drift-prevention boundary
//!
//! The re-export surface introduced at C5+ must be limited to modules
//! enumerated in §5.1.5–§5.1.14 + §5.1.17 + §5.1.18. Per §5.7's
//! reviewer rejection criterion, any added re-export not listed in
//! §5.1 is grounds for scope-creep rejection.

#![doc(hidden)]
