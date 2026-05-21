// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pure-software RandomX v2 verifier for Shekyl daemon block validation.
//!
//! Consumed exclusively by `shekyl-ffi` (Phase 3, not in scope at this
//! commit); never linked into the C++ miner path. The Monero RandomX
//! C/C++ library at `external/randomx-v2/` (pinned at fork commit
//! `aaafe71`, v2.0.1) remains the miner; this crate is the verifier
//! and the verifier only. See
//! [`RANDOMX_V2_PLAN.md`](../../docs/design/RANDOMX_V2_PLAN.md)'s
//! "Permanent architectural decisions" §1.
//!
//! # Decision substrate (locked; do not relitigate)
//!
//! - **Spec-first.**
//!   [`specs.md`](../../external/randomx-v2/doc/specs.md) is the source
//!   of truth. Disagreements with the C reference at
//!   `external/randomx-v2/src/` are bugs filed against the C fork,
//!   not amendments to this port. See
//!   [`RANDOMX_V2_RUST.md`](../../docs/design/RANDOMX_V2_RUST.md) §3.
//! - **Derived-first.** `Cache`, `Vm`, and `Hash` are transform-shaped
//!   per
//!   [`18-type-placement.mdc`](../../.cursor/rules/18-type-placement.mdc):
//!   their canonical definitions are functions (e.g.
//!   `Cache::derive(seedhash) -> Cache`); storage is a memoization of
//!   the function's output. See
//!   [`RANDOMX_V2_RUST.md`](../../docs/design/RANDOMX_V2_RUST.md) §4.
//! - **Isolation invariants.** No `#[no_mangle]`, no `extern "C" fn`,
//!   no `#[export_name]` (bare or `#[unsafe(…)]`), no module-level
//!   runtime-mutable state (`Mutex`, `RwLock`, `OnceCell`, `OnceLock`,
//!   `Lazy`, `static mut`, module-scope atomics). Immutable `const`
//!   tables are allowed. Phase 2f ships the CI greps that enforce
//!   these mechanically; the crate is written from its first commit as
//!   if those greps were already live. See
//!   [`RANDOMX_V2_RUST.md`](../../docs/design/RANDOMX_V2_RUST.md) §7.2.
//!
//! # Scope at this commit (Phase 2a)
//!
//! Workspace scaffold and the Argon2d "memory fill" primitive used by
//! `Cache::derive`. The primitive itself lands in the next commit
//! (`src/argon2d.rs`). Subsequent sub-PRs (per
//! [`RANDOMX_V2_PLAN.md`](../../docs/design/RANDOMX_V2_PLAN.md)
//! §"Track A — Phase 2"):
//!
//! - **2b:** AES round + SuperScalarHash.
//! - **2c:** `Vm<'a>` scratchpad + execution loop.
//! - **2d:** Bytecode opcode dispatch.
//! - **2e:** `Cache::derive` wrapping the Argon2d primitive landed
//!   here.
//! - **2f:** `CacheStore` LRU + crate-level CI invariant tests
//!   (mechanical enforcement of §7.2's isolation invariants).
//! - **2g:** C-side differential harness as a *separate* test-only
//!   artifact (not a `[dev-dependencies]` of this crate); the crate's
//!   own `cargo test` succeeds without the C library present.
//!
//! Phase 3 then exposes the verifier through `shekyl-ffi` and rewires
//! the C++ daemon to it; Phase 4 deletes the C++ verifier path.

#![deny(unsafe_code)]
#![deny(missing_docs)]

// CLIPPY: the `pub(crate)` items in `argon2d` (the RandomX-Argon2d
// constants, the compile-time-validated `PARAMS`, and `fill_cache`
// itself) are dead-by-construction until Phase 2e lands `Cache::derive`
// as the single production caller. The module-level `#[allow]` is the
// narrowest scope that covers all items without per-item annotations,
// per `.cursor/rules/45-rust-lint-checks.mdc`'s "as narrowly as
// possible" guidance balanced against the unit tests already exercising
// every item inside the module.
#[allow(dead_code)]
mod argon2d;
