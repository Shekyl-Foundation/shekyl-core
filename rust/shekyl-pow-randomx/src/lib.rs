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
//! # Scope at this PR (Phase 2b)
//!
//! Phase 2a landed the workspace scaffold and the Argon2d "memory fill"
//! primitive used by `Cache::derive`. Phase 2b lands the remaining v2
//! primitives the verifier needs plus spec-vector parity tests against
//! the v2 fork's reference at pin `aaafe71`:
//!
//! - `src/aes.rs` — AES single-round wrappers (`cipher_round`,
//!   `equiv_inv_cipher_round`) over `aes-0.9.0`'s `hazmat` API plus
//!   the §3.2-3.4 composites (`AesGenerator1R`, `AesGenerator4R`,
//!   `AesHash1R`), with 8 spec-vector parity tests consuming pre-
//!   committed reference bytes via `include_bytes!`; the reviewer-
//!   runnable C++ generator lives at
//!   `tests/vectors/reference/aes/_generator/`.
//! - `src/blake2_generator.rs` — `Blake2Generator` PRNG per spec §3.5.
//! - `src/superscalar.rs` — `SuperscalarHash` program generator and
//!   executor per spec §6 + §7.2, plus F4 structured 3-vector
//!   decomposition spec-vector tests (Layer A program serialization
//!   × 3 + Layer B execution × 3 + combined end-to-end attestation
//!   = 7 vectors); the reviewer-runnable C++ generator lives at
//!   `tests/vectors/reference/superscalar/_generator/`.
//! - F1 convergence on `src/argon2d.rs`'s `#[allow(dead_code)]`: moved
//!   from the module-level attribute on `mod argon2d` to per-item
//!   attributes inside the module, matching the per-entry-point
//!   discipline applied to the new modules. See
//!   [`RANDOMX_V2_PHASE2B_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2B_PLAN.md)
//!   §5.1.
//!
//! Subsequent sub-PRs (per
//! [`RANDOMX_V2_PLAN.md`](../../docs/design/RANDOMX_V2_PLAN.md)
//! §"Track A — Phase 2"):
//!
//! - **2c:** `Vm<'a>` scratchpad + execution loop.
//! - **2d:** Bytecode opcode dispatch.
//! - **2e:** `Cache::derive` wrapping the Argon2d primitive landed by
//!   Phase 2a and the SuperscalarHash primitive landed by Phase 2b.
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

mod aes;
mod argon2d;
mod blake2_generator;
mod cache;
mod superscalar;

pub use cache::Cache;
