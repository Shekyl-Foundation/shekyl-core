// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Stake workflow — archival persona secrets and bond/claim/drain assembly.
//!
//! Message handlers are split by family; the actor core keeps secrets (rule 36)
//! behind `pub(crate)` fields reachable only inside this tree.
//!
//! | Module | Role |
//! |--------|------|
//! | [`types`] | Domain values, errors, spawn args |
//! | [`helpers`] | Shared funding/vout prep, P-secrets, entry-gap draw |
//! | [`actor`] | `StakeEngine` struct, spawn, inherent methods, Actor |
//! | [`persona`] | Mint / activate / identity / PlanBondPost |
//! | [`bond`] | AssembleBond |
//! | [`drain`] | AssembleDrain shell |
//! | [`claim`] | AssembleEmissionClaim |
//! | [`scan`] | ScanStep |
//! | [`serve_set_source`] | Serve-set derivation from the connected bond record (SH-2) |
//! | [`retire`] | Retire / project-id |
//! | [`handle`] | `StakeEngineHandle` |
//!
//! Call sites keep `crate::engine::stake_engine::{…}`.

// S6 / DQ3 — the session RNG self-cert grader (`shekyl-standoff` `conformance`)
// is gated to **`x86_64` exactly** (the guard below is `target_arch = "x86_64"`,
// matching the `x86_64`-only CI conformance lane and the standoff conformance
// lane it mirrors): its goodness-of-fit is float, which is not bit-identical
// across architectures, and `x86_64` is the only target the diagnostic is built
// and run on. Rather than silently compile the self-cert out on a non-`x86_64`
// target (which would let a `--features conformance` diagnostic build report
// "conformance passed" when the grade never ran — false assurance), fail the
// build loudly: a diagnostic build that cannot run the diagnostic must say so at
// compile time, not pretend success at runtime. With this guard, `conformance`
// implies `x86_64`, so the self-cert call sites need only `cfg(feature)`.
// Single copy at the module root — not re-pasted into helpers/types/actor.
#[cfg(all(feature = "conformance", not(target_arch = "x86_64")))]
compile_error!(
    "the StakeEngine session RNG self-cert grader (shekyl-standoff `conformance`) \
     is `x86_64`-only — its float goodness-of-fit is not bit-identical across \
     architectures. Build the `conformance` feature on `x86_64` (where the CI \
     conformance lane runs); do not enable it on other targets (including 32-bit \
     x86)."
);

mod actor;
mod bond;
mod claim;
mod drain;
mod handle;
mod helpers;
mod persona;
mod retire;
mod scan;
pub(crate) mod serve_set_source;
mod types;

#[cfg(test)]
pub(crate) mod test_fixtures;

#[cfg(test)]
#[path = "stake_engine_tests.rs"]
mod tests;

// The out-of-module surface: exactly what `crate::engine::…` consumes. Message
// types whose only sender is a sibling handler are NOT re-exported — those
// import from the sibling directly (`handle.rs` does), so this list stays a
// true statement about the workflow's boundary rather than a mirror of every
// item the split happened to produce. Nothing here carries
// `#[allow(unused_imports)]`: a re-export that stops being consumed must fail
// rule 45's `-D warnings` gate, which is the only thing that keeps the
// statement true as handlers come and go.
pub(crate) use actor::persona_canonical_id;
pub(crate) use bond::AssembledBondPost;
pub(crate) use claim::{AssembleEmissionClaim, AssembledEmissionClaim};
pub(crate) use handle::StakeEngineHandle;
pub(crate) use helpers::prepare_funding_inputs;

// `derive_funding_key_image` crosses the boundary for exactly one consumer,
// `pscan/arm1_fire.rs`, which carries this same gate — so the re-export states
// the harness-only reach rather than advertising a production one.
#[cfg(all(feature = "test-helpers", not(test)))]
pub(crate) use helpers::derive_funding_key_image;

// These two have no *code* consumer outside this module: they are the paths
// five engine doc comments link to (`lib.rs`, `engine/mod.rs`, `lifecycle.rs`,
// `pscan/start.rs`, `bond_assembly.rs`), and `unused_imports` does not count
// intra-doc links. `expect` rather than `allow` so the exemption retires
// itself: the day either name gains a real caller the attribute becomes an
// unfulfilled expectation and fails the build until someone deletes it.
// The `cfg_attr` is load-bearing: the in-tree suite reaches this module with
// `use super::*`, and a glob import marks every re-export used, so `cfg(test)`
// compilations can never report either name. Stating the exemption for
// `not(test)` only keeps it exactly as wide as the target that can actually
// observe it.
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "rustdoc intra-doc link target; no code consumer outside this module"
    )
)]
pub(crate) use actor::StakeEngine;
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "rustdoc intra-doc link target; no code consumer outside this module"
    )
)]
pub(crate) use helpers::derive_p_source_secrets_bundle;
pub(crate) use types::{
    FundedSlots, PSlot, PersonaHandle, RetireOutcome, RetirementWitness, StakeEngineError,
    ARCHIVAL_PERSONA_LOOKAHEAD,
};
