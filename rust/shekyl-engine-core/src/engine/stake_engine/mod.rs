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
//! | [`persona`] | Mint / activate / identity / SignBond |
//! | [`bond`] | AssembleBond |
//! | [`drain`] | AssembleDrain shell |
//! | [`claim`] | AssembleEmissionClaim |
//! | [`scan`] | ScanStep |
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
    "the StakeEngine session RNG self-cert grader (shekyl-standoff `conformance`)      is `x86_64`-only — its float goodness-of-fit is not bit-identical across      architectures. Build the `conformance` feature on `x86_64` (where the CI      conformance lane runs); do not enable it on other targets (including 32-bit      x86)."
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
mod types;

#[cfg(test)]
pub(crate) mod test_fixtures;

#[cfg(test)]
#[path = "stake_engine_tests.rs"]
mod tests;

#[allow(unused_imports)]
pub(crate) use actor::{persona_canonical_id, StakeEngine, StakeEngineStartError};
#[allow(unused_imports)]
pub(crate) use bond::{AssembleBond, AssembledBondPost};
#[allow(unused_imports)]
pub(crate) use claim::{AssembleEmissionClaim, AssembledEmissionClaim};
#[allow(unused_imports)]
pub(crate) use handle::StakeEngineHandle;
#[allow(unused_imports)]
pub(crate) use helpers::{
    derive_funding_key_image, derive_p_source_secrets_bundle, draw_entry_gap_guarded,
    key_image_from_spend_key_x, prepare_funding_inputs,
};
#[allow(unused_imports)]
pub(crate) use persona::{
    ActivatePersona, ActivePersona, ActivePersonaReceiveAddress, MintPersonaHandle,
    PersonaIdentityOf, SignBond, SignedBondPost,
};
#[allow(unused_imports)]
pub(crate) use retire::{ProjectPersonaCanonicalId, RetireBondedPersona};
#[cfg(all(test, feature = "conformance"))]
pub(crate) use types::TestSelfCert;
#[allow(unused_imports)]
pub(crate) use types::{
    DegenerateDraw, FundedSlots, PSlot, PersonaHandle, PersonaIdentity, RetireOutcome,
    RetirementWitness, ScanSetupError, StakeEngineArgs, StakeEngineError,
    ARCHIVAL_PERSONA_LOOKAHEAD,
};
