// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Stake workflow — archival persona secrets and bond/claim/drain assembly.
//!
//! # Layout (StakeWorkflow ownership)
//!
//! This directory *is* the stake workflow. Carved from the monofile
//! `engine/stake_engine.rs` so types, shared spend helpers, and the actor
//! stay separate review units while secrets remain actor-local (rule 36).
//!
//! | Module | Role |
//! |--------|------|
//! | [`types`] | Domain values, errors, spawn args |
//! | [`helpers`] | Shared funding-input / vout construction |
//! | [`engine`] | `StakeEngine` actor, messages, handle |
//! | [`test_fixtures`] | C-4 fixtures (actor + claim_orchestrator KATs) |
//!
//! Call sites keep `crate::engine::stake_engine::{…}`.

mod engine;
mod helpers;
mod types;

#[cfg(test)]
pub(crate) mod test_fixtures;

#[cfg(test)]
#[path = "stake_engine_tests.rs"]
mod tests;

#[allow(unused_imports)] // crate surface re-exports for historical stake_engine:: paths
pub(crate) use engine::*;
#[allow(unused_imports)]
pub(crate) use helpers::{
    derive_funding_key_image, derive_p_source_secrets_bundle, key_image_from_spend_key_x,
    prepare_funding_inputs,
};
#[cfg(all(test, feature = "conformance"))]
pub(crate) use types::TestSelfCert;
#[allow(unused_imports)]
pub(crate) use types::{
    FundedSlots, PSlot, PersonaHandle, PersonaIdentity, RetireOutcome, RetirementWitness,
    ScanSetupError, StakeEngineArgs, StakeEngineError, ARCHIVAL_PERSONA_LOOKAHEAD,
};
