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
