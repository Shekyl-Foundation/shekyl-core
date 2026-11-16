// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The chain forge's library (`CHAIN_FORGE.md` §11.1): the plan schema,
//! the seed derivation, a forged chain's manifest and `blocks.txt`, and the
//! diff between two forgings.
//!
//! The forge itself, the executor that turns a plan into a corpus, is not
//! here. It is a module tree outside `src/` (`executor/`), compiled only
//! into this crate's test-kind targets (the `forge` example and the
//! determinism test) against the scenario driver, the harness spender and
//! the seeded entry points, all `[dev-dependencies]`. This library has no
//! normal-edge dependency on any of them, so a crate that only reads a
//! manifest takes this library alone, and no shipped build can reach a
//! seeded prover through it (`CHAIN_FORGE.md` §5.3, §11.1).

#![deny(unsafe_code)]

pub mod ledger;
pub mod manifest;
pub mod plan;
pub mod seed;

pub use ledger::{BlocksTxt, Branch, Difference, LedgerFault, Line};
pub use manifest::{
    sha256_hex, EventRecord, Manifest, ManifestFault, PlanRef, ScheduleRecord, SwitchRecord,
    MANIFEST_FORMAT_VERSION,
};
pub use plan::{Action, EpochBlocks, Plan, PlanFault, Schedule, Step};
pub use seed::{seed_for, PlanSeed, Role, SeedFault, SEED_CUSTOMIZATION};
