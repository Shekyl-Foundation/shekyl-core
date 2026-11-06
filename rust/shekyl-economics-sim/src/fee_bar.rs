// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The convergence bar the two fee instruments score against, defined once.
//!
//! FL-E1 (`docs/design/FEE_LADDER_DERIVATION.md` §11.5) pre-registered it
//! for the floor-in-the-loop run, and FL-C7's oscillation reading in the
//! ladder instrument scores against the same bar: a feedback cell has
//! settled when the paid fee's tail amplitude is at or under this many
//! basis points. Neither instrument owns it, so neither restates it.

/// Tail amplitude of the paid fee, in basis points, at or under which a
/// feedback cell counts as converged.
pub const CONVERGED_AMPLITUDE_BP: u64 = 50;
