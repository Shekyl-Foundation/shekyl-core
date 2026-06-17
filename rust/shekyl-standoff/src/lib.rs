//! Funding-seam entry-standoff draw — single-sourced and build-float-free.
//!
//! The funding seam (`docs/design/ARCHIVAL_FIREWALL_GATE6.md` §10.12) is
//! decorrelated by a randomized **standoff window**: at a private intent the
//! actor draws a gap `s ~ U[0, window]` between its observable funding/entry
//! event and the bond-post, plus a fair **order coin** so the bond may appear
//! *before or after* the entry (the inversion that removes the adversary's
//! "bond-post follows a recent spend" ordering prior). This crate is the single
//! source for that draw: the simulator, the published conformance vector, and
//! (when the V3.0 funding flow is built) the wallet all import the **same**
//! [`draw_entry_gap`], so "what we validated is what ships" holds by
//! construction rather than by vigilance.
//!
//! # Determinism boundary (what the cross-arch guarantee covers)
//!
//! The draw is **pure integer arithmetic** (unbiased rejection sampling, no
//! float, no modulo bias). Given an RNG, the `(spread, bond_first)` sequence is
//! deterministic and **bit-identical across architectures** — the same property
//! `reward_arithmetic` gets from being pure-integer, and the reason the
//! published integer golden vector (`tests/golden_vector.rs`) runs on the
//! aarch64 CI lane. The float goodness-of-fit *grading* (the `conformance`
//! feature) is graded **by margin, not asserted bit-identical**: float is not
//! bit-identical across architectures, so the grading stays x86-only and the
//! lane's cross-arch guarantee is scoped to the integer sequence.
//!
//! # Build-enforced float-freeness
//!
//! Float-freeness of the production (wallet) path is a **build property, not a
//! module-boundary claim**. The default build is the [`draw`] module only and
//! contains **zero `#[allow(clippy::cast_*)]`** — clippy has nothing to step
//! around, so the workspace's strict float-cast denies machine-enforce that the
//! shipped path never touches a float. The grading/self-cert machinery, which
//! is inherently float-bearing, lives behind the `conformance` feature and is
//! never compiled into a default build.
//!
//! # Conformance is self-test, not enforcement
//!
//! The crate controls the *gap*. The *anchor* (when the actor acts) is entirely
//! consumer-side and **consensus-unenforceable** — funding is FCMP++-hidden, so
//! nothing on-chain can police the draw. The [`conformance`] instruments are
//! therefore a demonstration plus a wallet **self-certification** tool ("here is
//! the tool you run to prove your CSPRNG is good", paired with operator
//! education), not something the crate prevents. The grade is on the
//! **property** (uniform, fair, serially independent), not on emitting any
//! particular sequence: the fixed seed in the KAT is *reference determinism*,
//! not a PRNG mandate.

pub mod draw;

pub use draw::{draw_entry_gap, GapRng};

#[cfg(feature = "conformance")]
pub mod conformance;
