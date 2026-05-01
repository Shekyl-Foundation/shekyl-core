// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! Shared helpers for the `engine_trait_bench_*` benchmark family.
//!
//! See `docs/design/STAGE_0_HARNESS.md` §4.2 "Scope guard for
//! `benches/common/`":
//!
//! > `engine_fixture.rs` has one job: construct a real
//! > `Engine<SoloSigner>` via the production `Engine::create` entry
//! > point. Anything else lives in the bench file that needs it. If two
//! > bench files end up needing the same secondary helper, it migrates
//! > to `common/` deliberately, with a comment naming both call sites.
//!
//! Adding a second helper without explicit two-caller justification
//! defeats the bound. Reviewers gate growth here on §4.2 of the design
//! doc; the rule applies to every Stage 1 per-trait PR that introduces
//! its own bench.

pub mod engine_fixture;
