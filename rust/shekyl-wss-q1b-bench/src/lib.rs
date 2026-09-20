// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `WSS-Q1(b)` grading harness — the two ruled measurements, at the ruled
//! boundary.
//!
//! `WALLET_SIDE_STORE.md` §6.3.4 adopts `WSS-Q1`(b) — *the principal's proving
//! state is not a store* — **subject to four measurements**. Two of them are
//! timings with budgets, and this crate is their instrument:
//!
//! | | Measurement | Budget |
//! | --- | --- | --- |
//! | **Spend edge** | spend-intent through constructed `Path` | `delta <= max(2 s, 15 % of proving time)` |
//! | **Open edge** | refetching the held buffer at wallet open | `<= 5 s`, local-daemon posture |
//!
//! The other two (§6.3.4 rows 1 and 4 — `rollback_to_fork`'s refusal semantics
//! and property tests against `build_layers`) are behavioural rather than
//! timed, and are **not** this crate's: they belong with the proving-state
//! increment, against code §6.3 has not built yet.
//!
//! # What this crate does not do
//!
//! **It never declares `WSS-Q1`(b) discharged.** It measures; on the pinned rig
//! it applies the ruled arithmetic; the verdict is the maintainer's. And it
//! implements no part of §6.3 — no frontier, no buffer, no membership-path
//! store. Modelling the replay is [`fixture::replay`]'s job, and that module
//! states the model's direction of error per term rather than asserting a bound.
//!
//! # Lifecycle
//!
//! This is **not** a `-spike`. The disposable measurement crates in this
//! workspace (`shekyl-sp-t3-spike`, `shekyl-tor-transit-spike`) carry a
//! deletion trigger at birth under [`15-deletion-and-debt`]; this one carries
//! the opposite obligation, because §6.3.4 requires a **re-grade on a material
//! prover-pin change**. It must outlive its first run and keep compiling.
//! `shekyl-economics-sim` is the precedent.
//!
//! Nothing in the production dependency graph may depend on this crate. That is
//! enforced by `scripts/ci/check_bench_not_a_dependency.py`, not by this
//! sentence — a crate-doc line is not a check
//! ([`47-gate-subject-assertion`]).
//!
//! [`15-deletion-and-debt`]: ../../../.cursor/rules/15-deletion-and-debt.mdc
//! [`47-gate-subject-assertion`]: ../../../.cursor/rules/47-gate-subject-assertion.mdc

pub mod corpus;
pub mod fixture;
pub mod openedge;
pub mod report;
pub mod rig;
pub mod timing;
