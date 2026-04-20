// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Regression guard: the `#[must_use]` attribute on `LoggerGuard` must
//! fire when `init(...)` is called and the returned guard is dropped at
//! the statement's `;` without any binding. If a future refactor removes
//! the attribute, this test fails.
//!
//! The compile-fail fixture (`tests/trybuild/must_use_unbound.rs`) sets
//! `#![deny(unused_must_use)]`, so `trybuild` asserts against the
//! resulting *error* — not a warning — in the `.stderr` snapshot. The
//! distinction matters: a passive `#[must_use]` warning alone would
//! still let a careless caller drop the guard silently, which is the
//! exact foot-gun this test exists to prevent.

#[test]
fn must_use_warnings_fire_when_logger_guard_is_unbound() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/trybuild/must_use_unbound.rs");
}
