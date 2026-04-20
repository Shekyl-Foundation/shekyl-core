// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Regression guard: the `#[must_use]` attribute on `LoggerGuard` must
//! fire when `init(...)` is called and the returned guard is dropped at
//! the statement's `;` without any binding. If a future refactor removes
//! the attribute, this test fails (its reference output shows the
//! must-use warning).

#[test]
fn must_use_warnings_fire_when_logger_guard_is_unbound() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/trybuild/must_use_unbound.rs");
}
