// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared helpers for the crate's in-tree live tests (`#[cfg(test)]` only).

use std::path::PathBuf;

/// The test `tor` binary path — **any** tor works (these are lifecycle tests,
/// not the SP-T0c pin gate; the pinned-binary contract is
/// `SHEKYL_TEST_PINNED_TOR_BINARY` in `binary.rs`). **Hard-fail** (not skip) when
/// a live test runs, so a missing binary is a loud misconfiguration rather than a
/// silent no-op. `var_os`: a non-UTF-8 path is still a valid path.
pub(crate) fn tor_binary() -> PathBuf {
    std::env::var_os("SHEKYL_TEST_TOR_BINARY")
        .map(PathBuf::from)
        .expect("SHEKYL_TEST_TOR_BINARY must point at a tor binary on the integration lane")
}
