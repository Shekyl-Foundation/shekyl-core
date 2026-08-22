// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

/// Decode budgets. Encode does not consult these.
///
/// Matching C++ `portable_storage::limits_t`:
/// - **objects** — nested sections (the root is not counted)
/// - **fields** — sum of per-section field counts
/// - **strings** — scalar strings plus reserved string-array slots
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Nested-object budget.
    pub objects: usize,
    /// Field-count budget.
    pub fields: usize,
    /// String-count budget.
    pub strings: usize,
}

impl Limits {
    /// `default_levin_limits` in `levin_abstract_invoke2.h`.
    pub const LEVIN: Self = Self {
        objects: 8192,
        fields: 16384,
        strings: 16384,
    };

    /// `default_http_bin_limits` (65536 × 3), formerly in the C++
    /// `http_abstract_invoke.h`. That header left with the epee HTTP client
    /// (2026-08-21); this constant is now the only holder of the bound.
    pub const HTTP_BIN: Self = Self {
        objects: 196_608,
        fields: 196_608,
        strings: 196_608,
    };

    /// C++ `load_from_binary` with a null limits pointer (`size_t` max).
    pub const UNLIMITED: Self = Self {
        objects: usize::MAX,
        fields: usize::MAX,
        strings: usize::MAX,
    };
}
