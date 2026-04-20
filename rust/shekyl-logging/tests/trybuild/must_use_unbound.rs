// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unused_must_use)]

use shekyl_logging::{init, Config};

fn main() {
    // `init(...)?;` with no binding drops `LoggerGuard` at the `;`,
    // silently losing any buffered events. `#[must_use]` is the primary
    // defense against this; see `src/lib.rs`.
    //
    // We use `.unwrap()` rather than `?` so this test is a self-contained
    // `fn main()` without a result type. Both shapes drop the guard at
    // the statement's `;`.
    init(Config::stderr_only(tracing::Level::WARN)).unwrap();
}
