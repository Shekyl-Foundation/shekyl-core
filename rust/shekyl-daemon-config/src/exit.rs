// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's exit statuses for a refusal and a failure (IG-11). The one
//! way a start's refusal reaches the operator is `shekyl-daemon`'s
//! `run::StartEnd`: standard error, and the log file when it can be opened.

/// A configuration refusal.
pub const EXIT_REFUSED: i32 = 2;
/// A runtime failure.
pub const EXIT_FAILED: i32 = 1;
