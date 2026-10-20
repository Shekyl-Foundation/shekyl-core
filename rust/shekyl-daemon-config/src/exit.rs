// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's exit statuses for a refusal and a failure (IG-11), and the
//! one way a refusal reaches the operator. The daemon's start and the
//! snapshot export (`shekyl-ffi`) both refuse through here.

use std::io::Write;

use shekyl_options::Diagnostic;

/// A configuration refusal.
pub const EXIT_REFUSED: i32 = 2;
/// A runtime failure.
pub const EXIT_FAILED: i32 = 1;

/// Each diagnostic on its own line of standard error, prefixed with the
/// daemon's name. Returns [`EXIT_REFUSED`]. A closed stream does not change
/// the status.
pub fn refuse(diagnostics: &[Diagnostic]) -> i32 {
    let mut err = std::io::stderr();
    for d in diagnostics {
        drop(writeln!(err, "shekyld: {}", d.render()));
    }
    EXIT_REFUSED
}
