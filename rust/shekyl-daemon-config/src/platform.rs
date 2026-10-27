// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the machine and the account contribute to the defaults (IG-13).
//!
//! The composition root reads these once, from the operating system's own
//! interfaces, never from `HOME`, `XDG_*` or `%APPDATA%`, and hands them in.
//! This crate takes them as values so every path rule is testable without
//! an account to run under.

use std::path::PathBuf;

/// The daemon's run mode (DC-Q17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    /// Run as a user: the per-account root.
    User,
    /// Run by the Windows service manager: the machine-wide root.
    Service,
}

/// The account's and the machine's roots, as the operating system reports
/// them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Platform {
    /// The account's home: the passwd entry on Unix, `FOLDERID_LocalAppData`
    /// on Windows. `None` when the account has none.
    pub home: Option<PathBuf>,
    /// `%ProgramData%` on Windows; `None` elsewhere.
    pub program_data: Option<PathBuf>,
}
