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
    /// The account's per-user session directory, from the platform's own
    /// interface and never the environment (IG-Q14): `/run/user/<uid>` on
    /// Linux when the session or linger keeps it, and
    /// `confstr(_CS_DARWIN_USER_TEMP_DIR)` on macOS. `None` where there is
    /// none: under `sudo -u`, cron, most containers, a service account,
    /// FreeBSD, and Windows, whose owner leg is a pipe
    /// (`RPC_CHANNEL.md` §7.1).
    pub session_dir: Option<PathBuf>,
}
