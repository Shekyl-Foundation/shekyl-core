// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Terminal safety for secret display.
//!
//! Secrets (seed, viewkey, spendkey) must never leak through pipes, log files,
//! or terminal scrollback. This module gates display behind safety checks.

use std::io::{self, IsTerminal, Write};
use zeroize::Zeroize;

/// Result of a display-safety preflight check.
#[derive(Debug)]
pub enum DisplaySafetyError {
    NotATty,
    UserDeclined,
}

impl std::fmt::Display for DisplaySafetyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotATty => write!(
                f,
                "Refusing to display secret: stdout is not a terminal. Pipe/redirect detected."
            ),
            Self::UserDeclined => write!(f, "Cancelled."),
        }
    }
}

/// Preflight the terminal for a one-time secret display, WITHOUT printing
/// anything:
///
/// 1. Refuse if stdout is not a TTY (pipe / redirect / log file).
/// 2. Under a terminal multiplexer (tmux, screen) whose scrollback may retain
///    the secret, require an explicit `YES`.
///
/// This MUST be called *before* the secret exists (before the wallet is
/// created), so that a refusal creates nothing rather than orphaning a wallet
/// whose one-time backup can never be shown — the server never re-exposes it.
/// The deliberate, auditable way to capture a seed non-interactively is the
/// `create --seed-out <path>` subcommand, not a redirected terminal.
pub fn preflight_secret_display() -> Result<(), DisplaySafetyError> {
    if !io::stdout().is_terminal() {
        return Err(DisplaySafetyError::NotATty);
    }

    if let Some(warning) = multiplexer_warning() {
        eprintln!("WARNING: {warning}");
        eprintln!("Scrollback may retain this secret.");
        eprint!("Type YES to proceed: ");
        let _ = io::stderr().flush();

        let mut confirm = String::new();
        if io::stdin().read_line(&mut confirm).is_err() || confirm.trim() != "YES" {
            return Err(DisplaySafetyError::UserDeclined);
        }
    }

    Ok(())
}

/// Display a secret to the terminal and best-effort clear it afterwards, then
/// zeroize `secret`. Call ONLY after [`preflight_secret_display`] returned
/// `Ok` (stdout is a TTY and any multiplexer warning was accepted); there is
/// deliberately no non-TTY fallback here, so the secret can never reach a pipe
/// or file.
pub fn show_secret(label: &str, secret: &mut String) {
    println!("\n{label}:");
    println!("{secret}");
    println!();

    eprint!("Press Enter to clear screen...");
    let _ = io::stderr().flush();
    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf);

    // Best-effort scrollback + screen clear.
    // \x1b[3J clears scrollback on xterm and most derivatives.
    // \x1b[2J clears the visible screen. \x1b[H moves cursor to top-left.
    print!("\x1b[3J\x1b[2J\x1b[H");
    let _ = io::stdout().flush();

    eprintln!(
        "NOTE: Your terminal may still have this secret in scrollback.\n\
         Clear it manually (Cmd+K / Ctrl+Shift+K / your terminal's\n\
         clear-scrollback command) before walking away."
    );

    secret.zeroize();
}

/// Check for well-known terminal multiplexer environment variables.
fn multiplexer_warning() -> Option<&'static str> {
    if std::env::var_os("TMUX").is_some() {
        return Some("Running under tmux.");
    }
    if std::env::var_os("STY").is_some() {
        return Some("Running under GNU screen.");
    }
    if let Some(term_prog) = std::env::var_os("TERM_PROGRAM") {
        let s = term_prog.to_string_lossy();
        if s.contains("tmux") || s.contains("screen") {
            return Some("Running under a terminal multiplexer.");
        }
    }
    None
}

/// Returns true if the given command name is a secret-displaying command
/// whose input line should NOT be added to readline history.
pub fn is_secret_command(cmd: &str) -> bool {
    matches!(cmd, "seed" | "viewkey" | "spendkey")
}
