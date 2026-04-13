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

/// Display a secret with full terminal-safety protocol:
///
/// 1. Refuse if stdout is not a TTY.
/// 2. Warn if running under a terminal multiplexer (tmux, screen).
/// 3. Print the secret.
/// 4. Wait for Enter, then best-effort clear screen + scrollback.
/// 5. Print honest residual-scrollback warning.
/// 6. Zeroize the secret string.
pub fn display_secret(label: &str, secret: &mut String) -> Result<(), DisplaySafetyError> {
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
            secret.zeroize();
            return Err(DisplaySafetyError::UserDeclined);
        }
    }

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
    Ok(())
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
