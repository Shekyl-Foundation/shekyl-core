// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Terminal safety for secret display.
//!
//! Secrets (the once-only seed backup at create/restore time) must never
//! leak through pipes, log files, or terminal scrollback. This module gates
//! display behind safety checks.

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
        let _flushed = io::stderr().flush();

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
    let _flushed = io::stderr().flush();
    let mut buf = String::new();
    let _read = io::stdin().read_line(&mut buf);

    // Best-effort scrollback + screen clear.
    // \x1b[3J clears scrollback on xterm and most derivatives.
    // \x1b[2J clears the visible screen. \x1b[H moves cursor to top-left.
    print!("\x1b[3J\x1b[2J\x1b[H");
    let _flushed = io::stdout().flush();

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

/// Returns true if the given command's input line carries secret material
/// and must NOT be added to readline history. `restore`'s arguments are the
/// BIP-39 mnemonic itself. The proof-check commands carry someone's proof
/// string, a bearer artifact: an OUTBOUND tx proof embeds the raw per-tx
/// key, and a reserve proof is a permanent spend-detection beacon (contract
/// DISCLOSURE SEMANTICS) — neither belongs in a plaintext history file.
/// (The wallet2-era secret-*display* commands — seed/viewkey/spendkey —
/// were removed in WI-RPC-2b; their input lines carried no secret.)
pub fn is_secret_command(cmd: &str) -> bool {
    matches!(cmd, "restore" | "check_tx_proof" | "check_reserve_proof")
}

/// Neutralize control characters in free-form, externally-supplied text before
/// printing it to the terminal, replacing each with the Unicode replacement
/// char. A payment-request label is free-form and, when carried on a
/// counterparty's `shekyl:` URI (`parse_uri`), attacker-controlled — rendering
/// it raw would let a crafted value inject ANSI/OSC escape sequences (cursor
/// moves, screen clears, clipboard writes). Borrows unchanged when the text is
/// already clean, so the common path does not allocate.
pub fn sanitize_for_terminal(s: &str) -> std::borrow::Cow<'_, str> {
    if s.chars().any(char::is_control) {
        std::borrow::Cow::Owned(
            s.chars()
                .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
                .collect(),
        )
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_for_terminal;
    use std::borrow::Cow;

    #[test]
    fn sanitize_neutralizes_control_chars_and_borrows_clean_text() {
        // An embedded ANSI clear-screen escape and a newline are neutralized.
        let cleaned = sanitize_for_terminal("safe\u{1b}[2Jmore\ntail");
        assert!(
            !cleaned.chars().any(char::is_control),
            "no control chars survive: {cleaned:?}"
        );
        assert!(cleaned.contains('\u{FFFD}'));
        // Clean text is borrowed unchanged — no allocation on the common path.
        assert!(matches!(
            sanitize_for_terminal("plain label"),
            Cow::Borrowed("plain label")
        ));
    }
}
