// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! JSON-RPC error sanitization.
//!
//! Wallet2 error messages can contain filesystem paths, internal hex strings,
//! and output indices. This module strips sensitive data from error messages
//! shown to users, while routing raw details to a safe location when --debug
//! is active.

use shekyl_wallet_rpc::WalletError;
use std::io::{IsTerminal, Write};

/// Known-safe error codes whose full message can be shown to the user.
const SAFE_ERROR_CODES: &[i32] = &[
    -1,  // unknown method
    -2,  // wallet not open
    -3,  // wallet already open
    -4,  // invalid address
    -5,  // invalid payment id
    -6,  // transfer error (insufficient balance etc.)
    -17, // daemon busy
    -9,  // daemon not connected
];

/// Produce a user-safe error message from a WalletError.
pub fn sanitize_error(err: &WalletError) -> String {
    if SAFE_ERROR_CODES.contains(&err.code) {
        let cleaned = strip_paths(&err.message);
        return format!("Error: {cleaned}");
    }
    format!(
        "Wallet error (code {}). Run with --debug for details.",
        err.code
    )
}

/// Write raw (unsanitized) error details to a safe destination.
///
/// - If stderr is a TTY: print to stderr (user must deliberately redirect it).
/// - Otherwise: write to ~/.shekyl/debug.log with 0600 permissions.
///
/// Never writes raw errors to stdout.
pub fn emit_debug_error(err: &WalletError) {
    let detail = format!(
        "[DEBUG] Wallet error code={} message={:?}",
        err.code, err.message
    );

    if std::io::stderr().is_terminal() {
        eprintln!("{detail}");
    } else {
        match write_debug_log(&detail) {
            Ok(path) => println!("Debug details written to {path}"),
            Err(e) => {
                eprintln!("Warning: could not write debug log: {e}");
                eprintln!("{detail}");
            }
        }
    }
}

/// Handle a WalletError: always print the sanitized version to stdout,
/// and if debug mode is on, also emit the raw details.
pub fn report_wallet_error(err: &WalletError, debug: bool) {
    eprintln!("{}", sanitize_error(err));
    if debug {
        emit_debug_error(err);
    }
}

/// Strip filesystem paths from error messages.
fn strip_paths(msg: &str) -> String {
    let mut result = msg.to_string();

    // Unix paths
    let unix_re = regex_lite::Regex::new(r"(/[a-zA-Z0-9_./-]+){2,}").unwrap();
    result = unix_re.replace_all(&result, "<path>").to_string();

    // Windows paths
    let win_re = regex_lite::Regex::new(r"[A-Z]:\\[a-zA-Z0-9_.\\-]+").unwrap();
    result = win_re.replace_all(&result, "<path>").to_string();

    // Long hex strings (>64 chars) that are likely internal data
    let hex_re = regex_lite::Regex::new(r"\b[0-9a-fA-F]{65,}\b").unwrap();
    result = hex_re.replace_all(&result, "<hex>").to_string();

    result
}

fn write_debug_log(detail: &str) -> Result<String, Box<dyn std::error::Error>> {
    let dir = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .ok_or("Cannot determine home directory")?
        .join(".shekyl");
    std::fs::create_dir_all(&dir)?;

    let path = dir.join("debug.log");

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        writeln!(file, "{detail}")?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        writeln!(file, "{detail}")?;
    }

    Ok(path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_unix_paths() {
        let msg = "Failed to open /home/user/.shekyl/wallet.keys";
        let cleaned = strip_paths(msg);
        assert!(!cleaned.contains("/home/user"), "path not stripped: {cleaned}");
        assert!(cleaned.contains("<path>"), "missing <path>: {cleaned}");
    }

    #[test]
    fn test_strip_windows_paths() {
        let msg = r"Cannot read C:\Users\foo\wallet.keys";
        let cleaned = strip_paths(msg);
        assert!(!cleaned.contains(r"C:\Users"), "path not stripped: {cleaned}");
        assert!(cleaned.contains("<path>"), "missing <path>: {cleaned}");
    }

    #[test]
    fn test_strip_long_hex() {
        let hex = "a".repeat(128);
        let msg = format!("Key image {hex} not found");
        let cleaned = strip_paths(&msg);
        assert!(!cleaned.contains(&hex), "hex not stripped: {cleaned}");
        assert!(cleaned.contains("<hex>"), "missing <hex>: {cleaned}");
    }

    #[test]
    fn test_safe_code_shows_message() {
        let err = WalletError {
            code: -4,
            message: "Invalid destination address".to_string(),
        };
        let output = sanitize_error(&err);
        assert!(
            output.contains("Invalid destination address"),
            "safe code message hidden: {output}"
        );
    }

    #[test]
    fn test_unknown_code_hides_message() {
        let err = WalletError {
            code: -999,
            message: "internal panic at /home/user/src/wallet.rs:42".to_string(),
        };
        let output = sanitize_error(&err);
        assert!(
            !output.contains("/home/user"),
            "path leaked for unknown code: {output}"
        );
        assert!(
            output.contains("code -999"),
            "code not shown: {output}"
        );
    }
}
