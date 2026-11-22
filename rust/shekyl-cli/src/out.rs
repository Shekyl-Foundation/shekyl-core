// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CLI's one way to write to its standard output and standard error.
//!
//! `println!` and its kin panic when the stream is gone (a parent that
//! died, `| head`, a closed terminal), and every profile builds with
//! `panic = "abort"`, so a closed output aborted the session: no wallet
//! close, no save, the server's socket directory left behind (Rick,
//! 2026-11-21). These writers return the error instead. The first failed
//! write to standard output marks the output closed; later writes to it are
//! not attempted. The session checks [`output_closed`] and ends through its
//! normal shutdown. The line it then writes depends on whether that close
//! saved the wallet (`rpc_client::WalletClose`).
//!
//! Every write in the crate goes through the four macros here; a test holds
//! the sources to it (`no_write_bypasses_the_writer`).

use std::fmt;
use std::io::{self, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};

/// Set by the first write to standard output that fails.
static OUTPUT_CLOSED: AtomicBool = AtomicBool::new(false);

/// The exit status of a session ended because its output was closed.
pub const CLOSED_OUTPUT_EXIT: i32 = 1;

/// Write `args` to standard output, with a newline when `line`.
///
/// # Errors
///
/// The write's failure; after the first, every write refuses with
/// `BrokenPipe` without trying.
pub fn stdout(args: fmt::Arguments<'_>, line: bool) -> io::Result<()> {
    if OUTPUT_CLOSED.load(Ordering::Relaxed) {
        return Err(io::ErrorKind::BrokenPipe.into());
    }
    let mut out = io::stdout().lock();
    let written = if line {
        writeln!(out, "{args}")
    } else {
        write!(out, "{args}")
    };
    if written.is_err() {
        OUTPUT_CLOSED.store(true, Ordering::Relaxed);
    }
    written
}

/// Write `args` to standard error, with a newline when `line`.
///
/// # Errors
///
/// The write's failure. A closed standard error ends nothing: the session's
/// answers are on standard output.
pub fn stderr(args: fmt::Arguments<'_>, line: bool) -> io::Result<()> {
    let mut err = io::stderr().lock();
    if line {
        writeln!(err, "{args}")
    } else {
        write!(err, "{args}")
    }
}

/// Whether a write to standard output has failed.
#[must_use]
pub fn output_closed() -> bool {
    OUTPUT_CLOSED.load(Ordering::Relaxed)
}

/// A line to standard output (in place of `println!`). A failure marks the
/// output closed and is otherwise dropped here: the session reads
/// [`output_closed`].
#[macro_export]
macro_rules! out_line {
    () => {
        drop($crate::out::stdout(::core::format_args!(""), true))
    };
    ($($arg:tt)*) => {
        drop($crate::out::stdout(::core::format_args!($($arg)*), true))
    };
}

/// Text to standard output with no newline (in place of `print!`).
#[macro_export]
macro_rules! out_inline {
    ($($arg:tt)*) => {
        drop($crate::out::stdout(::core::format_args!($($arg)*), false))
    };
}

/// A line to standard error (in place of `eprintln!`).
#[macro_export]
macro_rules! err_line {
    () => {
        drop($crate::out::stderr(::core::format_args!(""), true))
    };
    ($($arg:tt)*) => {
        drop($crate::out::stderr(::core::format_args!($($arg)*), true))
    };
}

/// Text to standard error with no newline (in place of `eprint!`).
#[macro_export]
macro_rules! err_inline {
    ($($arg:tt)*) => {
        drop($crate::out::stderr(::core::format_args!($($arg)*), false))
    };
}

#[cfg(test)]
mod tests {
    /// Every write in the crate's sources goes through this module's
    /// macros: `println!`, `print!`, `eprintln!` and `eprint!` panic on a
    /// closed stream, and the panic aborts the session (the module doc).
    /// Bites on any of the four in any source file but this one.
    #[test]
    fn no_write_bypasses_the_writer() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src") {
                let path = entry.expect("an entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs")
                    || path.file_name().and_then(|n| n.to_str()) == Some("out.rs")
                {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("read a source");
                for (n, line) in text.lines().enumerate() {
                    let code = line.split("//").next().unwrap_or("");
                    for banned in ["println!", "print!(", "eprintln!", "eprint!("] {
                        if code.contains(banned) {
                            found.push(format!("{}:{}: {banned}", path.display(), n + 1));
                        }
                    }
                }
            }
        }
        assert!(
            found.is_empty(),
            "writes that bypass shekyl_cli::out: {found:#?}"
        );
    }
}
