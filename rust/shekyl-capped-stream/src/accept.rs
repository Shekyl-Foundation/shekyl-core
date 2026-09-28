// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which `accept` errors are a flood, and which end the listener.
//!
//! `EMFILE`, `ENFILE`, and `ECONNABORTED` are what a flood produces.
//! They are not the listener closing. A connector records those and
//! keeps accepting. Any other error is the listener stopping.

use std::io::Error;

/// Process file-descriptor ceiling. Linux and the BSDs use this number.
const EMFILE: i32 = 24;
/// System-wide file-descriptor ceiling. Linux and the BSDs use this number.
const ENFILE: i32 = 23;
/// Windows `ERROR_TOO_MANY_OPEN_FILES`.
#[cfg(windows)]
const ERROR_TOO_MANY_OPEN_FILES: i32 = 4;

/// A transient `accept` failure. The listener keeps the socket and retries.
#[must_use]
pub fn accept_error_is_transient(err: &Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
    ) || too_many_open_files(err.raw_os_error())
}

fn too_many_open_files(code: Option<i32>) -> bool {
    let Some(code) = code else {
        return false;
    };
    #[cfg(unix)]
    {
        code == EMFILE || code == ENFILE
    }
    #[cfg(windows)]
    {
        code == ERROR_TOO_MANY_OPEN_FILES
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = code;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::accept_error_is_transient;

    #[test]
    fn a_flood_of_accept_errors_is_transient_and_a_dead_listener_is_not() {
        #[cfg(unix)]
        let code = super::EMFILE;
        #[cfg(windows)]
        let code = super::ERROR_TOO_MANY_OPEN_FILES;
        #[cfg(any(unix, windows))]
        {
            let refused = std::io::Error::from_raw_os_error(code);
            assert!(accept_error_is_transient(&refused));
        }
        let aborted = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "aborted");
        assert!(accept_error_is_transient(&aborted));
        let closed = std::io::Error::new(std::io::ErrorKind::NotConnected, "closed");
        assert!(!accept_error_is_transient(&closed));
    }
}
