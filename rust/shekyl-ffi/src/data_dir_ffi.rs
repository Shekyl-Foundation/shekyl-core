// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's default data directory, for the C++ blockchain utilities
//! (`DAEMON_CONFIG_CUTOVER.md` §2.6, DC-Q5).
//!
//! A utility opens the store the daemon writes, so its default directory is
//! the daemon's: [`shekyl_daemon_config::paths`], the account's root as the
//! operating system reports it (the passwd entry on Unix,
//! `FOLDERID_LocalAppData` on Windows) and the network's subdirectory. There
//! is no second layout in C++ to drift from this one, and nothing is read
//! from the environment (IG-13). The utilities run as a user, never under the
//! service manager, so the run mode is `User`.

use std::ffi::{c_char, CStr};

use shekyl_daemon_config::{paths, Network, RunMode};

/// The default data directory, as UTF-8, of the network `network` names.
fn default_for(word: &str) -> Option<String> {
    let network = Network::from_word(word)?;
    let root = paths::root(&crate::platform::current(), RunMode::User, "data-dir").ok()?;
    paths::data_dir_default(&root, network)
        .into_os_string()
        .into_string()
        .ok()
}

/// Write the daemon's default data directory for `network` into `out`.
///
/// `network` is a NUL-terminated network word (`mainnet`, `testnet`,
/// `stagenet`, `regtest`). Returns the path's length in bytes, without a
/// terminator; the path is written only when `capacity` holds it, so a
/// caller asks with a capacity of 0 and then with that length. Returns 0
/// when the word is not a network, the account has no home, or the path is
/// not UTF-8: a default path is never empty.
///
/// # Safety
///
/// `network` is null or a valid NUL-terminated string; `out` is null or
/// points at `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_data_dir_default(
    network: *const c_char,
    out: *mut u8,
    capacity: usize,
) -> usize {
    if network.is_null() {
        return 0;
    }
    // SAFETY: the caller's contract above.
    let Ok(word) = unsafe { CStr::from_ptr(network) }.to_str() else {
        return 0;
    };
    let Some(path) = default_for(word) else {
        return 0;
    };
    if !out.is_null() && capacity >= path.len() {
        // SAFETY: `out` holds `capacity` bytes, at least `path.len()`.
        unsafe { std::ptr::copy_nonoverlapping(path.as_ptr(), out, path.len()) };
    }
    path.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_daemon_config::Platform;

    fn ask(word: &str) -> Option<String> {
        let c = std::ffi::CString::new(word).unwrap();
        // SAFETY: a valid C string and a null buffer of capacity 0.
        let len = unsafe { shekyl_daemon_data_dir_default(c.as_ptr(), std::ptr::null_mut(), 0) };
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len];
        // SAFETY: `buf` holds `len` bytes.
        let again = unsafe { shekyl_daemon_data_dir_default(c.as_ptr(), buf.as_mut_ptr(), len) };
        assert_eq!(again, len, "the length is stable across the two calls");
        Some(String::from_utf8(buf).unwrap())
    }

    /// The export is the daemon's own default: the same root and the same
    /// subdirectory, mainnet's being none.
    #[test]
    fn the_utilities_default_is_the_daemons() {
        let platform = Platform {
            home: crate::platform::account_home(),
            program_data: crate::platform::program_data(),
        };
        let Ok(root) = paths::root(&platform, RunMode::User, "data-dir") else {
            assert_eq!(ask("mainnet"), None, "no home: the export refuses");
            return;
        };
        for network in Network::ALL {
            assert_eq!(
                ask(network.name()).as_deref().map(std::path::PathBuf::from),
                Some(paths::data_dir_default(&root, network)),
                "{}",
                network.name()
            );
        }
        assert!(ask("regtest").unwrap().ends_with("regtest"));
        assert_eq!(ask("mainnet").unwrap(), root.display().to_string());
    }

    #[test]
    fn a_word_that_is_not_a_network_and_a_short_buffer_write_nothing() {
        assert_eq!(ask("fakechain"), None, "the table's words only");
        let c = std::ffi::CString::new("testnet").unwrap();
        let mut one = [0xAAu8; 1];
        // SAFETY: `one` holds 1 byte; a longer path is not written.
        let len = unsafe { shekyl_daemon_data_dir_default(c.as_ptr(), one.as_mut_ptr(), 1) };
        if len > 1 {
            assert_eq!(one, [0xAA], "a buffer too short is left untouched");
        }
        // SAFETY: a null word is refused.
        assert_eq!(
            unsafe { shekyl_daemon_data_dir_default(std::ptr::null(), std::ptr::null_mut(), 0) },
            0
        );
    }
}
