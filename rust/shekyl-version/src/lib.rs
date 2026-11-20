// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The build's identity, and the protocol version
//! (`DAEMON_CONFIG_CUTOVER.md` DC-Q20).
//!
//! `cmake/Version.cmake` is the one home of the build identity: the
//! version, its tag, whether the build is a release, and the release name.
//! It passes those to every cargo-built binary as three environment
//! variables, read here at compile time and nowhere else:
//!
//! | Variable | Constant |
//! | --- | --- |
//! | `SHEKYL_VERSION_FULL` | [`VERSION_FULL`] |
//! | `SHEKYL_RELEASE_NAME` | [`RELEASE_NAME`] |
//! | `SHEKYL_VERSION_IS_RELEASE` (`true` / `false`) | [`IS_RELEASE`] |
//!
//! A bare `cargo build` sets none of them. It then cannot name its release
//! and says so: the version is the crate's with `-unknown`, the release
//! name is `unknown`, and the build is **not** a release. The absent case
//! never passes itself off as a tagged build.
//!
//! [`PROTOCOL_VERSION`] is a Rust constant, not a build fact: it names the
//! protocol the binary speaks, and changes only with the protocol
//! (`docs/VERSIONING.md`). The C++ `SHEKYL_PROTOCOL_VERSION` define is
//! deleted; the one C++ reader of it was `main.cpp`, which no longer
//! exists.

#![no_std]
#![deny(unsafe_code)]

/// The release version string, hyphenated with its tag
/// (`3.1.0-alpha.11-release`); `<crate version>-unknown` when the build
/// did not pass one.
pub const VERSION_FULL: &str = match option_env!("SHEKYL_VERSION_FULL") {
    Some(version) => version,
    None => concat!(env!("CARGO_PKG_VERSION"), "-unknown"),
};

/// The release name (`Shekyl NG`); `unknown` when the build did not pass
/// one.
pub const RELEASE_NAME: &str = match option_env!("SHEKYL_RELEASE_NAME") {
    Some(name) => name,
    None => "unknown",
};

/// Whether this build is a release: a tarball or tagged build. The same
/// fact the version string's `-release` tag is built from, not
/// `debug_assertions` (FLIP-Q3). Absent means not a release.
pub const IS_RELEASE: bool = is_true(option_env!("SHEKYL_VERSION_IS_RELEASE"));

/// The Shekyl protocol version. One integer, independent of the software
/// version (`docs/VERSIONING.md`):
///
/// - 3: FCMP++ curve tree, hybrid PQC (Ed25519+ML-DSA-65, X25519+ML-KEM-768)
/// - 4: lattice-only threshold signatures (future, pending standardisation)
pub const PROTOCOL_VERSION: u32 = 3;

/// `true` for exactly the text `true`. Anything else, including absence,
/// is `false`: a misspelt or mis-set flag does not make a release.
const fn is_true(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() == 4 && bytes[0] == b't' && bytes[1] == b'r' && bytes[2] == b'u' && bytes[3] == b'e'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_word_true_is_a_release() {
        assert!(is_true(Some("true")));
        assert!(!is_true(Some("false")));
        assert!(!is_true(Some("TRUE")));
        assert!(!is_true(Some("")));
        assert!(!is_true(None));
    }

    /// The constants are never empty: an absent build fact has a spelled
    /// fallback, so a `--version` line always carries a value.
    #[test]
    fn the_facts_are_never_empty() {
        assert!(!VERSION_FULL.is_empty());
        assert!(!RELEASE_NAME.is_empty());
        assert_eq!(PROTOCOL_VERSION, 3);
    }
}
