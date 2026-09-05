// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The rules and network axes of the connect-time identity tuple
//! (`docs/design/CLIENT_VERSION_CONSTANTS_VALIDATION.md` §2; slice `VC-1`).
//!
//! A client establishes, once per connection, that the daemon it dialed is
//! the daemon it was built for, on three axes: **wire** ([`CORE_RPC_VERSION`]),
//! **rules** ([`CONSENSUS_CONSTANTS_DIGEST`]) and **network**
//! ([`DaemonNetwork`]). This module carries the second and third. Neither is
//! on the wire yet: `VC-2` adds both to `get_version` and bumps the version;
//! `VC-3` (console) and `VC-4` (wallet engine) are the consumers. Until then
//! this is the constant, its pins and its type — nothing reads it, and that
//! is stated here rather than left for the next census to rediscover.
//!
//! [`CORE_RPC_VERSION`]: crate::CORE_RPC_VERSION

use std::fmt;

use serde::{Deserialize, Serialize};

include!(concat!(env!("OUT_DIR"), "/consensus_constants_digest.rs"));

/// `const`-evaluable `&str` equality, for the sentinel below (`str`'s
/// `PartialEq` is not `const`).
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

// The live-file sentinel (VC-D3): a change to `config/consensus_constants.json`
// is a reviewed change to this line, in the convention of the Decision-14
// `const _: () = assert!(...)` pins in `shekyl-daemon-rpc/src/lib.rs` — except
// that this one covers every constant in the file rather than the ones someone
// thought to pin. Re-pinning is the review: does a different value of what
// moved make a different chain? If yes, then once VC-2…VC-4 land, every client
// built before this change will refuse every daemon built after it (VC-D7) —
// the mechanism working. If no, the constant does not belong in that file
// (§3.7's membership rule). Nothing compares the digest yet (module doc).
const _: () = assert!(
    str_eq(
        CONSENSUS_CONSTANTS_DIGEST,
        "5a5cc72b8b9c473e8ee8802edddcf0e95cccc111b3de567f461812e011f35cce"
    ),
    "config/consensus_constants.json changed: its canonical-form digest no longer matches \
     the pinned value. Review the consensus implications (CLIENT_VERSION_CONSTANTS_VALIDATION.md \
     §3.7), then re-pin here. Once VC-2…VC-4 land, every client built before this change will \
     refuse every daemon built after it."
);

/// The network a daemon reports it runs, as `get_version.nettype` will carry
/// it (`VC-2`) and as `/get_info.nettype` carries it today.
///
/// A **wire-side** type: it has the fourth variant the daemon can report
/// (`cryptonote::FAKECHAIN`, `shekyld --regtest`), which
/// `shekyl_address::Network` deliberately does not — adding it there is the
/// workspace-wide change `V3_WALLET_DECISION_LOG.md` :1397 deferred, and this
/// type exists so the handshake does not need it. The mapping between the two
/// is the network-axis comparison in `VC-4` (design §3.6.4): equal networks
/// pass; `Fakechain` passes only under a typed `FakechainPolicy::Accept`.
///
/// Serialises as the daemon's lowercase strings. An unknown string is a
/// deserialisation error, never a default — a daemon reporting a network this
/// build does not know is a daemon this build cannot vouch for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DaemonNetwork {
    /// `cryptonote::MAINNET`.
    Mainnet,
    /// `cryptonote::TESTNET`.
    Testnet,
    /// `cryptonote::STAGENET`.
    Stagenet,
    /// `cryptonote::FAKECHAIN` — `shekyld --regtest`.
    Fakechain,
}

impl DaemonNetwork {
    /// The daemon's spelling (`core_rpc_server.cpp`'s `on_get_info`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Stagenet => "stagenet",
            Self::Fakechain => "fakechain",
        }
    }
}

impl fmt::Display for DaemonNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
#[path = "../build_support/consensus_canonical.rs"]
mod canonical;

#[cfg(test)]
mod tests {
    use super::canonical::{canonical_form, digest_hex, CanonicalError, CANONICAL_HEADER};
    use super::*;

    /// A document exercising every rule: prose keys (one holding an object),
    /// unsorted keys, `0`, `u8::MAX` and `u64::MAX`.
    const KAT_JSON: &str = r#"{"_comment": "prose", "zeta": 7, "alpha": 0, "_x": {"nested": 1}, "mid_key": 18446744073709551615, "beta": 255}"#;
    const KAT_CANONICAL: &str =
        "shekyl-consensus-constants-canonical-v1\nalpha 0\nbeta 255\nmid_key 18446744073709551615\nzeta 7\n";
    /// Computed by an independent implementation of §3.3 (Python's `json` +
    /// `hashlib.sha256` over the same rules), so agreement here pins the
    /// rules as language-neutral rather than as whatever this file does.
    const KAT_DIGEST: &str = "ed8e9a5139f9a601f2e6c3a749951dc3d99c3f5c07d4b8a47d8bab2d2828892e";

    #[test]
    fn kat_pins_the_canonical_form_and_its_digest() {
        let canonical = canonical_form(KAT_JSON).expect("the KAT document canonicalises");
        assert_eq!(canonical, KAT_CANONICAL);
        assert_eq!(digest_hex(&canonical), KAT_DIGEST);
    }

    #[test]
    fn the_build_used_these_rules_on_the_live_file() {
        // The generator and this test include the same source file; this
        // checks the build actually ran it over the file it names (a stale
        // OUT_DIR or a wrong path would disagree here).
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/consensus_constants.json"
        );
        let live = std::fs::read_to_string(path).expect("the JSON authority is readable");
        let canonical = canonical_form(&live).expect("the live file canonicalises");
        assert_eq!(canonical, CONSENSUS_CONSTANTS_CANONICAL);
        assert_eq!(digest_hex(&canonical), CONSENSUS_CONSTANTS_DIGEST);
        assert_eq!(CONSENSUS_CONSTANTS_DIGEST.len(), 64);
        assert!(CONSENSUS_CONSTANTS_DIGEST
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn the_live_canonical_form_has_the_shape_the_design_pins() {
        let mut lines = CONSENSUS_CONSTANTS_CANONICAL.lines();
        assert_eq!(lines.next(), Some(CANONICAL_HEADER));
        let body: Vec<&str> = lines.collect();
        // Rule 47: the subject exists. The DAA target is genesis-frozen and
        // named by the design; its absence would mean the form is of some
        // other file.
        assert!(
            body.contains(&"daa_target_seconds 120"),
            "the canonical form does not carry the DAA target"
        );
        assert!(
            body.len() >= 22,
            "fewer constants than the file had at VC-1"
        );
        for line in &body {
            assert!(
                !line.starts_with('_'),
                "prose key leaked into the form: {line}"
            );
            let (key, value) = line.split_once(' ').expect("key SP value");
            assert!(!key.is_empty() && !key.contains(' '));
            assert!(
                value.bytes().all(|b| b.is_ascii_digit())
                    && (value == "0" || !value.starts_with('0')),
                "not a plain decimal: {value}"
            );
        }
        let mut sorted = body.clone();
        sorted.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(body, sorted, "keys are not in bytewise order");
        assert!(CONSENSUS_CONSTANTS_CANONICAL.ends_with('\n'));
    }

    #[test]
    fn prose_whitespace_and_key_order_do_not_move_the_digest() {
        let reordered = r#"  {
            "beta"  : 255 ,
            "_comment": "entirely different prose",
            "mid_key": 18446744073709551615,
            "alpha": 0, "zeta": 7
        }"#;
        assert_eq!(
            canonical_form(reordered).expect("canonicalises"),
            KAT_CANONICAL
        );
    }

    #[test]
    fn every_non_integer_value_under_a_constant_key_is_refused_by_name() {
        let cases: [(&str, CanonicalError); 6] = [
            (
                r#"{"k": "120"}"#,
                CanonicalError::NotAnInteger {
                    key: "k".into(),
                    found: "a string",
                },
            ),
            (
                r#"{"k": true}"#,
                CanonicalError::NotAnInteger {
                    key: "k".into(),
                    found: "a boolean",
                },
            ),
            (
                r#"{"k": 1.5}"#,
                CanonicalError::NotAnInteger {
                    key: "k".into(),
                    found: "a non-integer number",
                },
            ),
            (
                r#"{"k": [1]}"#,
                CanonicalError::NotAnInteger {
                    key: "k".into(),
                    found: "an array",
                },
            ),
            (
                r#"{"k": null}"#,
                CanonicalError::NotAnInteger {
                    key: "k".into(),
                    found: "null",
                },
            ),
            (r#"{"k": -1}"#, CanonicalError::Negative { key: "k".into() }),
        ];
        for (json, expected) in cases {
            assert_eq!(canonical_form(json), Err(expected), "for {json}");
        }
        // The same values under a prose key are fine: prose is not digested.
        assert_eq!(
            canonical_form(r#"{"_k": "120", "_j": [1.5, null], "a": 1}"#).unwrap(),
            format!("{CANONICAL_HEADER}\na 1\n")
        );
        assert_eq!(canonical_form("[1]"), Err(CanonicalError::NotAnObject));
        assert!(matches!(canonical_form("{"), Err(CanonicalError::Json(_))));
    }

    #[test]
    fn an_edit_to_a_constant_moves_the_digest() {
        // The property the whole mechanism rests on, observed rather than
        // assumed: one unit of one constant is a different digest.
        let bumped = KAT_JSON.replace(r#""zeta": 7"#, r#""zeta": 8"#);
        assert_ne!(bumped, KAT_JSON, "the replacement found its target");
        let d = digest_hex(&canonical_form(&bumped).unwrap());
        assert_ne!(d, KAT_DIGEST);
        assert_eq!(d.len(), 64);
    }

    #[test]
    fn daemon_network_round_trips_the_daemons_spellings() {
        for (variant, text) in [
            (DaemonNetwork::Mainnet, "\"mainnet\""),
            (DaemonNetwork::Testnet, "\"testnet\""),
            (DaemonNetwork::Stagenet, "\"stagenet\""),
            (DaemonNetwork::Fakechain, "\"fakechain\""),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), text);
            let back: DaemonNetwork = serde_json::from_str(text).unwrap();
            assert_eq!(back, variant);
            assert_eq!(format!("\"{variant}\""), text);
            assert_eq!(variant.as_str(), text.trim_matches('"'));
        }
    }

    #[test]
    fn daemon_network_refuses_a_spelling_this_build_does_not_know() {
        for text in ["\"regtest\"", "\"Mainnet\"", "\"\"", "0", "null"] {
            assert!(
                serde_json::from_str::<DaemonNetwork>(text).is_err(),
                "{text} must not parse as a network"
            );
        }
    }
}
