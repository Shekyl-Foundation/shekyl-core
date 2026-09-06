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

// The live-file sentinel (VC-D3, VC-D12): a change to `config/consensus_constants.json`
// or `config/economics_params.json` is a reviewed change to this line, in the convention of the Decision-14
// `const _: () = assert!(...)` pins in `shekyl-daemon-rpc/src/lib.rs` — except
// that this one covers every constant in the file rather than the ones someone
// thought to pin. Re-pinning is the review: does a different value of what
// moved make a different chain? If yes, then once VC-2…VC-4 land, every client
// built before this change will refuse every daemon built after it (VC-D7) —
// the mechanism working. If no, the constant does not belong in that file
// (§3.7's membership rule). A change detector, not a freeze: values a file
// marks provisional (the D2 escalation numbers, under a GF-7 freeze ceremony)
// move it too, and the re-pin is how the ceremony shows, not a gate against
// it. Nothing compares the digest yet (module doc).
const _: () = assert!(
    str_eq(
        CONSENSUS_CONSTANTS_DIGEST,
        "6e1f9125232c522c475ef83b77799e11de6e7fc6e1867c261c83be4268026ab8"
    ),
    "config/consensus_constants.json or config/economics_params.json changed: the canonical-form digest no longer matches \
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
    use super::canonical::{
        canonical_form, digest_hex, CanonicalError, CANONICAL_FILES, CANONICAL_HEADER,
    };
    use super::*;

    /// Two documents exercising every rule: prose keys (one holding an
    /// object), unsorted keys, `0`, `u8::MAX` and `u64::MAX`, and a second
    /// file whose keys sort differently from the first's.
    const KAT_A: &str = r#"{"_comment": "prose", "zeta": 7, "alpha": 0, "_x": {"nested": 1}, "mid_key": 18446744073709551615, "beta": 255}"#;
    const KAT_B: &str = r#"{"coin": 1000000000, "_c": "p", "a": 1}"#;
    const KAT_CANONICAL: &str = "shekyl-consensus-constants-canonical-v2\n\
        = config/consensus_constants.json\nalpha 0\nbeta 255\nmid_key 18446744073709551615\nzeta 7\n\
        = config/economics_params.json\na 1\ncoin 1000000000\n";
    /// Computed by an independent implementation of §3.3/§3.12 (Python's
    /// `json` + `hashlib.sha256` over the same rules), so agreement here pins
    /// the rules as language-neutral rather than as whatever this file does.
    const KAT_DIGEST: &str = "5e19c87dad7c59a9d5692bb69c6b4fa1f5ea4ad02feca440a9af19cc02c8aa8e";

    fn kat() -> Vec<(&'static str, &'static str)> {
        vec![(CANONICAL_FILES[0], KAT_A), (CANONICAL_FILES[1], KAT_B)]
    }

    fn live_files() -> Vec<(&'static str, String)> {
        CANONICAL_FILES
            .iter()
            .map(|file| {
                let path = format!("{}/../../{file}", env!("CARGO_MANIFEST_DIR"));
                (
                    *file,
                    std::fs::read_to_string(path).expect("the JSON authority is readable"),
                )
            })
            .collect()
    }

    #[test]
    fn kat_pins_the_canonical_form_and_its_digest() {
        let canonical = canonical_form(&kat()).expect("the KAT documents canonicalise");
        assert_eq!(canonical, KAT_CANONICAL);
        assert_eq!(digest_hex(&canonical), KAT_DIGEST);
    }

    #[test]
    fn the_build_used_these_rules_on_the_live_files() {
        // The generator and this test include the same source file; this
        // checks the build actually ran it over the files it names (a stale
        // OUT_DIR or a wrong path would disagree here).
        let owned = live_files();
        let pairs: Vec<(&str, &str)> = owned.iter().map(|(f, s)| (*f, s.as_str())).collect();
        let canonical = canonical_form(&pairs).expect("the live files canonicalise");
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
        // Rule 47: the subject exists, in both files. The DAA target and the
        // atomic-unit denominator are genesis-frozen and named by the design;
        // either's absence would mean the form is of some other file.
        assert!(
            body.contains(&"daa_target_seconds 120"),
            "the canonical form does not carry the DAA target"
        );
        assert!(
            body.contains(&"coin 1000000000"),
            "the canonical form does not carry the atomic-unit denominator"
        );
        let sections: Vec<&str> = body
            .iter()
            .copied()
            .filter(|l| l.starts_with("= "))
            .collect();
        let expected: Vec<String> = CANONICAL_FILES.iter().map(|f| format!("= {f}")).collect();
        assert_eq!(
            sections, expected,
            "section lines are not the file set in order"
        );
        assert_eq!(
            body[0], expected[0],
            "the first file's section line follows the header"
        );

        let mut keys_in_section: Vec<&str> = Vec::new();
        let mut constants = 0usize;
        for line in body.iter().chain(std::iter::once(&"= end")) {
            if line.starts_with("= ") {
                let mut sorted = keys_in_section.clone();
                sorted.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                assert_eq!(keys_in_section, sorted, "keys are not in bytewise order");
                keys_in_section.clear();
                continue;
            }
            constants += 1;
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
            keys_in_section.push(key);
        }
        assert!(
            constants >= 22 + 18,
            "fewer constants than the two files had at VC-1 ({constants})"
        );
        assert!(CONSENSUS_CONSTANTS_CANONICAL.ends_with('\n'));
    }

    #[test]
    fn prose_whitespace_and_key_order_do_not_move_the_digest() {
        let reordered_a = r#"  {
            "beta"  : 255 ,
            "_comment": "entirely different prose",
            "mid_key": 18446744073709551615,
            "alpha": 0, "zeta": 7
        }"#;
        let reordered_b = r#"{"a":1,"coin":1000000000,"_c":"other"}"#;
        let files = [
            (CANONICAL_FILES[0], reordered_a),
            (CANONICAL_FILES[1], reordered_b),
        ];
        assert_eq!(
            canonical_form(&files).expect("canonicalises"),
            KAT_CANONICAL
        );
    }

    #[test]
    fn file_order_and_file_identity_are_part_of_the_form() {
        // Swapping the two documents between their section names yields a
        // different digest: which file a constant lives in is part of the
        // binding, exactly as its key is.
        let swapped = [(CANONICAL_FILES[0], KAT_B), (CANONICAL_FILES[1], KAT_A)];
        let d = digest_hex(&canonical_form(&swapped).unwrap());
        assert_ne!(d, KAT_DIGEST);
        // And an unknown section name is simply a different form, not an
        // error — the file set is the caller's (`CANONICAL_FILES`), so the
        // canonicaliser does not second-guess it.
        let other = [("config/other.json", KAT_A)];
        assert!(canonical_form(&other)
            .unwrap()
            .contains("= config/other.json\n"));
    }

    #[test]
    fn every_non_integer_value_under_a_constant_key_is_refused_by_name() {
        let f = CANONICAL_FILES[1].to_owned();
        let cases: [(&str, CanonicalError); 6] = [
            (
                r#"{"k": "120"}"#,
                CanonicalError::NotAnInteger {
                    file: f.clone(),
                    key: "k".into(),
                    found: "a string",
                },
            ),
            (
                r#"{"k": true}"#,
                CanonicalError::NotAnInteger {
                    file: f.clone(),
                    key: "k".into(),
                    found: "a boolean",
                },
            ),
            (
                r#"{"k": 1.5}"#,
                CanonicalError::NotAnInteger {
                    file: f.clone(),
                    key: "k".into(),
                    found: "a non-integer number",
                },
            ),
            (
                r#"{"k": [1]}"#,
                CanonicalError::NotAnInteger {
                    file: f.clone(),
                    key: "k".into(),
                    found: "an array",
                },
            ),
            (
                r#"{"k": null}"#,
                CanonicalError::NotAnInteger {
                    file: f.clone(),
                    key: "k".into(),
                    found: "null",
                },
            ),
            (
                r#"{"k": -1}"#,
                CanonicalError::Negative {
                    file: f.clone(),
                    key: "k".into(),
                },
            ),
        ];
        for (json, expected) in cases {
            // The bad document sits in the SECOND file, so the error must
            // name that file rather than the first.
            let files = [(CANONICAL_FILES[0], KAT_A), (CANONICAL_FILES[1], json)];
            assert_eq!(canonical_form(&files), Err(expected), "for {json}");
        }
        // The same values under a prose key are fine: prose is not digested.
        let files = [(
            CANONICAL_FILES[0],
            r#"{"_k": "120", "_j": [1.5, null], "a": 1}"#,
        )];
        assert_eq!(
            canonical_form(&files).unwrap(),
            format!("{CANONICAL_HEADER}\n= {}\na 1\n", CANONICAL_FILES[0])
        );
        assert_eq!(
            canonical_form(&[(CANONICAL_FILES[0], "[1]")]),
            Err(CanonicalError::NotAnObject {
                file: CANONICAL_FILES[0].to_owned()
            })
        );
        assert!(matches!(
            canonical_form(&[(CANONICAL_FILES[0], "{")]),
            Err(CanonicalError::Json { .. })
        ));
    }

    #[test]
    fn an_edit_to_a_constant_moves_the_digest_in_either_file() {
        // The property the whole mechanism rests on, observed rather than
        // assumed: one unit of one constant is a different digest, whichever
        // file it lives in.
        let bumped_a = KAT_A.replace(r#""zeta": 7"#, r#""zeta": 8"#);
        assert_ne!(bumped_a, KAT_A, "the replacement found its target");
        let d = digest_hex(
            &canonical_form(&[(CANONICAL_FILES[0], &bumped_a), (CANONICAL_FILES[1], KAT_B)])
                .unwrap(),
        );
        assert_ne!(d, KAT_DIGEST);
        assert_eq!(d.len(), 64);

        let bumped_b = KAT_B.replace(r#""a": 1"#, r#""a": 2"#);
        assert_ne!(bumped_b, KAT_B, "the replacement found its target");
        let d = digest_hex(
            &canonical_form(&[(CANONICAL_FILES[0], KAT_A), (CANONICAL_FILES[1], &bumped_b)])
                .unwrap(),
        );
        assert_ne!(d, KAT_DIGEST);

        // A key rename with the value unchanged moves it too: a constant is a
        // name bound to a value, and the name is part of the binding (VC-D12).
        let renamed = KAT_A.replace(r#""zeta": 7"#, r#""zeta_renamed": 7"#);
        let d = digest_hex(
            &canonical_form(&[(CANONICAL_FILES[0], &renamed), (CANONICAL_FILES[1], KAT_B)])
                .unwrap(),
        );
        assert_ne!(d, KAT_DIGEST);
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
