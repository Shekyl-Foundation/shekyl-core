// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `SETCONF HSLayer2Nodes/HSLayer3Nodes` wire path — the typed,
//! injection-safe way to pin a serving persona's vanguard layer-2/layer-3
//! guard sets.
//!
//! # Why this is here, and what it is *not* (PR-C ruling, 2026-08-11)
//!
//! `ARCHIVAL_CHALLENGE_MECHANISM.md` §7.4 rules that the vanguards
//! **path-selection** half is built natively in Rust rather than by
//! adopting the upstream `vanguards` Python addon (a distro-dropped
//! dependency that would run as a second process holding full control-port
//! authority — a worse breach of the no-passthrough control-plane invariant
//! than the torrc escape hatch that policy forbids). This module is **only
//! the wire path**: fingerprints and the pin line. Selection, rotation, and
//! persistence live in [`crate::vanguard_rotation`].
//!
//! # Why typed, not a validated string (`SETCONF` is the dangerous verb)
//!
//! `SETCONF` takes `key=value` pairs; a free-form value is precisely the
//! control-line-injection surface the crate refuses elsewhere (the onion
//! args are types "because no invalid value exists to reject — the
//! rule-preferred shape, unrepresentable over validated"). A relay
//! fingerprint is 20 bytes rendered as `$` + 40 hex, an alphabet with no
//! space, no comma, and no control byte, so [`RelayFingerprint`] **cannot**
//! render a token that splits the line or smuggles a second command. The
//! set-config line is therefore infallible to build, exactly like
//! `ADD_ONION`.

use std::fmt;

/// Vanguard set sizes — **spec-pinned, not provisional** (mechanism ruling
/// §7.4, corrected). These come from the full-vanguards Sybil rotation table:
/// with `NUM_LAYER3_GUARDS = 6`, 50 % Sybil success takes ~15.75 days for a
/// 1 % adversary, ~4 days at 5 %, ~2.62 days at 10 % — a property of the Tor
/// network's adversary model, not of our traffic. What the W₂ rig derives is
/// **capacity** (whether a 4-node L2 set comfortably carries a serving
/// persona's concurrent rendezvous load), a different question with different
/// parameters. Named here so the wire path and the rotation manager share one
/// source of truth.
pub const NUM_LAYER2_GUARDS: usize = 4;
/// See [`NUM_LAYER2_GUARDS`].
pub const NUM_LAYER3_GUARDS: usize = 6;

/// A Tor relay identity fingerprint (the 20-byte SHA-1 of the relay's
/// identity key), the unit `HSLayer2Nodes`/`HSLayer3Nodes` name a guard by.
///
/// Rendered as `$` followed by 40 **uppercase** hex digits — Tor's canonical
/// by-identity relay specifier. The fixed hex alphabet is what makes the
/// `SETCONF` line injection-free by construction.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayFingerprint([u8; 20]);

impl RelayFingerprint {
    /// Wrap the raw 20-byte identity digest.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Parse a fingerprint from Tor's textual forms: exactly 40 hex digits,
    /// with or without the leading `$`, any case. Anything else — wrong
    /// length, a non-hex byte, embedded whitespace — is `None`, so a
    /// fingerprint that reached this type is always renderable safely.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let hex = raw.strip_prefix('$').unwrap_or(raw);
        if hex.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = hex.as_bytes()[2 * i];
            let lo = hex.as_bytes()[2 * i + 1];
            *byte = (hex_val(hi)? << 4) | hex_val(lo)?;
        }
        Some(Self(out))
    }

    /// The canonical `$<40 UPPER hex>` specifier.
    #[must_use]
    pub fn to_specifier(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut s = String::with_capacity(41);
        s.push('$');
        for byte in self.0 {
            s.push(HEX[(byte >> 4) as usize] as char);
            s.push(HEX[(byte & 0x0f) as usize] as char);
        }
        s
    }
}

/// A fingerprint is public consensus data, so `Debug` renders it — the
/// persona-linking secret is the *assembled set* ([`HsLayerPins`]), which
/// redacts.
impl fmt::Debug for RelayFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelayFingerprint({})", self.to_specifier())
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// A serving persona's layer-2 and layer-3 vanguard pin set, ready to apply
/// with one `SETCONF`.
///
/// Holds **non-empty** L2 and L3 sets by construction ([`Self::new`]) — an
/// empty set would render `HSLayer2Nodes=` (a *clear*, handing selection
/// back to tor's built-in vanguards-lite), which is a different operation
/// this type deliberately cannot express. Spec set sizes
/// ([`NUM_LAYER2_GUARDS`] / [`NUM_LAYER3_GUARDS`]) are enforced by the
/// rotation manager that produces the sets; the wire type only needs the
/// injection-safety invariant.
pub struct HsLayerPins {
    layer2: Vec<RelayFingerprint>,
    layer3: Vec<RelayFingerprint>,
}

impl HsLayerPins {
    /// A pin set for non-empty `layer2` and `layer3`. `None` if either is
    /// empty — clearing a layer is not this type's job.
    #[must_use]
    pub fn new(layer2: Vec<RelayFingerprint>, layer3: Vec<RelayFingerprint>) -> Option<Self> {
        if layer2.is_empty() || layer3.is_empty() {
            return None;
        }
        Some(Self { layer2, layer3 })
    }

    /// The `SETCONF HSLayer2Nodes=… HSLayer3Nodes=…` line (no trailing
    /// CRLF). Every token is a `$hex` specifier, so no value can carry a
    /// space or control byte — the line is injection-free by construction,
    /// which is why [`crate::control::Command::to_wire`] treats this arm as
    /// infallible.
    pub(super) fn to_wire_line(&self) -> String {
        format!(
            "SETCONF HSLayer2Nodes={} HSLayer3Nodes={}",
            specifier_list(&self.layer2),
            specifier_list(&self.layer3),
        )
    }
}

/// A persona's vanguard topology is exactly what an adversary wants to
/// learn, so the assembled set redacts to counts — never the fingerprints.
impl fmt::Debug for HsLayerPins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HsLayerPins")
            .field("layer2_count", &self.layer2.len())
            .field("layer3_count", &self.layer3.len())
            .finish()
    }
}

/// Comma-joined `$hex` specifiers — the value form `HSLayerNNodes` takes.
fn specifier_list(fps: &[RelayFingerprint]) -> String {
    fps.iter()
        .map(RelayFingerprint::to_specifier)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_both_textual_forms_and_round_trips_uppercase() {
        let lower = "aabbccddeeff00112233445566778899aabbccdd";
        let with_dollar = format!("${lower}");
        let a = RelayFingerprint::parse(lower).expect("bare 40-hex");
        let b = RelayFingerprint::parse(&with_dollar).expect("$-prefixed");
        assert_eq!(a, b);
        // Canonical render is $ + uppercase, whatever the input case.
        assert_eq!(a.to_specifier(), format!("${}", lower.to_ascii_uppercase()));
    }

    #[test]
    fn parse_rejects_everything_that_could_break_the_wire_line() {
        // Wrong length, non-hex, and — critically — the injection bytes a
        // string-validated path would have to catch: space, comma, CR/LF.
        for bad in [
            "",
            "abc",
            "aabbccddeeff00112233445566778899aabbccd", // 39
            "aabbccddeeff00112233445566778899aabbccddee", // 42
            "aabbccddeeff00112233445566778899aabbccdg", // non-hex 'g'
            "aabb ccddeeff00112233445566778899aabbccd", // space
            "aabbccddeeff0011,2233445566778899aabbccd", // comma
            "aabbccddeeff00112233445566778899aabbcc\r\n", // CRLF
        ] {
            assert!(
                RelayFingerprint::parse(bad).is_none(),
                "{bad:?} must not parse"
            );
        }
    }

    #[test]
    fn pins_require_non_empty_layers() {
        let fp = RelayFingerprint::from_bytes([0x11; 20]);
        assert!(HsLayerPins::new(vec![], vec![fp]).is_none());
        assert!(HsLayerPins::new(vec![fp], vec![]).is_none());
        assert!(HsLayerPins::new(vec![fp], vec![fp]).is_some());
    }

    #[test]
    fn wire_line_is_the_exact_setconf_and_carries_no_injection_bytes() {
        let l2 = vec![
            RelayFingerprint::from_bytes([0xaa; 20]),
            RelayFingerprint::from_bytes([0xbb; 20]),
        ];
        let l3 = vec![RelayFingerprint::from_bytes([0xcc; 20])];
        let line = HsLayerPins::new(l2, l3).expect("non-empty").to_wire_line();
        assert_eq!(
            line,
            "SETCONF HSLayer2Nodes=$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,\
             $BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB \
             HSLayer3Nodes=$CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
        );
        // The FIFO correlation depends on one command per line: no bare CR/LF
        // anywhere in the rendered line.
        assert!(!line.contains('\r') && !line.contains('\n'));
    }

    #[test]
    fn assembled_set_debug_redacts_to_counts() {
        let fp = RelayFingerprint::from_bytes([0x42; 20]);
        let pins = HsLayerPins::new(vec![fp, fp], vec![fp]).expect("non-empty");
        let rendered = format!("{pins:?}");
        assert!(rendered.contains("layer2_count: 2"));
        assert!(rendered.contains("layer3_count: 1"));
        // The persona-linking fingerprints must not leak through Debug.
        assert!(!rendered.contains("4242"));
    }
}
