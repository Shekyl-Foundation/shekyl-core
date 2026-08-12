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
//! than the torrc escape hatch that policy forbids). This module is **C1**:
//! only the wire path. It does **not** select relays (that is C2:
//! bandwidth-weighted selection from the consensus) or rotate/persist them
//! (C3: the rotation manager the supervisor reloads on restart). And the
//! circuit-killing half — Bandguards / Rendguards — is deferred entirely:
//! their thresholds are the W₂ rig's output, and guess-tuned they would arm
//! a circuit-killer against our own bulk transfers.
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

use super::consensus::ConsensusRelay;

/// Vanguard set sizes — **spec-pinned, not provisional** (mechanism ruling
/// §7.4, corrected). These come from the full-vanguards Sybil rotation table:
/// with `NUM_LAYER3_GUARDS = 6`, 50 % Sybil success takes ~15.75 days for a
/// 1 % adversary, ~4 days at 5 %, ~2.62 days at 10 % — a property of the Tor
/// network's adversary model, not of our traffic. What the W₂ rig derives is
/// **capacity** (whether a 4-node L2 set comfortably carries a serving
/// persona's concurrent rendezvous load), a different question with different
/// parameters. Named here so C2 selection and C3 rotation share one source.
pub const NUM_LAYER2_GUARDS: usize = 4;
/// See [`NUM_LAYER2_GUARDS`].
pub const NUM_LAYER3_GUARDS: usize = 6;

/// A source of randomness for vanguard selection — a seam so the weighted
/// draw is deterministic under test yet a real CSPRNG in production.
///
/// Selection must be **unpredictable** (an adversary who could predict our
/// draw could bias toward landing in the set), so the production impl
/// ([`OsVanguardRng`]) pulls from the OS CSPRNG; tests use a seeded
/// generator. Modeled on the `challenge_coverage` sim's local-PRNG
/// precedent rather than pulling a `rand` dependency.
pub trait VanguardRng {
    /// The next 64 random bits.
    fn next_u64(&mut self) -> u64;
}

/// Production RNG: OS CSPRNG bytes via `getrandom`.
pub struct OsVanguardRng;

impl VanguardRng for OsVanguardRng {
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("OS CSPRNG");
        u64::from_le_bytes(buf)
    }
}

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
    pub fn to_specifier(self) -> String {
        let mut s = String::with_capacity(41);
        s.push('$');
        for byte in self.0 {
            s.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble"));
            s.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("nibble"));
        }
        s.to_ascii_uppercase()
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
/// this type deliberately cannot express. The set sizes are spec-pinned
/// ([`NUM_LAYER2_GUARDS`] / [`NUM_LAYER3_GUARDS`]); this type just pins
/// whatever set the selector produced.
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
        .map(|fp| fp.to_specifier())
        .collect::<Vec<_>>()
        .join(",")
}

/// Why a vanguard set could not be selected from the candidate relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionError {
    /// Fewer eligible, positive-bandwidth relays than the `l2 + l3` seats to
    /// fill — the consensus is too small (or too heavily filtered) to build
    /// a disjoint vanguard topology. A real consensus has thousands, so this
    /// is a not-yet-bootstrapped / degraded-network state, surfaced rather
    /// than silently under-filling a layer.
    TooFewEligible {
        /// Eligible, positive-bandwidth candidates.
        available: usize,
        /// Seats to fill (`l2 + l3`).
        needed: usize,
    },
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewEligible { available, needed } => write!(
                f,
                "only {available} eligible relays for {needed} vanguard seats"
            ),
        }
    }
}

impl std::error::Error for SelectionError {}

/// Select disjoint layer-2 and layer-3 vanguard sets from the consensus,
/// **weighted by consensus bandwidth** (PR-C2).
///
/// The draw is bandwidth-weighted without replacement: Tor's own path
/// selection weights middles by the consensus `w Bandwidth=`, and a
/// vanguard set drawn from a *different* distribution would both be a
/// deviation-from-Tor fingerprint and break the anonymity math full
/// vanguards assumes. Only [`ConsensusRelay::eligible`] relays with nonzero
/// bandwidth are candidates; L2 is drawn first, then L3 from the remainder,
/// so the two layers are disjoint by construction.
///
/// **Provisional weighting (rule 21 reopen criterion):** this uses the raw
/// consensus bandwidth — the dominant term. The fully faithful form scales
/// it by the middle-position weights (`Wmg`/`Wmd`) from the consensus
/// `bandwidth-weights` footer; whether that footer is reachable over the
/// control port, and whether the second-order correction changes the W₂
/// exposure, is a rig question. Reopen when the rig reports.
///
/// # Errors
///
/// [`SelectionError::TooFewEligible`] when the candidate pool cannot fill
/// `l2 + l3` disjoint seats.
pub fn select_hs_layers(
    relays: &[ConsensusRelay],
    l2: usize,
    l3: usize,
    rng: &mut impl VanguardRng,
) -> Result<HsLayerPins, SelectionError> {
    let (layer2, layer3) =
        select_disjoint(relays, l2, l3, rng).ok_or(SelectionError::TooFewEligible {
            available: eligible_pool(relays).len(),
            needed: l2 + l3,
        })?;
    // Both non-empty by construction (select_disjoint filled l2 and l3 seats).
    HsLayerPins::new(layer2, layer3).ok_or(SelectionError::TooFewEligible {
        available: relays.len(),
        needed: l2 + l3,
    })
}

/// Draw disjoint layer-2 and layer-3 fingerprint sets, bandwidth-weighted —
/// the selection primitive the rotation manager builds on (it attaches the
/// per-node timers). `None` if the eligible pool cannot fill `l2 + l3` seats.
/// L2 is drawn first, L3 from the remainder, so the sets are disjoint.
#[must_use]
pub fn select_disjoint(
    relays: &[ConsensusRelay],
    l2: usize,
    l3: usize,
    rng: &mut impl VanguardRng,
) -> Option<(Vec<RelayFingerprint>, Vec<RelayFingerprint>)> {
    let mut pool = eligible_pool(relays);
    if pool.len() < l2 + l3 {
        return None;
    }
    let layer2 = draw_weighted(&mut pool, l2, rng);
    let layer3 = draw_weighted(&mut pool, l3, rng);
    Some((layer2, layer3))
}

/// Draw **one** replacement relay, bandwidth-weighted, excluding everything
/// in `exclude` — the primitive the rotation manager uses to swap a
/// dead-relay or expired node without re-drawing the whole set. `None` if
/// nothing eligible remains.
#[must_use]
pub fn draw_replacement(
    relays: &[ConsensusRelay],
    exclude: &[RelayFingerprint],
    rng: &mut impl VanguardRng,
) -> Option<RelayFingerprint> {
    let mut pool: Vec<(RelayFingerprint, u64)> = eligible_pool(relays)
        .into_iter()
        .filter(|(fp, _)| !exclude.contains(fp))
        .collect();
    if pool.is_empty() {
        return None;
    }
    Some(draw_weighted(&mut pool, 1, rng).remove(0))
}

/// The candidate pool: eligible relays with positive bandwidth, as
/// `(fingerprint, weight)` pairs.
fn eligible_pool(relays: &[ConsensusRelay]) -> Vec<(RelayFingerprint, u64)> {
    relays
        .iter()
        .filter(|r| r.eligible && r.bandwidth > 0)
        .map(|r| (r.fingerprint, r.bandwidth))
        .collect()
}

/// Draw `count` fingerprints from `pool` weighted by their bandwidth,
/// **removing each as it is drawn** (without replacement). Assumes
/// `pool.len() >= count` (the caller checked the total).
fn draw_weighted(
    pool: &mut Vec<(RelayFingerprint, u64)>,
    count: usize,
    rng: &mut impl VanguardRng,
) -> Vec<RelayFingerprint> {
    let mut drawn = Vec::with_capacity(count);
    for _ in 0..count {
        let total: u128 = pool.iter().map(|(_, bw)| u128::from(*bw)).sum();
        // total > 0: every pool entry has bandwidth > 0 and pool is
        // non-empty (we drew fewer than len).
        let mut target = (u128::from(rng.next_u64()) % total) + 1;
        let mut idx = 0;
        for (i, (_, bw)) in pool.iter().enumerate() {
            target = target.saturating_sub(u128::from(*bw));
            if target == 0 {
                idx = i;
                break;
            }
        }
        drawn.push(pool.swap_remove(idx).0);
    }
    drawn
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seeded SplitMix64 — a deterministic test RNG (no `rand` dep), the same
    /// local-PRNG shape the `challenge_coverage` sim uses.
    struct SeededRng(u64);
    impl VanguardRng for SeededRng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    fn candidate(byte: u8, bandwidth: u64, eligible: bool) -> ConsensusRelay {
        ConsensusRelay {
            fingerprint: RelayFingerprint::from_bytes([byte; 20]),
            bandwidth,
            eligible,
        }
    }

    /// A pool of `n` eligible relays, ids `1..=n`, uniform bandwidth.
    fn uniform_pool(n: u8) -> Vec<ConsensusRelay> {
        (1..=n).map(|b| candidate(b, 1000, true)).collect()
    }

    #[test]
    fn selection_is_disjoint_and_the_right_sizes() {
        let pool = uniform_pool(20);
        let mut rng = SeededRng(1);
        let pins = select_hs_layers(&pool, NUM_LAYER2_GUARDS, NUM_LAYER3_GUARDS, &mut rng)
            .expect("pool is large enough");
        assert_eq!(pins.layer2.len(), NUM_LAYER2_GUARDS);
        assert_eq!(pins.layer3.len(), NUM_LAYER3_GUARDS);
        // Disjoint by construction (L3 drawn from the L2 remainder).
        for fp2 in &pins.layer2 {
            assert!(!pins.layer3.contains(fp2), "L2 and L3 must not overlap");
        }
        // No duplicates within a layer either.
        let mut all: Vec<_> = pins.layer2.iter().chain(&pins.layer3).collect();
        all.sort_by_key(|fp| fp.to_specifier());
        all.dedup();
        assert_eq!(all.len(), NUM_LAYER2_GUARDS + NUM_LAYER3_GUARDS);
    }

    #[test]
    fn selection_ignores_ineligible_and_zero_bandwidth_relays() {
        // Exactly enough eligible+positive relays for 1+1; everything else
        // is ineligible or zero-bandwidth and must never be drawn.
        let mut pool = vec![candidate(1, 500, true), candidate(2, 500, true)];
        pool.push(candidate(3, 999_999, false)); // huge bw but ineligible
        pool.push(candidate(4, 0, true)); // eligible but zero bw
        let mut rng = SeededRng(7);
        let pins = select_hs_layers(&pool, 1, 1, &mut rng).expect("two eligible");
        // The only selectable relays are #1 and #2 — the ineligible (#3,
        // huge bandwidth) and zero-bandwidth (#4) relays must never be drawn.
        let ok = [
            RelayFingerprint::from_bytes([1; 20]),
            RelayFingerprint::from_bytes([2; 20]),
        ];
        for fp in pins.layer2.iter().chain(&pins.layer3) {
            assert!(ok.contains(fp), "drew an ineligible/zero-bw relay");
        }
    }

    #[test]
    fn too_few_eligible_relays_is_a_typed_refusal() {
        // 9 seats needed (4+5) but only 8 eligible — refuse, never
        // under-fill a layer silently.
        let pool = uniform_pool(8);
        let mut rng = SeededRng(3);
        let err = select_hs_layers(&pool, 4, 5, &mut rng).unwrap_err();
        assert_eq!(
            err,
            SelectionError::TooFewEligible {
                available: 8,
                needed: 9
            }
        );
    }

    #[test]
    fn bandwidth_dominates_the_draw() {
        // One relay with overwhelming weight is picked into L2 essentially
        // always; a statistical check that the draw is weighted, not uniform.
        let mut pool = vec![candidate(1, 1_000_000, true)];
        for b in 2..=12u8 {
            pool.push(candidate(b, 1, true)); // negligible weight
        }
        let heavy = RelayFingerprint::from_bytes([1; 20]);
        let mut hits = 0;
        for seed in 0..200u64 {
            let mut rng = SeededRng(seed);
            let pins = select_hs_layers(&pool, 4, 6, &mut rng).expect("enough");
            if pins.layer2.contains(&heavy) || pins.layer3.contains(&heavy) {
                hits += 1;
            }
        }
        // With ~1e6 vs ~11 total light weight, the heavy relay is drawn on
        // the first pick with probability ~0.99999; across 200 runs it is
        // present essentially every time.
        assert!(hits >= 199, "bandwidth weighting not applied: {hits}/200");
    }

    #[test]
    fn selection_is_deterministic_under_a_fixed_seed() {
        let pool = uniform_pool(20);
        let a = select_hs_layers(&pool, 4, 6, &mut SeededRng(42)).unwrap();
        let b = select_hs_layers(&pool, 4, 6, &mut SeededRng(42)).unwrap();
        assert_eq!(a.to_wire_line(), b.to_wire_line());
    }

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
