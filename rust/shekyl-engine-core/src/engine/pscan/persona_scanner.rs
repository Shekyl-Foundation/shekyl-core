// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-1 — the `ArchivalPKeys` → `GuaranteedViewPair` adapter.
//!
//! Builds the **burning-bug-immune** scanner variant (`GuaranteedViewPair` /
//! `GuaranteedScanner`, DQ7) for an archival persona `P` from its
//! [`ArchivalPKeys`]. It is a thin lift that **mirrors the principal wallet's
//! `ViewMaterial` construction** (`engine::view_material`) — the archival keys
//! were designed to mirror it (`archival_p.rs:339` derives `x25519_pk =
//! montgomery(view_pk)`, "same birational map as principal").
//!
//! ## Why `x25519_sk` is the view secret, not a separate key
//!
//! The persona's X25519 scan secret **is** its `view_sk`: the Ed25519 view
//! scalar double-duties as the Curve25519 (Montgomery) secret. This is *forced*,
//! not chosen — `x25519_pk` is stored as `montgomery(view_pk)`, so the only
//! secret whose public key equals it is `montgomery(view_sk)` (the view scalar
//! wearing its Montgomery hat). Any other source (e.g. a fresh seed derivation)
//! would yield an **inconsistent keypair** and a *silently-failing* ECDH half of
//! the scan. The parameter-free Edwards→Montgomery map is also the one derivation
//! safe to recompute on demand — there are no HKDF labels to drift between
//! scan-time and sign-time (a labeled derivation would have to be stored).
//!
//! The Montgomery *interpretation* of those bytes (unclamped scalar) and the
//! low-order peer-point rejection both happen downstream at the scanner's ECDH
//! site (the canonical `crate::montgomery` path); this adapter only supplies the
//! canonical bytes and fails closed on non-canonical encodings — the same
//! discipline `view_material.rs` applies for the principal.
//!
//! No new resident secret: the derived `x25519_sk` lives only inside the
//! transient per-persona `GuaranteedViewPair`, wiped on drop after that persona's
//! scan-step (DQ5). It is a representation of a secret Model-D already holds.

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_scanner::{GuaranteedScanner, GuaranteedViewPair, ViewPairError};
use zeroize::Zeroizing;

/// Why building a persona's scanner from its [`ArchivalPKeys`] failed.
///
/// All arms are *fail-closed* rejections of malformed key material — never a
/// silent weakening (a weak `x25519_sk` from a malformed view key is exactly the
/// failure mode to guard, per `30-cryptography.mdc`).
//
// `allow(dead_code)`: transient — the non-test consumer is the SP-5 scan loop
// (module "Staging note" in `block_source`); removed when SP-5 lands.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum PersonaScanError {
    /// `spend_pk` is not a valid 32-byte compressed Edwards encoding.
    SpendKeyEncoding,
    /// `spend_pk` decodes but is not a curve point.
    SpendKeyOffCurve,
    /// `view_sk` is not a canonical scalar (high bit set or value ≥ ℓ) — the
    /// in-memory key state may be corrupted.
    NonCanonicalViewSecret,
    /// The scanner rejected the assembled view pair.
    ViewPair(ViewPairError),
}

impl std::fmt::Display for PersonaScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpendKeyEncoding => {
                write!(
                    f,
                    "persona spend_pk is not a valid compressed Edwards point"
                )
            }
            Self::SpendKeyOffCurve => {
                write!(f, "persona spend_pk does not decompress to a curve point")
            }
            Self::NonCanonicalViewSecret => {
                write!(
                    f,
                    "persona view_sk is not a canonical scalar (corrupted key state)"
                )
            }
            Self::ViewPair(e) => write!(f, "persona view pair rejected: {e}"),
        }
    }
}

impl std::error::Error for PersonaScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ViewPair(e) => Some(e),
            Self::SpendKeyEncoding | Self::SpendKeyOffCurve | Self::NonCanonicalViewSecret => None,
        }
    }
}

/// Build persona `P`'s burning-bug-immune [`GuaranteedViewPair`] from its
/// [`ArchivalPKeys`] (SP-1).
///
/// Fail-closed: rejects a non-canonical `view_sk`, a malformed/off-curve
/// `spend_pk`, or a view pair the scanner refuses — it never produces a
/// silently-weakened scanner.
#[allow(dead_code)] // transient — SP-5 scan loop is the non-test consumer.
pub(crate) fn archival_guaranteed_view_pair(
    p_keys: &ArchivalPKeys,
) -> Result<GuaranteedViewPair, PersonaScanError> {
    let spend = CompressedEdwardsY::from_slice(p_keys.spend_pk.as_canonical_bytes())
        .map_err(|_| PersonaScanError::SpendKeyEncoding)?
        .decompress()
        .ok_or(PersonaScanError::SpendKeyOffCurve)?;

    let view = Zeroizing::new(
        Option::<Scalar>::from(Scalar::from_canonical_bytes(
            *p_keys.view_sk.as_canonical_bytes(),
        ))
        .ok_or(PersonaScanError::NonCanonicalViewSecret)?,
    );

    // The view secret double-duties as the X25519 (Montgomery) secret — the SAME
    // canonical bytes (`montgomery(view_sk)`), consistent by construction with the
    // stored `x25519_pk = montgomery(view_pk)`. Mirrors `view_material.rs:262`.
    let x25519_sk: Zeroizing<[u8; 32]> = Zeroizing::new(*p_keys.view_sk.as_canonical_bytes());
    let ml_kem_dk: Zeroizing<Vec<u8>> =
        Zeroizing::new(p_keys.ml_kem_dk.as_canonical_bytes().to_vec());

    GuaranteedViewPair::new(spend, view, x25519_sk, ml_kem_dk).map_err(PersonaScanError::ViewPair)
}

/// Build a ready-to-scan [`GuaranteedScanner`] for persona `P` — the
/// [`archival_guaranteed_view_pair`] plus `P`'s spend secret (which the scanner
/// uses for the ownership compare and key-image derivation).
///
/// Transient by design: drop it after the persona's scan-step to wipe the secrets
/// (DQ5); it adds no resident secret surface beyond the `view_sk` Model-D holds.
#[allow(dead_code)] // transient — SP-5 scan loop is the non-test consumer.
pub(crate) fn guaranteed_scanner_for_persona(
    p_keys: &ArchivalPKeys,
) -> Result<GuaranteedScanner, PersonaScanError> {
    let view_pair = archival_guaranteed_view_pair(p_keys)?;
    let spend_secret = Zeroizing::new(*p_keys.spend_sk.as_canonical_bytes());
    Ok(GuaranteedScanner::new(view_pair, spend_secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
    use shekyl_crypto_pq::archival_p::derive_archival_p_keys;
    use shekyl_crypto_pq::kem::HybridKemPublicKey;
    use shekyl_scanner::bench_fixtures::scannable_block_for_recipient;

    /// The adapter-built scanner recovers a persona's *own* output.
    ///
    /// This is the keypair-consistency proof: the output is encapsulated to the
    /// persona's stored `x25519_pk` (= `montgomery(view_pk)`), and the adapter
    /// decaps with `x25519_sk = view_sk`. Recovery only succeeds if those
    /// correspond — a wrong secret (e.g. a seed derivation) would silently fail
    /// the ECDH half and recover nothing. So `len() == 1` is exactly the check
    /// that `montgomery(view_sk)` is the right secret.
    #[test]
    fn adapter_scanner_recovers_a_persona_owned_output() {
        let seed = [0x07u8; MASTER_SEED_BYTES];
        let persona =
            derive_archival_p_keys(&seed, DerivationNetwork::Fakechain, SeedFormat::Raw32, 0)
                .expect("derive a test persona");

        // One output addressed to the persona — KEM to its (x25519_pk, ml_kem_ek),
        // one-time key to its spend_pk.
        let kem_pk = HybridKemPublicKey {
            x25519: persona.x25519_pk,
            ml_kem: persona.ml_kem_ek.to_vec(),
        };
        let block =
            scannable_block_for_recipient(1, &kem_pk, persona.spend_pk.as_canonical_bytes());

        let mut scanner = guaranteed_scanner_for_persona(&persona).expect("build persona scanner");
        let recovered = scanner.scan(block).expect("scan must not error");
        assert_eq!(
            recovered.len(),
            1,
            "persona must recover its own output via the adapter (keypair consistency)"
        );
    }

    /// A *different* persona must NOT recover the first persona's output — the
    /// negative control that the recovery above is genuine ownership, not a
    /// fixture that matches anything.
    #[test]
    fn adapter_scanner_rejects_a_foreign_output() {
        let seed = [0x07u8; MASTER_SEED_BYTES];
        let mine =
            derive_archival_p_keys(&seed, DerivationNetwork::Fakechain, SeedFormat::Raw32, 0)
                .expect("derive persona 0");
        let other =
            derive_archival_p_keys(&seed, DerivationNetwork::Fakechain, SeedFormat::Raw32, 1)
                .expect("derive persona 1");

        // Output addressed to `other`.
        let other_kem = HybridKemPublicKey {
            x25519: other.x25519_pk,
            ml_kem: other.ml_kem_ek.to_vec(),
        };
        let block =
            scannable_block_for_recipient(1, &other_kem, other.spend_pk.as_canonical_bytes());

        // Scanned with `mine` — recovers nothing.
        let mut scanner = guaranteed_scanner_for_persona(&mine).expect("build persona scanner");
        let recovered = scanner.scan(block).expect("scan must not error");
        assert!(
            recovered.is_empty(),
            "a persona must not recover a different persona's output"
        );
    }
}
