// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-output logical label encryption (5-T substrate, §5.7.11).
//!
//! Every output carries a fixed 8-byte **plaintext** XOR-encrypted under
//! per-output `k_label`, with a 1-byte `label_tag` integrity check — same
//! discipline as amounts.
//!
//! **Normative:** `SENTINEL_PLAINTEXT` (`0xFF…`) is the plaintext when no
//! cooperative tag is sent. On-wire `enc_label` bytes are `plaintext XOR
//! k_label[..8]` and **differ per output** even for sentinel sends. There is
//! **no** cleartext-constant wire path (writing `0xFF` directly into `enc_label`
//! is forbidden). `label_tag` is HKDF-derived like `amount_tag`; it is **not**
//! a sentinel-vs-tag category flag — classification happens only after decrypt.

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};
use zeroize::Zeroizing;

/// SP 800-185 customization for wallet-side display fingerprints of decrypted
/// label plaintext (`ReceiveAttribution::LabelUnknown::echoed_label_hash`).
/// Non-consensus; spec leaves the algorithm open (`SUBADDRESS_UNDER_PQC.md`
/// §5.7.9). Matches the cSHAKE256 discipline used for [`crate::handle`].
pub const RECEIVE_LABEL_DISPLAY_HASH_CUSTOMIZATION: &[u8] = b"shekyl/receive-label-hash-v1";

/// Normative sentinel plaintext: no cooperative label (launch default).
pub const SENTINEL_PLAINTEXT: [u8; 8] = [0xFF; 8];

/// Wire version for meaningful (non-sentinel) tags.
pub const LABEL_WIRE_VERSION: u8 = 0x01;

/// `label_kind` for payment-request echo (`rid` in bytes [2..7]).
pub const LABEL_KIND_REQUEST: u8 = 0x01;

/// Return the 8-byte sentinel plaintext block (always encrypted on wire).
#[must_use]
pub fn sentinel_plaintext() -> [u8; 8] {
    SENTINEL_PLAINTEXT
}

/// XOR-encrypt an 8-byte label plaintext with `k_label[..8]`.
#[must_use]
pub fn encrypt_label_plaintext(plaintext: &[u8; 8], k_label: &[u8; 32]) -> [u8; 8] {
    let pt = Zeroizing::new(*plaintext);
    let mut enc = [0u8; 8];
    for i in 0..8 {
        enc[i] = pt[i] ^ k_label[i];
    }
    enc
}

/// XOR-decrypt an on-chain `enc_label` with `k_label[..8]`.
#[must_use]
pub fn decrypt_label_plaintext(enc_label: &[u8; 8], k_label: &[u8; 32]) -> [u8; 8] {
    let mut pt = [0u8; 8];
    for i in 0..8 {
        pt[i] = enc_label[i] ^ k_label[i];
    }
    pt
}

/// True if decrypted plaintext is the sentinel (no cooperative label).
#[must_use]
pub fn is_sentinel_plaintext(plaintext: &[u8; 8]) -> bool {
    *plaintext == SENTINEL_PLAINTEXT
}

/// Classification of a decrypted 8-byte label plaintext block (§5.7.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelPlaintextKind {
    Sentinel,
    Request(u64),
    Unknown([u8; 8]),
}

/// Classify decrypted label plaintext per §5.7.11.
#[must_use]
pub fn classify_label_plaintext(plaintext: &[u8; 8]) -> LabelPlaintextKind {
    if is_sentinel_plaintext(plaintext) {
        return LabelPlaintextKind::Sentinel;
    }
    if plaintext[0] == LABEL_WIRE_VERSION && plaintext[1] == LABEL_KIND_REQUEST {
        let mut rid_le = [0u8; 8];
        rid_le[..6].copy_from_slice(&plaintext[2..8]);
        let rid = u64::from_le_bytes(rid_le);
        if rid == 0 {
            return LabelPlaintextKind::Unknown(*plaintext);
        }
        return LabelPlaintextKind::Request(rid);
    }
    LabelPlaintextKind::Unknown(*plaintext)
}

/// Maximum `rid` encodable in bytes `[2..7]` (u48 LE). Keep in sync with
/// `shekyl_engine_state::PAYMENT_REQUEST_RID_U48_MAX`.
pub const REQUEST_RID_U48_MAX: u64 = (1u64 << 48) - 1;

/// Hash decrypted label plaintext for ledger display/logging (§5.7.9).
///
/// Cleartext labels must not appear in logs; this 32-byte fingerprint lets the
/// UI correlate `LabelUnknown` rows without persisting the plaintext.
#[must_use]
pub fn hash_label_plaintext_for_display(plaintext: &[u8; 8]) -> [u8; 32] {
    let core = CShake256Core::new(RECEIVE_LABEL_DISPLAY_HASH_CUSTOMIZATION);
    let mut hasher: CShake256 = CoreWrapper::from_core(core);
    hasher.update(plaintext);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

/// Build the 8-byte REQUEST plaintext for cooperative send (§5.7.11).
///
/// Returns `None` if `rid` is `0`, exceeds u48, or the encoding would collide
/// with sentinel.
pub fn encode_request_plaintext(rid: u64) -> Option<[u8; 8]> {
    if rid == 0 || rid > REQUEST_RID_U48_MAX {
        return None;
    }
    let mut pt = [0u8; 8];
    pt[0] = LABEL_WIRE_VERSION;
    pt[1] = LABEL_KIND_REQUEST;
    let le = rid.to_le_bytes();
    pt[2..8].copy_from_slice(&le[..6]);
    if pt == SENTINEL_PLAINTEXT {
        return None;
    }
    Some(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_round_trip() {
        let k = [0x42u8; 32];
        let enc = encrypt_label_plaintext(&SENTINEL_PLAINTEXT, &k);
        let pt = decrypt_label_plaintext(&enc, &k);
        assert!(is_sentinel_plaintext(&pt));
    }

    #[test]
    fn request_plaintext_roundtrip() {
        let rid = 0x0000_1234_5678_9ABC_u64;
        let pt = encode_request_plaintext(rid).unwrap();
        assert_eq!(
            classify_label_plaintext(&pt),
            LabelPlaintextKind::Request(rid)
        );
        assert!(!is_sentinel_plaintext(&pt));
    }

    #[test]
    fn request_plaintext_rejects_rid_above_u48() {
        assert!(encode_request_plaintext(REQUEST_RID_U48_MAX).is_some());
        assert!(encode_request_plaintext(REQUEST_RID_U48_MAX + 1).is_none());
    }

    #[test]
    fn display_hash_is_deterministic() {
        let pt = encode_request_plaintext(0x1234).unwrap();
        let a = hash_label_plaintext_for_display(&pt);
        let b = hash_label_plaintext_for_display(&pt);
        assert_eq!(a, b);
        assert_ne!(a, hash_label_plaintext_for_display(&SENTINEL_PLAINTEXT));
    }

    /// Normative `enc_label` indistinguishability invariant
    /// (`SUBADDRESS_UNDER_PQC.md` §5.7.10): the on-wire octets are
    /// indistinguishable from uniform to a non-recipient **independent of
    /// plaintext**, and the real-label / sentinel wire distributions are
    /// identical. This is the test that retires the R2-F8 wallet gate — it
    /// proves the real-label path is exactly as safe to an observer as the
    /// sentinel path it already runs, so gating real-label population delivers
    /// no privacy benefit.
    ///
    /// Both arms are drawn through the **real** `derive_output_secrets` path
    /// (not a synthetic uniform key) so a plumbing regression — a low-entropy
    /// `k_label`, a content-dependent encoding — fails CI. A zero-key negative
    /// control (plaintext straight onto the wire) proves the grading instrument
    /// actually bites.
    #[test]
    fn real_label_indistinguishable_from_sentinel() {
        use crate::derivation::derive_output_secrets;
        use sha2::{Digest, Sha512};

        // 4096 outputs × 8 octets = 32_768 samples/arm ⇒ ~128 expected per
        // bucket.
        const N: u32 = 4096;
        // enc_label octets are bytes ⇒ BUCKETS possible values per position.
        // The chi-square degrees of freedom (uniformity *and* the 2×BUCKETS
        // homogeneity contingency alike) are BUCKETS − 1; deriving df and the
        // per-bucket expectation from BUCKETS keeps them in lockstep if the
        // width ever changes, rather than repeating 255/256 as literals.
        const BUCKETS: usize = 256;
        let buckets_f64 = f64::from(u32::try_from(BUCKETS).expect("BUCKETS fits u32"));
        let df = buckets_f64 - 1.0;
        // Strict rejection threshold, *derived* (not hand-picked) from the
        // Wilson–Hilferty chi-square upper quantile at α = 1e-6 (≈ 377.3 for
        // df = 255). A correct PRF (chi2 ≈ df ± sqrt(2·df)) sits ~5.4σ below it,
        // so false-fails occur at ~α by construction, while a degenerate key
        // lands in the tens of thousands. The seed is fixed (reference-
        // determinism, not a PRNG mandate); the chi-square is the grading
        // instrument.
        let reject = chi_square_upper_crit(df, Z_ALPHA_1E6);

        let real = encode_request_plaintext(0x0000_1234_5678_9ABC).expect("valid rid");
        assert!(!is_sentinel_plaintext(&real));

        // u32 counts: max per arm is N*8 = 32_768, exactly representable in
        // both u32 and f64, so `f64::from` is lossless (the workspace denies
        // `cast_precision_loss` for crypto crates — see rust/Cargo.toml).
        let mut sentinel_hist = [0u32; BUCKETS];
        let mut real_hist = [0u32; BUCKETS];
        let mut broken_hist = [0u32; BUCKETS];

        for i in 0..N {
            // Deterministic per-output combined_ss; models an independent
            // hybrid shared secret per output, as seen by a non-recipient.
            let mut h = Sha512::new();
            Digest::update(&mut h, b"shekyl/label-indist-test-v1");
            Digest::update(&mut h, i.to_le_bytes());
            let combined_ss = h.finalize();
            let secrets = derive_output_secrets(combined_ss.as_ref(), u64::from(i));

            let enc_sentinel = encrypt_label_plaintext(&SENTINEL_PLAINTEXT, &secrets.k_label);
            let enc_real = encrypt_label_plaintext(&real, &secrets.k_label);
            // Negative control: a zero key leaks the plaintext onto the wire
            // (enc == plaintext, constant across outputs).
            let enc_broken = encrypt_label_plaintext(&real, &[0u8; 32]);

            for b in 0..8 {
                sentinel_hist[enc_sentinel[b] as usize] += 1;
                real_hist[enc_real[b] as usize] += 1;
                broken_hist[enc_broken[b] as usize] += 1;
            }
        }

        let expected = f64::from(N * 8) / buckets_f64;
        let uniformity_chi2 = |hist: &[u32; BUCKETS]| -> f64 {
            hist.iter()
                .map(|&o| {
                    let d = f64::from(o) - expected;
                    d * d / expected
                })
                .sum()
        };

        let chi2_sentinel = uniformity_chi2(&sentinel_hist);
        let chi2_real = uniformity_chi2(&real_hist);
        let chi2_broken = uniformity_chi2(&broken_hist);

        // (1) Per-plaintext uniformity: real-label and sentinel enc_label are
        //     both uniform under the real derivation path.
        assert!(
            chi2_sentinel < reject,
            "sentinel enc_label not uniform: chi2={chi2_sentinel:.1} (reject>={reject:.1})"
        );
        assert!(
            chi2_real < reject,
            "real-label enc_label not uniform: chi2={chi2_real:.1} (reject>={reject:.1})"
        );

        // (2) Homogeneity: the real-label and sentinel wire distributions are
        //     statistically identical (2×BUCKETS contingency, df = BUCKETS − 1).
        let homogeneity_chi2: f64 = (0..BUCKETS)
            .map(|b| {
                let s = f64::from(sentinel_hist[b]);
                let r = f64::from(real_hist[b]);
                if s + r == 0.0 {
                    0.0
                } else {
                    (s - r) * (s - r) / (s + r)
                }
            })
            .sum();
        assert!(
            homogeneity_chi2 < reject,
            "real-label distinguishable from sentinel: chi2={homogeneity_chi2:.1} (reject>={reject:.1})"
        );

        // Negative control: the same uniformity instrument that the real path
        // passes must reject plaintext-on-the-wire, or the test is vacuous.
        assert!(
            chi2_broken > reject,
            "uniformity instrument failed to reject plaintext-on-wire: chi2={chi2_broken:.1} (reject>={reject:.1})"
        );
    }

    /// Upper-tail standard-normal quantile for α = 1e-6 (z ≈ 4.7534). Same
    /// constant the staking-sim conformance suite uses
    /// (`shekyl-staking-sim::standoff`); duplicated here as a literal rather
    /// than taking a dev-dependency on a sim crate that opts out of the
    /// workspace cast lints.
    const Z_ALPHA_1E6: f64 = 4.753_424;

    /// Wilson–Hilferty chi-square upper-tail critical value for `df` degrees of
    /// freedom at normal upper quantile `z`. Dependency-free; mirrors
    /// `standoff::chi_square_upper_crit`.
    fn chi_square_upper_crit(df: f64, z: f64) -> f64 {
        let a = 2.0 / (9.0 * df);
        let t = 1.0 - a + z * a.sqrt();
        df * t * t * t
    }
}
