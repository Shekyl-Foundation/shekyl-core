// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-output PQC leaf commitment (`PL-D3`).
//!
//! The leaf's 4th scalar is the Wei25519 x-coordinate of
//! `CM = k·G_k + r·J`, `k = H_ℓ(hybrid_pk)` (cSHAKE256 under
//! [`DOMAIN_PQC_LEAF_KEY`]). The verifier recomputes `K = k·G_k` from the
//! key the spend reveals; the circuit proves `K + r·J = CM`. The published
//! `tx_extra` `0x07` entry is [`PqcLeafEntry`]: `CM ‖ record`.
//!
//! ```text
//! hybrid_pk ── cSHAKE256("shekyl/pqc-leaf-key-v1") ── k ──·G_k── K
//! combined_ss ── HKDF("shekyl-pqc-leaf-blind" ‖ idx ‖ ctr) ── r
//! CM = K + r·J     record = cSHAKE256("shekyl/pqc-leaf-record-v1", pk ‖ r_h)
//! ```

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use hkdf::Hkdf;
use sha2::Sha512;
use shekyl_crypto_hash::{cshake256_32, cshake256_64};
use shekyl_curve_generators::{PQC_LEAF_COMMITMENT_G_K_TABLE, PQC_LEAF_COMMITMENT_J_TABLE};
use zeroize::{Zeroize, Zeroizing};

use crate::derivation::{expand_32_into, expand_wide_scalar, make_info, HKDF_SALT_OUTPUT_DERIVE};
use crate::CryptoError;

/// cSHAKE256 customization for the per-output PQC **key scalar**
/// `k = H_ℓ(hybrid_pk)` (`PL-D3`, `docs/design/FCMP_SPEND_LINKABILITY.md` §6.2).
///
/// This crate is the **single source** for `k`: [`pqc_key_scalar`] is what the
/// sender, the scanner, the FCMP++ verifiers (through `shekyl_fcmp::PqcKeyScalar`)
/// and the emission backing gate all call.
pub const DOMAIN_PQC_LEAF_KEY: &[u8] = b"shekyl/pqc-leaf-key-v1";

/// cSHAKE256 customization for the per-output post-quantum **record**
/// `cSHAKE256(pk ‖ r_h)` published beside the commitment point in `tx_extra`
/// `0x07` (`PL-D3a`). Commits to the canonical key bytes, not to `k`, so it
/// survives into a lattice-only world without Ed25519 arithmetic to define it.
pub const DOMAIN_PQC_LEAF_RECORD: &[u8] = b"shekyl/pqc-leaf-record-v1";

/// HKDF info label for the PQC leaf-commitment blind `r` (`PL-D3`); the info is
/// `label ‖ idx_le64 ‖ ctr` with the one-byte guard counter appended.
const LABEL_OUTPUT_PQC_LEAF_BLIND: &[u8] = b"shekyl-pqc-leaf-blind";
/// HKDF info label for the post-quantum record blind `r_h` (`PL-D3a`).
const LABEL_OUTPUT_PQC_LEAF_RECORD_BLIND: &[u8] = b"shekyl-pqc-leaf-record-blind";

/// Width of one output's `0x07` entry: the compressed commitment point `CM`
/// followed by the 32-byte record (`PL-D3` + `PL-D3a`).
pub const PQC_LEAF_ENTRY_LEN: usize = 64;

/// Width of the compressed commitment point `CM` — the first slice of the
/// `0x07` entry. Single owner of the entry's internal split; wire and
/// curve-tree consumers pin against this rather than a local `32`.
pub const PQC_LEAF_POINT_LEN: usize = 32;

/// Width of the post-quantum record — the second slice of the `0x07` entry.
pub const PQC_LEAF_RECORD_LEN: usize = 32;

// The entry is exactly `point ‖ record`. Relates three independently-editable
// constants: moving any one of them without the others fails this assert.
const _: () = assert!(PQC_LEAF_POINT_LEN + PQC_LEAF_RECORD_LEN == PQC_LEAF_ENTRY_LEN);

/// One output's published `tx_extra` `0x07` entry: compressed `CM` then the
/// post-quantum record. The leaf's 4th scalar is `CM.x`, extracted at
/// `construct_leaf`. Consensus ignores the record (admission checks only
/// the point); the recipient's scan verifies the whole entry against its
/// own derivation, and a mismatch is received-but-unspendable
/// (`FCMP_SPEND_LINKABILITY.md` §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqcLeafEntry {
    /// Compressed Ed25519 point `CM = k·G_k + r·J`.
    pub point: [u8; PQC_LEAF_POINT_LEN],
    /// `cSHAKE256(pk ‖ r_h)` under [`DOMAIN_PQC_LEAF_RECORD`].
    pub record: [u8; PQC_LEAF_RECORD_LEN],
}

impl PqcLeafEntry {
    /// [`PQC_LEAF_ENTRY_LEN`].
    pub const LEN: usize = PQC_LEAF_ENTRY_LEN;

    /// Split a 64-byte `0x07` entry into `(CM, record)`.
    #[must_use]
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        let mut point = [0u8; PQC_LEAF_POINT_LEN];
        let mut record = [0u8; PQC_LEAF_RECORD_LEN];
        point.copy_from_slice(&bytes[..PQC_LEAF_POINT_LEN]);
        record.copy_from_slice(&bytes[PQC_LEAF_POINT_LEN..]);
        Self { point, record }
    }

    /// Concatenate `point ‖ record` as published on the wire.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut e = [0u8; Self::LEN];
        e[..PQC_LEAF_POINT_LEN].copy_from_slice(&self.point);
        e[PQC_LEAF_POINT_LEN..].copy_from_slice(&self.record);
        e
    }
}

/// The per-output PQC key scalar `k = H_ℓ(hybrid_pk)` as an Ed25519 `Scalar`.
/// Single reduction of the 64-byte cSHAKE read; [`pqc_key_scalar`] and
/// [`pqc_key_point`] both go through here so `k → K` cannot drift from `k`.
/// `k` is a pre-spend secret (it opens the commitment's key component), so it
/// travels wrapped and wipes on drop.
fn key_scalar(pqc_pk_bytes: &[u8]) -> Zeroizing<Scalar> {
    let mut wide = cshake256_64(DOMAIN_PQC_LEAF_KEY, pqc_pk_bytes);
    let scalar = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));
    wide.zeroize();
    scalar
}

/// The per-output PQC key scalar `k = H_ℓ(hybrid_pk)`: a 64-byte cSHAKE256 read
/// of the canonical hybrid public key under [`DOMAIN_PQC_LEAF_KEY`], reduced into
/// the **Ed25519 scalar field** (`PL-D3`). The leaf's 4th scalar is the
/// x-coordinate of `CM = k·G_k + r·J`; the verifier recomputes `K = k·G_k` from
/// the key the spend reveals and the circuit proves `K + r·J = CM`.
///
/// This is the single source for `k`; `shekyl_fcmp::PqcKeyScalar` wraps it.
/// The returned bytes are the caller's product — the caller owns their wipe.
pub fn pqc_key_scalar(pqc_pk_bytes: &[u8]) -> [u8; 32] {
    let k = key_scalar(pqc_pk_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(k.as_bytes());
    out
}

/// `K = k·G_k` from an already-reduced Ed25519 scalar. The one multiply every
/// verifier path (this crate and `PqcKeyScalar::point`) uses — fixed-base over
/// the precomputed `G_k` table (pinned to the frozen point in
/// `shekyl-curve-generators`).
#[must_use]
pub fn pqc_key_point_from_scalar(k: &Scalar) -> [u8; 32] {
    (&*PQC_LEAF_COMMITMENT_G_K_TABLE * k).compress().to_bytes()
}

/// The verifier-side public point `K = k·G_k` for a revealed hybrid public key,
/// compressed. Never on the wire: derived from `pqc_auths[i].hybrid_public_key`
/// by every verifier.
pub fn pqc_key_point(pqc_pk_bytes: &[u8]) -> [u8; 32] {
    pqc_key_point_from_scalar(&key_scalar(pqc_pk_bytes))
}

/// The post-quantum record `cSHAKE256(pk ‖ r_h)` published beside `CM` in
/// `tx_extra` `0x07` (`PL-D3a`). Checked by nothing live; Keccak-chained into the
/// block; what a transparent claim (`PL-D5`) opens with `(pk, r_h)`.
pub fn pqc_leaf_record(pqc_pk_bytes: &[u8], record_blind: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(pqc_pk_bytes.len() + 32);
    preimage.extend_from_slice(pqc_pk_bytes);
    preimage.extend_from_slice(record_blind);
    let out = cshake256_32(DOMAIN_PQC_LEAF_RECORD, &preimage);
    preimage.zeroize();
    out
}

/// The sender's / owner's opening of one output's PQC leaf commitment.
///
/// Deliberately **not** `Clone` (rule 35): the blinds are secrets, and no
/// caller duplicates the opening — it is derived where needed and moved once
/// into its owning output struct.
#[derive(Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PqcLeafCommitment {
    /// `CM = k·G_k + r·J`, compressed Ed25519 (the first 32 bytes of the `0x07`
    /// entry; its Wei25519 x-coordinate is the leaf's 4th scalar).
    #[zeroize(skip)]
    pub point: [u8; PQC_LEAF_POINT_LEN],
    /// The record `cSHAKE256(pk ‖ r_h)` (the second 32 bytes of the `0x07` entry).
    #[zeroize(skip)]
    pub record: [u8; PQC_LEAF_RECORD_LEN],
    /// The blind `r` (Ed25519 scalar) — the prover's in-circuit witness. Secret.
    pub blind: [u8; 32],
    /// The record blind `r_h`. Secret; opens the record at a transparent claim.
    pub record_blind: [u8; 32],
    /// The re-derivation counter the exceptional-value guard settled on
    /// (`0` in all but a ~2⁻²⁵² fraction of outputs).
    #[zeroize(skip)]
    pub counter: u8,
}

impl PqcLeafCommitment {
    /// The typed `0x07` entry for this output: `point ‖ record`.
    #[must_use]
    pub fn entry(&self) -> PqcLeafEntry {
        PqcLeafEntry {
            point: self.point,
            record: self.record,
        }
    }

    /// Wire bytes of the `0x07` entry (`CM ‖ record`).
    #[must_use]
    pub fn entry_bytes(&self) -> [u8; PQC_LEAF_ENTRY_LEN] {
        self.entry().to_bytes()
    }
}

/// Failure of [`pqc_leaf_commitment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcLeafCommitmentError {
    /// `K = k·G_k` is the identity — the key scalar reduced to `0 mod ℓ`, a
    /// ~2⁻²⁵² property of the public key alone. The guard counter varies only
    /// the blind, so no counter walk can repair it; refused before the retry
    /// loop rather than misreported as a 256-counter exhaustion.
    IdentityKeyPoint,
    /// 256 counter values all produced an exceptional blind — impossible in
    /// practice (each rejection is a ~2⁻²⁵² event); returned rather than looped
    /// so the guard is a rule with a visible failure, not an assumption.
    GuardExhausted,
}

/// Derive the blind `r` for one output under the guard counter `ctr`
/// (`HKDF-Expand(prk, "shekyl-pqc-leaf-blind" ‖ idx_le64 ‖ ctr, 64) mod ℓ`).
/// The wide reduction is [`expand_wide_scalar`] — the same body the
/// output-secrets scalars (`ho`, `y`, `z`) come through; only the one-byte
/// counter suffix on the info distinguishes this derivation.
fn derive_pqc_leaf_blind(hk: &Hkdf<Sha512>, output_index: u64, ctr: u8) -> Zeroizing<Scalar> {
    let mut info = make_info(LABEL_OUTPUT_PQC_LEAF_BLIND, output_index);
    info.push(ctr);
    expand_wide_scalar(hk, &info)
}

/// Build the output's PQC leaf commitment and record from the owner's
/// `combined_ss` and the output's canonical hybrid public key (`PL-D3`, `PL-D3a`).
///
/// **Exceptional-value guard** (round doc §6.2): `r = 0` would make `CM = k·G_k`,
/// a deterministic function of the key — the very leak `PL-D1` names — and the
/// circuit's incomplete addition rejects an identity operand or equal/opposite
/// operands. Each is rejected here and the blind re-derived under the next
/// counter; the recipient reproduces the same walk at scan, so no counter is
/// carried on the wire.
///
/// Every named secret below (`k`, `K`, `r`, `r·J`, the blinds) lives in a
/// `Zeroizing` wrapper, so each exit — per-iteration `continue`, success,
/// refusal — wipes it structurally (rule 35). The `Copy` rvalue temporaries
/// the wrappers are built from are rule 35's documented small-N residue.
pub fn pqc_leaf_commitment(
    combined_ss: &[u8],
    output_index: u64,
    pqc_pk_bytes: &[u8],
) -> Result<PqcLeafCommitment, PqcLeafCommitmentError> {
    let k = key_scalar(pqc_pk_bytes);
    let big_k = Zeroizing::new(&*PQC_LEAF_COMMITMENT_G_K_TABLE * &*k);
    if *big_k == EdwardsPoint::identity() {
        return Err(PqcLeafCommitmentError::IdentityKeyPoint);
    }
    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT_OUTPUT_DERIVE), combined_ss);
    let mut record_blind = Zeroizing::new([0u8; 32]);
    expand_32_into(
        &hk,
        LABEL_OUTPUT_PQC_LEAF_RECORD_BLIND,
        output_index,
        &mut record_blind,
    );
    for ctr in 0u8..=u8::MAX {
        let r = derive_pqc_leaf_blind(&hk, output_index, ctr);
        if *r == Scalar::ZERO {
            continue;
        }
        let r_j = Zeroizing::new(&*PQC_LEAF_COMMITMENT_J_TABLE * &*r);
        // The circuit opens `CM` with incomplete addition over the operands
        // `(K, r·J)`; its exceptional cases map onto these checks:
        //   - equal operands (a doubling):          `K == r·J`
        //   - opposite operands (`CM` = identity):  `K == -r·J` — the same
        //     condition as `K + r·J == identity`, checked once in operand form
        //   - an identity operand: `K == identity` is a property of the key
        //     alone, refused before the loop; `r·J == identity` is unreachable
        //     here — `J` is prime-order (cofactor-cleared NUMS) and `r` is a
        //     canonical nonzero scalar after the `r == 0` re-derivation above.
        let neg_r_j = Zeroizing::new(-&*r_j);
        if *big_k == *r_j || *big_k == *neg_r_j {
            continue;
        }
        // CLIPPY: borrowed operands on purpose (35-secure-memory.mdc) — the
        // suggested value operands would copy both secret points onto the
        // stack outside their `Zeroizing` wrappers.
        #[allow(clippy::op_ref)]
        let cm = &*big_k + &*r_j;
        let mut leaf = PqcLeafCommitment {
            point: cm.compress().to_bytes(),
            record: pqc_leaf_record(pqc_pk_bytes, &record_blind),
            blind: [0u8; 32],
            record_blind: [0u8; 32],
            counter: ctr,
        };
        leaf.blind.copy_from_slice(r.as_bytes());
        leaf.record_blind.copy_from_slice(&*record_blind);
        return Ok(leaf);
    }
    Err(PqcLeafCommitmentError::GuardExhausted)
}

pub use shekyl_curve_generators::pqc_leaf_point_valid;

/// Derive the output's PQC leaf commitment (`CM ‖ record`, blinds, counter) from
/// the owner's combined shared secret and output index, without returning any
/// signing key material (`PL-D3`).
///
/// Internally derives the full hybrid keypair via `derive_output_secrets` +
/// `keygen_from_seed`, encodes the public key canonically, and zeroizes the
/// secret key on drop.
pub fn derive_pqc_leaf(
    combined_ss: &[u8; 64],
    output_index: u64,
) -> Result<PqcLeafCommitment, CryptoError> {
    let pk_bytes = crate::derivation::derive_pqc_public_key(combined_ss, output_index)?;
    pqc_leaf_commitment(combined_ss, output_index, &pk_bytes)
        .map_err(|e| CryptoError::KeyGenerationFailed(format!("PQC leaf commitment guard: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation::{derive_pqc_public_key, ML_DSA_65_PK_LEN};
    use crate::test_support::regen_decision_or_refuse;
    // The tests open commitments with the plain frozen points on purpose:
    // production multiplies over the precomputed tables, so agreement here is
    // an implicit table↔point pin on the real path (the explicit pin lives in
    // shekyl-curve-generators' frozen-point tests).
    use shekyl_curve_generators::{PQC_LEAF_COMMITMENT_G_K, PQC_LEAF_COMMITMENT_J};

    #[test]
    fn derivation_deterministic() {
        let ss = [0xab; 64];
        let a = derive_pqc_leaf(&ss, 0).unwrap();
        let b = derive_pqc_leaf(&ss, 0).unwrap();
        assert_eq!(a.entry(), b.entry());
        assert_eq!(a.blind, b.blind);
        assert_eq!(a.record_blind, b.record_blind);
        assert_eq!(a.counter, b.counter);
    }

    #[test]
    fn different_indices_different_leaves() {
        let ss = [0xab; 64];
        let a = derive_pqc_leaf(&ss, 0).unwrap();
        let b = derive_pqc_leaf(&ss, 1).unwrap();
        assert_ne!(a.point, b.point);
        assert_ne!(a.record, b.record);
        assert_ne!(a.blind, b.blind);
    }

    #[test]
    fn different_secrets_different_leaves() {
        let a = derive_pqc_leaf(&[0xab; 64], 0).unwrap();
        let b = derive_pqc_leaf(&[0xcd; 64], 0).unwrap();
        assert_ne!(a.point, b.point);
        assert_ne!(a.record, b.record);
    }

    #[test]
    fn pqc_key_scalar_deterministic() {
        let pk = vec![0xab; ML_DSA_65_PK_LEN];
        assert_eq!(pqc_key_scalar(&pk), pqc_key_scalar(&pk));
    }

    #[test]
    fn pqc_key_scalar_is_canonical_nonzero_ed25519_scalar() {
        for pk in [
            vec![],
            vec![0x01],
            vec![0xab; 32],
            vec![0xff; ML_DSA_65_PK_LEN],
        ] {
            let k = pqc_key_scalar(&pk);
            assert!(
                bool::from(Scalar::from_canonical_bytes(k).is_some()),
                "k must be a canonical Ed25519 scalar (len {})",
                pk.len()
            );
            assert_ne!(k, [0u8; 32], "k must not be zero (len {})", pk.len());
        }
    }

    #[test]
    fn pqc_key_scalar_different_lengths_differ() {
        assert_ne!(
            pqc_key_scalar(&[0xab; 32]),
            pqc_key_scalar(&[0xab; ML_DSA_65_PK_LEN])
        );
    }

    #[test]
    fn pqc_key_scalar_is_domain_separated() {
        let pk = vec![0xab; 64];
        let under_key = cshake256_64(DOMAIN_PQC_LEAF_KEY, &pk);
        let under_record = cshake256_64(DOMAIN_PQC_LEAF_RECORD, &pk);
        assert_ne!(under_key, under_record);
    }

    #[test]
    fn pqc_key_point_is_k_times_g_k() {
        let pk = vec![0xab; ML_DSA_65_PK_LEN];
        let k = key_scalar(&pk);
        assert_eq!(pqc_key_point(&pk), pqc_key_point_from_scalar(&k));
        assert_eq!(
            pqc_key_point(&pk),
            (*PQC_LEAF_COMMITMENT_G_K * *k).compress().to_bytes()
        );
        assert!(
            pqc_leaf_point_valid(&pqc_key_point(&pk)).is_some(),
            "K is a valid prime-order point"
        );
    }

    /// Cross-crate agreement pin: `shekyl_fcmp::PqcKeyScalar::from_pqc_public_key`
    /// forwards to [`pqc_key_scalar`] (the single source). Pins value agreement
    /// only; the byte pins live in `PQC_KEY_SCALAR_KAT.json`.
    #[test]
    fn key_scalar_matches_fcmp_wrapper() {
        use shekyl_fcmp::leaf::PqcKeyScalar;

        let ss = [0xab; 64];
        let pk_bytes = derive_pqc_public_key(&ss, 0).unwrap();
        let wrapper = PqcKeyScalar::from_pqc_public_key(&pk_bytes);
        assert_eq!(pqc_key_scalar(&pk_bytes), *wrapper.as_bytes());
        assert_eq!(pqc_key_point(&pk_bytes), wrapper.point());
    }

    #[test]
    fn commitment_opens_to_key_point_under_blind() {
        let ss = [0xab; 64];
        let pk = derive_pqc_public_key(&ss, 7).unwrap();
        let leaf = pqc_leaf_commitment(&ss, 7, &pk).unwrap();
        let cm = pqc_leaf_point_valid(&leaf.point).expect("CM is a valid point");
        let r = Scalar::from_canonical_bytes(leaf.blind).expect("blind is canonical");
        assert_ne!(r, Scalar::ZERO);
        let k_point = cm - (*PQC_LEAF_COMMITMENT_J * r);
        assert_eq!(k_point.compress().to_bytes(), pqc_key_point(&pk));
        assert_eq!(leaf.counter, 0, "guard counter is 0 for a normal output");
    }

    #[test]
    fn record_is_cshake_of_pk_and_record_blind() {
        let ss = [0xab; 64];
        let pk = derive_pqc_public_key(&ss, 3).unwrap();
        let leaf = pqc_leaf_commitment(&ss, 3, &pk).unwrap();
        let mut preimage = pk.clone();
        preimage.extend_from_slice(&leaf.record_blind);
        assert_eq!(leaf.record, cshake256_32(DOMAIN_PQC_LEAF_RECORD, &preimage));
        assert_eq!(leaf.record, pqc_leaf_record(&pk, &leaf.record_blind));
        let other_pk = derive_pqc_public_key(&ss, 4).unwrap();
        assert_ne!(leaf.record, pqc_leaf_record(&other_pk, &leaf.record_blind));
    }

    #[test]
    fn commitment_hides_the_key_across_outputs() {
        let pk = derive_pqc_public_key(&[0xab; 64], 0).unwrap();
        let a = pqc_leaf_commitment(&[0x11; 64], 0, &pk).unwrap();
        let b = pqc_leaf_commitment(&[0x22; 64], 0, &pk).unwrap();
        assert_ne!(a.point, b.point);
        assert_ne!(a.point, pqc_key_point(&pk), "CM must not equal K");
    }

    #[test]
    fn entry_is_point_then_record() {
        let leaf = derive_pqc_leaf(&[0xab; 64], 0).unwrap();
        let e = leaf.entry();
        assert_eq!(e.to_bytes().len(), PQC_LEAF_ENTRY_LEN);
        assert_eq!(e.point, leaf.point);
        assert_eq!(e.record, leaf.record);
        assert_eq!(PqcLeafEntry::from_bytes(e.to_bytes()), e);
    }

    #[test]
    fn blind_counter_changes_the_blind() {
        let ss = [0xab; 64];
        let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT_OUTPUT_DERIVE), &ss);
        let r0 = derive_pqc_leaf_blind(&hk, 0, 0);
        let r1 = derive_pqc_leaf_blind(&hk, 0, 1);
        // Canonicality is structural now — the derivation returns a `Scalar`,
        // not bytes — so only the counter's effect is left to assert.
        assert_ne!(*r0, *r1, "the guard counter must re-derive the blind");
    }

    #[test]
    fn leaf_point_admission_rejects_identity_torsion_and_noncanonical() {
        use curve25519_dalek::constants::EIGHT_TORSION;

        assert!(pqc_leaf_point_valid(&EdwardsPoint::identity().compress().to_bytes()).is_none());
        for t in EIGHT_TORSION.iter().skip(1) {
            assert!(
                pqc_leaf_point_valid(&t.compress().to_bytes()).is_none(),
                "small-order point must be refused"
            );
        }
        assert!(pqc_leaf_point_valid(&[0xff; 32]).is_none());
        let mut noncanonical = [0u8; 32];
        noncanonical[0] = 0xee;
        for b in noncanonical.iter_mut().skip(1) {
            *b = 0xff;
        }
        noncanonical[31] = 0x7f;
        assert!(pqc_leaf_point_valid(&noncanonical).is_none());
        let leaf = derive_pqc_leaf(&[0xab; 64], 0).unwrap();
        assert!(pqc_leaf_point_valid(&leaf.point).is_some());
    }

    fn vectors_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/test_vectors")
    }

    fn key_scalar_kat_inputs() -> Vec<Vec<u8>> {
        vec![
            vec![],
            vec![0x01],
            vec![0xab; 32],
            derive_pqc_public_key(&[0xab; 64], 0).unwrap(),
        ]
    }

    #[derive(serde::Deserialize)]
    struct KeyScalarKat {
        pqc_pk: String,
        k: String,
        k_point: String,
    }

    #[derive(serde::Deserialize)]
    struct KeyScalarKatFile {
        vectors: Vec<KeyScalarKat>,
    }

    #[test]
    fn pqc_key_scalar_known_answer_vectors() {
        use shekyl_fcmp::leaf::PqcKeyScalar;

        let json = include_str!("../../../docs/test_vectors/PQC_KEY_SCALAR_KAT.json");
        let file: KeyScalarKatFile =
            serde_json::from_str(json).expect("failed to parse PQC_KEY_SCALAR_KAT.json");
        assert_eq!(
            file.vectors.len(),
            4,
            "PQC_KEY_SCALAR_KAT.json is a frozen pin set — vectors are never added or removed"
        );
        for (i, v) in file.vectors.iter().enumerate() {
            let pk = hex::decode(&v.pqc_pk).unwrap_or_else(|_| panic!("vector {i}: pqc_pk hex"));
            let k = hex::decode(&v.k).unwrap_or_else(|_| panic!("vector {i}: k hex"));
            let k_point =
                hex::decode(&v.k_point).unwrap_or_else(|_| panic!("vector {i}: k_point hex"));
            assert_eq!(
                pqc_key_scalar(&pk).as_slice(),
                k.as_slice(),
                "vector {i}: pqc_key_scalar drifted for input length {}",
                pk.len()
            );
            assert_eq!(
                PqcKeyScalar::from_pqc_public_key(&pk).as_bytes().as_slice(),
                k.as_slice(),
                "vector {i}: PqcKeyScalar::from_pqc_public_key drifted for input length {}",
                pk.len()
            );
            assert_eq!(
                pqc_key_point(&pk).as_slice(),
                k_point.as_slice(),
                "vector {i}: pqc_key_point drifted for input length {}",
                pk.len()
            );
        }
    }

    /// ```text
    /// SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
    ///   cargo test -p shekyl-crypto-pq --lib -- --ignored regenerate_pqc_key_scalar_kat
    /// ```
    #[test]
    #[ignore = "armed fixture regenerator; requires SHEKYL_PINNED_REGEN_DECISION"]
    fn regenerate_pqc_key_scalar_kat() {
        let decision = regen_decision_or_refuse("PQC_KEY_SCALAR_KAT.json");
        let vectors: Vec<serde_json::Value> = key_scalar_kat_inputs()
            .iter()
            .map(|pk| {
                serde_json::json!({
                    "pqc_pk": hex::encode(pk),
                    "k": hex::encode(pqc_key_scalar(pk)),
                    "k_point": hex::encode(pqc_key_point(pk)),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "description": "PL-D3 pins for k = H_l(hybrid_pk) (cSHAKE256 under \
                shekyl/pqc-leaf-key-v1, 64-byte read reduced mod the Ed25519 group \
                order) and K = k*G_k. Inputs: the degenerate lengths (empty, 1 byte, \
                32 bytes) and one real derived hybrid public key. Consumed by \
                pqc_key_scalar_known_answer_vectors in \
                rust/shekyl-crypto-pq/src/leaf_commitment.rs, which asserts both \
                consensus entry points (pqc_key_scalar and the shekyl-fcmp \
                PqcKeyScalar wrapper). Frozen: never regenerated without a \
                decision-log entry (SHEKYL_PINNED_REGEN_DECISION).",
            "regeneration_decision": decision,
            "vectors": vectors,
        });
        let path = vectors_dir().join("PQC_KEY_SCALAR_KAT.json");
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
        eprintln!("wrote {}", path.display());
    }

    #[derive(serde::Deserialize)]
    struct LeafCommitmentKat {
        combined_ss: String,
        output_index: u64,
        point: String,
        record: String,
        blind: String,
        record_blind: String,
        counter: u8,
    }

    #[derive(serde::Deserialize)]
    struct LeafCommitmentKatFile {
        vectors: Vec<LeafCommitmentKat>,
    }

    fn leaf_commitment_kat_inputs() -> Vec<([u8; 64], u64)> {
        vec![
            ([0x00; 64], 0),
            ([0x00; 64], 1),
            ([0xab; 64], 0),
            ([0xab; 64], 7),
            ([0xff; 64], u64::MAX),
        ]
    }

    #[test]
    fn pqc_leaf_commitment_known_answer_vectors() {
        let json = include_str!("../../../docs/test_vectors/PQC_LEAF_COMMITMENT_KAT.json");
        let file: LeafCommitmentKatFile =
            serde_json::from_str(json).expect("failed to parse PQC_LEAF_COMMITMENT_KAT.json");
        assert_eq!(
            file.vectors.len(),
            leaf_commitment_kat_inputs().len(),
            "PQC_LEAF_COMMITMENT_KAT.json is a frozen pin set"
        );
        for (i, v) in file.vectors.iter().enumerate() {
            let css: [u8; 64] = hex::decode(&v.combined_ss)
                .unwrap_or_else(|_| panic!("vector {i}: combined_ss hex"))
                .try_into()
                .unwrap_or_else(|_| panic!("vector {i}: combined_ss not 64 bytes"));
            let leaf = derive_pqc_leaf(&css, v.output_index)
                .unwrap_or_else(|e| panic!("vector {i}: derive_pqc_leaf failed: {e}"));
            assert_eq!(hex::encode(leaf.point), v.point, "vector {i}: point");
            assert_eq!(hex::encode(leaf.record), v.record, "vector {i}: record");
            assert_eq!(hex::encode(leaf.blind), v.blind, "vector {i}: blind");
            assert_eq!(
                hex::encode(leaf.record_blind),
                v.record_blind,
                "vector {i}: record_blind"
            );
            assert_eq!(leaf.counter, v.counter, "vector {i}: counter");
        }
    }

    /// ```text
    /// SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
    ///   cargo test -p shekyl-crypto-pq --lib -- --ignored regenerate_pqc_leaf_commitment_kat
    /// ```
    #[test]
    #[ignore = "armed fixture regenerator; requires SHEKYL_PINNED_REGEN_DECISION"]
    fn regenerate_pqc_leaf_commitment_kat() {
        let decision = regen_decision_or_refuse("PQC_LEAF_COMMITMENT_KAT.json");
        let vectors: Vec<serde_json::Value> = leaf_commitment_kat_inputs()
            .iter()
            .map(|(css, idx)| {
                let leaf = derive_pqc_leaf(css, *idx).unwrap();
                serde_json::json!({
                    "combined_ss": hex::encode(css),
                    "output_index": idx,
                    "point": hex::encode(leaf.point),
                    "record": hex::encode(leaf.record),
                    "blind": hex::encode(leaf.blind),
                    "record_blind": hex::encode(leaf.record_blind),
                    "counter": leaf.counter,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "description": "PL-D3 / PL-D3a pins for the owner-side tx_extra 0x07 entry: \
                CM = k*G_k + r*J (k = H_l(hybrid_pk), r = HKDF-Expand(prk, \
                \"shekyl-pqc-leaf-blind\" || idx_le64 || ctr, 64) mod l), record = \
                cSHAKE256(shekyl/pqc-leaf-record-v1, pk || r_h), r_h = HKDF-Expand(prk, \
                \"shekyl-pqc-leaf-record-blind\" || idx_le64, 32), per (combined_ss, \
                output_index). Consumed by pqc_leaf_commitment_known_answer_vectors in \
                rust/shekyl-crypto-pq/src/leaf_commitment.rs. Frozen: never regenerated \
                without a decision-log entry (SHEKYL_PINNED_REGEN_DECISION).",
            "regeneration_decision": decision,
            "vectors": vectors,
        });
        let path = vectors_dir().join("PQC_LEAF_COMMITMENT_KAT.json");
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
        eprintln!("wrote {}", path.display());
    }
}
