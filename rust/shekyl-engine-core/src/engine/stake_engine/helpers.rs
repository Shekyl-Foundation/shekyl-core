// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared funding-input preparation and vout construction (bond / claim).

use curve25519_dalek::Scalar;
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_crypto_pq::derivation::{derive_output_secrets, derive_pqc_public_key};
use shekyl_crypto_pq::kem::HybridCiphertext;
use shekyl_crypto_pq::output::{construct_output, recover_combined_ss};
use shekyl_curve_generators::biased_hash_to_point;
use shekyl_engine_state::pscan_state::PFundingOutputRecord;
use shekyl_standoff::draw::{draw_entry_gap, GapRng};
use shekyl_tx_builder::{LeafEntry, SpendInput};
use shekyl_types::GlobalOutputIndex;
use shekyl_units::AtomicUnits;
use zeroize::Zeroizing;

use super::types::*;
use crate::engine::bond_assembly::{BondAssemblyError, FundingInputContext};
use crate::engine::error::KeyEngineError;
use crate::engine::traits::key::SourceSecretsBundle;

// ---------------------------------------------------------------------------
// Shared funding-input preparation (AssembleBond + AssembleEmissionClaim)
// ---------------------------------------------------------------------------

/// One prepared spend input: the tx-builder [`SpendInput`] (owned secrets)
/// plus the public companions the wire needs (key image, PQC slot pubkey,
/// reservation gindex).
pub(crate) struct PreparedInput {
    pub(crate) spend: SpendInput,
    pub(crate) key_image: [u8; 32],
    pub(crate) pqc_pubkey: Vec<u8>,
    pub(crate) gindex: GlobalOutputIndex,
}

/// One constructed vout batch to `P`'s base address — the shared
/// output-construction loop of [`AssembleBond`] (two confidential change
/// vouts) and [`AssembleEmissionClaim`] (loud reward + two change vouts):
/// per output, `construct_output` → KEM blob layout → leaf-hash blob →
/// `[u8; 9]` enc-amount/enc-label packing → tx-builder `OutputInfo`. Both
/// change vouts return to `P`'s base spend key (the pscan
/// `GuaranteedScanner` claims against `spend_pk` directly), so change
/// re-enters the funding set on the next sweep.
pub(crate) struct ConstructedVouts {
    pub(crate) output_infos: Vec<shekyl_tx_builder::OutputInfo>,
    pub(crate) output_keys: Vec<[u8; 32]>,
    pub(crate) view_tags: Vec<Option<u8>>,
    pub(crate) kem_blobs: Vec<Vec<u8>>,
    pub(crate) leaf_hash_blob: Vec<u8>,
}

/// Construct `amounts` as vouts to `P`'s base address. `capture` sees each
/// constructed output `(index, &OutputData)` before its fields are packed,
/// so the emission path lifts its reward commit without a second loop or a
/// parallel construction site.
pub(crate) fn construct_vouts_to_base(
    keys: &ArchivalPKeys,
    tx_key_secret: &Zeroizing<[u8; 32]>,
    amounts: &[u64],
    error_site: &'static str,
    mut capture: impl FnMut(usize, &shekyl_crypto_pq::output::OutputData),
) -> Result<ConstructedVouts, BondAssemblyError> {
    let mut vouts = ConstructedVouts {
        output_infos: Vec::with_capacity(amounts.len()),
        output_keys: Vec::with_capacity(amounts.len()),
        view_tags: Vec::with_capacity(amounts.len()),
        kem_blobs: Vec::with_capacity(amounts.len()),
        leaf_hash_blob: Vec::with_capacity(32 * amounts.len()),
    };
    for (idx, &amount) in amounts.iter().enumerate() {
        let constructed = construct_output(
            tx_key_secret,
            &keys.x25519_pk,
            &keys.ml_kem_ek,
            keys.spend_pk.as_canonical_bytes(),
            amount,
            idx as u64,
        )
        .map_err(|e| BondAssemblyError::build(error_site, e))?;
        capture(idx, &constructed);
        let mut kem_blob = Vec::with_capacity(32 + constructed.kem_ciphertext_ml_kem.len());
        kem_blob.extend_from_slice(&constructed.kem_ciphertext_x25519);
        kem_blob.extend_from_slice(&constructed.kem_ciphertext_ml_kem);
        vouts.kem_blobs.push(kem_blob);
        vouts.leaf_hash_blob.extend_from_slice(&constructed.h_pqc);
        vouts.output_keys.push(constructed.output_key);
        vouts.view_tags.push(Some(constructed.view_tag_prefilter));
        vouts.output_infos.push(shekyl_tx_builder::OutputInfo {
            dest_key: constructed.output_key,
            amount: AtomicUnits::from_raw(amount),
            commitment_mask: constructed.z,
            enc_amount: {
                let mut enc = [0u8; 9];
                enc[..8].copy_from_slice(&constructed.enc_amount);
                enc[8] = constructed.amount_tag;
                enc
            },
            enc_label: {
                let mut enc = [0u8; 9];
                enc[..8].copy_from_slice(&constructed.enc_label);
                enc[8] = constructed.label_tag;
                enc
            },
        });
    }
    Ok(vouts)
}

/// One record's re-derived spend-side parts — the shared per-record body of
/// [`prepare_funding_inputs`] (bond + emission fee spends) and the emission
/// handler's **backing** leg, which is the same derivation minus the key
/// image (membership-only). One definition: a correction to the bundle
/// derivation, the leaf-chunk `h_pqc` lookup, or the `combined_ss` handling
/// lands once, or the backing proof's secrets silently diverge from the fee
/// path's and every claim fails its own leaf gate.
pub(crate) struct DerivedSpendParts {
    pub(crate) bundle: SourceSecretsBundle,
    /// The first 64 bytes of the bundle's combined secret — the
    /// per-output-PQC derivation operand (the backing leg retains it for
    /// Auth-B signing).
    pub(crate) combined64: Zeroizing<[u8; 64]>,
    /// The record's leaf hash, read back from its own leaf chunk (`h_pqc`
    /// is not persisted on the record — public identity only).
    pub(crate) h_pqc: [u8; 32],
    /// The per-output PQC public key derived from `combined64`.
    pub(crate) pqc_pubkey: Vec<u8>,
}

/// Re-derive one funding record's spend-side parts (rule 36: secrets are
/// re-derived from the record's `(ciphertext, index)` inside the actor,
/// never carried in the message).
pub(crate) fn derive_spend_parts(
    keys: &ArchivalPKeys,
    rec: &PFundingOutputRecord,
    leaf_chunk: &[LeafEntry],
) -> Result<DerivedSpendParts, BondAssemblyError> {
    let ciphertext = HybridCiphertext {
        x25519: rec.ciphertext_x25519,
        ml_kem: rec.ciphertext_ml_kem.clone(),
    };
    let bundle = derive_p_source_secrets_bundle(keys, &ciphertext, rec.index_in_transaction)
        .map_err(|e| BondAssemblyError::build("spend-bundle derivation", e))?;

    let h_pqc = leaf_chunk
        .iter()
        .find(|leaf| leaf.output_key == rec.output_key)
        .map(|leaf| leaf.h_pqc)
        .ok_or_else(|| {
            BondAssemblyError::build(
                "leaf-chunk lookup",
                "funding output missing from its own leaf chunk",
            )
        })?;

    let combined64: Zeroizing<[u8; 64]> =
        Zeroizing::new(bundle.combined_ss[..64].try_into().map_err(|_| {
            BondAssemblyError::build("spend-bundle derivation", "combined_ss wrong length")
        })?);
    let pqc_pubkey = derive_pqc_public_key(&combined64, rec.index_in_transaction)
        .map_err(|e| BondAssemblyError::build("pqc public-key derivation", e))?;

    Ok(DerivedSpendParts {
        bundle,
        combined64,
        h_pqc,
        pqc_pubkey,
    })
}

impl DerivedSpendParts {
    /// The tx-builder [`SpendInput`] over these parts, moving the
    /// membership vecs in (never deep-copying them).
    pub(crate) fn into_spend_input(
        self,
        rec: &PFundingOutputRecord,
        leaf_chunk: Vec<LeafEntry>,
        c1_layers: Vec<Vec<[u8; 32]>>,
        c2_layers: Vec<Vec<[u8; 32]>>,
    ) -> SpendInput {
        SpendInput {
            output_key: rec.output_key,
            commitment: rec.commitment,
            amount: rec.amount,
            spend_key_x: *self.bundle.spend_key_x,
            spend_key_y: *self.bundle.spend_key_y,
            commitment_mask: *self.bundle.commitment_mask,
            h_pqc: self.h_pqc,
            combined_ss: self.bundle.combined_ss.to_vec(),
            output_index: rec.index_in_transaction,
            leaf_chunk,
            c1_layers,
            c2_layers,
        }
    }
}

/// Re-derive spend bundles for the selected funding inputs, compute key
/// images, and build the tx-builder [`SpendInput`]s — the shared spend-side
/// leg of [`AssembleBond`] and [`AssembleEmissionClaim`] (rule 36: secrets are
/// re-derived from each record's `(ciphertext, index)` inside the actor,
/// never carried in the message).
///
/// Consumes `funding` by value: the curve-tree membership vecs (`leaf_chunk`,
/// `c1_layers`, `c2_layers` — many 32-byte node vecs per tree layer) MOVE into
/// each `SpendInput` rather than deep-copy. The returned set is sorted
/// strictly DESCENDING by key image — the consensus order shared by the
/// proof, the wire key-image list, and the pqc_auths slots (same rule as the
/// transfer path).
// `pub(crate)`: the F-D2 drain assembly (`drain_assembly.rs`) reuses this exact
// persona-keyed spend-side leg — the drain spends `P`-funding inputs identically
// to a bond/claim fee sweep (same key-image derivation, same descending order),
// so there is one definition of "turn selected P-funding records into signed
// spend inputs," never a drain-specific fork (rule 36 + composition discipline).
pub(crate) fn prepare_funding_inputs(
    keys: &ArchivalPKeys,
    funding: Vec<FundingInputContext>,
) -> Result<Vec<PreparedInput>, BondAssemblyError> {
    let mut prepared = Vec::with_capacity(funding.len());
    for ctx in funding {
        let rec = &ctx.record;
        let mut parts = derive_spend_parts(keys, rec, &ctx.leaf_chunk)?;

        // KI = x·Hp(O) — the single shared definition (see
        // `key_image_from_spend_key_x`; the watch path derives through the
        // same leg, so watch and sweep cannot diverge). The full-path-only
        // leg (the backing's membership-only leg has none).
        let key_image = key_image_from_spend_key_x(&parts.bundle.spend_key_x, rec.output_key)
            .map_err(|e| BondAssemblyError::build("key-image derivation", e))?;

        let pqc_pubkey = std::mem::take(&mut parts.pqc_pubkey);
        let gindex = rec.gindex;
        prepared.push(PreparedInput {
            spend: parts.into_spend_input(rec, ctx.leaf_chunk, ctx.c1_layers, ctx.c2_layers),
            key_image,
            pqc_pubkey,
            gindex,
        });
    }
    prepared.sort_by_key(|b| std::cmp::Reverse(b.key_image));
    Ok(prepared)
}

// ---------------------------------------------------------------------------
// WI-2 D-A3 step 1 — P-side per-output spend-bundle derivation
// ---------------------------------------------------------------------------

/// Re-derive the per-output spend-secrets bundle for a **P-owned** funding
/// output — the persona analog of
/// [`LocalKeys::derive_primary_source_secrets_bundle`]
/// (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.3 actor step 1), over the same
/// pipeline with `P`'s keys substituted for the principal's:
///
/// 1. `combined_ss` ← [`recover_combined_ss`]`(P.view_sk, P.ml_kem_dk,
///    ciphertext)` — hybrid X25519 + ML-KEM-768 re-decap and HKDF-SHA-512
///    combination.
/// 2. Per-output secrets ← [`derive_output_secrets`]`(combined_ss,
///    output_index)`.
/// 3. Spend scalar `x = ho + b` with `b` = `P.spend_sk`. **No claim offset**,
///    for the same reason as the principal path: `P`'s funding outputs are
///    paid to the *base* spend key `b·G` (the scan's `GuaranteedScanner`
///    claims against `spend_pk` directly), so `O = x·G + y·T` and
///    `KI = x·Hp(O)` both bind to `b`.
///
/// This is exactly the WI-2 D-A1 re-derivation contract: the persisted
/// `PFundingOutputRecord` carries only `(ciphertext, index_in_transaction)`
/// public identity; the secrets drop in the scan's offload closure (rule 16,
/// the M3d discipline) and are recomputed here, inside the actor, at
/// assemble time. Every intermediate is `Zeroizing`; only the bundle's own
/// wiped-on-drop fields leave the frame — and the bundle itself never leaves
/// the actor (rule 36).
///
/// A free function rather than a `StakeEngine` method: it needs only the
/// borrowed [`ArchivalPKeys`], and the `AssembleBond` handler calls it per
/// selected funding record before entering the proving offload.
///
/// [`LocalKeys::derive_primary_source_secrets_bundle`]: crate::engine::local_keys::LocalKeys
/// [`recover_combined_ss`]: shekyl_crypto_pq::output::recover_combined_ss
/// [`derive_output_secrets`]: shekyl_crypto_pq::derivation::derive_output_secrets
#[allow(dead_code)] // transient — consumed by the WI-2 `AssembleBond` handler as it lands.
pub(crate) fn derive_p_source_secrets_bundle(
    keys: &ArchivalPKeys,
    source_ciphertext: &HybridCiphertext,
    output_index: u64,
) -> Result<SourceSecretsBundle, KeyEngineError> {
    let combined_ss = recover_combined_ss(
        keys.view_sk.as_canonical_bytes(),
        keys.ml_kem_dk.as_canonical_bytes(),
        &source_ciphertext.x25519,
        &source_ciphertext.ml_kem,
    )?;

    let secrets = derive_output_secrets(&combined_ss.0, output_index);

    // `x = ho + b` — see the principal-path comment in `local_keys.rs` for
    // why there is no claim-offset term. Each intermediate `Scalar` is
    // `Zeroizing` so the canonical-byte materializations wipe on drop.
    let ho_scalar: Zeroizing<Scalar> = Zeroizing::new(
        Option::from(Scalar::from_canonical_bytes(secrets.ho))
            .expect("ho from wide_reduce is always canonical (per derive_output_secrets)"),
    );
    let b_scalar: Zeroizing<Scalar> = Zeroizing::new(Scalar::from_bytes_mod_order(
        *keys.spend_sk.as_canonical_bytes(),
    ));
    let x_scalar: Zeroizing<Scalar> = Zeroizing::new(*ho_scalar + *b_scalar);
    let spend_key_x = Zeroizing::new(x_scalar.to_bytes());

    Ok(SourceSecretsBundle {
        spend_key_x,
        spend_key_y: Zeroizing::new(secrets.y),
        commitment_mask: Zeroizing::new(secrets.z),
        combined_ss: Zeroizing::new(combined_ss.0.to_vec()),
        output_index,
    })
}

/// `KI = x·Hp(O)` for one funding record, from its public
/// `(ciphertext, index, output_key)` identity and the owning persona's
/// vaulted keys — **the** single definition of the funding key image
/// (SP-R0 arm #1). Every consumer — the actor's watch derive-on-add, the
/// assemble path ([`prepare_funding_inputs`] via
/// [`key_image_from_spend_key_x`], sharing the leg after its own bundle
/// derivation), and the DQ-F fire harness — derives through here, so the
/// construction cannot diverge between the watch and the sweep. A divergence
/// would mean derived watch key images stop matching on-chain spends, prunes
/// never fire, and the stale-record poison [`SpentRecordsDurablyPruned`]
/// precludes returns — which is why this is one function, not three copies.
///
/// The derived intermediates are `Zeroizing`; only the key image leaves.
/// Errors are public reason text, never key material.
pub(crate) fn derive_funding_key_image(
    keys: &ArchivalPKeys,
    ciphertext_x25519: [u8; 32],
    ciphertext_ml_kem: &[u8],
    index_in_transaction: u64,
    output_key: [u8; 32],
) -> Result<[u8; 32], String> {
    let ciphertext = HybridCiphertext {
        x25519: ciphertext_x25519,
        ml_kem: ciphertext_ml_kem.to_vec(),
    };
    let bundle = derive_p_source_secrets_bundle(keys, &ciphertext, index_in_transaction)
        .map_err(|e| format!("spend-bundle derivation: {e}"))?;
    key_image_from_spend_key_x(&bundle.spend_key_x, output_key)
}

/// The key-image leg of [`derive_funding_key_image`] alone — for the
/// assemble path, which already holds the derived bundle (it needs the
/// bundle's other secrets too) and must compute the same `KI = x·Hp(O)` the
/// FCMP++ verifier checks.
pub(crate) fn key_image_from_spend_key_x(
    spend_key_x: &[u8; 32],
    output_key: [u8; 32],
) -> Result<[u8; 32], String> {
    let x_scalar: Zeroizing<Scalar> = Zeroizing::new(
        Option::from(Scalar::from_canonical_bytes(*spend_key_x))
            .ok_or_else(|| "non-canonical x".to_owned())?,
    );
    Ok((biased_hash_to_point(output_key) * *x_scalar)
        .compress()
        .to_bytes())
}

/// Draw an entry gap and check for the double-jitter-trap degeneracy pattern
/// (S5, Round 3 — per-draw guard, float-free, integer-only).
///
/// Draws twice from `rng`. If the two `spread` values are equal, the guard
/// fires and [`DegenerateDraw`] is returned — the caller maps this to
/// [`StakeEngineError::RngDegeneracy`]. On success, the first draw's `spread`
/// is returned; the probe draw is consumed and discarded.
///
/// **Why two draws?** The double-jitter trap produces a triangular spread
/// distribution (peaked at 0) by computing `|a - b|`; consecutive draws from
/// such a source are statistically likely to cluster. Two consecutive equal
/// spreads from a correct CSPRNG occur with probability ≈ 1/(window+1) ≈
/// 0.17 % — rare enough to fire on a stuck RNG without triggering excessive
/// retries on a correct one.
///
/// **False-positive handling:** the caller (the `PlanBondPost` handler) surfaces
/// `RngDegeneracy` and the user retries. A single false positive in 601 bond
/// requests is acceptable; multiple consecutive false positives signal a
/// broken entropy source.
///
/// **Extracted for testability** (S7(b)): tests feed degenerate `GapRng`
/// implementations directly into this function without going through the actor
/// or `OsRng`.
///
/// # Precondition: `window > 0`
///
/// A zero-width window draws `spread == 0` deterministically on every call, so
/// the two probe draws are *trivially* equal and the guard would fire — but that
/// is a **window misconfiguration**, not RNG degeneracy: a zero-width standoff
/// provides no funding↔bond-post decorrelation, defeating the gate-6 firewall
/// the draw exists to serve. The operational caller always passes
/// [`DEFAULT_ENTRY_GAP`] (600), so a zero window is unreachable in
/// production; the `debug_assert` catches any future misuse loudly in test/debug
/// builds rather than silently mislabelling it as `RngDegeneracy`. (More
/// generally the guard is only well-behaved for windows large enough that
/// `1/(window+1)` is an acceptable false-positive rate — 600 gives ≈ 0.17 %.)
///
/// The draw yields a single `spread` — there is no order coin (retired: only the
/// bond post is chain-attributable, so there is no second event to order,
/// `ARCHIVAL_FIREWALL_GATE6.md` method note 8).
pub(crate) fn draw_entry_gap_guarded<R: GapRng>(
    window: u64,
    rng: &mut R,
) -> Result<u64, DegenerateDraw> {
    debug_assert!(
        window > 0,
        "entry-gap window must be > 0: a zero-width standoff provides no \
         decorrelation and makes the degeneracy guard fire unconditionally; \
         pass the operational DEFAULT_ENTRY_GAP window"
    );
    let spread_draw = draw_entry_gap(window, rng);
    let spread_probe = draw_entry_gap(window, rng);
    if spread_draw == spread_probe {
        return Err(DegenerateDraw);
    }
    Ok(spread_draw)
}
