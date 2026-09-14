// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared C-4 fixtures for stake-engine and claim_orchestrator KATs.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::{derive_archival_p_keys, ArchivalPKeys};
use shekyl_crypto_pq::output::construct_output;
use shekyl_curve_generators::biased_hash_to_point;
use shekyl_engine_state::pscan_state::{MintLineageOutput, PFundingOutputRecord};
use shekyl_tx_builder::LeafEntry;

use super::{PSlot, StakeEngineHandle};
use crate::engine::test_support::funding_record;

/// Deterministic test seed (matches the `archival_p` module's KAT fixture).
pub(crate) const TEST_SEED: [u8; MASTER_SEED_BYTES] = [0x33u8; MASTER_SEED_BYTES];

/// One tx-key for every fixture output (outputs differ by index).
pub(crate) const FIXTURE_TX_KEY: [u8; 32] = [0x5Au8; 32];

/// Derive a persona bundle for `p_slot` on mainnet/bip39 (a permitted pair).
/// Re-derivable on demand because `ArchivalPKeys` is `!Clone` and derivation
/// is deterministic — each spawn gets its own freshly-derived bundle.
pub(crate) fn derive_bundle(p_slot: u32) -> ArchivalPKeys {
    derive_archival_p_keys(
        &TEST_SEED,
        DerivationNetwork::Mainnet,
        SeedFormat::Bip39,
        p_slot,
    )
    .expect("oracle derivation succeeds for mainnet/bip39")
}

/// Spawn a handle over a pre-derived derive-forward set: `held` slots, of
/// which `bonded` carry a live bond, with optional initial `active` slot.
pub(crate) fn spawn_over(held: &[u32], bonded: &[u32], active: Option<u32>) -> StakeEngineHandle {
    let bundles: BTreeMap<PSlot, ArchivalPKeys> = held
        .iter()
        .map(|&s| (PSlot::from_raw(s), derive_bundle(s)))
        .collect();
    let bonded: BTreeSet<PSlot> = bonded.iter().map(|&s| PSlot::from_raw(s)).collect();
    StakeEngineHandle::spawn(bundles, bonded, active.map(PSlot::from_raw))
}

/// A REAL P-paid output for `keys`: a funding record carrying the
/// exact public identity `construct_output` emitted (so the actor's
/// re-derivation chain — combined-ss recovery, spend/mask scalars,
/// per-output PQC keypair — reproduces the construction) plus the
/// matching curve-tree leaf with the REAL `CM.x` (`PL-D3`). The real value
/// is load-bearing: the signer re-derives the leaf opening from the
/// record's secrets and refuses if the leaf is not that derivation, and
/// the verifier's circuit opens the leaf to the backing key's point.
pub(crate) fn constructed_record(
    keys: &ArchivalPKeys,
    gindex: u64,
    height: u64,
    amount: u64,
    index_in_transaction: u64,
    lineage: MintLineageOutput,
) -> (PFundingOutputRecord, LeafEntry) {
    let (record, leaf, _entry) =
        constructed_record_with_entry(keys, gindex, height, amount, index_in_transaction, lineage);
    (record, leaf)
}

/// [`constructed_record`] plus the output's 64-byte `0x07` entry
/// (`CM ‖ record`, `PL-D3`) — what a test that ingests the output into a
/// real curve-tree client must publish for it, since the client slices one
/// entry per output and takes the commitment point from it.
pub(crate) fn constructed_record_with_entry(
    keys: &ArchivalPKeys,
    gindex: u64,
    height: u64,
    amount: u64,
    index_in_transaction: u64,
    lineage: MintLineageOutput,
) -> (PFundingOutputRecord, LeafEntry, [u8; 64]) {
    let constructed = construct_output(
        &FIXTURE_TX_KEY,
        &keys.x25519_pk,
        &keys.ml_kem_ek,
        keys.spend_pk.as_canonical_bytes(),
        amount,
        index_in_transaction,
    )
    .expect("fixture output constructs");
    let mut record = funding_record(0, gindex, height, amount, lineage);
    record.index_in_transaction = index_in_transaction;
    record.output_key = constructed.output_key;
    record.commitment = constructed.commitment;
    record.ciphertext_x25519 = constructed.kem_ciphertext_x25519;
    record.ciphertext_ml_kem = constructed.kem_ciphertext_ml_kem.clone();
    let leaf = LeafEntry {
        output_key: constructed.output_key,
        key_image_gen: biased_hash_to_point(constructed.output_key)
            .compress()
            .to_bytes(),
        commitment: constructed.commitment,
        cm_x: shekyl_fcmp::PqcLeafScalar::from_commitment_point(&constructed.pqc_leaf.point)
            .expect("constructed leaf commitment decompresses")
            .0,
    };
    (record, leaf, constructed.pqc_leaf.entry_bytes())
}
