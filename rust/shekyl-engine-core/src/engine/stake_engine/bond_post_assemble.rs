// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared prove / sign / encode tail for a bond-post transaction.
//!
//! [`AssembleBond`] and [`AssembleUnbond`] are debit/credit twins of one
//! wire shape: funding spends + one bond-post extra input + two confidential
//! vouts to `P`'s base + `pqc_auths` with the bond slot last. The policy
//! that differs — funding equation, extra-term side, which key signs the
//! bond slot — stays at the call site. This module is the mechanical tail
//! both handlers already shared by copy.
//!
//! The drain path established the composition: a thin actor handler, and a
//! single constructor so two callers cannot drift (`drain_assembly` /
//! `assemble_transfer_wire`). This is that constructor for bond posts.
//!
//! **GF-1 is not a parameter of this function.** The caller builds
//! [`BondPostAssembleArgs::bond_auth_pk`] and the `sign_bond_slot` closure
//! from the named key. A "which key" bag would hide the one fact the exit
//! exists to keep visible: a debit signs with `bond_spend_sk`, a credit with
//! `hybrid_sign_sk`.

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::Scalar;
use rand_core::RngCore as _;
use shekyl_archival_retention::bond_post::bond_post_funding_floor_met;
use shekyl_archival_retention::bond_wire::ArchivalBondPostVin;
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_scanner::extra::Extra;
use shekyl_tx_builder::{
    phase1_payload_hashes, sign_pqc_auths, sign_transaction_with_terms,
    tx_prefix_hash_from_parts_with_extra, InputTerm, OutputTerm, PqcAuth, TreeContext,
    WireEncodeInput,
};
use shekyl_types::{GlobalOutputIndex, PCanonicalId};
use shekyl_units::AtomicUnits;
use shekyl_wire::Input;
use zeroize::Zeroizing;

use super::helpers::{construct_vouts_to_base, prepare_funding_inputs, ConstructedVouts};
use crate::engine::bond_assembly::{
    finalize_bond_tx, wire_bond_post_input, BondAssemblyError, FundingInputContext, PBoundBytes,
};

/// Inputs the shared tail does not decide: amounts, terms, vin, and the
/// already-encoded bond-slot public key.
///
/// `extra_input_terms` is the debit side; `extra_output_terms` is the credit
/// side. Swapping them balances a *different* transaction than the one being
/// built — that is why the sides are two fields, not one signed term.
pub(crate) struct BondPostAssembleArgs<'a> {
    /// Resident persona bundle. Secrets stay in this frame (rule 36).
    pub keys: &'a ArchivalPKeys,
    /// Canonical id the bytes will be bound to (pin P-1).
    pub persona: PCanonicalId,
    /// Selected funding inputs; consumed (membership vecs move into spends).
    pub funding: Vec<FundingInputContext>,
    /// Curve-tree context the paths were assembled against.
    pub tree_ctx: TreeContext,
    /// Canonical weight-priced fee.
    pub fee: u64,
    /// The two confidential output amounts (daemon `vout.size() < 2` rejects).
    pub amounts: [u64; 2],
    /// Cleartext terms on the input side of the CT balance (Unbond debit).
    pub extra_input_terms: Vec<InputTerm>,
    /// Cleartext terms on the output side of the CT balance (JoinMarket credit).
    pub extra_output_terms: Vec<OutputTerm>,
    /// The constructed vin — the single source of the prefix bond-post input.
    pub vin: &'a ArchivalBondPostVin,
    /// Public key that occupies the bond `pqc_auths` slot. Built at the call
    /// site from the named key (identity for credit, `bond_spend_pk` for debit).
    pub bond_auth_pk: Vec<u8>,
    /// Failure-site label for vout construction.
    pub output_site: &'static str,
}

/// Persona-bound wire bytes plus the spent funding gindexes.
pub(crate) struct AssembledBondPostTx {
    pub bound_tx: PBoundBytes,
    pub funding_gindexes: Vec<GlobalOutputIndex>,
}

/// Refuse an empty funding set under the consensus name.
///
/// Handlers call this **before** amount arithmetic so empty funding is
/// `FundingInputsRequired` on both credit and debit, matching the chain.
/// [`assemble_signed_bond_post`] calls it again so a future caller cannot skip it.
pub(crate) fn require_funding_inputs(count: usize) -> Result<(), BondAssemblyError> {
    if bond_post_funding_floor_met(count) {
        Ok(())
    } else {
        Err(BondAssemblyError::FundingInputsRequired)
    }
}

/// Prove, sign, encode, and mint a bond-post transaction.
///
/// `sign_bond_slot` is invoked with the phase-1 payload hash of the bond
/// slot and must return that slot's canonical signature bytes. The caller
/// closes over the named secret.
pub(crate) async fn assemble_signed_bond_post(
    args: BondPostAssembleArgs<'_>,
    sign_bond_slot: impl FnOnce(&[u8; 32]) -> Result<Vec<u8>, BondAssemblyError>,
) -> Result<AssembledBondPostTx, BondAssemblyError> {
    require_funding_inputs(args.funding.len())?;

    let mut tx_key_secret = Zeroizing::new([0u8; 32]);
    rand_core::OsRng.fill_bytes(tx_key_secret.as_mut());
    let tx_pubkey = &Scalar::from_bytes_mod_order(*tx_key_secret) * ED25519_BASEPOINT_TABLE;

    let ConstructedVouts {
        output_infos,
        output_keys,
        view_tags,
        kem_blobs,
        leaf_hash_blob,
    } = construct_vouts_to_base(
        args.keys,
        &tx_key_secret,
        &args.amounts,
        args.output_site,
        |_, _| {},
    )?;

    let mut extra = Extra::for_hybrid_transfer(tx_pubkey, kem_blobs);
    extra.push_pqc_leaf_hashes(leaf_hash_blob);
    let tx_extra = extra.serialize();

    let prepared = prepare_funding_inputs(args.keys, args.funding)?;
    let key_images: Vec<[u8; 32]> = prepared.iter().map(|p| p.key_image).collect();
    let funding_gindexes: Vec<GlobalOutputIndex> = prepared.iter().map(|p| p.gindex).collect();

    let prefix_bond_input: Input = wire_bond_post_input(args.vin)?;
    let extra_inputs = vec![prefix_bond_input];

    let prefix_hash = tx_prefix_hash_from_parts_with_extra(
        &key_images,
        &extra_inputs,
        &output_keys,
        &vec![0; output_keys.len()],
        &view_tags,
        &tx_extra,
    )
    .map_err(|e| BondAssemblyError::build("prefix hash", e))?;

    let mut spend_inputs = Vec::with_capacity(prepared.len());
    let mut pqc_pubkeys = Vec::with_capacity(prepared.len());
    for p in prepared {
        spend_inputs.push(p.spend);
        pqc_pubkeys.push(p.pqc_pubkey);
    }
    let outputs_for_prove = output_infos.clone();
    let tree = args.tree_ctx.clone();
    let fee = args.fee;
    let extra_input_terms = args.extra_input_terms;
    let extra_output_terms = args.extra_output_terms;
    let (signed, spend_inputs) = tokio::task::spawn_blocking(move || {
        sign_transaction_with_terms(
            prefix_hash,
            &spend_inputs,
            &outputs_for_prove,
            AtomicUnits::from_raw(fee),
            &extra_input_terms,
            &extra_output_terms,
            &tree,
        )
        .map(|signed| (signed, spend_inputs))
    })
    .await
    .map_err(|e| BondAssemblyError::build("proving offload join", e))?
    .map_err(|e| BondAssemblyError::build("proving", e))?;

    let bulletproof = Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice())
        .map_err(|e| BondAssemblyError::build("bulletproof parse", e))?;

    let mut wire = WireEncodeInput {
        key_images,
        extra_inputs,
        output_amounts: vec![0; output_keys.len()],
        output_keys,
        view_tags,
        tx_extra,
        fee,
        enc_amounts: signed.enc_amounts,
        enc_labels: signed.enc_labels,
        out_commitments: signed.commitments,
        pseudo_outs: signed.pseudo_outs,
        bulletproof,
        reference_block: signed.reference_block,
        fcmp_proof: signed.fcmp_proof,
        pqc_auths: pqc_pubkeys
            .into_iter()
            .map(|pk| PqcAuth {
                auth_version: 1,
                signature: Vec::new(),
                public_key: pk,
            })
            .chain(std::iter::once(PqcAuth {
                auth_version: 1,
                signature: Vec::new(),
                public_key: args.bond_auth_pk.clone(),
            }))
            .collect(),
        fcmp_layers: signed.tree_depth,
    };

    let payload_hashes = phase1_payload_hashes(&wire)
        .map_err(|e| BondAssemblyError::build("phase1 payload hash", e))?;
    if payload_hashes.len() != spend_inputs.len() + 1 {
        return Err(BondAssemblyError::build(
            "phase1 payload hash",
            format!(
                "expected {} payload hashes, got {}",
                spend_inputs.len() + 1,
                payload_hashes.len()
            ),
        ));
    }
    let mut pqc_auths = sign_pqc_auths(&payload_hashes[..spend_inputs.len()], &spend_inputs)
        .map_err(|e| BondAssemblyError::build("pqc auth signing", e))?;
    let bond_payload_hash = payload_hashes[spend_inputs.len()];
    let bond_sig = sign_bond_slot(&bond_payload_hash)?;
    pqc_auths.push(PqcAuth {
        auth_version: 1,
        signature: bond_sig,
        public_key: args.bond_auth_pk,
    });
    wire.pqc_auths = pqc_auths;
    drop(spend_inputs);

    let bound_tx = finalize_bond_tx(args.persona, &wire)?;
    Ok(AssembledBondPostTx {
        bound_tx,
        funding_gindexes,
    })
}
