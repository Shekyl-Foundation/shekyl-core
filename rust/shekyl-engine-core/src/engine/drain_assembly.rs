// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! F-D2 — the `P`→principal **drain** assembly (`ARCHIVAL_P_DRAIN.md` §DS-PR-1).
//!
//! A drain moves value **out** of an archival persona's `P`-space back to the
//! wallet's own principal address: it spends the persona's sealed
//! [`PFundingOutputRecord`] funding slice (persona-keyed, exactly like a bond or
//! claim fee sweep) and produces a **transfer-shaped** transaction — a
//! confidential payment to the principal plus a confidential `P`-space change
//! output.
//!
//! # The composite wire-shape arm (T-DS-6 ∧ T-DS-7)
//!
//! The gate-6 firewall's value-out leg must not be a fingerprint: a drain's
//! **full wire serialization** is byte-identical to a modal 2-out confidential
//! transfer (modulo the hidden amounts). This module holds that property *by
//! construction* — it owns no wire-shaping decision of its own. Every leg is the
//! **same primitive the transfer path uses**, and the whole wire record is built
//! by the **single shared constructor**
//! [`assemble_transfer_wire`](super::sign_bridge::assemble_transfer_wire) that
//! [`sign_bridge::sign_tx`](super::sign_bridge) itself calls: transfer-parity is
//! then a compile-time fact (one constructor, two callers), not a property a test
//! has to re-establish.
//!
//! - **Wire record** is assembled by `assemble_transfer_wire` from the shared
//!   [`SignedProofs`](shekyl_tx_builder::SignedProofs), so the `WireEncodeInput`
//!   shape cannot drift from the transfer path.
//! - **Outputs** are built by [`build_output`] (the exact `sign_tx` output
//!   primitive), so a drain vout is bit-for-bit an ordinary transfer vout.
//! - **Spend inputs** come from [`prepare_funding_inputs`] (the exact bond/claim
//!   fee-sweep leg): persona-keyed derivation, key images, strict-descending
//!   order.
//! - **Prefix hash / proving / PQC auth** use the plain transfer calls
//!   ([`tx_prefix_hash_from_parts`], [`sign_transaction`],
//!   [`phase1_payload_hashes`] + [`sign_pqc_auths`]) with **empty
//!   `extra_inputs`** and **spend-only `pqc_auths`** — no bond `Input`, no
//!   identity auth slot, nothing that a bond/claim carries and a transfer does
//!   not.
//!
//! The one degree of freedom the shared constructor does *not* pin — that
//! split-on-drain-all reshapes the amounts without perturbing the skeleton — is
//! guarded by a **whole-tx normalized byte-diff** (`drain_assembly_shape::
//! drain_partial_and_drain_all_are_wire_identical`): partial and drain-all
//! serialize identically modulo the hidden/committed leaves.
//! - **Two nonzero outputs, always** (T-DS-6): every valid tx already carries
//!   `vout.size() >= 2` (consensus, `blockchain.cpp`) with **no zero-value**
//!   output (the shared transfer prover rejects `ZeroOutputAmount`), so the modal
//!   confidential tx is exactly *two nonzero* confidential outputs. A drain
//!   matches that shape in both regimes:
//!     - **partial** (`change > 0`): `[principal payment, P-space change]`;
//!     - **drain-all** (`change == 0`): the principal payment is **split into two
//!       nonzero principal outputs** `[principal a, principal b]` (a sweep to
//!       self) — never a single output plus a distinguishable zero-value change.
//!   Because Pedersen commitments are perfectly hiding, both regimes serialize to
//!   the same two-confidential-output wire shape; an observer cannot tell a
//!   partial drain from a drain-all, nor either from an ordinary 2-out transfer.
//!
//! # Change returns to `P`, not to principal (T-DS-3)
//!
//! On a **partial** drain the change output pays **`P`'s own base spend key**
//! (`keys.spend_pk`), the same destination the bond/claim change uses, so
//! residual `P` value re-enters the funding set on the next sweep and never
//! silently crosses the firewall to principal-space as an unrequested by-product
//! of the drain. On a **drain-all** there is no residual `P` value, so both
//! outputs are the (split) principal payment — nothing is left behind in `P` to
//! return. The principal destination is **not** caller-supplied — the
//! orchestrator resolves it engine-side from the wallet's own primary address
//! (see the [`DrainDestination`] doc).
//!
//! # Secret-locality (rule 36)
//!
//! Persona secrets are re-derived from each record's `(ciphertext, index)`
//! inside [`prepare_funding_inputs`] and never appear in this module's message
//! surface; the reply carries only the persona-bound [`PBoundBytes`] and the
//! spent funding gindexes (the reservation set).

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::Scalar;
use rand_core::{OsRng, RngCore as _};
use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_scanner::extra::Extra;
use shekyl_tx_builder::{
    phase1_payload_hashes, sign_pqc_auths, sign_transaction, tx_prefix_hash_from_parts, OutputInfo,
    TreeContext,
};
use shekyl_types::GlobalOutputIndex;
use shekyl_units::AtomicUnits;
use zeroize::Zeroizing;

use super::bond_assembly::{finalize_bond_tx, BondAssemblyError, FundingInputContext, PBoundBytes};
use super::sign_bridge::{assemble_transfer_wire, build_output};
use super::stake_engine::{prepare_funding_inputs, PersonaHandle, StakeEngineError};

/// The principal destination a drain pays to (vout 0).
///
/// **Not caller-supplied** (T-DS-3): the drain always pays the wallet's *own*
/// principal address, which the orchestrator resolves engine-side from the
/// master `LocalKeys` and packs into this value. Carrying only the public
/// halves (spend key, X25519 view half, ML-KEM encapsulation key) keeps the
/// message key-shaped-free — the same public triple the transfer path decodes
/// out of a `ShekylAddress`.
#[derive(Clone)]
pub(crate) struct DrainDestination {
    /// Principal base spend public key.
    pub spend_pk: [u8; 32],
    /// Principal view key's X25519 half (Montgomery), the KEM encapsulation
    /// target — the transfer path's `ed25519_pk_to_x25519_pk(view_key)`.
    pub x25519_pk: [u8; 32],
    /// Principal ML-KEM-768 encapsulation key.
    pub ml_kem_ek: Vec<u8>,
}

/// Assemble the **full, broadcast-ready** `P`→principal drain transaction
/// inside the actor (`ARCHIVAL_P_DRAIN.md` §DS-PR-1).
///
/// Carries the held-slot capability plus the **public** funding contexts the
/// Engine-side orchestrator selected and path-assembled (records, membership
/// paths, tree context), the resolved principal [`DrainDestination`], and the
/// payment/fee split. The spend secrets are **not** in the message — they are
/// re-derived from each record's `(ciphertext, index)` inside the handler
/// (rule 36).
///
/// Dead_code allow: the assembly handler lands here; the Engine orchestrator
/// entry (DS-PR-2) and the RPC drain entry are the remaining wiring (rule-21 —
/// reopened when the orchestrator dispatch consumes this message).
#[allow(dead_code)]
pub(crate) struct AssembleDrain {
    /// Operation-scoped capability proving the slot is currently held.
    pub handle: PersonaHandle,
    /// The selected funding inputs with their assembled membership paths —
    /// public identity + public tree data only.
    pub funding: Vec<FundingInputContext>,
    /// The curve-tree reference context the paths were assembled against.
    pub tree_ctx: TreeContext,
    /// The wallet's own principal destination (vout 0), resolved engine-side.
    pub dest: DrainDestination,
    /// Value to pay to the principal (vout 0). The `P`-space change (vout 1) is
    /// `available - payment_amount - fee`, possibly zero.
    pub payment_amount: u64,
    /// The fee the Engine-side selection was run against.
    pub fee: u64,
}

/// Reply of [`AssembleDrain`]: the persona-bound wire bytes (minted at the
/// single P-1 site, [`finalize_bond_tx`]) and the spent funding gindexes for
/// the caller's reservation record. Secrets never cross the boundary.
///
/// Dead_code allow: reply type of the assembly handler; same gate as
/// [`AssembleDrain`].
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct AssembledDrain {
    /// The fully-signed, wire-encoded drain transaction, persona-bound.
    pub bound_tx: PBoundBytes,
    /// The spent funding records' gindexes — the reservation set.
    pub funding_gindexes: Vec<GlobalOutputIndex>,
}

/// Assemble a signed, wire-encoded, **transfer-shaped** drain from persona
/// `keys`, the resolved principal `dest`, and the selected `funding` slice.
///
/// The heavy lifting of [`AssembleDrain`]; the actor handler
/// (`stake_engine.rs`) is the thin validate-and-delegate shell over this. See
/// the module doc for the composite wire-shape arm this function realizes.
///
/// `pub(super)`: the only caller is the [`AssembleDrain`] handler in the sibling
/// `stake_engine` module.
pub(super) async fn assemble_drain_tx(
    keys: &ArchivalPKeys,
    dest: &DrainDestination,
    funding: Vec<FundingInputContext>,
    tree_ctx: TreeContext,
    payment_amount: u64,
    fee: u64,
) -> Result<AssembledDrain, StakeEngineError> {
    // ── Step 1: funding arithmetic (checked). `available == payment + fee +
    // change` exactly; `change` is the residual returned to `P` (T-DS-3), zero
    // on a drain-all. ──
    let mut available: u64 = 0;
    for ctx in &funding {
        available = available
            .checked_add(ctx.record.amount.to_raw())
            .ok_or(BondAssemblyError::AmountOverflow)?;
    }
    let required = payment_amount
        .checked_add(fee)
        .ok_or(BondAssemblyError::AmountOverflow)?;
    if available < required {
        return Err(BondAssemblyError::InsufficientFunding {
            available,
            required,
        }
        .into());
    }
    let change = available - required;

    // ── Step 2: resolve the two output specs `[vout 0, vout 1]`. Every valid tx
    // carries exactly two NONZERO confidential outputs (consensus `vout >= 2` +
    // the shared prover's zero-output rejection), and a drain matches that modal
    // shape in both regimes (T-DS-6):
    //
    //   - partial (`change > 0`): [principal payment, P-space change] — the
    //     change returns to `P`'s own base spend key (T-DS-3);
    //   - drain-all (`change == 0`): the principal payment is SPLIT into two
    //     nonzero principal outputs (a sweep to self) — there is no residual `P`
    //     value to return, and a single output + zero-value change would be a
    //     distinguishable 1-out shape the prover rejects anyway.
    //
    // Because Pedersen commitments are perfectly hiding, both regimes serialize
    // to the same two-confidential-output wire shape. Each spec is
    // `(spend_pk, x25519_pk, ml_kem_ek, amount)`. ──
    struct OutSpec<'a> {
        spend_pk: &'a [u8; 32],
        x25519_pk: &'a [u8; 32],
        ml_kem_ek: &'a [u8],
        amount: u64,
    }
    let p_change_spec = OutSpec {
        spend_pk: keys.spend_pk.as_canonical_bytes(),
        x25519_pk: &keys.x25519_pk,
        ml_kem_ek: &keys.ml_kem_ek,
        amount: change,
    };
    let [spec0, spec1] = if change > 0 {
        [
            OutSpec {
                spend_pk: &dest.spend_pk,
                x25519_pk: &dest.x25519_pk,
                ml_kem_ek: &dest.ml_kem_ek,
                amount: payment_amount,
            },
            p_change_spec,
        ]
    } else {
        // Drain-all: split `payment_amount` into two nonzero halves, both to the
        // principal. Requires `payment_amount >= 2`; a 1-atomic net drain cannot
        // form two nonzero outputs (refused loudly — T-DS-6 never yields a 1-out).
        if payment_amount < 2 {
            return Err(StakeEngineError::DrainPaymentUnsplittable {
                net: payment_amount,
            });
        }
        let second = payment_amount / 2; // >= 1 for payment_amount >= 2
        let first = payment_amount - second; // >= 1
        [
            OutSpec {
                spend_pk: &dest.spend_pk,
                x25519_pk: &dest.x25519_pk,
                ml_kem_ek: &dest.ml_kem_ek,
                amount: first,
            },
            OutSpec {
                spend_pk: &dest.spend_pk,
                x25519_pk: &dest.x25519_pk,
                ml_kem_ek: &dest.ml_kem_ek,
                amount: second,
            },
        ]
    };

    // Both outputs built by the transfer path's `build_output` primitive, so a
    // drain vout is bit-for-bit an ordinary transfer vout.
    let mut tx_key_secret = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(tx_key_secret.as_mut());
    let tx_pubkey = &Scalar::from_bytes_mod_order(*tx_key_secret) * ED25519_BASEPOINT_TABLE;

    let vout0 = build_output(
        &tx_key_secret,
        spec0.spend_pk,
        spec0.x25519_pk,
        spec0.ml_kem_ek,
        spec0.amount,
        0,
    )
    .map_err(|e| BondAssemblyError::build("drain vout0 construction", e))?;
    let vout1 = build_output(
        &tx_key_secret,
        spec1.spend_pk,
        spec1.x25519_pk,
        spec1.ml_kem_ek,
        spec1.amount,
        1,
    )
    .map_err(|e| BondAssemblyError::build("drain vout1 construction", e))?;

    let built_outputs = [vout0, vout1];
    let output_infos: Vec<OutputInfo> = built_outputs.iter().map(|b| b.info.clone()).collect();
    let output_keys: Vec<[u8; 32]> = built_outputs.iter().map(|b| b.output_key).collect();
    let view_tags: Vec<Option<u8>> = built_outputs.iter().map(|b| b.view_tag).collect();
    let kem_blobs: Vec<Vec<u8>> = built_outputs.iter().map(|b| b.kem_blob.clone()).collect();
    let leaf_hash_blob: Vec<u8> = built_outputs.iter().flat_map(|b| b.h_pqc).collect();

    // ── Step 3: tx_extra — tx pubkey + per-output KEM blobs + the `0x07` PQC
    // leaf hashes (identical layout + order to the transfer path; without the
    // `0x07` field the outputs ingest with a zero `h_pqc` leaf and are
    // unspendable). ──
    let mut extra = Extra::for_hybrid_transfer(tx_pubkey, kem_blobs);
    extra.push_pqc_leaf_hashes(leaf_hash_blob);
    let tx_extra = extra.serialize();

    // ── Step 4: persona-keyed spend inputs — the shared bond/claim fee-sweep
    // leg (rule 36: secrets re-derived inside; strict-descending key-image
    // order). ──
    let prepared = prepare_funding_inputs(keys, funding)?;
    let key_images: Vec<[u8; 32]> = prepared.iter().map(|p| p.key_image).collect();
    let funding_gindexes: Vec<GlobalOutputIndex> = prepared.iter().map(|p| p.gindex).collect();

    // ── Step 5: prefix hash from PUBLIC parts — the plain transfer variant
    // (`tx_prefix_hash_from_parts`, NO `extra_inputs`): a drain carries no bond
    // `Input`, so its prefix is exactly a transfer's. Confidential amounts
    // (wire 0) are derived from the output count, same as the wire encode
    // below, so the two sites cannot disagree on arity. ──
    let prefix_hash = tx_prefix_hash_from_parts(&key_images, &output_keys, &view_tags, &tx_extra);

    // ── Step 6: offload proving (Bp+ + FCMP membership) to `spawn_blocking`
    // (SP-5 pattern). SpendInputs (owned secrets) MOVE into the closure and
    // come back for the fast inline PQC signing; the caller holds `&mut self`
    // across the await so the mailbox cannot interleave. ──
    let mut spend_inputs = Vec::with_capacity(prepared.len());
    let mut pqc_pubkeys = Vec::with_capacity(prepared.len());
    for p in prepared {
        spend_inputs.push(p.spend);
        pqc_pubkeys.push(p.pqc_pubkey);
    }
    let outputs_for_prove = output_infos.clone();
    let tree = tree_ctx;
    let (signed, spend_inputs) = tokio::task::spawn_blocking(move || {
        sign_transaction(
            prefix_hash,
            &spend_inputs,
            &outputs_for_prove,
            AtomicUnits::from_raw(fee),
            &tree,
        )
        .map(|signed| (signed, spend_inputs))
    })
    .await
    .map_err(|e| BondAssemblyError::build("drain proving offload join", e))?
    .map_err(|e| BondAssemblyError::build("drain proving", e))?;

    // ── Step 7: assemble the wire input through the SHARED transfer-wire
    // constructor (`sign_bridge::assemble_transfer_wire`) — the exact same
    // constructor `sign_bridge::sign_tx` uses. Empty `extra_inputs`, all-zero
    // (confidential) `output_amounts`, one placeholder `pqc_auth` per spend (no
    // bond identity slot). Routing both paths through one constructor is what
    // makes a drain byte-shape-identical to a modal transfer *by construction*
    // (T-DS-6 ∧ T-DS-7), rather than by a hand-copied literal that could drift.
    // ──
    let mut wire = assemble_transfer_wire(
        key_images,
        output_keys,
        view_tags,
        tx_extra,
        fee,
        &signed,
        &pqc_pubkeys,
    )
    .map_err(|e| BondAssemblyError::build("drain wire assembly", e))?;

    // ── Step 8: PQC auth completion (fast; inline). One payload hash per spend
    // slot — no `+1` bond slot (the byte-shape difference between a drain and a
    // bond is exactly this: a drain has no identity auth). ──
    let payload_hashes = phase1_payload_hashes(&wire)
        .map_err(|e| BondAssemblyError::build("phase1 payload hash", e))?;
    if payload_hashes.len() != spend_inputs.len() {
        return Err(BondAssemblyError::build(
            "phase1 payload hash",
            format!(
                "expected {} payload hashes, got {}",
                spend_inputs.len(),
                payload_hashes.len()
            ),
        )
        .into());
    }
    wire.pqc_auths = sign_pqc_auths(&payload_hashes, &spend_inputs)
        .map_err(|e| BondAssemblyError::build("pqc auth signing", e))?;
    drop(spend_inputs); // secrets end here; nothing below needs them

    // ── Step 9: encode + mint at the P-1 site. The drain is a P-spend, so its
    // bytes are persona-bound exactly like a bond/claim. ──
    let hybrid_pk_bytes = keys
        .hybrid_sign_pk
        .to_canonical_bytes()
        .map_err(|e| BondAssemblyError::build("identity encoding", e))?;
    let persona = p_canonical_id_from_hybrid_pubkey(&hybrid_pk_bytes);
    let bound_tx = finalize_bond_tx(persona, &wire)?;

    Ok(AssembledDrain {
        bound_tx,
        funding_gindexes,
    })
}
