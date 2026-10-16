// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Open a proved spend and seal its extra auth slots.
//!
//! [`sign_transaction_with_terms`] returns proofs and an empty `pqc_auths`.
//! The payload hash of each prefix input covers that slot's public key, so
//! the keys have to be in place before any slot is signed, and a signature
//! cannot be filled in before its own hash exists. [`open_spend`] is that
//! sequence for every caller that builds a spend: it parses the range proof,
//! hashes every slot, signs the spend slots, and checks that each derived
//! spend key is the key the hash covered.
//!
//! An extra prefix input (a bond post, a reward-emission vin) occupies an
//! auth slot and no pseudo-out. Its key is hashed here with the spend keys;
//! its signature is the caller's, over [`OpenSpend::extra_payload`], and
//! [`OpenSpend::seal`] installs it. The builder stays bond-agnostic: an extra
//! slot is a public key plus a later signature, not a bond or emission type.
//!
//! Output construction and who holds the signing key stay at the call site.
//! A spend with no extra input seals with an empty signature list.

use shekyl_bulletproofs::Bulletproof;
use shekyl_types::SigningPayloadHash;
use shekyl_wire::Input;

use crate::error::TxBuilderError;
use crate::sign::sign_pqc_auths;
use crate::types::{PqcAuth, SignedProofs, SpendInput, PQC_AUTH_VERSION};
use crate::wire::{encode_final_tx, phase1_payload_hashes, WireEncodeInput};

/// Hybrid public keys that occupy `pqc_auths`, split by who signs them.
///
/// Spend slots are signed inside [`open_spend`] from the spend inputs. Extra
/// slots stay unsigned until [`OpenSpend::seal`]; the caller signs each one
/// over [`OpenSpend::extra_payload`]. Prefix order is spend slots, then extra
/// slots, matching `key_images` then `extra_inputs`.
#[derive(Clone, Debug)]
pub struct AuthSlots {
    /// One hybrid public key per spend input.
    pub spend: Vec<Vec<u8>>,
    /// One hybrid public key per extra (non-`ToKey`) prefix input.
    /// Empty when the spend has no extra input.
    pub extra: Vec<Vec<u8>>,
}

/// The prefix and the auth-slot keys of a spend whose proofs already exist.
///
/// Amounts, outputs, the fee, and the extra inputs are the caller's. This
/// type does not prove anything; [`open_spend`] refuses a layout whose slot
/// families do not match its prefix inputs.
#[derive(Clone, Debug)]
pub struct SpendLayout {
    /// Spend-input key images, prefix order.
    pub key_images: Vec<[u8; 32]>,
    /// Non-`ToKey` prefix inputs, appended after the spends. `Input::ToKey`
    /// here is rejected by the encoder: spends go through `key_images`.
    pub extra_inputs: Vec<Input>,
    /// One-time output keys.
    pub output_keys: Vec<[u8; 32]>,
    /// Per-output plaintext wire amount. `0` for a confidential output.
    /// A loud emission vout carries its consensus amount.
    pub output_amounts: Vec<u64>,
    /// Per-output view tag. `None` is rejected: genesis outputs carry one.
    pub view_tags: Vec<Option<u8>>,
    /// Serialized `tx_extra`.
    pub tx_extra: Vec<u8>,
    /// Cleartext fee, atomic units.
    pub fee: u64,
    /// Public keys for every auth slot.
    pub slots: AuthSlots,
}

/// A proved spend whose spend slots are signed and whose extra slots are not.
///
/// The phase-1 hashes were taken over [`SpendLayout::slots`]. [`OpenSpend::seal`]
/// fills the extra signatures and returns the wire input the encoder consumes.
#[derive(Debug)]
pub struct OpenSpend {
    wire: WireEncodeInput,
    /// Spend-slot count. The wire's `pqc_auths` is this many spend auths
    /// followed by the extra slots.
    spend_slots: usize,
    /// One payload hash per prefix input, spend slots first.
    payload_hashes: Vec<SigningPayloadHash>,
}

/// Placeholder auth: the version and the public key the payload hash reads,
/// and an empty signature. [`sign_pqc_auths`] replaces spend slots; [`OpenSpend::seal`]
/// replaces extra slots. The version matches the signed auth so the hash and
/// the final encoding agree on it.
fn placeholder_auth(public_key: Vec<u8>) -> PqcAuth {
    PqcAuth {
        auth_version: PQC_AUTH_VERSION,
        signature: Vec::new(),
        public_key,
    }
}

/// Sign the spend slots of a proved spend, leaving every extra slot open.
///
/// `signed` is the output of [`crate::sign_transaction_with_terms`] (or
/// [`crate::sign_transaction`]). `spend_inputs` are the inputs that were
/// proved, in the same order as `layout.key_images` and `layout.slots.spend`.
/// The layer count on the returned spend is `signed.tree_depth`: the FCMP++
/// layer count `L`, which the encoder serializes as `L - 1`.
///
/// # Errors
///
/// [`TxBuilderError::NoInputs`] when `spend_inputs` is empty.
/// [`TxBuilderError::WireError`] when the layout's key images, extra inputs,
/// or auth-slot families disagree, when the range proof does not parse, or
/// when phase 1 does not yield one payload hash per prefix input.
/// [`TxBuilderError::PqcSignError`] when a spend slot fails to sign, or when
/// the key derived for that slot is not the key the payload hash covered.
pub fn open_spend(
    signed: SignedProofs,
    spend_inputs: &[SpendInput],
    layout: SpendLayout,
) -> Result<OpenSpend, TxBuilderError> {
    let spend_slots = spend_inputs.len();
    if spend_slots == 0 {
        return Err(TxBuilderError::NoInputs);
    }
    if layout.key_images.len() != spend_slots {
        return Err(TxBuilderError::WireError(format!(
            "key images ({}) and spend inputs ({spend_slots}) disagree",
            layout.key_images.len()
        )));
    }
    if layout.slots.spend.len() != spend_slots {
        return Err(TxBuilderError::WireError(format!(
            "spend auth slots ({}) and spend inputs ({spend_slots}) disagree",
            layout.slots.spend.len()
        )));
    }
    if layout.slots.extra.len() != layout.extra_inputs.len() {
        return Err(TxBuilderError::WireError(format!(
            "extra auth slots ({}) and extra inputs ({}) disagree",
            layout.slots.extra.len(),
            layout.extra_inputs.len()
        )));
    }

    let bulletproof = Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice())
        .map_err(|e| TxBuilderError::WireError(format!("bulletproof parse: {e}")))?;

    let slot_count = spend_slots + layout.extra_inputs.len();
    let mut wire = WireEncodeInput {
        key_images: layout.key_images,
        extra_inputs: layout.extra_inputs,
        output_keys: layout.output_keys,
        output_amounts: layout.output_amounts,
        view_tags: layout.view_tags,
        tx_extra: layout.tx_extra,
        fee: layout.fee,
        enc_amounts: signed.enc_amounts,
        enc_labels: signed.enc_labels,
        out_commitments: signed.commitments,
        pseudo_outs: signed.pseudo_outs,
        bulletproof,
        reference_block: signed.reference_block,
        fcmp_proof: signed.fcmp_proof,
        pqc_auths: layout
            .slots
            .spend
            .into_iter()
            .chain(layout.slots.extra)
            .map(placeholder_auth)
            .collect(),
        fcmp_layers: signed.tree_depth,
    };

    let payload_hashes = phase1_payload_hashes(&wire)?;
    if payload_hashes.len() != slot_count {
        return Err(TxBuilderError::WireError(format!(
            "phase 1 produced {} payload hashes for {slot_count} prefix inputs",
            payload_hashes.len()
        )));
    }

    let spend_auths = sign_pqc_auths(&payload_hashes[..spend_slots], spend_inputs)?;
    for (index, (auth, slot)) in spend_auths.iter().zip(wire.pqc_auths.iter()).enumerate() {
        if auth.public_key != slot.public_key {
            return Err(TxBuilderError::PqcSignError {
                index,
                reason: "derived spend key is not the key the phase-1 payload hashed".into(),
            });
        }
    }
    for (slot, auth) in wire.pqc_auths.iter_mut().zip(spend_auths) {
        *slot = auth;
    }

    Ok(OpenSpend {
        wire,
        spend_slots,
        payload_hashes,
    })
}

impl OpenSpend {
    /// How many extra (non-spend) auth slots this spend carries.
    #[must_use]
    pub fn extra_slot_count(&self) -> usize {
        self.payload_hashes.len() - self.spend_slots
    }

    /// Payload hash of extra slot `index` (zero is the first extra input,
    /// not a spend).
    ///
    /// # Errors
    ///
    /// [`TxBuilderError::WireError`] when `index` is past the extra slots.
    pub fn extra_payload(&self, index: usize) -> Result<&SigningPayloadHash, TxBuilderError> {
        let at = self.spend_slots.checked_add(index).ok_or_else(|| {
            TxBuilderError::WireError(format!("extra auth slot index {index} overflows"))
        })?;
        self.payload_hashes.get(at).ok_or_else(|| {
            TxBuilderError::WireError(format!(
                "extra auth slot {index} is past the {} extra slot(s)",
                self.extra_slot_count()
            ))
        })
    }

    /// Payload hash of the one extra slot.
    ///
    /// The bond-post and emission-claim shapes each carry exactly one extra
    /// prefix input. A spend with any other extra-slot count is a different
    /// shape and uses [`Self::extra_payload`].
    ///
    /// # Errors
    ///
    /// [`TxBuilderError::WireError`] when this spend does not have exactly
    /// one extra slot.
    pub fn sole_extra_payload(&self) -> Result<&SigningPayloadHash, TxBuilderError> {
        let extra = self.extra_slot_count();
        if extra != 1 {
            return Err(TxBuilderError::WireError(format!(
                "sole extra payload requires exactly one extra auth slot, found {extra}"
            )));
        }
        self.extra_payload(0)
    }

    /// The FCMP++ membership proof blob, for a caller that verifies the
    /// spend before sealing it.
    #[must_use]
    pub fn fcmp_proof(&self) -> &[u8] {
        &self.wire.fcmp_proof
    }

    /// Per-spend pseudo-output commitments, in spend-input order.
    #[must_use]
    pub fn pseudo_outs(&self) -> &[[u8; 32]] {
        &self.wire.pseudo_outs
    }

    /// FCMP++ layer count `L` (`signed.tree_depth`). The encoder writes `L - 1`
    /// as `curve_trees_tree_depth`; a verifier reconstructs `L` from that field.
    #[must_use]
    pub fn layers(&self) -> u8 {
        self.wire.fcmp_layers
    }

    /// Install one signature per extra slot and return the wire input.
    ///
    /// Signatures are extra-slot order, which is prefix order after the
    /// spends. The public key hashed in phase 1 stays the key on the slot.
    ///
    /// # Errors
    ///
    /// [`TxBuilderError::WireError`] when `extra_signatures` does not cover
    /// every extra slot.
    pub fn seal(
        mut self,
        extra_signatures: Vec<Vec<u8>>,
    ) -> Result<WireEncodeInput, TxBuilderError> {
        let extra = self.extra_slot_count();
        if extra_signatures.len() != extra {
            return Err(TxBuilderError::WireError(format!(
                "extra signatures ({}) must cover every extra auth slot ({extra})",
                extra_signatures.len()
            )));
        }
        for (slot, signature) in self.wire.pqc_auths[self.spend_slots..]
            .iter_mut()
            .zip(extra_signatures)
        {
            slot.signature = signature;
        }
        Ok(self.wire)
    }

    /// [`Self::seal`], then the canonical encoder.
    ///
    /// # Errors
    ///
    /// The seal error, or [`TxBuilderError::WireError`] from the encoder.
    pub fn encode(self, extra_signatures: Vec<Vec<u8>>) -> Result<Vec<u8>, TxBuilderError> {
        encode_final_tx(&self.seal(extra_signatures)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SignedProofs;
    use shekyl_types::BlockHash;
    use shekyl_units::AtomicUnits;

    fn blank_signed() -> SignedProofs {
        SignedProofs {
            bulletproof_plus: Vec::new(),
            commitments: Vec::new(),
            enc_amounts: Vec::new(),
            enc_labels: Vec::new(),
            pseudo_outs: Vec::new(),
            fcmp_proof: Vec::new(),
            pqc_auths: Vec::new(),
            reference_block: BlockHash::from_bytes([0; 32]),
            tree_depth: 2,
        }
    }

    fn blank_spend() -> SpendInput {
        SpendInput {
            output_key: [0; 32],
            commitment: [0; 32],
            amount: AtomicUnits::from_raw(1),
            spend_key_x: [0; 32],
            spend_key_y: [0; 32],
            commitment_mask: [0; 32],
            combined_ss: vec![0; 64],
            output_index: 0,
            leaf_chunk: Vec::new(),
            c1_layers: Vec::new(),
            c2_layers: Vec::new(),
        }
    }

    fn layout_with(spend_keys: usize, extra_inputs: usize, extra_keys: usize) -> SpendLayout {
        SpendLayout {
            key_images: vec![[1; 32]; spend_keys],
            extra_inputs: vec![Input::Gen(0); extra_inputs],
            output_keys: vec![[2; 32]],
            output_amounts: vec![0],
            view_tags: vec![Some(1)],
            tx_extra: Vec::new(),
            fee: 0,
            slots: AuthSlots {
                spend: vec![vec![3]; spend_keys],
                extra: vec![vec![4]; extra_keys],
            },
        }
    }

    #[test]
    fn open_spend_refuses_an_empty_spend() {
        let err = open_spend(blank_signed(), &[], layout_with(0, 0, 0)).unwrap_err();
        assert!(matches!(err, TxBuilderError::NoInputs));
    }

    #[test]
    fn open_spend_refuses_a_key_image_count_mismatch() {
        let err = open_spend(blank_signed(), &[blank_spend()], layout_with(2, 0, 0)).unwrap_err();
        assert!(matches!(err, TxBuilderError::WireError(_)));
    }

    #[test]
    fn open_spend_refuses_an_extra_slot_count_mismatch() {
        let err = open_spend(blank_signed(), &[blank_spend()], layout_with(1, 1, 0)).unwrap_err();
        assert!(matches!(err, TxBuilderError::WireError(_)));
    }
}
