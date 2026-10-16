// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A bond post riding a spend. The spender lists it as the transaction's
//! `Input::BondPost`, balances the cleartext term on the side the kind
//! fixes, and has it sign the bond slot (the last `pqc_auths` entry) over
//! the same phase-1 payload hash the spend's inputs sign.
//!
//! The persona that builds the post — the vin constructors, the keys, the
//! holdings — lives with the ingest's archival driver; what the spender
//! needs is only the input, the term, and the signer, which is this type.

use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridSecretKey, SignatureScheme as _, SCHEME_DOMAIN_PQC_AUTH_TX,
};
use shekyl_tx_builder::{InputTerm, OutputTerm};
use shekyl_types::SigningPayloadHash;
use shekyl_wire::Input;

/// A bond post riding a spend: the prefix input, the cleartext term on the
/// side the kind fixes, and the key that signs the bond `pqc_auths` slot.
///
/// The term is two `Option`s, not one signed amount, for the reason the
/// production assembler gives: swapping the sides balances a different
/// transaction than the one being built.
pub struct PostedBond<'a> {
    /// The `Input::BondPost` as it goes on the wire.
    pub input: Input,
    /// A debit — released collateral entering as a **source** (Release).
    pub debit: Option<InputTerm>,
    /// A credit — the bond leaving as a **sink** (JoinMarket).
    pub credit: Option<OutputTerm>,
    /// The public key occupying the bond slot (the last `pqc_auths` entry).
    pub slot_pk: Vec<u8>,
    /// The key that signs the slot: the identity key for a credit,
    /// `bond_spend_sk` for a debit.
    slot_sk: &'a HybridSecretKey,
}

impl<'a> PostedBond<'a> {
    /// A post whose slot `slot_sk` signs. `slot_pk` is the public half the
    /// vin carries — the identity key for a join or a reinstate, the bond
    /// spend key for a release; the caller pairs them, as the production
    /// assembler does.
    #[must_use]
    pub fn signed_by(
        input: Input,
        debit: Option<InputTerm>,
        credit: Option<OutputTerm>,
        slot_pk: Vec<u8>,
        slot_sk: &'a HybridSecretKey,
    ) -> Self {
        Self {
            input,
            debit,
            credit,
            slot_pk,
            slot_sk,
        }
    }

    /// The bond slot's signature over its phase-1 payload hash — the
    /// production assembler's `sign_bond_slot`, verbatim.
    #[must_use]
    pub fn sign_slot(&self, payload: &SigningPayloadHash) -> Vec<u8> {
        HybridEd25519MlDsa
            .sign(self.slot_sk, SCHEME_DOMAIN_PQC_AUTH_TX, payload.as_bytes())
            .expect("the persona's key signs")
            .to_canonical_bytes()
            .expect("a hybrid signature encodes")
    }
}
