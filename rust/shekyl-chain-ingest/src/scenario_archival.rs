// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Archival bodies for the scenario driver (DRS-E4 commit 4,
//! `DRS_E4_ARCHIVAL_WRITER.md` §6 row 4): a persona whose bond posts ride
//! the driver's real spend, and the serve credit it responds with.
//!
//! What is real: the persona's keys (`derive_archival_p_keys`, the wallet's
//! derivation from a master seed and a slot); the post (`build_join_market_vin`
//! / `build_release_vin`, the constructors `shekyl-engine-core`'s
//! `AssembleBond` / `AssembleRelease` call, so the vin carries the identity
//! key, the derived `P_canonical_id`, the floor-priced total and the
//! genesis-frozen term side); the transaction around it
//! ([`Spender::spend_coinbase_posting`](crate::scenario_spend::Spender::spend_coinbase_posting):
//! funding spend, two confidential outputs, `sign_transaction_with_terms`
//! with the post's term on its side, the bond slot last in `pqc_auths` and
//! signed by the named key — the identity key for a credit, `bond_spend_sk`
//! for a debit, GF-1's one visible fact). CEN-H21 judges the balance with
//! the terms, CEN-I18 verifies every slot's signature, and CEN-L7 judges the
//! post over the store's view — the same path a wallet's post takes.
//!
//! What is not the subject: a serve credit's Ed25519 countersignature. The
//! kept half is the production wire type ([`ArchivalServeCreditResponse`])
//! and the transaction is CEN-H20's shape, but no Rust countersigner exists
//! (the challenger side is not built) and no rule verifies the
//! countersignature (CEN-J1/J4/J10 pending in the census), so the bytes here
//! are a marker, not a signature. When J10 lands, [`Persona::serve_credit`]
//! is where the signer goes.
//!
//! The vin-to-wire mapping is
//! [`shekyl_archival_bond_builder::bond_post_input`]: every
//! [`shekyl_archival_retention::BondKind`] has one image there, and this
//! driver calls it. The wallet's `wire_bond_post_input` is the producer
//! policy over that same function.

use shekyl_archival_bond_builder::{bond_post_input, build_join_market_vin, build_release_vin};
use shekyl_archival_retention::{
    p_canonical_id_from_hybrid_pubkey, ArchivalServeCreditResponse, HoldingsDescriptor,
    HoldingsKind,
};
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::{derive_archival_p_keys, ArchivalPKeys};
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridSecretKey, SignatureScheme as _, SCHEME_DOMAIN_PQC_AUTH_TX,
};
use shekyl_tx_builder::{InputTerm, OutputTerm};
use shekyl_types::{PCanonicalId, SigningPayloadHash};
use shekyl_wire::transaction::{BondPost, TxPrefix};
use shekyl_wire::{Ct, CtBase, Input, Transaction};

/// The driver's persona master seed. Any 64 bytes; fixed so the personas
/// (and their canonical ids) are the same in every run.
const MASTER: [u8; MASTER_SEED_BYTES] = [0x51; MASTER_SEED_BYTES];

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

impl PostedBond<'_> {
    /// The bond slot's signature over its phase-1 payload hash — the
    /// production assembler's `sign_bond_slot`, verbatim.
    pub fn sign_slot(&self, payload: &SigningPayloadHash) -> Vec<u8> {
        HybridEd25519MlDsa
            .sign(self.slot_sk, SCHEME_DOMAIN_PQC_AUTH_TX, payload.as_bytes())
            .expect("the persona's key signs")
            .to_canonical_bytes()
            .expect("a hybrid signature encodes")
    }
}

/// An archival persona: the keys a wallet derives for slot `p_slot`.
pub struct Persona {
    keys: ArchivalPKeys,
}

impl Persona {
    /// Derive the persona at `p_slot` from the driver's master seed.
    pub fn at(p_slot: u32) -> Self {
        let keys = derive_archival_p_keys(
            &MASTER,
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
            p_slot,
        )
        .expect("the driver's seed derives a persona");
        Self { keys }
    }

    /// The identity key, canonical bytes — `hybrid_public_key` on every
    /// post, and the bond slot's key on a credit.
    pub fn identity(&self) -> Vec<u8> {
        self.keys
            .bond_post_keys()
            .identity_pk()
            .to_canonical_bytes()
            .expect("the identity key encodes")
    }

    /// The GF-1 debit authorizer, canonical bytes — `bond_spend_pk` on a
    /// JoinMarket, and the bond slot's key on a Release.
    pub fn bond_spend(&self) -> Vec<u8> {
        self.keys
            .bond_post_keys()
            .bond_spend_pk()
            .to_canonical_bytes()
            .expect("the bond-spend key encodes")
    }

    /// `P_canonical_id`, derived from the identity key as the verifier
    /// derives it.
    pub fn id(&self) -> PCanonicalId {
        p_canonical_id_from_hybrid_pubkey(&self.identity())
    }

    /// A JoinMarket over `holdings` at `endpoint`, through the production
    /// constructor: the total is the floor of the holdings, the credit is
    /// the total, the slot is the identity key's.
    pub fn join(&self, holdings: HoldingsDescriptor, endpoint: [u8; 32]) -> PostedBond<'_> {
        let built = build_join_market_vin(self.keys.bond_post_keys(), holdings, endpoint)
            .expect("the production constructor builds the join");
        PostedBond {
            input: bond_post_input(built.vin()),
            debit: None,
            credit: Some(built.credit_term()),
            slot_pk: built.vin().hybrid_public_key.clone(),
            slot_sk: &self.keys.hybrid_sign_sk,
        }
    }

    /// A Release of `record_bonded_total`, through the production
    /// constructor: the debit is the whole balance, the slot is
    /// `bond_spend_pk`'s and `bond_spend_sk` signs it.
    pub fn release(&self, record_bonded_total: u64) -> PostedBond<'_> {
        let built = build_release_vin(self.keys.bond_post_keys(), record_bonded_total)
            .expect("the production constructor builds the release");
        PostedBond {
            input: bond_post_input(built.vin()),
            debit: Some(built.debit_term()),
            credit: None,
            slot_pk: self.bond_spend(),
            slot_sk: &self.keys.bond_spend_sk,
        }
    }

    /// A post shaped by hand — for the refusals no constructor emits (a
    /// Reinstate, which has no wallet producer yet; an unknown kind; a
    /// compact join holding nothing or a shard twice). The identity key
    /// signs the slot; the terms are the post's own `bond_credit` /
    /// `bond_debit`, so CEN-H21 balances and the refusal that fires is the
    /// arm under test, not the balance.
    pub fn post_by_hand(&self, post: BondPost) -> PostedBond<'_> {
        let credit = (post.bond_credit != 0)
            .then(|| OutputTerm::new(shekyl_units::AtomicUnits::from_raw(post.bond_credit)));
        let debit = (post.bond_debit != 0)
            .then(|| InputTerm::new(shekyl_units::AtomicUnits::from_raw(post.bond_debit)));
        PostedBond {
            input: Input::BondPost(Box::new(post)),
            debit,
            credit,
            slot_pk: self.identity(),
            slot_sk: &self.keys.hybrid_sign_sk,
        }
    }

    /// A JoinMarket `BondPost` with the production constructor's fields,
    /// for [`Self::post_by_hand`] to mutate: what a join *would* carry for
    /// `holdings`, before the caller changes one thing.
    pub fn join_post(&self, holdings: HoldingsDescriptor, endpoint: [u8; 32]) -> BondPost {
        let built = build_join_market_vin(self.keys.bond_post_keys(), holdings, endpoint)
            .expect("the production constructor builds the join");
        let Input::BondPost(post) = bond_post_input(built.vin()) else {
            unreachable!("a vin maps to a bond post");
        };
        *post
    }

    /// The serve-credit-only transaction (CEN-H20's shape) for `shard` in
    /// `settlement_epoch` — the kept half on the production wire type. The
    /// countersignature is a marker (module docs).
    pub fn serve_credit(&self, shard: u64, settlement_epoch: u64) -> Transaction {
        let kept = ArchivalServeCreditResponse {
            p_canonical_id: *self.id().as_bytes(),
            shard_id: shard,
            settlement_epoch,
            ed25519_countersignature: [0x5c; 64],
        };
        Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::ServeCredit {
                    canonical_bytes: kept.serialize().expect("a kept half serializes"),
                }],
                outputs: Vec::new(),
                extra: Vec::new(),
            },
            ct: Ct::Fcmp {
                fee: 0,
                reference_block: shekyl_types::BlockHash::NULL,
                base: CtBase {
                    enc_amounts: Vec::new(),
                    enc_labels: Vec::new(),
                    commitments: Vec::new(),
                },
                pqc_auths: Vec::new(),
                prunable: None,
            },
        }
    }
}

/// A compact shard-set holding.
pub fn shard_set(ids: Vec<u64>) -> HoldingsDescriptor {
    HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: shekyl_archival_retention::ShardSet::new(ids).expect("distinct, under the cap"),
    }
}

/// A complete-tree holding.
pub fn complete_tree() -> HoldingsDescriptor {
    HoldingsDescriptor {
        kind: HoldingsKind::CompleteTree,
        shard_ids: shekyl_archival_retention::ShardSet::new(Vec::new()).expect("empty"),
    }
}
