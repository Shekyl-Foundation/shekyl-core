// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! An archival persona and the bond posts it rides on a spend.
//!
//! What is real: the persona's keys (`derive_archival_p_keys`, the wallet's
//! derivation from a master seed and a slot); the post
//! (`build_join_market_vin` / `build_release_vin`, the constructors
//! `shekyl-engine-core`'s `AssembleBond` / `AssembleRelease` call, so the
//! vin carries the identity key, the derived `P_canonical_id`, the
//! floor-priced total and the genesis-frozen term side); and the
//! transaction around it ([`Spender::spend_coinbase_posting`]: funding
//! spend, two confidential outputs, `sign_transaction_with_terms` with the
//! post's term on its side, the bond slot last in `pqc_auths` and signed
//! by the named key — the identity key for a credit, `bond_spend_sk` for a
//! debit, GF-1's one visible fact). CEN-H21 judges the balance with the
//! terms, CEN-I18 verifies every slot's signature, CEN-J27 judges the
//! funding spend's reference and proof as CEN-I13/I15 judge a regular
//! spend's, and CEN-L7 judges the post over the store's view — the same
//! path a wallet's post takes.
//!
//! This was the ingest's `scenario_archival::Persona`. It moved here with
//! CEN-J27 (`CHAIN_RULES_SLICE_6.md` §5 row 6): once the funding half of a
//! bond post is judged, a fixture join — a filler spend with a post on it
//! — connects nowhere, and the store's tests need a real one as much as
//! the ingest's. The serve credit a persona responds with stays in the
//! ingest: it is a wire body with no spend, and its pruned record is the
//! rules harness's.
//!
//! The vin-to-wire mapping is
//! [`shekyl_archival_bond_builder::bond_post_input`]: every
//! [`shekyl_archival_retention::BondKind`] has one image there, and this
//! module calls it. The wallet's `wire_bond_post_input` is the producer
//! policy over that same function.

use shekyl_archival_bond_builder::{bond_post_input, build_join_market_vin, build_release_vin};
use shekyl_archival_retention::{
    p_canonical_id_from_hybrid_pubkey, ArchivalBondPostVin, ArchivalServeCreditResponse,
    HoldingsDescriptor, HoldingsKind, ShardSet,
};
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::{derive_archival_p_keys, ArchivalPKeys};
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, SignatureScheme, SCHEME_DOMAIN_PQC_AUTH_TX};
use shekyl_tx_builder::{InputTerm, OutputTerm};
use shekyl_types::archival::{BondRecord, Holdings};
use shekyl_types::{PCanonicalId, SigningPayloadHash};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::BondPost;
use shekyl_wire::Input;

use crate::PostedBond;

/// The harness's persona master seed. Any 64 bytes; fixed so the personas
/// (and their canonical ids) are the same in every run and every crate —
/// the ingest's replica fixtures name them by id.
const MASTER: [u8; MASTER_SEED_BYTES] = [0x51; MASTER_SEED_BYTES];

/// An archival persona: the keys a wallet derives for slot `p_slot`.
pub struct Persona {
    keys: ArchivalPKeys,
}

impl Persona {
    /// Derive the persona at `p_slot` from the harness's master seed.
    #[must_use]
    pub fn at(p_slot: u32) -> Self {
        let keys = derive_archival_p_keys(
            &MASTER,
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
            p_slot,
        )
        .expect("the harness's seed derives a persona");
        Self { keys }
    }

    /// The whole bundle — what the emission claim's assembly signs and
    /// scans with, and what [`crate::Owner::persona`] reads to source the
    /// outputs a coinbase spend paid it.
    #[must_use]
    pub fn keys(&self) -> &ArchivalPKeys {
        &self.keys
    }

    /// The identity key, canonical bytes — `hybrid_public_key` on every
    /// post, and the bond slot's key on a credit.
    #[must_use]
    pub fn identity(&self) -> Vec<u8> {
        self.keys
            .bond_post_keys()
            .identity_pk()
            .to_canonical_bytes()
            .expect("the identity key encodes")
    }

    /// The GF-1 debit authorizer, canonical bytes — `bond_spend_pk` on a
    /// JoinMarket, and the bond slot's key on a Release.
    #[must_use]
    pub fn bond_spend(&self) -> Vec<u8> {
        self.keys
            .bond_post_keys()
            .bond_spend_pk()
            .to_canonical_bytes()
            .expect("the bond-spend key encodes")
    }

    /// `P_canonical_id`, derived from the identity key as the verifier
    /// derives it.
    #[must_use]
    pub fn id(&self) -> PCanonicalId {
        p_canonical_id_from_hybrid_pubkey(&self.identity())
    }

    /// The identity key's signature over a slot's signing hash — what the
    /// emission slot of this persona's claim carries (CEN-J20 keys that
    /// slot with the identity; CEN-I18 verifies it), for a harness that
    /// builds the claim's body itself (the rules fixture's
    /// `signed_claiming`).
    #[must_use]
    pub fn identity_signature(&self, payload: &SigningPayloadHash) -> Vec<u8> {
        HybridEd25519MlDsa
            .sign(
                &self.keys.hybrid_sign_sk,
                SCHEME_DOMAIN_PQC_AUTH_TX,
                payload.as_bytes(),
            )
            .expect("the persona's identity key signs")
            .to_canonical_bytes()
            .expect("a hybrid signature encodes")
    }

    /// The serve-credit vin crediting this persona for `shard` in
    /// `settlement_epoch`: the kept half of a pass record on the production
    /// wire type ([`ArchivalServeCreditResponse`]), naming [`Self::id`] so
    /// CEN-J4 finds the record a [`Self::join`] wrote. The
    /// countersignature is a **marker**, not a signature: no Rust
    /// countersigner exists (the challenger side is not built) and no
    /// landed rule verifies it (CEN-J1/J4/J10 pending in the census). The
    /// body around it — CEN-H20's shape with its `RF-D1` pruned record — is
    /// the rules harness's to build (`fixture::serve_credit_only_with`).
    #[must_use]
    pub fn serve_credit_vin(&self, shard: u64, settlement_epoch: u64) -> Input {
        let kept = ArchivalServeCreditResponse {
            p_canonical_id: *self.id().as_bytes(),
            shard_id: shard,
            settlement_epoch,
            ed25519_countersignature: [0x5c; 64],
        };
        Input::ServeCredit {
            canonical_bytes: kept.serialize().expect("a kept half serializes"),
        }
    }

    /// A JoinMarket over `holdings` at `endpoint`, through the production
    /// constructor: the total is the floor of the holdings, the credit is
    /// the total, the slot is the identity key's.
    #[must_use]
    pub fn join(&self, holdings: HoldingsDescriptor, endpoint: [u8; 32]) -> PostedBond<'_> {
        let built = build_join_market_vin(self.keys.bond_post_keys(), holdings, endpoint)
            .expect("the production constructor builds the join");
        PostedBond::signed_by(
            bond_post_input(built.vin()),
            None,
            Some(built.credit_term()),
            built.vin().hybrid_public_key.clone(),
            &self.keys.hybrid_sign_sk,
        )
    }

    /// A Release of `record_bonded_total`, through the production
    /// constructor: the debit is the whole balance, the slot is
    /// `bond_spend_pk`'s and `bond_spend_sk` signs it.
    #[must_use]
    pub fn release(&self, record_bonded_total: u64) -> PostedBond<'_> {
        let built = build_release_vin(self.keys.bond_post_keys(), record_bonded_total)
            .expect("the production constructor builds the release");
        PostedBond::signed_by(
            bond_post_input(built.vin()),
            Some(built.debit_term()),
            None,
            self.bond_spend(),
            &self.keys.bond_spend_sk,
        )
    }

    /// The Reinstate vin for `record` — the shape
    /// [`verify_reinstate_bond_post`](shekyl_archival_retention::verify_reinstate_bond_post)
    /// reads: zero money (no credit, no debit, the record's total
    /// unchanged) over exactly the holdings the record holds, under the
    /// 2026-09-20 immutable-bond ruling. No wallet constructor exists for
    /// a Reinstate (`build_reinstate_vin` is not in the builder crate;
    /// `PRINCIPAL_STAKE_LIFECYCLE.md` §5 item 2), so the harness assembles
    /// the vin through the retention crate's own constructor; when the
    /// producer lands this is the site that calls it instead. Split from
    /// [`Self::reinstate`] so a test can hand the same vin to the
    /// wallet-side verify and the fold.
    #[must_use]
    pub fn reinstate_vin(&self, record: &BondRecord) -> ArchivalBondPostVin {
        let holdings = match &record.holdings {
            Holdings::CompleteTree => complete_tree(),
            Holdings::ShardSet(held) => {
                shard_set(held.as_slice().iter().map(|h| h.shard.to_raw()).collect())
            }
        };
        ArchivalBondPostVin::reinstate(
            self.identity(),
            self.id().to_bytes(),
            holdings,
            record.bonded_total.to_raw(),
            0,
            0,
        )
    }

    /// A Reinstate of `record` ([`Self::reinstate_vin`]) riding a spend:
    /// no term on either side, the identity key in the slot — a credit
    /// arm's key (gate-4 §9.11), as the C++ `apply_archival_reinstate`'s
    /// authorizer.
    #[must_use]
    pub fn reinstate(&self, record: &BondRecord) -> PostedBond<'_> {
        PostedBond::signed_by(
            bond_post_input(&self.reinstate_vin(record)),
            None,
            None,
            self.identity(),
            &self.keys.hybrid_sign_sk,
        )
    }

    /// A Release `BondPost` with the production constructor's fields, for
    /// [`Self::post_by_hand`] to mutate — what [`Self::release`] carries,
    /// before the caller changes one thing. Through `post_by_hand` the
    /// **identity** key signs the slot where `release` signs with
    /// `bond_spend_sk`: a Release under the wrong key, which is the J13
    /// fixture (`CHAIN_RULES_SLICE_8.md` §5 row 4).
    #[must_use]
    pub fn release_post(&self, record_bonded_total: u64) -> BondPost {
        let built = build_release_vin(self.keys.bond_post_keys(), record_bonded_total)
            .expect("the production constructor builds the release");
        let Input::BondPost(post) = bond_post_input(built.vin()) else {
            unreachable!("a vin maps to a bond post");
        };
        *post
    }

    /// A post shaped by hand — for the posts no constructor emits (an
    /// unknown kind; a compact join holding nothing or a shard twice; a
    /// post whose `p_canonical_id` hint names another persona; a Release
    /// under the identity key). The identity key signs the slot; the
    /// terms are the post's own `bond_credit` / `bond_debit`, so CEN-H21
    /// balances and the refusal that fires — or the connect that should
    /// not — is the arm under test, not the balance.
    #[must_use]
    pub fn post_by_hand(&self, post: BondPost) -> PostedBond<'_> {
        let credit = (post.bond_credit != 0)
            .then(|| OutputTerm::new(AtomicUnits::from_raw(post.bond_credit)));
        let debit =
            (post.bond_debit != 0).then(|| InputTerm::new(AtomicUnits::from_raw(post.bond_debit)));
        PostedBond::signed_by(
            Input::BondPost(Box::new(post)),
            debit,
            credit,
            self.identity(),
            &self.keys.hybrid_sign_sk,
        )
    }

    /// A JoinMarket `BondPost` with the production constructor's fields,
    /// for [`Self::post_by_hand`] to mutate: what a join *would* carry for
    /// `holdings`, before the caller changes one thing.
    #[must_use]
    pub fn join_post(&self, holdings: HoldingsDescriptor, endpoint: [u8; 32]) -> BondPost {
        let built = build_join_market_vin(self.keys.bond_post_keys(), holdings, endpoint)
            .expect("the production constructor builds the join");
        let Input::BondPost(post) = bond_post_input(built.vin()) else {
            unreachable!("a vin maps to a bond post");
        };
        *post
    }
}

/// A compact shard-set holding.
#[must_use]
pub fn shard_set(ids: Vec<u64>) -> HoldingsDescriptor {
    HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: ShardSet::new(ids).expect("distinct, under the cap"),
    }
}

/// A complete-tree holding.
#[must_use]
pub fn complete_tree() -> HoldingsDescriptor {
    HoldingsDescriptor {
        kind: HoldingsKind::CompleteTree,
        shard_ids: ShardSet::new(Vec::new()).expect("empty"),
    }
}
