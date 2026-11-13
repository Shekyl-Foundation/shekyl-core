// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Archival transaction fixtures: the bond floor, a serve-credit vin, the
//! JoinMarket that opens a persona's record, the serve-credit-only body
//! that follows it, and a parseable emission claim for a persona.
//!
//! **Personas are named by tag, never by id.** Every `p: [u8; 32]` these
//! builders take is a [`FixturePersona`] tag; the persona's identity key,
//! bond-spend key and `P_canonical_id` are derived from it
//! ([`persona`]). The id is the recompute over the identity key, as the
//! verifier derives it (CEN-J11), and the key that signs a bond slot is
//! the persona's ([`signed`](super::signed) finds it by the post's
//! identity key) — the identity key for a credit, the bond-spend key for
//! a Release (CEN-J13). A test that reads a record back asks
//! `persona(tag).id`, not `tag`.
//!
//! *Records-was:* until E6 slice 8 row 4 the builders took `p` **as the
//! id**, put a filled `[0xb1; LEN]` in `hybrid_public_key`, and let
//! `signed` key the bond slot from its input position — three facts J11
//! and J13 refuse (the id did not recompute, and no slot carried the
//! persona's key). Every bond-post fixture in three crates was built on
//! that admission; this module is where the migration landed, in the
//! commit before the rules.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use shekyl_archival_retention::p_canonical_id_from_hybrid_pubkey;
use shekyl_crypto_pq::derivation::derive_pqc_public_key;
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
use shekyl_crypto_pq::multisig::SINGLE_SIG_CANONICAL_LEN;
use shekyl_types::archival::ReceiptSignPk;
use shekyl_types::PCanonicalId;
use shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN;
use shekyl_wire::{BondPost, BondPostKind, Holdings, Input, Transaction};

use super::{balanced_bond_post, FIXTURE_OUTPUT_INDEX};

/// A fixture **persona**: the keys the archival bodies for one `tag` are
/// built with, and the id they are recorded under. The identity key and
/// the GF-1 bond-spend key are each derived from a seed the tag fixes
/// ([`seed_of`], [`IDENTITY_HALF`], [`BOND_SPEND_HALF`]); the id is
/// [`p_canonical_id_from_hybrid_pubkey`] over the identity key. The seeds
/// are stored beside the persona, keyed by the identity key, so a later
/// sign can find them without the tag.
/// So a join for `tag`, a credit naming `tag`, and the slot that signs
/// either agree by construction, and a test that mis-pairs them is a
/// test of J11 or J13, not a fixture accident.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixturePersona {
    /// The tag the persona was derived from.
    pub tag: [u8; 32],
    /// The identity key, canonical bytes — a post's `hybrid_public_key`,
    /// and the bond slot's key on a credit.
    pub identity: Vec<u8>,
    /// The bond-spend key, canonical bytes — a JoinMarket's
    /// `bond_spend_pk`, and the bond slot's key on a Release.
    pub bond_spend: Vec<u8>,
    /// The receipt key a JoinMarket commits: a real Ed25519 + FN-DSA-1024
    /// key ([`RECEIPT_ED_HALF`], [`RECEIPT_FN_DSA_HALF`]), so the fixture
    /// join passes CEN-J28 as a wallet's does.
    pub receipt: ReceiptSignPk,
    /// `P_canonical_id`: the recompute over `identity`.
    pub id: PCanonicalId,
}

/// The constant half of an identity seed.
const IDENTITY_HALF: u8 = 0x1D;
/// The constant half of a bond-spend seed.
const BOND_SPEND_HALF: u8 = 0x5D;
/// The fill of the receipt key's Ed25519 seed, after the tag's first half.
const RECEIPT_ED_HALF: u8 = 0x2E;
/// The fill of the receipt key's FN-DSA seed, after the tag's first half.
const RECEIPT_FN_DSA_HALF: u8 = 0x2F;

/// A 32-byte receipt-key seed for `tag`: its first sixteen bytes, then
/// `half`. Distinct per tag as far as the fixtures' tags differ in their
/// first half, and distinct per `half`.
fn receipt_seed_of(tag: [u8; 32], half: u8) -> [u8; 32] {
    let mut seed = [half; 32];
    seed[..16].copy_from_slice(&tag[..16]);
    seed
}

/// The identity-key seed `tag`'s persona signs with — for
/// [`signed_as`](super::signed_as), which keys and signs a slot as a
/// persona other than the one the post names.
pub(super) fn identity_seed_of(tag: [u8; 32]) -> [u8; 64] {
    seed_of(tag, IDENTITY_HALF)
}

fn seed_of(tag: [u8; 32], half: u8) -> [u8; 64] {
    let mut seed = [half; 64];
    seed[..32].copy_from_slice(&tag);
    seed
}

type Personas = HashMap<[u8; 32], FixturePersona>;

/// The two seeds a persona signs with, keyed by its identity-key bytes.
/// [`signed`](super::signed) has the post and not the tag, and the key the
/// post carries is what the verifier reads (CEN-J13).
#[derive(Clone, Copy)]
pub(super) struct SlotSeeds {
    pub(super) identity: [u8; 64],
    pub(super) bond_spend: [u8; 64],
}

type SeedsByIdentity = HashMap<Vec<u8>, SlotSeeds>;

fn personas() -> &'static Mutex<Personas> {
    static PERSONAS: OnceLock<Mutex<Personas>> = OnceLock::new();
    PERSONAS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn seeds_by_identity() -> &'static Mutex<SeedsByIdentity> {
    static SEEDS: OnceLock<Mutex<SeedsByIdentity>> = OnceLock::new();
    SEEDS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The persona for `tag` — derived once per process and memoized (two
/// hybrid key derivations per tag), so every builder and every test that
/// names `tag` sees the same keys and id.
#[must_use]
pub fn persona(tag: [u8; 32]) -> FixturePersona {
    let mut table = personas()
        .lock()
        .expect("the fixture persona table is not poisoned");
    table
        .entry(tag)
        .or_insert_with(|| {
            let identity_seed = seed_of(tag, IDENTITY_HALF);
            let bond_spend_seed = seed_of(tag, BOND_SPEND_HALF);
            let identity = derive_pqc_public_key(&identity_seed, FIXTURE_OUTPUT_INDEX)
                .expect("a fixture seed derives an identity key");
            let bond_spend = derive_pqc_public_key(&bond_spend_seed, FIXTURE_OUTPUT_INDEX)
                .expect("a fixture seed derives a bond-spend key");
            let displaced = seeds_by_identity()
                .lock()
                .expect("the fixture seed table is not poisoned")
                .insert(
                    identity.clone(),
                    SlotSeeds {
                        identity: identity_seed,
                        bond_spend: bond_spend_seed,
                    },
                );
            assert!(displaced.is_none(), "a tag's identity key is derived once");
            let id = p_canonical_id_from_hybrid_pubkey(&identity);
            let receipt = HybridEd25519FnDsa::keypair_from_seeds(
                &receipt_seed_of(tag, RECEIPT_ED_HALF),
                &receipt_seed_of(tag, RECEIPT_FN_DSA_HALF),
            )
            .expect("a fixture seed derives a receipt key")
            .0
            .to_receipt_sign_pk();
            FixturePersona {
                tag,
                identity,
                bond_spend,
                receipt,
                id,
            }
        })
        .clone()
}

/// The seeds for the persona whose identity key is `identity`, if [`persona`]
/// derived one. `None` for a key no persona owns: a hand-built post, which
/// no fixture seed can sign for. The lookup is the key, not a scan of every
/// persona the process has built.
pub(super) fn slot_seeds_for(identity: &[u8]) -> Option<SlotSeeds> {
    seeds_by_identity()
        .lock()
        .expect("the fixture seed table is not poisoned")
        .get(identity)
        .copied()
}

/// The id of the persona tagged `[fill; 32]` — the record a [`join_market`]
/// for that tag writes, and the persona an [`emission_vin`] built with
/// `fill` claims as.
#[must_use]
pub fn claimant(p_pubkey_fill: u8) -> [u8; 32] {
    *persona([p_pubkey_fill; 32]).id.as_bytes()
}

/// A parseable **emission-claim vin** for the persona tagged
/// `[p_pubkey_fill; 32]` ([`claimant`]) claiming `epochs`, one shard-7
/// serve-credit entry per epoch, a membership-only backing and filler
/// auths: enough for CEN-L7's claim arm to read the persona and the
/// epochs (and for the block-level G9, which reads the claims), and for the
/// emission statics (CEN-J19 parses it; CEN-J20 reads `p_pubkey`, which is
/// the persona's identity key, so the slot is keyed and signed by the
/// persona — [`signed`](super::signed)). Nothing here verifies the backing
/// or the auths: CEN-J25's witness is the driven claim, not this.
/// [`balanced_emission`](super::balanced_emission) puts it in a body
/// CEN-H22 balances.
pub fn emission_vin(p_pubkey_fill: u8, epochs: &[u64]) -> Input {
    emission_vin_for(persona([p_pubkey_fill; 32]).identity, epochs)
}

/// [`emission_vin`] for a persona named by its **identity key** rather than
/// a fixture tag — the harness spender's keyed persona, whose record a real
/// join wrote (CEN-J27 judges a fixture join's funding spend as any spend,
/// so a driven store has no fixture-persona record to claim against).
/// Everything but `p_pubkey` is the fixture's filler, as above.
pub fn emission_vin_for(p_pubkey: Vec<u8>, epochs: &[u64]) -> Input {
    use shekyl_archival_retention::{
        ArchivalRewardEmissionVin, HoldingsDescriptor, HoldingsKind, MembershipOnlyBacking,
        ShardSet, ShardWorkEntry, WorkEpochClaim,
    };
    let vin = ArchivalRewardEmissionVin {
        p_pubkey,
        holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7]).expect("one shard"),
        },
        settlement_epochs: epochs.to_vec(),
        work_claim: epochs
            .iter()
            .map(|&epoch| WorkEpochClaim {
                epoch,
                shard_entries: vec![ShardWorkEntry {
                    shard_id: 7,
                    serve_credit_bit: true,
                    scarcity_micro: 1_000,
                }],
            })
            .collect(),
        backing: MembershipOnlyBacking {
            proof: vec![0xee; 64],
            pseudo_out: [0x22; 32],
            backing_pubkey: vec![0xb2; PQC_HYBRID_SINGLE_KEY_LEN],
            tree_depth: 3,
        },
        reward_amount_plain: epochs.iter().map(|_| 1_000_000).collect(),
        auth_backing: vec![0xc3; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0xd4; SINGLE_SIG_CANONICAL_LEN],
    };
    Input::ArchivalRewardEmission {
        canonical_bytes: vin.serialize().expect("an emission vin serializes"),
    }
}

/// The bond floor a [`join_market`] posts and is bonded at — the
/// complete-tree floor, one bond (`bond_floor_of(CompleteTree, _)`).
pub const BOND_FLOOR: u64 = shekyl_archival_retention::archival_params().bond_floor_atomic;

/// A **JoinMarket bond post** for the persona tagged `p` (CEN-H21's shape
/// on [`balanced_bond_post`]): a complete-tree holding bonded at
/// [`BOND_FLOOR`], funded by the spend of `key_image`. The one archival
/// body that connects on a chain with **no archival state** — it creates
/// the persona's record, under `persona(p).id` — so it is what precedes a
/// claim for `p` in a block (CEN-L7 refuses one for a persona without a
/// record). The post carries the persona's identity key
/// and its recompute (J11) and commits the persona's bond-spend key and its
/// receipt key, a real one (J28); the
/// slot that signs it is the identity key's (J13's credit arm).
pub fn join_market(key_image: [u8; 32], p: [u8; 32]) -> Transaction {
    let who = persona(p);
    balanced_bond_post(
        key_image,
        BondPost {
            hybrid_public_key: who.identity,
            p_canonical_id: who.id,
            kind: BondPostKind::JoinMarket {
                bond_spend_pk: who.bond_spend,
                receipt_sign_pk: who.receipt,
                endpoint: [0xe0; 32],
            },
            holdings: Holdings::CompleteTree,
            bonded_total_atomic: BOND_FLOOR,
            bond_credit: BOND_FLOOR,
            bond_debit: 0,
        },
    )
}
