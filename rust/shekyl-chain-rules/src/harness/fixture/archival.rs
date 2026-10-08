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
use shekyl_crypto_pq::multisig::SINGLE_SIG_CANONICAL_LEN;
use shekyl_types::PCanonicalId;
use shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN;
use shekyl_wire::{
    BondPost, BondPostKind, Ct, CtBase, Holdings, Input, Prunable, Transaction, TxPrefix,
};

use super::{balanced_bond_post, FIXTURE_OUTPUT_INDEX, UNRECORDED_REFERENCE};

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
    /// `P_canonical_id`: the recompute over `identity`.
    pub id: PCanonicalId,
}

/// The constant half of an identity seed.
const IDENTITY_HALF: u8 = 0x1D;
/// The constant half of a bond-spend seed.
const BOND_SPEND_HALF: u8 = 0x5D;

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
            FixturePersona {
                tag,
                identity,
                bond_spend,
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
    use shekyl_archival_retention::{
        ArchivalRewardEmissionVin, HoldingsDescriptor, HoldingsKind, MembershipOnlyBacking,
        ShardSet, ShardWorkEntry, WorkEpochClaim,
    };
    let vin = ArchivalRewardEmissionVin {
        p_pubkey: persona([p_pubkey_fill; 32]).identity,
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
pub const BOND_FLOOR: u64 = shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;

/// A parseable **serve-credit vin** — the kept half of the response
/// (`RF-D1`) crediting the persona tagged `p` for `shard` in
/// `settlement_epoch`, its countersignature filler (CEN-J10 reads that;
/// nothing here does).
pub fn serve_credit_vin(p: [u8; 32], shard: u64, settlement_epoch: u64) -> Input {
    let kept = shekyl_archival_retention::ArchivalServeCreditResponse {
        p_canonical_id: *persona(p).id.as_bytes(),
        shard_id: shard,
        settlement_epoch,
        ed25519_countersignature: [0x5c; 64],
    };
    Input::ServeCredit {
        canonical_bytes: kept.serialize().expect("a kept half serializes"),
    }
}

/// A **JoinMarket bond post** for the persona tagged `p` (CEN-H21's shape
/// on [`balanced_bond_post`]): a complete-tree holding bonded at
/// [`BOND_FLOOR`], funded by the spend of `key_image`. The one archival
/// body that connects on a chain with **no archival state** — it creates
/// the persona's record, under `persona(p).id` — so it is what precedes a
/// serve credit or a claim for `p` in a block (CEN-L7 refuses either for a
/// persona without a record). The post carries the persona's identity key
/// and its recompute (J11) and commits the persona's bond-spend key; the
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
                endpoint: [0xe0; 32],
            },
            holdings: Holdings::CompleteTree,
            bonded_total_atomic: BOND_FLOOR,
            bond_credit: BOND_FLOOR,
            bond_debit: 0,
        },
    )
}

/// The pruned half of one pass record in the serve-credit fixtures: a
/// non-empty opaque blob inside the wire's length bound. CEN-H20 counts the
/// records and the wire bounds their length; what one holds is CEN-J10's,
/// and no fixture claims to satisfy it.
pub const PRUNED_PASS_RECORD: [u8; 8] = [0xA5; 8];

/// A **serve-credit-only** transaction (CEN-H20's shape: serve-credit
/// inputs and nothing else, no outputs, zero fee, no spend material, and the
/// `RF-D1` prunable region holding one pruned pass record per serve-credit
/// vin — [`PRUNED_PASS_RECORD`], a marker no verifier reads)
/// crediting the persona tagged `p` for shard 0 in settlement epoch 1 — the first
/// epoch a persona who joined in epoch 0 may serve (CEN-J5: `E ≥ join +
/// 1`, and every fixture join is in epoch 0, the open epoch on any chain
/// shorter than one). Which epoch the listing chain is *in* is CEN-J7's
/// question (E6 slice C), not this body's. The one
/// legal non-coinbase shape with **no key image** — what a test needs
/// when it must list the same body twice (SI-3) without tripping the
/// spent-key-image set. It is judged against `p`'s record **on the view**
/// (CEN-J4; L7 at the fold and SI-15 at the store are the belts beneath),
/// which a [`join_market`] for `p` writes only once its own block has
/// connected — so over a chain holding no record (every `MockChain`) this
/// body is for `tx_form`, not for `validate`
/// ([`TxShape::reads_bond_state`]); its `validate` witness is a driven
/// chain that posted the join a block earlier.
pub fn serve_credit_only(p: [u8; 32]) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![serve_credit_vin(p, 0, 1)],
            outputs: Vec::new(),
            extra: Vec::new(),
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: UNRECORDED_REFERENCE,
            base: CtBase {
                enc_amounts: Vec::new(),
                enc_labels: Vec::new(),
                commitments: Vec::new(),
            },
            pqc_auths: Vec::new(),
            prunable: Some(Prunable {
                bulletproofs: Vec::new(),
                tree_depth: 0,
                fcmp_proof: Vec::new(),
                pseudo_outs: Vec::new(),
                serve_credit_pruned: vec![PRUNED_PASS_RECORD.to_vec()],
            }),
        },
    }
}
