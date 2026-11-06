// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One driver for a scenario chain, and the reads a pop is held to.
//!
//! [`Driven`] connects a block. In [`Recording::Straight`] that is the
//! scenario's own connect. In [`Recording::RoundTrip`] the block is then
//! popped and connected again, and the store is read at each step: the
//! archival snapshot, the logical-state digest, and every table as stored
//! bytes. A straight prefix — the proof fill, the walk up to a join — is
//! connected before [`Driven::round_trip_from_here`], so the fill is not
//! round-tripped.
//!
//! The pop equals its parent, except on a pruning boundary and only in the
//! tables and archival families the boundary batch retires. There the pop
//! is the keys the parent and the connect share, at the connect's value:
//! a row the connect deleted stays deleted, a row the connect rewrote keeps
//! the rewrite, and a row the connect added is gone. A pop that restores a
//! pruned row fails that predicate even when it equals the parent, which
//! is why a retired family is checked whether or not the snapshot diff
//! reports it. The reconnect is compared exactly, digest included, at
//! every block.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_archival_retention::settlement_select::issued_draw_term;
use shekyl_archival_retention::FAILURE_WINDOW_M;
use shekyl_chain_store::archival_snapshot::{ArchivalSnapshot, SnapshotFamily};
use shekyl_chain_store::store::RawRows;
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_harness_spender::{Owner, Spender};
use shekyl_types::archival::{IndexedDraw, IssuedDigest, IssuedDraw};
use shekyl_types::{BlockCount, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_wire::Transaction;
use zeroize::Zeroizing;

use crate::archival_driver::FEE;
use crate::connector::{ArchivalState, IssueDraws, Rewound};
use crate::emission_assembly::{assemble_emission_claim, ClaimTerms};
use crate::scenario::{FreeHash, Mined, NextBlock, Scenario, StepOutcome};
use crate::scenario_shard::{levered_schedule, EPOCH_BLOCKS};

/// Draws issued for one persona on one shard. Three is this driver's
/// witness, not [`shekyl_archival_retention`](shekyl_archival_retention)'s
/// `SUPPORT_DRAWS_PER_EPOCH`.
pub(crate) const DRAWS_PER_PAIR: u64 = 3;

/// Every draw issued here is index 0 of its block.
pub(crate) const WITNESS_DRAW_INDEX: u32 = 0;

/// How many times a relay fee is repriced before its varint width has
/// settled. The fee is an input of the weight it pays for, so the price
/// is a fixed point of that width.
pub(crate) const RELAY_FEE_REPRICE_STEPS: u32 = 8;

/// The tables a pruning boundary's batch retires rows from.
const RETIRED_AT_A_BOUNDARY: &[&str] = &[
    "txs_prunable",
    "txs_pqc_auths",
    "undo_log",
    "properties",
    "archival_slash_log",
    "archival_release_journal",
    "archival_block_draws",
    "archival_support_block",
    "archival_sigma_work",
    "archival_complete_trees",
    "archival_budget",
    "archival_settlement",
    "archival_support_settlement",
    "archival_issued_draw",
    "archival_support_issued",
    "archival_issued_digest",
    "archival_drawable_digest",
    "archival_slash_applied",
    "archival_r_market",
];

/// The archival families those tables carry.
const FAMILIES_RETIRED_AT_A_BOUNDARY: &[SnapshotFamily] = &[
    SnapshotFamily::SigmaWork,
    SnapshotFamily::Budget,
    SnapshotFamily::RMarket,
    SnapshotFamily::SlashLog,
    SnapshotFamily::SlashApplied,
];

/// Misses the levered slash waits for: [`FAILURE_WINDOW_M`].
pub(crate) fn failure_window_epochs() -> u64 {
    u64::from(FAILURE_WINDOW_M)
}

/// Whether the block at `height` runs the boundary batch on the levered
/// schedule: `E·SEB` with `E ≥ 2`.
pub(crate) fn is_pruning_boundary(height: BlockHeight) -> bool {
    let h = height.to_raw();
    h.is_multiple_of(EPOCH_BLOCKS) && h >= 2 * EPOCH_BLOCKS
}

/// The pop of a retired table: the keys `parent` and `connected` share,
/// each at `connected`'s value.
///
/// A key only the connect added is absent. A key the connect deleted is
/// absent. A key the connect rewrote keeps the rewrite. Restoring the
/// parent's value, or dropping a key the connect left alone, fails.
fn pop_keeps_the_prune(
    parent: &BTreeMap<Vec<u8>, Vec<u8>>,
    pop: &BTreeMap<Vec<u8>, Vec<u8>>,
    connected: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> bool {
    let shared = parent
        .keys()
        .filter(|key| connected.contains_key(*key))
        .count();
    pop.len() == shared
        && pop
            .iter()
            .all(|(key, value)| parent.contains_key(key) && connected.get(key) == Some(value))
}

/// One pair's draws for an epoch, as the regtest door records them.
pub(crate) struct IssuedPair {
    pub persona: PCanonicalId,
    pub shard: ShardId,
    /// Whether each of the pair's draws passed.
    pub passed: bool,
}

/// Issue `epoch`'s draws: [`DRAWS_PER_PAIR`] per pair, at the epoch's first
/// heights, each at [`WITNESS_DRAW_INDEX`]. One call per epoch — the door
/// writes the epoch's digest whole.
pub(crate) async fn issue_draws(
    scenario: &Scenario<FreeHash>,
    epoch: SettlementEpoch,
    draws_of: &[IssuedPair],
) {
    let open = levered_schedule().open_height(epoch.to_raw());
    let mut digest = IssuedDigest::ZERO;
    let mut draws = Vec::new();
    for pair in draws_of {
        for k in 0..DRAWS_PER_PAIR {
            let issuing_height = BlockHeight::from_raw(open + k);
            digest.fold(&issued_draw_term(
                &pair.persona,
                pair.shard,
                epoch,
                issuing_height,
                WITNESS_DRAW_INDEX,
            ));
            draws.push(IndexedDraw {
                persona: pair.persona,
                shard: pair.shard,
                issuing_height,
                draw: WITNESS_DRAW_INDEX,
                state: IssuedDraw {
                    revealed_at: BlockHeight::from_raw(open + k + 1),
                    passed: pair.passed,
                },
            });
        }
    }
    scenario
        .connector()
        .ask(IssueDraws {
            epoch,
            draws,
            digest,
        })
        .await
        .expect("the door issues the draws");
}

/// What an emission claim is priced from. The terms stay with the caller:
/// one chain prices every epoch from one share, another recomputes the
/// share per epoch.
pub(crate) struct EmissionClaimParts<'a> {
    pub spender: &'a Spender,
    pub owner: &'a Owner<'a>,
    pub keys: &'a ArchivalPKeys,
    pub backing_key: [u8; 32],
    pub fee_key: [u8; 32],
    pub terms: ClaimTerms,
    pub connecting: BlockHeight,
    pub tx_key: [u8; 32],
}

/// Assemble `parts` at the chain's relay floor, repricing until the fee's
/// varint covers the weight it pays for.
pub(crate) async fn priced_emission_claim(
    scenario: &mut Scenario<FreeHash>,
    parts: EmissionClaimParts<'_>,
) -> Transaction {
    let floor = scenario.connecting_relay_floor().await;
    let mut fee = FEE;
    for _ in 0..RELAY_FEE_REPRICE_STEPS {
        let backing = parts
            .spender
            .owned_input(parts.owner, parts.backing_key, parts.connecting);
        let fee_input = parts
            .spender
            .owned_input(parts.owner, parts.fee_key, parts.connecting);
        let claim = assemble_emission_claim(
            parts.keys,
            &Zeroizing::new(parts.tx_key),
            vec![fee_input.input],
            backing.input,
            parts.terms.clone(),
            fee,
            &backing.tree,
        );
        let tx = Transaction::from_bytes(&claim.bytes).expect("the claim parses");
        let weight = u64::try_from(tx.weight()).expect("a weight fits");
        let needed = shekyl_economics::quantized_fee(weight, floor).expect("priceable");
        if needed <= fee {
            return tx;
        }
        fee = needed;
    }
    panic!("the claim's floor price did not settle");
}

/// A spender that owns `keys` before the block at `join_height` is scanned,
/// then every later block. The outputs those keys name are paid in that
/// block; scanning it first and owning them after misses them.
pub(crate) fn spender_owning_before(
    chain: &[Mined],
    join_height: BlockHeight,
    keys: &[[u8; 32]],
) -> Spender {
    let split = usize::try_from(join_height.to_raw()).expect("a join height fits");
    let mut spender = Spender::over(&chain[..split]);
    for key in keys {
        spender.own(*key);
    }
    for block in &chain[split..] {
        spender.push(block);
    }
    spender
}

/// Feed `spender` every block of `chain` it has not seen.
pub(crate) fn catch_up(spender: &mut Spender, chain: &[Mined], seen: &mut usize) {
    for block in &chain[*seen..] {
        spender.push(block);
    }
    *seen = chain.len();
}

/// The store at one tip, as the three reads give it.
struct Tip {
    height: BlockHeight,
    archival: ArchivalSnapshot,
    digest: crate::trace::Digest,
    rows: BTreeMap<&'static str, RawRows>,
}

/// Read the store at its tip.
async fn tip_of(scenario: &Scenario<FreeHash>) -> Tip {
    let facts = scenario.facts().await.expect("facts");
    Tip {
        height: BlockHeight::from_raw(facts.connecting.to_raw() - 1),
        archival: scenario
            .connector()
            .ask(ArchivalState)
            .await
            .expect("the archival snapshot"),
        digest: scenario.digest().await.expect("the digest"),
        rows: scenario.table_rows().await.expect("the rows"),
    }
}

fn indexed(rows: &RawRows) -> BTreeMap<Vec<u8>, Vec<u8>> {
    rows.iter().cloned().collect()
}

/// `got` is the store `parent` describes. With `connected`, `got` is the
/// store after a pop of the block that wrote `connected`: retired tables
/// and families satisfy [`pop_keeps_the_prune`], and everything else is
/// equal. Without it, every read is equal — a reconnect, or a block that
/// did not prune.
fn assert_same(step: &str, parent: &Tip, got: &Tip, connected: Option<&Tip>) {
    assert_eq!(got.height, parent.height, "{step}: the tip");
    let families: Vec<_> = SnapshotFamily::ALL
        .into_iter()
        .filter(|family| {
            let want = parent.archival.rows(*family);
            let have = got.archival.rows(*family);
            let kept = match connected {
                Some(connected) if FAMILIES_RETIRED_AT_A_BOUNDARY.contains(family) => {
                    pop_keeps_the_prune(want, have, connected.archival.rows(*family))
                }
                _ => want == have,
            };
            !kept
        })
        .map(SnapshotFamily::name)
        .collect();
    assert!(
        families.is_empty(),
        "{step}: archival families differ: {families:?}"
    );
    let none = RawRows::new();
    let names: BTreeSet<&str> = parent.rows.keys().chain(got.rows.keys()).copied().collect();
    let differ: Vec<&str> = names
        .into_iter()
        .filter(|table| {
            let want = parent.rows.get(table).unwrap_or(&none);
            let have = got.rows.get(table).unwrap_or(&none);
            let kept = match connected {
                Some(connected) if RETIRED_AT_A_BOUNDARY.contains(table) => pop_keeps_the_prune(
                    &indexed(want),
                    &indexed(have),
                    &indexed(connected.rows.get(table).unwrap_or(&none)),
                ),
                _ => want == have,
            };
            !kept
        })
        .collect();
    let detail: Vec<String> = differ
        .iter()
        .map(|table| {
            table_diff(
                table,
                parent.rows.get(table).unwrap_or(&none),
                got.rows.get(table).unwrap_or(&none),
            )
        })
        .collect();
    assert!(
        differ.is_empty(),
        "{step}: tables differ: {differ:?}\n{}",
        detail.join("\n")
    );
    assert_eq!(got.digest, parent.digest, "{step}: the digest");
}

/// One table's difference, for the failure message: the row counts, then
/// up to four keys present on one side only or with unequal values.
fn table_diff(table: &str, want: &RawRows, got: &RawRows) -> String {
    let want: BTreeMap<&[u8], &[u8]> = want
        .iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
        .collect();
    let got: BTreeMap<&[u8], &[u8]> = got
        .iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
        .collect();
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let only_want: Vec<String> = want
        .keys()
        .filter(|key| !got.contains_key(*key))
        .take(4)
        .map(|key| hex(key))
        .collect();
    let only_got: Vec<String> = got
        .keys()
        .filter(|key| !want.contains_key(*key))
        .take(4)
        .map(|key| hex(key))
        .collect();
    let unequal: Vec<String> = want
        .iter()
        .filter_map(|(key, value)| {
            got.get(key)
                .filter(|held| *held != value)
                .map(|held| format!("{}: {} -> {}", hex(key), hex(value), hex(held)))
        })
        .take(4)
        .collect();
    format!(
        "  {table}: {} rows wanted, {} held; only wanted {only_want:?}; only held {only_got:?}; unequal {unequal:?}",
        want.len(),
        got.len()
    )
}

/// Blocks round-tripped since [`Driven::round_trip_from_here`], and the
/// store the next pop is compared against.
struct TripLedger {
    parent: Tip,
    trips: u64,
    boundaries: u64,
    /// Round-tripped blocks that closed an epoch: at a zero budget, and
    /// with one.
    closes: [u64; 2],
}

enum Recording {
    Straight,
    /// Boxed: the ledger holds three store snapshots, and a straight chain
    /// does not carry them.
    RoundTrip(Box<TripLedger>),
}

/// A scenario and the blocks connected on it. See the module docs.
pub(crate) struct Driven {
    pub scenario: Scenario<FreeHash>,
    pub chain: Vec<Mined>,
    recording: Recording,
}

impl Driven {
    /// A straight chain. Round-tripping starts at [`Self::round_trip_from_here`].
    pub(crate) fn begin(scenario: Scenario<FreeHash>, chain: Vec<Mined>) -> Self {
        Self {
            scenario,
            chain,
            recording: Recording::Straight,
        }
    }

    /// The height of the next block. Mined from genesis, the chain's length
    /// is that height.
    pub(crate) fn height(&self) -> BlockHeight {
        BlockHeight::from_raw(
            u64::try_from(self.chain.len()).expect("a test chain's length is a height"),
        )
    }

    /// The scenario and the chain, for a straight prefix (`close_shards`).
    ///
    /// # Panics
    ///
    /// If round-tripping has started: a prefix connected beside the ledger
    /// would make the next pop compare against a stale parent.
    pub(crate) fn parts_mut(&mut self) -> (&mut Scenario<FreeHash>, &mut Vec<Mined>) {
        assert!(
            matches!(self.recording, Recording::Straight),
            "a straight prefix is not round-tripped"
        );
        (&mut self.scenario, &mut self.chain)
    }

    /// From the next block on, [`Self::connect`] pops and reconnects.
    pub(crate) async fn round_trip_from_here(&mut self) {
        assert!(
            matches!(self.recording, Recording::Straight),
            "round-tripping starts once"
        );
        let parent = tip_of(&self.scenario).await;
        self.recording = Recording::RoundTrip(Box::new(TripLedger {
            parent,
            trips: 0,
            boundaries: 0,
            closes: [0, 0],
        }));
    }

    /// Blocks round-tripped. Zero on a straight chain.
    pub(crate) fn trips(&self) -> u64 {
        match &self.recording {
            Recording::RoundTrip(ledger) => ledger.trips,
            Recording::Straight => 0,
        }
    }

    /// Of [`Self::trips`], how many were pruning boundaries.
    pub(crate) fn boundaries(&self) -> u64 {
        match &self.recording {
            Recording::RoundTrip(ledger) => ledger.boundaries,
            Recording::Straight => 0,
        }
    }

    /// Round-tripped epoch closes: index 0 at a zero budget, index 1 with one.
    pub(crate) fn closes(&self) -> [u64; 2] {
        match &self.recording {
            Recording::RoundTrip(ledger) => ledger.closes,
            Recording::Straight => [0, 0],
        }
    }

    /// Connect the next block listing `listed`. A refusal is returned and
    /// not popped: the block never landed. A connected block is popped and
    /// connected again when round-tripping.
    pub(crate) async fn connect(&mut self, listed: Vec<Transaction>) -> Result<Mined, StepOutcome> {
        let block = self.scenario.mine_listing(listed).await?;
        if !matches!(self.recording, Recording::RoundTrip(_)) {
            self.chain.push(block.clone());
            return Ok(block);
        }
        let parent_height = match &self.recording {
            Recording::RoundTrip(ledger) => ledger.parent.height,
            Recording::Straight => unreachable!("round-tripping was just matched"),
        };
        assert_eq!(block.height, parent_height + BlockCount::ONE);
        let connected = tip_of(&self.scenario).await;
        let rewound = self
            .scenario
            .rewind_to(parent_height)
            .await
            .expect("the rewind answers");
        assert!(
            matches!(rewound, Rewound::Popped { popped: 1, .. }),
            "block {} pops: {rewound:?}",
            block.height
        );
        let popped = tip_of(&self.scenario).await;
        {
            let parent = match &self.recording {
                Recording::RoundTrip(ledger) => &ledger.parent,
                Recording::Straight => unreachable!("round-tripping was just matched"),
            };
            assert_same(
                &format!("popping block {}", block.height),
                parent,
                &popped,
                is_pruning_boundary(block.height).then_some(&connected),
            );
        }
        let again = self
            .scenario
            .connect_template(NextBlock {
                height: block.height,
                template: block.template.clone(),
                seed: block.seed,
                target: block.target,
            })
            .await
            .unwrap_or_else(|outcome| panic!("block {} reconnects: {outcome}", block.height));
        assert_eq!(again.hash, block.hash, "the same block");
        assert_eq!(again.archival, block.archival, "the same delta");
        let reconnected = tip_of(&self.scenario).await;
        assert_same(
            &format!("reconnecting block {}", block.height),
            &connected,
            &reconnected,
            None,
        );
        let close_slot = again
            .archival
            .close()
            .map(|close| usize::from(close.budget().to_raw() != 0));
        if let Recording::RoundTrip(ledger) = &mut self.recording {
            if let Some(slot) = close_slot {
                ledger.closes[slot] += 1;
            }
            ledger.trips += 1;
            ledger.boundaries += u64::from(is_pruning_boundary(again.height));
            ledger.parent = connected;
        }
        self.chain.push(again.clone());
        Ok(again)
    }

    /// Empty blocks until `to` is the next height. Each goes through
    /// [`Self::connect`].
    pub(crate) async fn advance_to(&mut self, to: BlockHeight) {
        while self.height() < to {
            self.connect(Vec::new()).await.expect("empty blocks land");
        }
    }

    /// [`issue_draws`], then reread the trip's parent. A draw is a write
    /// beside a block; the next pop compares against the store it left.
    pub(crate) async fn issue_draws(&mut self, epoch: SettlementEpoch, draws_of: &[IssuedPair]) {
        issue_draws(&self.scenario, epoch, draws_of).await;
        self.wrote_beside_a_block().await;
    }

    /// Reread the trip's parent after a write beside a block (an injected
    /// serve credit). A straight chain has no parent to reread.
    pub(crate) async fn wrote_beside_a_block(&mut self) {
        if matches!(self.recording, Recording::RoundTrip(_)) {
            let parent = tip_of(&self.scenario).await;
            if let Recording::RoundTrip(ledger) = &mut self.recording {
                ledger.parent = parent;
            }
        }
    }

    /// Stop the connector and remove the store.
    pub(crate) async fn close(self) {
        self.scenario.close().await;
    }
}

/// A restored prune is not the pop the boundary left. Red edit: accept a
/// pop that equals its parent without reading the connected row.
#[test]
fn a_restored_prune_is_not_the_parent_the_connect_left() {
    let key = vec![1];
    let parent_value = vec![9];
    let rewritten = vec![4];
    let parent = BTreeMap::from([(key.clone(), parent_value)]);
    let untouched = parent.clone();
    assert!(pop_keeps_the_prune(&parent, &parent, &untouched));

    let deleted = BTreeMap::new();
    assert!(pop_keeps_the_prune(&parent, &deleted, &deleted));
    assert!(
        !pop_keeps_the_prune(&parent, &parent, &deleted),
        "restoring a deleted key fails"
    );

    let connected = BTreeMap::from([(key.clone(), rewritten.clone())]);
    let kept = connected.clone();
    assert!(pop_keeps_the_prune(&parent, &kept, &connected));
    assert!(
        !pop_keeps_the_prune(&parent, &parent, &connected),
        "restoring a rewritten key fails"
    );

    let added = vec![2];
    let only_connected = BTreeMap::from([(added, vec![1])]);
    let empty = BTreeMap::new();
    assert!(pop_keeps_the_prune(&empty, &empty, &only_connected));
    assert!(
        !pop_keeps_the_prune(&empty, &only_connected, &only_connected),
        "a row the block added stays gone"
    );
    assert!(
        !pop_keeps_the_prune(&parent, &deleted, &untouched),
        "a pop does not delete a row the connect left"
    );
}
