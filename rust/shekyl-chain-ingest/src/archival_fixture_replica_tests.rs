// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `ARW-Q15` fixture's consumer (`DRS_E4_ARCHIVAL_WRITER.md` §6 row 8):
//! the one slash the C++ LMDB substrate ever wrote under test, rebuilt on
//! the Rust stack **by construction** and compared structurally.
//!
//! `fixtures/archival_fixture_slash_m_of_n.rows.json` is the LMDB
//! archival snapshot after `slash_scheduler_slashes_sustained_absence_at_m_of_n`
//! (`tests/unit_tests/archival_substrate_lmdb.cpp`): two bonds seeded by
//! hand, eleven serve passes written at one height, 130 001 minimal blocks
//! under the production epoch, the eleventh observed miss slashing the
//! persona that never answered. No captured chain slashes (`ARW-13`), so
//! that capture is the only evidence of what the C++ slash writer writes,
//! and this module is the only place the Rust slash writer meets it.
//!
//! # What is rebuilt and what is mapped
//!
//! The replica is the fixture's **state**, reached through the production
//! stack rather than seeded: two personas join through real bond posts,
//! the served persona's passes are the regtest injector's, and every block
//! is formed, judged and connected. It runs under the levered regtest
//! schedule (`scenario_shard`: a twenty-block settlement epoch, where the
//! production epoch is ten thousand) so epoch eleven's deadline is a
//! height a test can mine to. The capture and the replica are therefore
//! the same *shape* under two schedules, and the comparison is role-mapped
//! ([`Roles`]): persona by role, shard by role, epoch by offset, height
//! through each side's own schedule. A row that compares equal here
//! compares equal on the facts the inputs file names as state; what
//! differs **by construction** is enumerated in [`by_construction`] and
//! asserted to be exactly that, never skipped.
//!
//! # The shard, and the join epoch
//!
//! The fixture seeded both bonds on shard 7 in epoch 0, on a chain that
//! had closed no shard: the C++ admitted a join onto any shard id. CEN-J15
//! (E6 slice 8 §5 row 6) admits a compact join only onto a shard closed,
//! final and priced at its parent, so the replica fills shard 0 with real
//! spends first and both personas join it at the first height J15 admits
//! — epoch `E_join`, not 0. The role map carries both: fixture shard 7 is
//! replica shard 0, and fixture epoch `e` is replica epoch `e + E_join`.
//! Everything the fixture's state says about epochs — the join epoch, the
//! eleven pass epochs, the slash epoch, the deadline, the close families'
//! keys — compares through that offset; the replica's epochs below
//! `E_join`, which the fill mined through, are its own by construction.
//! The fill is a few hundred real proofs: this test runs in the live lane
//! (`cargo test -p shekyl-chain-ingest --features pipeline -- --ignored
//! the_lmdb_slash_fixture`).
//!
//! # What this does and does not discharge
//!
//! It evidences one disagreement exactly: the slash-log **key**. The
//! fixture's row sits at `slash_deadline_height(11) + 1` — the C++ keys the
//! fold by the block count after the connect — and the replica's at
//! `slash_deadline_height(11)`, the connecting height. Same decision, same
//! block, two names for it; [`the_slash_log_key_disagreement_is_exactly_the_one_posed`]
//! pins both equations so either side moving is a failure here. Which name
//! the row carries was `ARW-Q17`'s to rule, not this test's — ruled: the
//! connecting height, because the log's one reader asks *strictly above
//! `h`*; the fixture's `+ 1` is the C++'s live off-by-one against its own
//! reader (`ARW-27`), which this pin records rather than inherits.
//! It does **not** make the slash families corpus-exercised: the
//! sufficiency stamp's census still finds zero slash rows on every captured
//! chain. Whether that red stands or a slash-bearing capture is owed was
//! `ARW-Q18`, posed with this module's finding attached and ruled
//! 2026-10-02: no capture — the `0x04` record's slash families are pinned
//! at non-empty by `shekyl-chain-store`'s slash witness, from the
//! production writer's own state.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
use shekyl_chain_rules::{SettlementEpochBlocks, SettlementSchedule};
use shekyl_chain_store::archival_snapshot::{ArchivalSnapshot, SnapshotFamily};
use shekyl_chain_store::codec::Canonical;
use shekyl_types::archival::{
    BadInterval, BondRecord, HeldShard, Holdings, SlashLogEntry, SlashedHolding,
};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::archival_driver::first_spending_height;
use crate::connector::{ArchivalState, Inject, Injected};
use crate::scenario::{FreeHash, Scenario};
use crate::scenario_archival::{shard_set, Persona};
use crate::scenario_shard::{
    close_shards, first_admissible_compact_join, inside_one_epoch, levered_rules, mine_to,
    ClosedShard, EPOCH_BLOCKS,
};
use crate::scenario_spend::Spender;
use crate::snapshot_json::{from_json, unhex};
use crate::source::ServeCredit;

const ROWS: &str = include_str!("../fixtures/archival_fixture_slash_m_of_n.rows.json");
const INPUTS: &str = include_str!("../fixtures/archival_fixture_slash_m_of_n.inputs.json");

/// The one shard both fixture personas held — seeded, on a chain that had
/// closed none. The replica's is the shard the fill closes (module docs).
const FIXTURE_SHARD: u64 = 7;
/// The first coinbase the fill spends; the two joins ride coinbases 0 and 1.
const FILL_FROM_COINBASE: u64 = 10;
const FEE: u64 = 1_000_000;
const ENDPOINT: [u8; 32] = [0xEE; 32];

/// The fixture's named inputs, read off `inputs.json` rather than
/// restated: the two personas by role, the schedule's deadline and the
/// C++'s fold key for the slash epoch, and the height every pass was
/// written at.
struct Inputs {
    seb: u64,
    tip: BlockHeight,
    m: u64,
    slash_epoch: u64,
    /// `slash_deadline_height(slash_epoch)` under the fixture's schedule.
    deadline: BlockHeight,
    /// Where the fixture's slash-log row is keyed: the C++ fold **count**
    /// — typed as the quantity it is, which is the `ARW-26` point.
    log_key: ChainCount,
    pass_height: BlockHeight,
    seeded_bonded: u64,
    total_burned: u64,
    p_miss: PCanonicalId,
    p_served: PCanonicalId,
}

impl Inputs {
    fn read() -> Self {
        let inputs: serde_json::Value = serde_json::from_str(INPUTS).expect("inputs are JSON");
        assert_eq!(inputs["schema"], "shekyl_e4_fixture_inputs_v1");
        let u = |v: &serde_json::Value| v.as_u64().expect("u64");
        let persona = |v: &serde_json::Value| {
            PCanonicalId::from_bytes(
                unhex(v.as_str().expect("hex"))
                    .expect("persona hex")
                    .try_into()
                    .expect("32 bytes"),
            )
        };
        let slash_epoch = u(&inputs["expected"]["slash_epoch"]);
        let by_epoch = |table: &str| u(&inputs["schedule"][table][slash_epoch.to_string()]);
        let personas = inputs["personas"].as_array().expect("personas");
        assert_eq!(personas.len(), 2);
        let role = |needle: &str| {
            persona(
                &personas
                    .iter()
                    .find(|p| p["role"].as_str().expect("role").contains(needle))
                    .unwrap_or_else(|| panic!("a persona whose role says {needle:?}"))["id"],
            )
        };
        let passes = inputs["serve_passes"].as_array().expect("passes");
        let pass_heights: BTreeSet<u64> = passes.iter().map(|p| u(&p["height"])).collect();
        assert_eq!(
            pass_heights.len(),
            1,
            "the fixture wrote every pass at one height"
        );
        let slashed = persona(&inputs["expected"]["slashed_persona"]);
        let p_miss = role("answers no baseline");
        assert_eq!(
            slashed, p_miss,
            "the slashed persona is the one that never answered"
        );
        Self {
            seb: u(&inputs["schedule"]["settlement_epoch_blocks"]),
            tip: BlockHeight::from_raw(u(&inputs["chain"]["tip_height"])),
            m: u(&inputs["failure_window"]["m"]),
            slash_epoch,
            deadline: BlockHeight::from_raw(by_epoch("slash_deadline_height_by_epoch")),
            log_key: ChainCount::from_raw(by_epoch("slash_log_height_by_epoch")),
            pass_height: BlockHeight::from_raw(pass_heights.into_iter().next().expect("one")),
            seeded_bonded: u(&personas[0]["seed"]["bonded_total_atomic"]),
            total_burned: u(&inputs["expected"]["total_burned"]),
            p_miss,
            p_served: role("answers every baseline"),
        }
    }
}

/// The role map between the two sides: which replica persona plays which
/// fixture persona, which shard plays the fixture's, the epoch offset the
/// replica's join sits at, and each side's schedule.
struct Roles {
    personas: BTreeMap<PCanonicalId, PCanonicalId>,
    /// Fixture shard 7 is the replica's filled shard.
    shard: ShardId,
    /// Fixture epoch `e` is replica epoch `e + epoch_offset`: the fixture
    /// joined in epoch 0, the replica in the first epoch CEN-J15 admits.
    epoch_offset: u64,
    fixture: SettlementSchedule,
    replica: SettlementSchedule,
}

impl Roles {
    /// The fixture persona `theirs` as the replica knows it.
    fn persona(&self, theirs: &[u8]) -> PCanonicalId {
        let id = PCanonicalId::from_bytes(theirs.try_into().expect("32-byte persona"));
        *self
            .personas
            .get(&id)
            .unwrap_or_else(|| panic!("fixture persona {} has no role here", hex(theirs)))
    }

    /// The fixture shard `theirs` as the replica knows it.
    fn shard(&self, theirs: u64) -> u64 {
        assert_eq!(theirs, FIXTURE_SHARD, "the fixture holds one shard");
        self.shard.to_raw()
    }

    /// The fixture epoch `theirs` as the replica knows it.
    fn epoch(&self, theirs: u64) -> u64 {
        theirs + self.epoch_offset
    }

    fn settlement_epoch(&self, theirs: SettlementEpoch) -> SettlementEpoch {
        SettlementEpoch::from_raw(self.epoch(theirs.to_raw()))
    }

    /// A fixture interval through the offset; an open end stays open.
    fn interval(&self, theirs: &BadInterval) -> BadInterval {
        BadInterval {
            start_epoch: self.epoch(theirs.start_epoch),
            end_exclusive: if theirs.end_exclusive == BadInterval::OPEN_END {
                BadInterval::OPEN_END
            } else {
                self.epoch(theirs.end_exclusive)
            },
        }
    }

    /// The fixture's holdings through both maps.
    fn holdings(&self, theirs: &Holdings) -> Holdings {
        match theirs {
            Holdings::CompleteTree => Holdings::CompleteTree,
            Holdings::ShardSet(held) => Holdings::shard_set(
                held.as_slice()
                    .iter()
                    .map(|h| HeldShard {
                        shard: ShardId::from_raw(self.shard(h.shard.to_raw())),
                        add_epoch: self.settlement_epoch(h.add_epoch),
                    })
                    .collect(),
            )
            .expect("a mapped set is a set"),
        }
    }

    fn slashed_holding(&self, theirs: &SlashedHolding) -> SlashedHolding {
        match theirs {
            SlashedHolding::CompleteTree => SlashedHolding::CompleteTree,
            SlashedHolding::Shard { add_epoch } => SlashedHolding::Shard {
                add_epoch: self.settlement_epoch(*add_epoch),
            },
        }
    }
}

/// The replica, as built: the snapshot at its tip, the schedule it ran
/// under, the shard it filled and the heights its construction fixed.
struct Replica {
    snapshot: ArchivalSnapshot,
    schedule: SettlementSchedule,
    tip: BlockHeight,
    /// The shard the fill closed, and where.
    closed: ClosedShard,
    /// The first height CEN-J15 admitted a join onto it; the first join's.
    join_height: BlockHeight,
    /// The epoch both joins landed in — the fixture's epoch 0.
    join_epoch: u64,
    /// The one height every injected pass was attributed to.
    pass_height: BlockHeight,
    p_miss: Persona,
    p_served: Persona,
}

/// Build the fixture's state through the production stack under the
/// levered schedule: fill shard 0 and let it close, two joins onto it in
/// the first epoch CEN-J15 admits, `m` injected passes for the served
/// persona, then blocks through one past the mapped slash epoch's
/// deadline — the fixture's tip, mapped.
async fn build(inputs: &Inputs) -> Replica {
    let rules = levered_rules();
    let schedule = rules
        .in_force(BlockHeight::from_raw(0))
        .settlement_schedule();
    let mut scenario = Scenario::open_under("archival-fixture-replica", FreeHash, rules);
    let mut mined = scenario.mine(first_spending_height().to_raw()).await;
    let filled = close_shards(&mut scenario, &mut mined, FILL_FROM_COINBASE, 1).await;
    let closed = filled.closed[0];
    assert_eq!(closed.shard, ShardId::from_raw(0));

    // The two joins and the passes injected after them sit in one epoch,
    // as the fixture's did in epoch 0: the join height, the next, and the
    // tip the injector writes at are all inside it.
    let join_height = inside_one_epoch(first_admissible_compact_join(&rules, closed), 2);
    mine_to(&mut scenario, &mut mined, join_height).await;
    let join_epoch = schedule.epoch_at_height(join_height.to_raw());

    let p_miss = Persona::at(1);
    let p_served = Persona::at(2);
    for (coinbase, persona) in [(0u64, &p_miss), (1, &p_served)] {
        let spender = Spender::over(&mined);
        let connecting = u64::try_from(mined.len()).expect("small");
        assert_eq!(
            schedule.epoch_at_height(connecting),
            join_epoch,
            "both joins land in one epoch, as the fixture's in epoch 0"
        );
        let join = persona.join(shard_set(vec![closed.shard.to_raw()]), ENDPOINT);
        let block = scenario
            .mine_listing(vec![spender.spend_coinbase_posting(
                scenario.wallet(),
                coinbase,
                connecting,
                FEE,
                Some(&join),
            )])
            .await
            .unwrap_or_else(|outcome| panic!("the join connects: {outcome}"));
        mined.push(block);
    }

    let connector = scenario.connector().clone();
    let mut pass_heights = BTreeSet::new();
    for epoch in 1..=inputs.m {
        let Injected { at } = connector
            .ask(Inject(ServeCredit {
                persona: p_served.id(),
                shard: closed.shard,
                epoch: SettlementEpoch::from_raw(join_epoch + epoch),
            }))
            .await
            .expect("a bonded persona's pass is injected");
        pass_heights.insert(at);
    }
    assert_eq!(
        pass_heights.len(),
        1,
        "every pass at one height, as the fixture's"
    );
    let pass_height = pass_heights.into_iter().next().expect("one");

    let tip =
        BlockHeight::from_raw(schedule.slash_deadline_height(join_epoch + inputs.slash_epoch) + 1);
    mine_to(&mut scenario, &mut mined, tip + BlockCount::ONE).await;
    let snapshot = connector
        .ask(ArchivalState)
        .await
        .expect("the snapshot reads");
    scenario.close().await;
    Replica {
        snapshot,
        schedule,
        tip,
        closed,
        join_height,
        join_epoch,
        pass_height,
        p_miss,
        p_served,
    }
}

fn hex(bytes: &[u8]) -> String {
    shekyl_chain_store::archival_snapshot::hex(bytes)
}

fn le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("8 bytes"))
}

/// The row keys of `family` on `side`, as `u64`s — the epoch- and
/// height-keyed families.
fn u64_keys(side: &ArchivalSnapshot, family: SnapshotFamily) -> BTreeSet<u64> {
    assert_eq!(family.key_len(), 8, "{family} is not u64-keyed");
    side.rows(family).keys().map(|k| le(k)).collect()
}

/// What differs between the capture and the replica **by construction**,
/// each with the fact that makes it so. Asserted, not skipped: a
/// difference that stops being one — or a new one — fails here.
fn by_construction(inputs: &Inputs, replica: &Replica, roles: &Roles) {
    // Schedules: production versus the twenty-block lever; the tip is one
    // past the slash epoch's deadline on both, that epoch mapped.
    assert_eq!(roles.fixture.blocks().get(), inputs.seb);
    assert_eq!(roles.replica.blocks().get(), EPOCH_BLOCKS);
    assert_eq!(inputs.tip, inputs.deadline + BlockCount::ONE);
    assert_eq!(
        replica.tip.to_raw(),
        replica
            .schedule
            .slash_deadline_height(roles.epoch(inputs.slash_epoch))
            + 1
    );
    // The shard and the join epoch: the fixture seeded shard 7 on a chain
    // that had closed none (its `archival_r_market` rows are the credits',
    // not a close's, below); the replica's shard is the one it filled, and
    // its join epoch is the first CEN-J15 admits a join onto it — final
    // after `reorg_cap`, priced by an epoch close — adjusted only so the
    // joins and the passes sit in one epoch, as the fixture's do.
    assert_eq!(roles.shard, replica.closed.shard);
    assert_eq!(roles.epoch_offset, replica.join_epoch);
    let rules = levered_rules();
    let admissible = first_admissible_compact_join(&rules, replica.closed);
    assert!(
        admissible <= replica.join_height
            && replica.join_height.to_raw() - admissible.to_raw() < EPOCH_BLOCKS,
        "the join sits at or just after J15's first admissible height"
    );
    assert_eq!(
        replica.schedule.epoch_at_height(admissible.to_raw()),
        replica.join_epoch
    );
    assert!(replica.join_epoch > 0, "the fill mined through epoch 0");
    // Passes: the C++ test wrote its eleven bits at one height of its
    // choosing; the injector attributes a bit to the tip it is written at,
    // inside the join epoch.
    assert_eq!(inputs.pass_height, BlockHeight::from_raw(1_000));
    assert_eq!(
        replica
            .schedule
            .epoch_at_height(replica.pass_height.to_raw()),
        replica.join_epoch,
        "injected inside the join epoch"
    );
    // Bonds: the C++ seeded two floors per persona; a join pins exactly the
    // floor its holdings imply (gate-4 §4.1), one here.
    assert_eq!(inputs.seeded_bonded, 2 * ARCHIVAL_BOND_FLOOR_ATOMIC);
    assert_eq!(inputs.total_burned, ARCHIVAL_BOND_FLOOR_ATOMIC);
    // Identities: seeded bytes there, derived keys here.
    for persona in [&replica.p_miss, &replica.p_served] {
        let record = bond(&replica.snapshot, &persona.id());
        assert_eq!(record.hybrid_pubkey, persona.identity());
        assert_eq!(record.endpoint, ENDPOINT);
    }
}

/// `archival_bond[persona]` decoded off `side`.
fn bond(side: &ArchivalSnapshot, persona: &PCanonicalId) -> BondRecord {
    let row = side
        .rows(SnapshotFamily::Bond)
        .get(persona.as_bytes().as_slice())
        .unwrap_or_else(|| panic!("no bond row for {}", hex(persona.as_bytes())));
    BondRecord::decode(row).expect("a bond row decodes")
}

/// The one test: build the replica once, then hold every family of the
/// capture against it through the role map.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fills a shard with real proofs; minutes. Run in the live lane: cargo test -p shekyl-chain-ingest --features pipeline -- --ignored the_lmdb_slash_fixture"]
async fn the_lmdb_slash_fixture_rebuilt_on_the_rust_stack_matches_on_state_and_disagrees_on_the_key(
) {
    let inputs = Inputs::read();
    let theirs = from_json(ROWS).expect("the committed rows read back");
    let replica = build(&inputs).await;
    let ours = &replica.snapshot;
    let roles = Roles {
        personas: BTreeMap::from([
            (inputs.p_miss, replica.p_miss.id()),
            (inputs.p_served, replica.p_served.id()),
        ]),
        shard: replica.closed.shard,
        epoch_offset: replica.join_epoch,
        fixture: SettlementSchedule::new(SettlementEpochBlocks::new(inputs.seb).expect("non-zero")),
        replica: replica.schedule,
    };
    assert_eq!(
        roles.fixture.slash_deadline_height(inputs.slash_epoch),
        inputs.deadline.to_raw(),
        "the inputs' deadline is the schedule's"
    );

    by_construction(&inputs, &replica, &roles);
    bonds_match_on_state(&theirs, ours, &inputs, &replica, &roles);
    passes_match_by_persona_shard_epoch(&theirs, ours, &inputs, &replica, &roles);
    the_slash_log_key_disagreement_is_exactly_the_one_posed(
        &theirs, ours, &inputs, &replica, &roles,
    );
    slash_applied_and_watermark_match(&theirs, ours, &inputs, &roles);
    the_close_families_match_by_epoch(&theirs, ours, &inputs, &roles);
    assert!(
        theirs.rows(SnapshotFamily::AttestationWitness).is_empty()
            && ours.rows(SnapshotFamily::AttestationWitness).is_empty(),
        "neither side attests"
    );
}

/// Every state field the inputs name compares equal through the role map;
/// `bonded_total` compares as what left it — one floor from the slashed
/// persona, nothing from the served one — since the seeded total and the
/// pinned one differ by construction.
fn bonds_match_on_state(
    theirs: &ArchivalSnapshot,
    ours: &ArchivalSnapshot,
    inputs: &Inputs,
    replica: &Replica,
    roles: &Roles,
) {
    assert_eq!(theirs.rows(SnapshotFamily::Bond).len(), 2);
    assert_eq!(ours.rows(SnapshotFamily::Bond).len(), 2);
    for (key, row) in theirs.rows(SnapshotFamily::Bond) {
        let fixture = BondRecord::decode(row).expect("the fixture's bond row decodes");
        let persona = roles.persona(key);
        let rust = bond(ours, &persona);
        assert_eq!(
            rust.join_settlement_epoch,
            roles.settlement_epoch(fixture.join_settlement_epoch)
        );
        assert_eq!(
            rust.holdings,
            roles.holdings(&fixture.holdings),
            "{}",
            hex(key)
        );
        assert_eq!(
            rust.bad_intervals,
            fixture
                .bad_intervals
                .iter()
                .map(|i| roles.interval(i))
                .collect::<Vec<_>>(),
            "{}",
            hex(key)
        );
        assert_eq!(
            rust.claimed_settlement_epochs,
            fixture
                .claimed_settlement_epochs
                .iter()
                .map(|e| roles.settlement_epoch(*e))
                .collect::<Vec<_>>()
        );
        assert_eq!(fixture.first_paying_emission_height, None);
        assert_eq!(rust.first_paying_emission_height, None);
        let burned_there = inputs.seeded_bonded - fixture.bonded_total.to_raw();
        let burned_here = ARCHIVAL_BOND_FLOOR_ATOMIC - rust.bonded_total.to_raw();
        assert_eq!(burned_here, burned_there, "{}", hex(key));
        let slashed = persona == replica.p_miss.id();
        assert_eq!(
            burned_here,
            if slashed {
                ARCHIVAL_BOND_FLOOR_ATOMIC
            } else {
                0
            }
        );
        if slashed {
            assert_eq!(
                rust.holdings,
                Holdings::shard_set(Vec::new()).expect("empty")
            );
            assert_eq!(
                rust.bad_intervals,
                vec![BadInterval {
                    start_epoch: roles.epoch(inputs.slash_epoch),
                    end_exclusive: BadInterval::OPEN_END,
                }]
            );
        } else {
            assert_eq!(
                rust.holdings,
                Holdings::shard_set(vec![HeldShard {
                    shard: roles.shard,
                    add_epoch: SettlementEpoch::from_raw(roles.epoch(0)),
                }])
                .expect("one shard")
            );
            assert!(rust.bad_intervals.is_empty());
        }
    }
}

/// The passes are the same `(persona, shard, epoch)` set; the height in
/// each key is the one constant its side wrote every pass at.
fn passes_match_by_persona_shard_epoch(
    theirs: &ArchivalSnapshot,
    ours: &ArchivalSnapshot,
    inputs: &Inputs,
    replica: &Replica,
    roles: &Roles,
) {
    let split = |key: &[u8]| -> (Vec<u8>, u64, u64, u64) {
        (
            key[..32].to_vec(),
            le(&key[32..40]),
            le(&key[40..48]),
            le(&key[48..56]),
        )
    };
    let mut there = BTreeSet::new();
    for key in theirs.rows(SnapshotFamily::ServeCredit).keys() {
        let (persona, shard, epoch, height) = split(key);
        assert_eq!(height, inputs.pass_height.to_raw());
        there.insert((
            roles.persona(&persona),
            roles.shard(shard),
            roles.epoch(epoch),
        ));
    }
    let mut here = BTreeSet::new();
    for key in ours.rows(SnapshotFamily::ServeCredit).keys() {
        let (persona, shard, epoch, height) = split(key);
        assert_eq!(height, replica.pass_height.to_raw());
        here.insert((
            PCanonicalId::from_bytes(persona.try_into().expect("32")),
            shard,
            epoch,
        ));
    }
    assert_eq!(here, there);
    assert_eq!(here.len(), usize::try_from(inputs.m).expect("m"));
    assert!(here
        .iter()
        .all(|(p, s, _)| *p == replica.p_served.id() && *s == roles.shard.to_raw()));
}

/// One slash row on each side, equal on everything the entry records —
/// and keyed differently, by exactly the two operands `ARW-26` names: the
/// fixture at the fold **count** (`deadline + 1`), the replica at the
/// **connecting height** (`deadline`). Both equations are pinned; the
/// ruling between them is `ARW-Q17` — the connecting height — and the
/// fixture's side is the C++ defect `ARW-27` names, kept here as its record.
fn the_slash_log_key_disagreement_is_exactly_the_one_posed(
    theirs: &ArchivalSnapshot,
    ours: &ArchivalSnapshot,
    inputs: &Inputs,
    replica: &Replica,
    roles: &Roles,
) {
    let one = |side: &ArchivalSnapshot| -> (u64, u32, SlashLogEntry) {
        let rows = side.rows(SnapshotFamily::SlashLog);
        assert_eq!(rows.len(), 1, "one slash");
        let (key, value) = rows.iter().next().expect("one");
        (
            le(&key[..8]),
            u32::from_le_bytes(key[8..12].try_into().expect("seq")),
            SlashLogEntry::decode(value).expect("a slash row decodes"),
        )
    };
    let (height_there, seq_there, entry_there) = one(theirs);
    let (height_here, seq_here, entry_here) = one(ours);
    assert_eq!(seq_there, 0);
    assert_eq!(seq_here, 0);

    // The entry: who, which shard, which epoch's failure, what it took.
    assert_eq!(
        entry_here.persona,
        roles.persona(entry_there.persona.as_bytes())
    );
    assert_eq!(entry_here.persona, replica.p_miss.id());
    assert_eq!(
        entry_here.shard.to_raw(),
        roles.shard(entry_there.shard.to_raw())
    );
    assert_eq!(entry_here.epoch, roles.settlement_epoch(entry_there.epoch));
    assert_eq!(
        entry_here.epoch,
        SettlementEpoch::from_raw(roles.epoch(inputs.slash_epoch))
    );
    assert_eq!(
        entry_here.holding,
        roles.slashed_holding(&entry_there.holding)
    );

    // The key: the same decision, named two ways. Read each side's raw
    // `u64` as the quantity that side wrote — the count of the chain whose
    // tip is the deadline there, the deadline's own height here — and the
    // two are one bridge apart.
    let key_there = ChainCount::from_raw(height_there);
    let key_here = BlockHeight::from_raw(height_here);
    assert_eq!(
        key_there,
        ChainCount::with_tip(inputs.deadline).expect("a tip names a count"),
        "the C++ keys epoch {}'s fold by the block count after the connect",
        inputs.slash_epoch
    );
    assert_eq!(key_there, inputs.log_key, "as the inputs file states");
    assert_eq!(
        key_here,
        BlockHeight::from_raw(
            replica
                .schedule
                .slash_deadline_height(roles.epoch(inputs.slash_epoch))
        ),
        "the Rust writer keys it by the connecting height — the deadline itself"
    );
    // Through the bridge, both keys name the deadline block — the C++'s as
    // the count of the chain it tips, the Rust writer's as its height. The
    // disagreement is which of those two the row carries; `ARW-Q17` ruled
    // the height, since the reader scans strictly above its operand and the
    // C++'s own reader takes a height (`ARW-27`).
    assert_eq!(
        key_there.tip(),
        Some(inputs.deadline),
        "the C++ key, read as a count, tips at the deadline"
    );
}

/// The applied set and the watermark agree through the role map.
fn slash_applied_and_watermark_match(
    theirs: &ArchivalSnapshot,
    ours: &ArchivalSnapshot,
    inputs: &Inputs,
    roles: &Roles,
) {
    let applied = |side: &ArchivalSnapshot, map: &dyn Fn(&[u8]) -> PCanonicalId| {
        side.rows(SnapshotFamily::SlashApplied)
            .keys()
            .map(|k| (map(&k[..32]), le(&k[32..40]), le(&k[40..48])))
            .collect::<BTreeSet<_>>()
    };
    let there = applied(theirs, &|p| roles.persona(p))
        .into_iter()
        .map(|(p, s, e)| (p, roles.shard(s), roles.epoch(e)))
        .collect::<BTreeSet<_>>();
    let here = applied(ours, &|p| {
        PCanonicalId::from_bytes(p.try_into().expect("32"))
    });
    assert_eq!(here, there);
    assert_eq!(
        here,
        BTreeSet::from([(
            roles.persona(inputs.p_miss.as_bytes()),
            roles.shard.to_raw(),
            roles.epoch(inputs.slash_epoch)
        )])
    );
    assert_eq!(
        u64_keys(theirs, SnapshotFamily::LastSlashEpoch)
            .into_iter()
            .map(|e| roles.epoch(e))
            .collect::<BTreeSet<_>>(),
        u64_keys(ours, SnapshotFamily::LastSlashEpoch)
    );
    assert_eq!(
        u64_keys(ours, SnapshotFamily::LastSlashEpoch),
        BTreeSet::from([roles.epoch(inputs.slash_epoch)])
    );
}

/// The close families compare by **epoch**, through the offset: the
/// fixture closed epochs `0..=12` and holds 13 open; the replica closed
/// `0..=E_join + 12` and holds `E_join + 13` open — the epochs below
/// `E_join` are the fill's, by construction, and exactly those. Their
/// values do not compare — the C++ fixture's minimal blocks accrue nothing
/// (`accrual_per_block: 0`), the replica's coinbases are priced — so the
/// fixture's are asserted zero and the replica's are the close writer's,
/// witnessed by the captured corpus.
fn the_close_families_match_by_epoch(
    theirs: &ArchivalSnapshot,
    ours: &ArchivalSnapshot,
    inputs: &Inputs,
    roles: &Roles,
) {
    let fill_epochs = (0..roles.epoch_offset).collect::<BTreeSet<_>>();
    for family in [SnapshotFamily::SigmaWork, SnapshotFamily::Budget] {
        let mapped = u64_keys(theirs, family)
            .into_iter()
            .map(|e| roles.epoch(e))
            .collect::<BTreeSet<_>>();
        let here = u64_keys(ours, family);
        assert_eq!(
            here.difference(&mapped).copied().collect::<BTreeSet<_>>(),
            fill_epochs,
            "{family}: the replica's extra closes are the fill's epochs"
        );
        assert!(mapped.is_subset(&here), "{family}");
    }
    assert_eq!(
        u64_keys(theirs, SnapshotFamily::BudgetAccruing)
            .into_iter()
            .map(|e| roles.epoch(e))
            .collect::<BTreeSet<_>>(),
        u64_keys(ours, SnapshotFamily::BudgetAccruing)
    );
    assert_eq!(
        u64_keys(ours, SnapshotFamily::Budget),
        (0..roles.epoch(inputs.slash_epoch + 2)).collect::<BTreeSet<_>>()
    );
    assert_eq!(
        u64_keys(ours, SnapshotFamily::BudgetAccruing),
        BTreeSet::from([roles.epoch(inputs.slash_epoch + 2)])
    );
    for family in [SnapshotFamily::Budget, SnapshotFamily::BudgetAccruing] {
        for value in theirs.rows(family).values() {
            assert_eq!(
                AtomicUnits::decode(value).expect("atomic units"),
                AtomicUnits::from_raw(0),
                "the fixture accrues nothing"
            );
        }
    }
    // `archival_r_market` is the non-zero set: `(shard, epoch) → r`, one
    // row per epoch the served persona was credited in, `r = 1` — the
    // fixture's on its seeded shard, the replica's on the filled one, the
    // same epochs through the offset. (The fixture's rows are the credits'
    // alone: its chain closed no shard, so no close priced one.)
    let r_rows = |side: &ArchivalSnapshot, map: &dyn Fn(u64, u64) -> (u64, u64)| {
        side.rows(SnapshotFamily::RMarket)
            .iter()
            .map(|(k, v)| (map(le(&k[..8]), le(&k[8..16])), v.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let there = r_rows(theirs, &|shard, epoch| {
        (roles.shard(shard), roles.epoch(epoch))
    });
    let here = r_rows(ours, &|shard, epoch| (shard, epoch));
    assert_eq!(here, there);
    assert_eq!(
        here.keys().copied().collect::<BTreeSet<_>>(),
        (1..=inputs.m)
            .map(|e| (roles.shard.to_raw(), roles.epoch(e)))
            .collect::<BTreeSet<_>>(),
        "one priced row per pass epoch"
    );
}
