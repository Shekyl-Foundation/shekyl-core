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
//! is formed, judged and connected. It runs under a levered regtest
//! schedule — a hundred-block settlement epoch, where the production
//! epoch is ten thousand — so epoch eleven's deadline is a height a test
//! can mine to. The capture and the replica are therefore the same
//! *shape* under two schedules, and the comparison is role-mapped
//! ([`Roles`]): persona by role, epoch by epoch, height through each
//! side's own schedule. A row that compares equal here compares equal on
//! the facts the inputs file names as state; what differs **by
//! construction** is enumerated in [`by_construction`] and asserted to be
//! exactly that, never skipped.
//!
//! # What this does and does not discharge
//!
//! It evidences one disagreement exactly: the slash-log **key**. The
//! fixture's row sits at `slash_deadline_height(11) + 1` — the C++ keys the
//! fold by the block count after the connect — and the replica's at
//! `slash_deadline_height(11)`, the connecting height. Same decision, same
//! block, two names for it; [`the_slash_log_key_disagreement_is_exactly_the_one_posed`]
//! pins both equations so either side moving is a failure here, and the
//! ruling on which name the row carries is `ARW-Q17`'s, not this test's.
//! It does **not** make the slash families corpus-exercised: the
//! sufficiency stamp's census still finds zero slash rows on every captured
//! chain, and whether that red stands or a slash-bearing capture is owed is
//! `ARW-Q18`, posed with this module's finding attached.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU128;

use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
use shekyl_chain_rules::{FakechainSchedule, SettlementEpochBlocks, SettlementSchedule};
use shekyl_chain_store::archival_snapshot::{ArchivalSnapshot, SnapshotFamily};
use shekyl_chain_store::codec::Canonical;
use shekyl_types::archival::{BadInterval, BondRecord, HeldShard, Holdings, SlashLogEntry};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::connector::{ArchivalState, Inject, Injected};
use crate::scenario::{FreeHash, Scenario};
use crate::scenario_archival::{shard_set, Persona};
use crate::scenario_spend::Spender;
use crate::schedule::ChainRules;
use crate::snapshot_json::{from_json, unhex};
use crate::source::ServeCredit;

const ROWS: &str = include_str!("../fixtures/archival_fixture_slash_m_of_n.rows.json");
const INPUTS: &str = include_str!("../fixtures/archival_fixture_slash_m_of_n.inputs.json");

/// The replica's settlement epoch: the smallest the fixture's shape fits
/// in. Both joins must land in epoch 0, and a coinbase first spends 71
/// blocks after its height (unlock window 60, spendable age 10, one more).
const REPLICA_SEB: u64 = 100;
/// The reorg cap under the replica schedule; any `0 < cap < SEB`.
const REPLICA_CAP: u64 = 50;
/// The one shard both personas hold, as the fixture's.
const SHARD: u64 = 7;
const FEE: u64 = 1_000_000;
const ENDPOINT: [u8; 32] = [0xEE; 32];

/// The replica's rules: regtest at difficulty one, on the levered epoch.
fn replica_rules() -> ChainRules {
    ChainRules::Regtest {
        fixed_difficulty: Some(NonZeroU128::MIN),
        schedule: FakechainSchedule::new(
            SettlementEpochBlocks::new(REPLICA_SEB).expect("non-zero"),
            BlockCount::from_raw(REPLICA_CAP),
        )
        .expect("50 is inside 100"),
    }
}

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
/// fixture persona, and each side's schedule.
struct Roles {
    personas: BTreeMap<PCanonicalId, PCanonicalId>,
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
}

/// The replica, as built: the snapshot at its tip, the schedule it ran
/// under, and the heights its construction fixed.
struct Replica {
    snapshot: ArchivalSnapshot,
    schedule: SettlementSchedule,
    tip: BlockHeight,
    /// The one height every injected pass was attributed to.
    pass_height: BlockHeight,
    p_miss: Persona,
    p_served: Persona,
}

/// Build the fixture's state through the production stack under the
/// replica schedule: two joins in epoch 0, `m` injected passes for the
/// served persona, then blocks through one past epoch `slash_epoch`'s
/// deadline — the fixture's tip, mapped.
async fn build(inputs: &Inputs) -> Replica {
    let rules = replica_rules();
    let in_force = rules.in_force(BlockHeight::from_raw(0));
    let schedule = in_force.settlement_schedule();
    let first_spend =
        in_force.mined_money_unlock_window().to_raw() + in_force.tx_spendable_age().to_raw() + 1;
    let mut scenario = Scenario::open_under("archival-fixture-replica", FreeHash, rules);
    let mut mined = scenario.mine(first_spend).await;

    let p_miss = Persona::at(1);
    let p_served = Persona::at(2);
    for (coinbase, persona) in [(0u64, &p_miss), (1, &p_served)] {
        let spender = Spender::over(&mined);
        let connecting = u64::try_from(mined.len()).expect("small");
        assert_eq!(
            schedule.epoch_at_height(connecting),
            0,
            "both joins land in the join epoch the fixture seeds"
        );
        let join = persona.join(shard_set(vec![SHARD]), ENDPOINT);
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
                shard: ShardId::from_raw(SHARD),
                epoch: SettlementEpoch::from_raw(epoch),
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

    let tip = BlockHeight::from_raw(schedule.slash_deadline_height(inputs.slash_epoch) + 1);
    let have = ChainCount::from_raw(u64::try_from(mined.len()).expect("small"));
    let want = ChainCount::with_tip(tip).expect("a tip names a count");
    scenario.mine((want - have).to_raw()).await;
    let snapshot = connector
        .ask(ArchivalState)
        .await
        .expect("the snapshot reads");
    scenario.close().await;
    Replica {
        snapshot,
        schedule,
        tip,
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
    // Schedules: production versus the hundred-block lever; the tip is
    // one past epoch `slash_epoch`'s deadline on both.
    assert_eq!(roles.fixture.blocks().get(), inputs.seb);
    assert_eq!(roles.replica.blocks().get(), REPLICA_SEB);
    assert_eq!(inputs.tip, inputs.deadline + BlockCount::ONE);
    assert_eq!(
        replica.tip.to_raw(),
        replica.schedule.slash_deadline_height(inputs.slash_epoch) + 1
    );
    // Passes: the C++ test wrote its eleven bits at one height of its
    // choosing; the injector attributes a bit to the tip it is written at.
    assert_eq!(inputs.pass_height, BlockHeight::from_raw(1_000));
    assert!(
        replica.pass_height.to_raw() < REPLICA_SEB,
        "injected inside epoch 0"
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
    the_close_families_match_by_epoch(&theirs, ours);
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
        assert_eq!(rust.join_settlement_epoch, fixture.join_settlement_epoch);
        assert_eq!(rust.holdings, fixture.holdings, "{}", hex(key));
        assert_eq!(rust.bad_intervals, fixture.bad_intervals, "{}", hex(key));
        assert_eq!(
            rust.claimed_settlement_epochs,
            fixture.claimed_settlement_epochs
        );
        assert_eq!(
            rust.first_paying_emission_height,
            fixture.first_paying_emission_height
        );
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
                    start_epoch: inputs.slash_epoch,
                    end_exclusive: BadInterval::OPEN_END,
                }]
            );
        } else {
            assert_eq!(
                rust.holdings,
                Holdings::shard_set(vec![HeldShard {
                    shard: ShardId::from_raw(SHARD),
                    add_epoch: SettlementEpoch::from_raw(0),
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
        there.insert((roles.persona(&persona), shard, epoch));
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
        .all(|(p, s, _)| *p == replica.p_served.id() && *s == SHARD));
}

/// One slash row on each side, equal on everything the entry records —
/// and keyed differently, by exactly the two operands `ARW-26` names: the
/// fixture at the fold **count** (`deadline + 1`), the replica at the
/// **connecting height** (`deadline`). Both equations are pinned; the
/// ruling between them is `ARW-Q17`.
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
    assert_eq!(entry_here.shard, entry_there.shard);
    assert_eq!(entry_here.epoch, entry_there.epoch);
    assert_eq!(
        entry_here.epoch,
        SettlementEpoch::from_raw(inputs.slash_epoch)
    );
    assert_eq!(entry_here.holding, entry_there.holding);

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
        BlockHeight::from_raw(replica.schedule.slash_deadline_height(inputs.slash_epoch)),
        "the Rust writer keys it by the connecting height — the deadline itself"
    );
    // Through the bridge, both keys name the deadline block — the C++'s as
    // the count of the chain it tips, the Rust writer's as its height. The
    // disagreement is which of those two the row carries (`ARW-Q17`).
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
    let there = applied(theirs, &|p| roles.persona(p));
    let here = applied(ours, &|p| {
        PCanonicalId::from_bytes(p.try_into().expect("32"))
    });
    assert_eq!(here, there);
    assert_eq!(
        here,
        BTreeSet::from([(
            roles.persona(inputs.p_miss.as_bytes()),
            SHARD,
            inputs.slash_epoch
        )])
    );
    assert_eq!(
        u64_keys(theirs, SnapshotFamily::LastSlashEpoch),
        u64_keys(ours, SnapshotFamily::LastSlashEpoch)
    );
    assert_eq!(
        u64_keys(ours, SnapshotFamily::LastSlashEpoch),
        BTreeSet::from([inputs.slash_epoch])
    );
}

/// The close families compare by **epoch**: both sides closed epochs
/// `0..=12` and hold epoch 13 open. Their values do not compare — the C++
/// fixture's minimal blocks accrue nothing (`accrual_per_block: 0`), the
/// replica's coinbases are priced — so the fixture's are asserted zero and
/// the replica's are the close writer's, witnessed by the captured corpus.
fn the_close_families_match_by_epoch(theirs: &ArchivalSnapshot, ours: &ArchivalSnapshot) {
    for family in [
        SnapshotFamily::SigmaWork,
        SnapshotFamily::Budget,
        SnapshotFamily::BudgetAccruing,
    ] {
        assert_eq!(u64_keys(theirs, family), u64_keys(ours, family), "{family}");
    }
    assert_eq!(
        u64_keys(ours, SnapshotFamily::Budget),
        (0..13).collect::<BTreeSet<_>>()
    );
    assert_eq!(
        u64_keys(ours, SnapshotFamily::BudgetAccruing),
        BTreeSet::from([13])
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
    // `archival_r_market` is the non-zero set: both sides' passes are
    // bits, not responses the close counts.
    assert_eq!(
        theirs
            .rows(SnapshotFamily::RMarket)
            .keys()
            .collect::<Vec<_>>(),
        ours.rows(SnapshotFamily::RMarket)
            .keys()
            .collect::<Vec<_>>()
    );
}
