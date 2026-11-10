// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One slash chain, judged in phases (`CHAIN_RULES_SLICE_8.md` §5 rows 2,
//! 3 and 5), on admitted bundles.
//!
//! The chain runs the settled schedule (`scenario_shard::settled_rules`):
//! admitted draws give a pair its counted draws only there. One persona
//! joins two shards, serves one of them, and is slashed on the shard it
//! never served. Every drawing block's bundle is filed and admitted by the
//! next block (`admitted_draws::serve_to`); the persona passes its draws on
//! the served shard and withholds those on the other, so the admitted
//! bundles file those as misses. The phases then run on that record, in
//! order, without re-mining the chain:
//!
//! - The chain fills shards 0 and 1 with real spends and lets them close
//!   (`scenario_shard`, §5 row 6): a compact join names only shards that
//!   are closed, final and priced at its parent (CEN-J15). One block before
//!   both operands lift, the join is refused on J15; at the first
//!   admissible height it connects.
//! - The failure window: eleven epochs of draws on both pairs, the served
//!   one passed and the other withheld, then the slash in the deadline
//!   block.
//! - The driver's Reinstate connects, and the wallet-side
//!   `verify_reinstate_bond_post` agrees with the fold on the same vin.
//! - J18 refuses a second Reinstate and one whose holdings changed. J16
//!   refuses a Release inside the cooldown, then accepts one at the
//!   cooldown's boundary over the served anchor: the last epoch in which a
//!   draw on the kept shard passed.
//!
//! Live lane: the fill is some five hundred real proofs
//! (`cargo test -p shekyl-chain-ingest --features pipeline -- --ignored
//! the_slash_chain`).

use shekyl_archival_retention::{
    verify_reinstate_bond_post, HoldingsKind, ARCHIVAL_BOND_FLOOR_ATOMIC, RELEASE_COOLDOWN_EPOCHS,
};
use shekyl_bundle_producer::DrawTarget;
use shekyl_chain_rules::{CenRow, RecordWriteKind, SettlementSchedule};
use shekyl_types::archival::{BadInterval, BondRecord, HeldShard, Holdings, SettlementOutcome};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::admitted_draws::{serve_to, DriverWitness};
use crate::archival_driver::{
    at_post, first_spending_height, record_of, refused_at, ENDPOINT, FEE,
};
use crate::chain_drive::{failure_window_epochs, Driven};
use crate::scenario::{FreeHash, Mined, Scenario};
use crate::scenario_archival::{shard_set, Persona};
use crate::scenario_shard::{
    close_shards, first_admissible_compact_join, first_pricing_epoch, settled_rules,
    settled_schedule, Filled, FILL_FROM_COINBASE,
};
use crate::schedule::ChainRules;
use shekyl_harness_spender::Spender;

/// The join this chain is about: two shards, one of them never served.
struct Joined {
    persona: Persona,
    served: u64,
    unserved: u64,
    join_epoch: u64,
}

/// The record after the slash, before the reinstate.
struct Slashed {
    record: BondRecord,
    slash_epoch: u64,
}

/// The record after the reinstate closed the interval.
struct Reinstated {
    stored: BondRecord,
    reinstate_epoch: u64,
}

/// The chain the phases share. Each phase mines forward; none rebuilds it.
struct SlashChain {
    rules: ChainRules,
    schedule: SettlementSchedule,
    drive: Driven,
    /// The two shards the fill closed, ascending.
    filled: Filled,
    /// The witness every served block commits to.
    witness: DriverWitness,
}

impl SlashChain {
    /// The height of the next block.
    fn height(&self) -> BlockHeight {
        self.drive.height()
    }

    /// Mine to the first spend, then fill shards 0 and 1 and let them close.
    /// The fill stays straight: round-tripping, when the caller asks for it,
    /// starts after this returns.
    async fn open(name: &str) -> Self {
        let rules = settled_rules();
        let schedule = settled_schedule();
        let mut scenario = Scenario::open_under(name, FreeHash, rules);
        let chain = scenario
            .mine(ChainCount::from_next_height(first_spending_height()).to_raw())
            .await;
        let mut drive = Driven::begin(scenario, chain);
        let filled = {
            let (scenario, chain) = drive.parts_mut();
            close_shards(scenario, chain, FILL_FROM_COINBASE, 2).await
        };
        assert_eq!(
            filled
                .closed
                .iter()
                .map(|c| c.shard.to_raw())
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        Self {
            rules,
            schedule,
            drive,
            filled,
            witness: DriverWitness::new(0x64),
        }
    }

    /// Serve every block up to `until`: `join`'s persona passes each draw
    /// on its served shard while `passes_through` (an epoch) allows, and
    /// withholds every other draw.
    async fn serve(&mut self, join: &Joined, passes_through: u64, until: BlockHeight) {
        let served = ShardId::from_raw(join.served);
        let schedule = self.schedule;
        let passes = move |h: BlockHeight, target: &DrawTarget| {
            target.shard == served && schedule.epoch_at_height(h.to_raw()) <= passes_through
        };
        let signers: [&shekyl_harness_spender::Persona; 1] = [&join.persona];
        serve_to(&mut self.drive, &self.witness, &signers, &passes, until).await;
    }

    /// The join onto shards 0 and 1 — one block early, refused on J15; at
    /// the first admissible height, connected (§5 row 6).
    async fn join_two_shards(&mut self) -> Joined {
        let persona = Persona::at(11);
        let served = 1u64;
        let unserved = 0u64;
        let admissible = self
            .filled
            .closed
            .iter()
            .map(|&close| first_admissible_compact_join(&self.rules, close))
            .max()
            .expect("two shards closed");
        let early = admissible - BlockCount::ONE;
        self.drive.advance_to(early).await;
        assert_eq!(self.height(), early);
        let riding = |chain: &[Mined], scenario: &Scenario<FreeHash>, height: BlockHeight| {
            Spender::over(chain).spend_coinbase_posting(
                scenario.wallet(),
                BlockHeight::ZERO,
                height,
                FEE,
                Some(&persona.join(shard_set(vec![unserved, served]), ENDPOINT)),
            )
        };
        let one_early = riding(&self.drive.chain, &self.drive.scenario, early);
        refused_at(
            self.drive.connect(vec![one_early]).await,
            CenRow::J15,
            at_post(0),
        );
        self.drive.advance_to(admissible).await;
        // The price the join reads: the slash pass that first finds the
        // later shard final gathers an `r_market` row for both, and that
        // epoch is the watermark at the join's parent.
        let priced_epoch = self
            .filled
            .closed
            .iter()
            .map(|&close| first_pricing_epoch(&self.rules, close))
            .max()
            .expect("two shards closed");
        let pass = self.schedule.slash_deadline_height(priced_epoch);
        assert_eq!(admissible.to_raw(), pass + 1, "the join follows that pass");
        let pricing = &self.drive.chain[usize::try_from(pass).expect("small")];
        let gather = pricing
            .archival
            .gathers()
            .iter()
            .find(|g| g.epoch().to_raw() == priced_epoch)
            .expect("the pass gathers the epoch it settles");
        for shard in [unserved, served] {
            assert!(
                gather.r_market().iter().any(|(id, _)| id.to_raw() == shard),
                "epoch {priced_epoch}'s gather priced shard {shard}"
            );
        }
        let join_height = self.height();
        let join_epoch = self.schedule.epoch_at_height(join_height.to_raw());
        let joining = riding(&self.drive.chain, &self.drive.scenario, join_height);
        let block = self
            .drive
            .connect(vec![joining])
            .await
            .unwrap_or_else(|outcome| panic!("the join connects at {join_height}: {outcome}"));
        assert!(
            block.judged_by.contains(&CenRow::J15),
            "J15 judged the join"
        );
        assert_eq!(block.archival.records()[0].kind(), RecordWriteKind::Insert);
        Joined {
            persona,
            served,
            unserved,
            join_epoch,
        }
    }

    /// The failure window on admitted bundles: draws on both pairs in every
    /// epoch from `E_join + 1`, passed on the served shard and withheld on
    /// the other, then the slash in the deadline block.
    async fn slash_the_unserved_shard(&mut self, join: &Joined) -> Slashed {
        let window = failure_window_epochs();
        let slash_epoch = join.join_epoch + window;
        let deadline = self.schedule.slash_deadline_height(slash_epoch);
        self.serve(join, u64::MAX, BlockHeight::from_raw(deadline))
            .await;
        self.drive
            .advance_to(BlockHeight::from_raw(deadline + 1))
            .await;
        let slashed_at: Vec<u64> = self
            .drive
            .chain
            .iter()
            .filter(|b| !b.archival.slashes().is_empty())
            .map(|b| b.height.to_raw())
            .collect();
        assert_eq!(
            slashed_at,
            vec![deadline],
            "one slash, in the deadline block"
        );
        // The rows the deadline block settled, ahead of the slash it
        // decided on them: the unserved shard Missed, the served one Served.
        let settled: Vec<(u64, SettlementOutcome)> = self
            .drive
            .chain
            .last()
            .expect("mined")
            .archival
            .settlements()
            .iter()
            .map(|s| {
                assert_eq!(s.persona, join.persona.id());
                assert_eq!(s.epoch.to_raw(), slash_epoch);
                (s.shard.to_raw(), s.row.outcome())
            })
            .collect();
        let mut expected = vec![
            (join.served, SettlementOutcome::Served),
            (join.unserved, SettlementOutcome::Missed),
        ];
        expected.sort_unstable_by_key(|(shard, _)| *shard);
        assert_eq!(settled, expected, "one row per pair, in shard order");
        let slash = &self.drive.chain.last().expect("mined").archival.slashes()[0];
        assert_eq!(slash.entry.persona, join.persona.id());
        assert_eq!(slash.entry.shard.to_raw(), join.unserved);
        assert_eq!(slash.entry.epoch.to_raw(), slash_epoch);
        assert_eq!(slash.burned.to_raw(), ARCHIVAL_BOND_FLOOR_ATOMIC);

        let record = record_of(&self.drive.scenario, &join.persona).await;
        assert_eq!(record.bonded_total.to_raw(), ARCHIVAL_BOND_FLOOR_ATOMIC);
        let Holdings::ShardSet(held) = &record.holdings else {
            panic!("compact");
        };
        assert_eq!(
            held.iter().map(|h| h.shard.to_raw()).collect::<Vec<_>>(),
            vec![join.served]
        );
        assert_eq!(
            record.bad_intervals,
            vec![BadInterval {
                start_epoch: slash_epoch,
                end_exclusive: BadInterval::OPEN_END,
            }]
        );
        Slashed {
            record,
            slash_epoch,
        }
    }

    /// The Reinstate connects. The wallet-side verify and the fold read the
    /// same vin, and the store holds the post-image.
    async fn reinstate_and_match_the_wallet_verify(
        &mut self,
        join: &Joined,
        slashed: &Slashed,
    ) -> Reinstated {
        let vin = join.persona.reinstate_vin(&slashed.record);
        verify_reinstate_bond_post(
            &vin,
            Some(slashed.record.bonded_total.to_raw()),
            HoldingsKind::ShardSetCompact,
            &[join.served],
            &slashed.record.bad_intervals,
        )
        .expect("the wallet-side verify accepts the driver's reinstate");
        let reinstate_height = self.height();
        let reinstate_epoch = self.schedule.epoch_at_height(reinstate_height.to_raw());
        let riding = {
            let spender = Spender::over(&self.drive.chain);
            spender.spend_coinbase_posting(
                self.drive.scenario.wallet(),
                BlockHeight::from_raw(1),
                reinstate_height,
                FEE,
                Some(&join.persona.reinstate(&slashed.record)),
            )
        };
        let reinstated = self
            .drive
            .connect(vec![riding])
            .await
            .expect("the reinstate connects");
        let write = &reinstated.archival.records()[0];
        assert_eq!(write.persona(), &join.persona.id());
        assert_eq!(write.kind(), RecordWriteKind::Update);
        assert_eq!(
            write.record().bad_intervals,
            vec![BadInterval {
                start_epoch: slashed.slash_epoch,
                end_exclusive: reinstate_epoch + 1,
            }]
        );
        assert_eq!(
            write.record().holdings,
            slashed.record.holdings,
            "holdings unchanged"
        );
        assert_eq!(
            write.record().bonded_total,
            slashed.record.bonded_total,
            "zero money"
        );
        // FN-DSA increment 3: the record carries the receipt key its join
        // committed — through the slash that opened the interval, and
        // through this Reinstate, which closes it in place.
        assert_eq!(
            slashed.record.receipt_sign_pk,
            join.persona.receipt_key(),
            "a slash does not touch the receipt key"
        );
        assert_eq!(
            write.record().receipt_sign_pk,
            join.persona.receipt_key(),
            "a Reinstate does not touch the receipt key"
        );
        let written = write.record().clone();
        let stored = record_of(&self.drive.scenario, &join.persona).await;
        assert_eq!(stored, written, "the store holds the post-image");
        Reinstated {
            stored,
            reinstate_epoch,
        }
    }

    /// J18's two belts, then J16's cooldown refusal. Every post rides
    /// coinbase 2 at the same height; a refused block leaves the chain
    /// where it was.
    async fn assert_j18_belts_and_the_early_release(
        &mut self,
        join: &Joined,
        slashed: &Slashed,
        reinstated: &Reinstated,
    ) {
        let height = self.height();
        let after_close = reinstated.reinstate_epoch + 1;
        let (no_open_interval, holdings_changed, early_release) = {
            let spender = Spender::over(&self.drive.chain);
            let riding = |bond| {
                spender.spend_coinbase_posting(
                    self.drive.scenario.wallet(),
                    BlockHeight::from_raw(2),
                    height,
                    FEE,
                    Some(&bond),
                )
            };
            let no_open_interval = riding(join.persona.reinstate(&reinstated.stored));
            let mut before_slash = reinstated.stored.clone();
            before_slash.holdings = Holdings::shard_set(
                [join.unserved, join.served]
                    .iter()
                    .map(|&s| HeldShard {
                        shard: ShardId::from_raw(s),
                        add_epoch: SettlementEpoch::from_raw(join.join_epoch),
                    })
                    .collect(),
            )
            .expect("two shards");
            before_slash.bad_intervals = slashed.record.bad_intervals.clone();
            let holdings_changed = riding(join.persona.reinstate(&before_slash));
            let current = self.schedule.epoch_at_height(height.to_raw());
            assert!(
                current < after_close + RELEASE_COOLDOWN_EPOCHS,
                "the release lists inside the cooldown ({current} < {after_close} + {RELEASE_COOLDOWN_EPOCHS})"
            );
            let early_release = riding(
                join.persona
                    .release(reinstated.stored.bonded_total.to_raw()),
            );
            (no_open_interval, holdings_changed, early_release)
        };
        refused_at(
            self.drive.connect(vec![no_open_interval]).await,
            CenRow::J18,
            at_post(0),
        );
        refused_at(
            self.drive.connect(vec![holdings_changed]).await,
            CenRow::J18,
            at_post(0),
        );
        refused_at(
            self.drive.connect(vec![early_release]).await,
            CenRow::J16,
            at_post(0),
        );
    }

    /// J16's accept over a served anchor. The anchor is the last epoch in
    /// which a draw on the kept shard passed: the persona serves through
    /// `after_close` and withholds after it. The two serving operands lift
    /// at one height: the slash fold settles `after_close` in the block at
    /// its deadline, and the next block is the first of the cooldown's
    /// boundary epoch. The pair is one block apart.
    async fn assert_j16_accepts_over_the_served_anchor(
        &mut self,
        join: &Joined,
        reinstated: &Reinstated,
    ) {
        let anchor = reinstated.reinstate_epoch + 1;
        self.serve(
            join,
            anchor,
            BlockHeight::from_raw(self.schedule.open_height(anchor + 1)),
        )
        .await;
        let boundary = self.schedule.slash_deadline_height(anchor);
        assert_eq!(self.schedule.epoch_at_height(boundary), anchor + 1);
        assert_eq!(
            self.schedule.epoch_at_height(boundary + 1),
            anchor + RELEASE_COOLDOWN_EPOCHS,
            "the block after the anchor's deadline opens the cooldown's boundary epoch"
        );
        while self.height().to_raw() < boundary {
            let block = self
                .drive
                .connect(Vec::new())
                .await
                .expect("empty blocks land");
            assert!(
                block.archival.slashes().is_empty(),
                "a persona serving past its closed interval is not slashed again (height {})",
                block.height
            );
        }
        // Each release is built over the chain it rides and before the mine
        // that follows it (the spender borrows the wallet, `mine_listing` the
        // scenario); the deadline block lands between the two.
        let full_release = join
            .persona
            .release(reinstated.stored.bonded_total.to_raw());
        let at_deadline = Spender::over(&self.drive.chain).spend_coinbase_posting(
            self.drive.scenario.wallet(),
            BlockHeight::from_raw(2),
            BlockHeight::from_raw(boundary),
            FEE,
            Some(&full_release),
        );
        refused_at(
            self.drive.connect(vec![at_deadline]).await,
            CenRow::J16,
            at_post(0),
        );
        let settling = self
            .drive
            .connect(Vec::new())
            .await
            .expect("the deadline block lands");
        assert_eq!(settling.height, BlockHeight::from_raw(boundary));
        assert!(
            settling.archival.slashes().is_empty(),
            "nothing to slash at the anchor's deadline"
        );
        let past_boundary = Spender::over(&self.drive.chain).spend_coinbase_posting(
            self.drive.scenario.wallet(),
            BlockHeight::from_raw(2),
            BlockHeight::from_raw(boundary + 1),
            FEE,
            Some(&full_release),
        );
        let released = self
            .drive
            .connect(vec![past_boundary])
            .await
            .unwrap_or_else(|outcome| {
                panic!(
                    "the release connects at the cooldown's boundary with the anchor settled: {outcome}"
                )
            });
        for row in [CenRow::J13, CenRow::J16] {
            assert!(
                released.judged_by.contains(&row),
                "{row} judged the release"
            );
        }
        let write = &released.archival.records()[0];
        assert_eq!(write.persona(), &join.persona.id());
        assert_eq!(write.kind(), RecordWriteKind::Update);
        assert_eq!(write.record().bonded_total, AtomicUnits::ZERO);
        assert_eq!(
            write.record().holdings,
            Holdings::shard_set(Vec::new()).expect("empty"),
            "a release empties the holdings"
        );
        assert_eq!(
            record_of(&self.drive.scenario, &join.persona).await,
            write.record().clone(),
            "the store holds the post-image"
        );
    }
}

/// How the slash chain's connects are judged.
pub(crate) enum ConnectMode {
    /// Connect each block once.
    Straight,
    /// Pop and reconnect each block after the fill.
    RoundTrip,
}

/// What a round-tripped run counted. Both are zero for [`ConnectMode::Straight`].
pub(crate) struct SlashRun {
    pub trips: u64,
    pub boundaries: u64,
}

/// The slash chain, one phase at a time (module docs). `mode` selects
/// whether each connect after the fill is popped and connected again.
pub(crate) async fn run_slash_chain(mode: ConnectMode) -> SlashRun {
    let name = match mode {
        ConnectMode::Straight => "slice-8-reinstate",
        ConnectMode::RoundTrip => "archival-pop-reinstate",
    };
    let mut chain = SlashChain::open(name).await;
    if matches!(mode, ConnectMode::RoundTrip) {
        chain.drive.round_trip_from_here().await;
    }
    let join = chain.join_two_shards().await;
    let slashed = chain.slash_the_unserved_shard(&join).await;
    let reinstated = chain
        .reinstate_and_match_the_wallet_verify(&join, &slashed)
        .await;
    chain
        .assert_j18_belts_and_the_early_release(&join, &slashed, &reinstated)
        .await;
    chain
        .assert_j16_accepts_over_the_served_anchor(&join, &reinstated)
        .await;
    let run = SlashRun {
        trips: chain.drive.trips(),
        boundaries: chain.drive.boundaries(),
    };
    chain.drive.close().await;
    run
}

/// The slash chain, one phase at a time. A refusal names the phase in the
/// stack: the chain is not re-mined as separate tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fills two shards with real proofs; minutes; run by nightly.yml's chain-ingest-ignored job"]
async fn the_slash_chain_judges_each_row_on_one_record() {
    run_slash_chain(ConnectMode::Straight).await;
}
