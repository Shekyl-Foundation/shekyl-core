// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One levered chain, judged in phases (`CHAIN_RULES_SLICE_8.md` §5 rows 2,
//! 3 and 5).
//!
//! A 20-block epoch with a 10-block reorg cap puts the first slash deadline
//! eleven settled misses can reach at height 319. One persona joins two
//! shards, serves one of them, and is slashed on the shard it never served.
//! The phases then run on that record, in order, without re-mining the chain:
//!
//! - J5 refuses a credit at the join epoch; the credit for `E_join + 1`
//!   connects, and is the first pass the slash counts.
//! - J6 refuses a credit inside the open interval, for the kept shard and
//!   for the shard the slash removed.
//! - The driver's Reinstate connects, and the wallet-side
//!   `verify_reinstate_bond_post` agrees with the fold on the same vin.
//! - J8's pin: after the interval closes, a credit for the shard no longer
//!   held still connects. The holding is Slice C's question, not J6's.
//! - J18 refuses a second Reinstate and one whose holdings changed. J16
//!   refuses a Release inside the cooldown, then accepts one at the
//!   cooldown's boundary over the served anchor.

use shekyl_archival_retention::{
    good_through, serve_credit_epoch_ok, verify_reinstate_bond_post, HoldingsKind,
    ARCHIVAL_BOND_FLOOR_ATOMIC, RELEASE_COOLDOWN_EPOCHS,
};
use shekyl_chain_rules::{
    CenRow, FakechainSchedule, Locus, RecordWriteKind, SettlementEpochBlocks, SettlementSchedule,
    TxSlot,
};
use shekyl_types::archival::{BadInterval, BondRecord, HeldShard, Holdings};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::archival_driver::{
    at_post, first_spending_height, record_of, refused_at, ENDPOINT, FEE,
};
use crate::connector::{Inject, Injected};
use crate::scenario::{FreeHash, Mined, Scenario};
use crate::scenario_archival::{shard_set, Persona};
use crate::scenario_spend::Spender;
use crate::schedule::ChainRules;
use crate::source::ServeCredit;

/// Epoch length, in blocks. With [`CAP`], the slash deadline at height 319
/// is inside what a test mines in seconds.
const EPOCH_BLOCKS: u64 = 20;

/// Reorg cap, in blocks. It sits inside [`EPOCH_BLOCKS`].
const REORG_CAP_BLOCKS: u64 = 10;

/// `FAILURE_WINDOW_M`: the misses a slash waits for, counted from the epoch
/// after the join.
const FAILURE_WINDOW: u64 = 11;

fn levered_rules() -> ChainRules {
    ChainRules::Regtest {
        fixed_difficulty: Some(std::num::NonZeroU128::MIN),
        schedule: FakechainSchedule::new(
            SettlementEpochBlocks::new(EPOCH_BLOCKS).expect("non-zero"),
            BlockCount::from_raw(REORG_CAP_BLOCKS),
        )
        .expect("the cap sits inside the epoch"),
    }
}

fn levered_schedule() -> SettlementSchedule {
    SettlementSchedule::new(SettlementEpochBlocks::new(EPOCH_BLOCKS).expect("non-zero"))
}

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
struct LeveredChain {
    schedule: SettlementSchedule,
    scenario: Scenario<FreeHash>,
    chain: Vec<Mined>,
}

impl LeveredChain {
    /// The height of the next block: the chain's length, as the driver mines
    /// from genesis.
    fn height(&self) -> u64 {
        self.chain.len() as u64
    }

    async fn open() -> Self {
        let schedule = levered_schedule();
        let mut scenario = Scenario::open_under("slice-8-reinstate", FreeHash, levered_rules());
        let chain = scenario
            .mine(ChainCount::from_next_height(first_spending_height()).to_raw())
            .await;
        Self {
            schedule,
            scenario,
            chain,
        }
    }

    async fn join_two_shards(&mut self) -> Joined {
        let persona = Persona::at(11);
        let served = 42u64;
        let unserved = 7u64;
        let join_height = self.height();
        let join_epoch = self.schedule.epoch_at_height(join_height);
        assert_eq!(join_epoch, 3, "71 / 20");
        let joining = {
            let spender = Spender::over(&self.chain);
            spender.spend_coinbase_posting(
                self.scenario.wallet(),
                0,
                join_height,
                FEE,
                Some(&persona.join(shard_set(vec![unserved, served]), ENDPOINT)),
            )
        };
        let block = self
            .scenario
            .mine_listing(vec![joining])
            .await
            .expect("the join connects");
        assert_eq!(block.archival.records()[0].kind(), RecordWriteKind::Insert);
        self.chain.push(block);
        Joined {
            persona,
            served,
            unserved,
            join_epoch,
        }
    }

    /// A credit at the join epoch is J5's. The credit for `E_join + 1`
    /// connects, and is the first pass the slash below counts.
    async fn assert_j5_refuses_the_join_epoch(&mut self, join: &Joined) {
        let at_credit = Locus::Input {
            slot: TxSlot::Listed(0),
            input: 0,
        };
        assert!(
            !serve_credit_epoch_ok(join.join_epoch, join.join_epoch),
            "the retention crate refuses a credit at E_join"
        );
        refused_at(
            self.scenario
                .mine_listing(vec![join
                    .persona
                    .serve_credit(join.served, join.join_epoch)])
                .await,
            CenRow::J5,
            at_credit,
        );
        let first_serving = self
            .scenario
            .mine_listing(vec![join
                .persona
                .serve_credit(join.served, join.join_epoch + 1)])
            .await
            .expect("the credit for E_join + 1 connects (J4, J5, J6 over the record)");
        assert_eq!(first_serving.archival.serve_credits().len(), 1);
        self.chain.push(first_serving);
    }

    /// Eleven passes on the served shard, none on the other, then the slash
    /// in the deadline block. The mined credit is the first pass; the
    /// injector writes the other ten.
    async fn slash_the_unserved_shard(&mut self, join: &Joined) -> Slashed {
        for epoch in (join.join_epoch + 2)..=(join.join_epoch + FAILURE_WINDOW) {
            let Injected { .. } = self
                .scenario
                .connector()
                .ask(Inject(ServeCredit {
                    persona: join.persona.id(),
                    shard: ShardId::from_raw(join.served),
                    epoch: SettlementEpoch::from_raw(epoch),
                }))
                .await
                .expect("the injector writes");
        }
        let slash_epoch = join.join_epoch + FAILURE_WINDOW;
        let deadline = self.schedule.slash_deadline_height(slash_epoch);
        assert_eq!(deadline, 319);
        while self.height() <= deadline {
            let block = self
                .scenario
                .mine_listing(Vec::new())
                .await
                .expect("empty blocks land");
            self.chain.push(block);
        }
        let slashed_at: Vec<u64> = self
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
        let slash = &self.chain.last().expect("mined").archival.slashes()[0];
        assert_eq!(slash.entry.persona, join.persona.id());
        assert_eq!(slash.entry.shard.to_raw(), join.unserved);
        assert_eq!(slash.entry.epoch.to_raw(), slash_epoch);
        assert_eq!(slash.burned.to_raw(), ARCHIVAL_BOND_FLOOR_ATOMIC);

        let record = record_of(&self.scenario, &join.persona).await;
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

    /// Inside the open interval both credits refuse on J6: the kept shard
    /// and the shard the slash removed. J6 reads the interval.
    async fn assert_j6_refuses_inside_the_open_interval(
        &mut self,
        join: &Joined,
        slashed: &Slashed,
    ) {
        let at_credit = Locus::Input {
            slot: TxSlot::Listed(0),
            input: 0,
        };
        let inside = slashed.slash_epoch + 1;
        assert!(
            !good_through(join.join_epoch, inside, &slashed.record.bad_intervals),
            "the retention crate says the persona is not good through `inside`"
        );
        for shard in [join.served, join.unserved] {
            refused_at(
                self.scenario
                    .mine_listing(vec![join.persona.serve_credit(shard, inside)])
                    .await,
                CenRow::J6,
                at_credit,
            );
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
        let reinstate_epoch = self.schedule.epoch_at_height(reinstate_height);
        let riding = {
            let spender = Spender::over(&self.chain);
            spender.spend_coinbase_posting(
                self.scenario.wallet(),
                1,
                reinstate_height,
                FEE,
                Some(&join.persona.reinstate(&slashed.record)),
            )
        };
        let reinstated = self
            .scenario
            .mine_listing(vec![riding])
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
        let written = write.record().clone();
        self.chain.push(reinstated);
        let stored = record_of(&self.scenario, &join.persona).await;
        assert_eq!(stored, written, "the store holds the post-image");
        Reinstated {
            stored,
            reinstate_epoch,
        }
    }

    /// Past the closed interval the persona is good through again. A credit
    /// for the shard it lost connects: J6 reads the interval, not the
    /// holdings. That connect is J8's pin (`holds_shard_at`, E6 slice C).
    async fn assert_j8_pin_an_unheld_shard_still_credits(
        &mut self,
        join: &Joined,
        reinstated: &Reinstated,
    ) {
        let after_close = reinstated.reinstate_epoch + 1;
        assert!(good_through(
            join.join_epoch,
            after_close,
            &reinstated.stored.bad_intervals
        ));
        let past_interval = self
            .scenario
            .mine_listing(vec![
                join.persona.serve_credit(join.served, after_close),
                join.persona.serve_credit(join.unserved, after_close),
            ])
            .await
            .expect("PIN (J8, slice C): a credit for a shard no longer held connects today");
        assert_eq!(past_interval.archival.serve_credits().len(), 2);
        self.chain.push(past_interval);
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
            let spender = Spender::over(&self.chain);
            let riding = |bond| {
                spender.spend_coinbase_posting(self.scenario.wallet(), 2, height, FEE, Some(&bond))
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
            let current = self.schedule.epoch_at_height(height);
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
            self.scenario.mine_listing(vec![no_open_interval]).await,
            CenRow::J18,
            at_post(0),
        );
        refused_at(
            self.scenario.mine_listing(vec![holdings_changed]).await,
            CenRow::J18,
            at_post(0),
        );
        refused_at(
            self.scenario.mine_listing(vec![early_release]).await,
            CenRow::J16,
            at_post(0),
        );
    }

    /// J16's accept over a served anchor. The two serving operands lift at
    /// one height: the slash fold settles `after_close` in the block at its
    /// deadline, and the next block is the first of the cooldown's boundary
    /// epoch. The pair is one block apart.
    async fn assert_j16_accepts_over_the_served_anchor(
        &mut self,
        join: &Joined,
        reinstated: &Reinstated,
    ) {
        let anchor = reinstated.reinstate_epoch + 1;
        let boundary = self.schedule.slash_deadline_height(anchor);
        assert_eq!(self.schedule.epoch_at_height(boundary), anchor + 1);
        assert_eq!(
            self.schedule.epoch_at_height(boundary + 1),
            anchor + RELEASE_COOLDOWN_EPOCHS,
            "the block after the anchor's deadline opens the cooldown's boundary epoch"
        );
        while self.height() < boundary {
            let block = self
                .scenario
                .mine_listing(Vec::new())
                .await
                .expect("empty blocks land");
            assert!(
                block.archival.slashes().is_empty(),
                "a persona serving past its closed interval is not slashed again (height {})",
                block.height
            );
            self.chain.push(block);
        }
        // Each release is built over the chain it rides and before the mine
        // that follows it (the spender borrows the wallet, `mine_listing` the
        // scenario); the deadline block lands between the two.
        let full_release = join
            .persona
            .release(reinstated.stored.bonded_total.to_raw());
        let at_deadline = Spender::over(&self.chain).spend_coinbase_posting(
            self.scenario.wallet(),
            2,
            boundary,
            FEE,
            Some(&full_release),
        );
        refused_at(
            self.scenario.mine_listing(vec![at_deadline]).await,
            CenRow::J16,
            at_post(0),
        );
        let settling = self
            .scenario
            .mine_listing(Vec::new())
            .await
            .expect("the deadline block lands");
        assert_eq!(settling.height, BlockHeight::from_raw(boundary));
        assert!(
            settling.archival.slashes().is_empty(),
            "nothing to slash at the anchor's deadline"
        );
        self.chain.push(settling);
        let past_boundary = Spender::over(&self.chain).spend_coinbase_posting(
            self.scenario.wallet(),
            2,
            boundary + 1,
            FEE,
            Some(&full_release),
        );
        let released = self
            .scenario
            .mine_listing(vec![past_boundary])
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
            record_of(&self.scenario, &join.persona).await,
            write.record().clone(),
            "the store holds the post-image"
        );
    }
}

/// The levered chain, one phase at a time. A refusal names the phase in the
/// stack: the chain is not re-mined as separate tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_levered_slash_chain_judges_each_row_on_one_record() {
    let mut chain = LeveredChain::open().await;
    let join = chain.join_two_shards().await;
    chain.assert_j5_refuses_the_join_epoch(&join).await;
    let slashed = chain.slash_the_unserved_shard(&join).await;
    chain
        .assert_j6_refuses_inside_the_open_interval(&join, &slashed)
        .await;
    let reinstated = chain
        .reinstate_and_match_the_wallet_verify(&join, &slashed)
        .await;
    chain
        .assert_j8_pin_an_unheld_shard_still_credits(&join, &reinstated)
        .await;
    chain
        .assert_j18_belts_and_the_early_release(&join, &slashed, &reinstated)
        .await;
    chain
        .assert_j16_accepts_over_the_served_anchor(&join, &reinstated)
        .await;
    chain.scenario.close().await;
}
