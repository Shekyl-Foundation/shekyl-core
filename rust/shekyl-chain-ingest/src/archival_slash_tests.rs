// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One levered chain, judged in phases (`CHAIN_RULES_SLICE_8.md` §5 rows 2,
//! 3 and 5).
//!
//! The levered schedule (`scenario_shard`: a 20-block epoch, a 10-block
//! reorg cap) puts the first slash deadline eleven settled misses can
//! reach inside what a test mines. One persona
//! joins two shards, serves one of them, and is slashed on the shard it
//! never served. Nothing admits a draw yet, so each epoch's draws are
//! issued through the connector's regtest door ([`IssueDraws`],
//! `ARCHIVAL_SETTLEMENT_WRITER.md` `SO-D10f`): three per shard, passed on
//! the served shard and not on the other. The phases then run on that record, in order, without
//! re-mining the chain:
//!
//! - The chain fills shards 0 and 1 with real spends and lets them close
//!   (`scenario_shard`, §5 row 6): a compact join names only shards that
//!   are closed, final and priced at its parent (CEN-J15). One block before
//!   both operands lift, the join is refused on J15; at the first
//!   admissible height it connects.
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
//!
//! Live lane: the fill is some five hundred real proofs
//! (`cargo test -p shekyl-chain-ingest --features pipeline -- --ignored
//! the_levered_slash_chain`).

use shekyl_archival_retention::settlement_select::issued_draw_term;
use shekyl_archival_retention::{
    good_through, serve_credit_epoch_ok, verify_reinstate_bond_post, HoldingsKind,
    ARCHIVAL_BOND_FLOOR_ATOMIC, RELEASE_COOLDOWN_EPOCHS,
};
use shekyl_chain_rules::{CenRow, Locus, RecordWriteKind, SettlementSchedule, TxSlot};
use shekyl_types::archival::{
    BadInterval, BondRecord, HeldShard, Holdings, IndexedDraw, IssuedDigest, IssuedDraw,
    SettlementOutcome,
};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::archival_driver::{
    at_post, first_spending_height, record_of, refused_at, ENDPOINT, FEE,
};
use crate::connector::{Inject, Injected, IssueDraws};
use crate::scenario::{FreeHash, Mined, Scenario};
use crate::scenario_archival::{shard_set, Persona};
use crate::scenario_shard::{
    close_shards, first_admissible_compact_join, levered_rules, levered_schedule, mine_to, Filled,
};
use crate::schedule::ChainRules;
use crate::source::ServeCredit;
use shekyl_harness_spender::Spender;

/// `FAILURE_WINDOW_M`: the misses a slash waits for, counted from the epoch
/// after the join.
const FAILURE_WINDOW: u64 = 11;

/// The first coinbase the fill spends. Coinbases below it ride the posts.
const FILL_FROM_COINBASE: u64 = 10;

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
    rules: ChainRules,
    schedule: SettlementSchedule,
    scenario: Scenario<FreeHash>,
    chain: Vec<Mined>,
    /// The two shards the fill closed, ascending.
    filled: Filled,
}

impl LeveredChain {
    /// The height of the next block. Mined from genesis, the chain's length
    /// is that height.
    fn height(&self) -> BlockHeight {
        BlockHeight::from_raw(
            u64::try_from(self.chain.len()).expect("a test chain's length is a height"),
        )
    }

    /// Mine to the first spend, then fill shards 0 and 1 and let them close.
    async fn open() -> Self {
        let rules = levered_rules();
        let schedule = levered_schedule();
        let mut scenario = Scenario::open_under("slice-8-reinstate", FreeHash, rules);
        let mut chain = scenario
            .mine(ChainCount::from_next_height(first_spending_height()).to_raw())
            .await;
        let filled = close_shards(&mut scenario, &mut chain, FILL_FROM_COINBASE, 2).await;
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
            scenario,
            chain,
            filled,
        }
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
        mine_to(&mut self.scenario, &mut self.chain, early).await;
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
        let one_early = riding(&self.chain, &self.scenario, early);
        refused_at(
            self.scenario.mine_listing(vec![one_early]).await,
            CenRow::J15,
            at_post(0),
        );
        mine_to(&mut self.scenario, &mut self.chain, admissible).await;
        // The price the join reads: the close that priced the later shard
        // carries an `r_market` row for both.
        let last_close = self
            .filled
            .closed
            .last()
            .expect("two")
            .close_height
            .to_raw();
        let priced_epoch = self.schedule.epoch_at_height(last_close + 1);
        let pricing =
            &self.chain[usize::try_from(self.schedule.last_block(priced_epoch)).expect("small")];
        let close = pricing
            .archival
            .close()
            .expect("the epoch closes at its last block");
        for shard in [unserved, served] {
            assert!(
                close.r_market().iter().any(|(id, _)| id.to_raw() == shard),
                "epoch {priced_epoch}'s close priced shard {shard}"
            );
        }
        let join_height = self.height();
        let join_epoch = self.schedule.epoch_at_height(join_height.to_raw());
        let joining = riding(&self.chain, &self.scenario, join_height);
        let block = self
            .scenario
            .mine_listing(vec![joining])
            .await
            .unwrap_or_else(|outcome| panic!("the join connects at {join_height}: {outcome}"));
        assert!(
            block.judged_by.contains(&CenRow::J15),
            "J15 judged the join"
        );
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

    /// Eleven epochs of three draws on each shard, every one passed on the
    /// served shard and none on the other, then the slash in the deadline
    /// block. The served shard also keeps its serve credits — the mined
    /// one and ten injected — which the Release's served anchor reads; the
    /// slash reads the draws.
    async fn slash_the_unserved_shard(&mut self, join: &Joined) -> Slashed {
        for epoch in (join.join_epoch + 1)..=(join.join_epoch + FAILURE_WINDOW) {
            self.issue_three_draws_each(join, epoch).await;
        }
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
        mine_to(
            &mut self.scenario,
            &mut self.chain,
            BlockHeight::from_raw(deadline + 1),
        )
        .await;
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
        // The rows the deadline block settled, ahead of the slash it
        // decided on them: the unserved shard Missed, the served one Served.
        let settled: Vec<(u64, SettlementOutcome)> = self
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

    /// Issue `epoch`'s draws for the persona's two pairs: three each, at
    /// the epoch's first heights, passed on the served shard only.
    async fn issue_three_draws_each(&mut self, join: &Joined, epoch: u64) {
        let persona = join.persona.id();
        let epoch_id = SettlementEpoch::from_raw(epoch);
        let open = self.schedule.open_height(epoch);
        let mut digest = IssuedDigest::ZERO;
        let mut draws = Vec::new();
        for (shard, passed) in [(join.served, true), (join.unserved, false)] {
            let shard = ShardId::from_raw(shard);
            for k in 0..3u64 {
                let issuing_height = BlockHeight::from_raw(open + k);
                digest.fold(&issued_draw_term(
                    &persona,
                    shard,
                    epoch_id,
                    issuing_height,
                    0,
                ));
                draws.push(IndexedDraw {
                    persona,
                    shard,
                    issuing_height,
                    draw: 0,
                    state: IssuedDraw {
                        revealed_at: BlockHeight::from_raw(open + k + 1),
                        passed,
                    },
                });
            }
        }
        self.scenario
            .connector()
            .ask(IssueDraws {
                epoch: epoch_id,
                draws,
                digest,
            })
            .await
            .expect("the door issues the draws");
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
        let reinstate_epoch = self.schedule.epoch_at_height(reinstate_height.to_raw());
        let riding = {
            let spender = Spender::over(&self.chain);
            spender.spend_coinbase_posting(
                self.scenario.wallet(),
                BlockHeight::from_raw(1),
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
                spender.spend_coinbase_posting(
                    self.scenario.wallet(),
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
        while self.height().to_raw() < boundary {
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
            BlockHeight::from_raw(2),
            BlockHeight::from_raw(boundary),
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
            BlockHeight::from_raw(2),
            BlockHeight::from_raw(boundary + 1),
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
#[ignore = "fills two shards with real proofs; minutes. Run in the live lane: cargo test -p shekyl-chain-ingest --features pipeline -- --ignored the_levered_slash_chain"]
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
