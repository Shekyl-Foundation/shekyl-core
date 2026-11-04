// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which rules are in force at a height — the driver's half of RD-Q10.
//!
//! `connect` takes the in-force [`RuleSet`] by value and compares; it holds
//! no schedule and no `Network` (rule 71). Resolving *height → set* is
//! therefore the driver's, and [`ChainRules`] is where it lives: one shape
//! for every network (`NETWORK_IDENTITY.md` NI-R4). The network's schedule
//! (`RuleSchedule::for_network`) names the issued set at each height, and
//! `RuleSet::for_id` resolves it — every schedule the rules crate defines
//! is `const`-asserted well-formed, so that resolution cannot fail.
//!
//! Two of a network's levers reach the rules: a **fixed** target
//! (`dev-difficulty`) and a **settlement schedule** other than the
//! production pair (`dev-settlement-epoch-blocks`,
//! `dev-archival-reorg-depth`, a [`FakechainSchedule`]). They apply onto the
//! network's own set (`RuleSet::with_levers`; DRS-E4 `ARW-15`: the schedule
//! is rule-set data, so a chain mined under a 512-block epoch is judged
//! under one). Which network may pull them is its row's `permits` (NI-R6),
//! asked once, at [`ChainRules::new`]: a network whose row does not permit
//! a lever refuses it there, by type, not at a height.
//!
//! What is deliberately *not* here: a seed-epoch override. The validator
//! derives the seed height with the production constants and reads no
//! environment (slice 2 F5, CEN-D3), so a driver that claimed seeds on a
//! faster schedule would earn `Stale::Seed` at every block. The daemon a
//! corpus is harvested from must run without seed-epoch levers (RD-F19).
//! Under a **live** target such a corpus is refused by CEN-D1 from the
//! first block mined under the fast schedule; under a fixed target of 1
//! every longhash satisfies the target and nothing in the chain data can
//! tell the two schedules apart — which is why the exporter refuses to run
//! with an override in its own environment, and why the recipe states the
//! daemon's.

use core::num::NonZeroU128;

use shekyl_chain_rules::{FakechainSchedule, GenesisPin, RuleSchedule, RuleSet, Trust};
use shekyl_network::{Lever, Network, Permit};
use shekyl_types::BlockHeight;

/// A lever pulled for a network whose row does not permit it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{} is a lever {network}'s row does not permit (NETWORK_IDENTITY.md NI-R6)", lever.name())]
pub struct LeverRefused {
    /// The network the lever was pulled for.
    pub network: Network,
    /// Which lever.
    pub lever: Lever,
}

/// The rules in force at each height of a run, and the genesis it is held
/// to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainRules {
    network: Network,
    /// `dev-difficulty`, if given.
    fixed_difficulty: Option<NonZeroU128>,
    /// The `(SEB, cap)` pair the chain runs under.
    schedule: FakechainSchedule,
    /// The genesis `validate` holds block 0 to: the table's for the
    /// network. Only a harness constructor empties it.
    genesis: GenesisPin,
}

impl ChainRules {
    /// The rules for `network` under the levers given, each checked against
    /// the network's row. The production schedule is not a lever pulled.
    ///
    /// # Errors
    ///
    /// [`LeverRefused`] for a fixed difficulty, a settlement epoch or a
    /// reorg cap the row does not permit, named in that order.
    pub const fn new(
        network: Network,
        fixed_difficulty: Option<NonZeroU128>,
        schedule: FakechainSchedule,
    ) -> Result<Self, LeverRefused> {
        let production = FakechainSchedule::PRODUCTION;
        let pulled = [
            (fixed_difficulty.is_some(), Lever::Difficulty),
            (
                schedule.settlement().blocks().get() != production.settlement().blocks().get(),
                Lever::SettlementEpochBlocks,
            ),
            (
                schedule.reorg_cap().to_raw() != production.reorg_cap().to_raw(),
                Lever::ArchivalReorgDepth,
            ),
        ];
        let mut i = 0;
        while i < pulled.len() {
            let (is_pulled, lever) = pulled[i];
            if is_pulled && !network.permits(lever) {
                return Err(LeverRefused { network, lever });
            }
            i += 1;
        }
        Ok(Self {
            network,
            fixed_difficulty,
            schedule,
            genesis: GenesisPin::for_network(network),
        })
    }

    /// A harness chain that mines its own genesis: these rules with block 0
    /// held to nothing. Test and harness builds only.
    #[cfg(any(test, feature = "harness"))]
    #[must_use]
    pub const fn unpinned(self) -> Self {
        Self {
            genesis: GenesisPin::NONE,
            ..self
        }
    }

    /// Regtest under `fixed_difficulty` and `schedule`, its row checked, for
    /// a harness chain that mines its own genesis. Test and harness builds
    /// only.
    ///
    /// # Panics
    ///
    /// Never: regtest's row permits every lever (NI-R6).
    #[cfg(any(test, feature = "harness"))]
    #[must_use]
    pub const fn harness_regtest(
        fixed_difficulty: Option<NonZeroU128>,
        schedule: FakechainSchedule,
    ) -> Self {
        match Self::new(Network::Regtest, fixed_difficulty, schedule) {
            Ok(rules) => rules.unpinned(),
            Err(_) => panic!("regtest's row permits every lever"),
        }
    }

    /// The network the rules are for.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// `dev-difficulty`, if given.
    #[must_use]
    pub const fn fixed_difficulty(&self) -> Option<NonZeroU128> {
        self.fixed_difficulty
    }

    /// The `(SEB, cap)` pair the chain runs under.
    #[must_use]
    pub const fn schedule(&self) -> FakechainSchedule {
        self.schedule
    }

    /// The network's permission for `lever`, for a callee that holds no
    /// network (the store's replay writes).
    #[must_use]
    pub const fn permit(&self, lever: Lever) -> Option<Permit> {
        self.network.permit(lever)
    }

    /// The rule set in force at `height`: the network's issued set, under
    /// the levers when any is pulled.
    #[must_use]
    pub fn in_force(&self, height: BlockHeight) -> RuleSet {
        let id = RuleSchedule::for_network(self.network).rules_at(height);
        let set = RuleSet::for_id(id).expect(
            "every schedule the rules crate defines names only issued sets (const-asserted well_formed)",
        );
        if self.fixed_difficulty.is_none() && self.schedule.is_production() {
            set
        } else {
            set.with_levers(self.fixed_difficulty, self.schedule)
        }
    }

    /// What this run takes on the release's word — `validate`'s `Trust`
    /// input (DRS-E6 slice 3; `PDM-Q5`): the network's table genesis, on
    /// every network (NI-Q8). Resolved here beside `in_force` because the
    /// two are the run's two chain-derived inputs to `validate` and the
    /// rules crate holds neither a schedule nor a `Network` (rule 71).
    #[must_use]
    pub const fn trust(&self) -> Trust {
        Trust::full(self.genesis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_chain_rules::SettlementEpochBlocks;
    use shekyl_types::BlockCount;

    const PRODUCTION: FakechainSchedule = FakechainSchedule::PRODUCTION;

    fn nz(n: u128) -> NonZeroU128 {
        NonZeroU128::new(n).expect("non-zero")
    }

    fn short() -> FakechainSchedule {
        FakechainSchedule::new(
            SettlementEpochBlocks::new(512).expect("non-zero"),
            BlockCount::from_raw(64),
        )
        .expect("64 is inside 512")
    }

    fn cap_only() -> FakechainSchedule {
        FakechainSchedule::new(PRODUCTION.settlement().blocks(), BlockCount::from_raw(64))
            .expect("64 is inside the production epoch")
    }

    /// Every network resolves its own schedule and is held to its own
    /// table genesis, regtest included; the levers are the row's.
    #[test]
    fn every_network_resolves_its_schedule_and_its_genesis() {
        for net in Network::ALL {
            let rules = ChainRules::new(net, None, PRODUCTION).expect("no lever");
            assert_eq!(rules.network(), net);
            assert_eq!(rules.in_force(BlockHeight::from_raw(0)), RuleSet::GENESIS);
            assert_eq!(
                rules.in_force(BlockHeight::from_raw(1_000_000)),
                RuleSet::GENESIS
            );
            assert_eq!(rules.trust(), Trust::full(GenesisPin::for_network(net)));
            assert_ne!(rules.trust(), Trust::UNPINNED);
        }
    }

    #[test]
    fn a_lever_is_refused_where_the_row_does_not_permit_it() {
        for net in Network::ALL.into_iter().filter(|n| *n != Network::Regtest) {
            assert_eq!(
                ChainRules::new(net, Some(nz(7)), PRODUCTION),
                Err(LeverRefused {
                    network: net,
                    lever: Lever::Difficulty
                })
            );
            assert_eq!(
                ChainRules::new(net, None, short()).map_err(|e| e.lever),
                Err(Lever::SettlementEpochBlocks)
            );
            assert_eq!(
                ChainRules::new(net, None, cap_only()).map_err(|e| e.lever),
                Err(Lever::ArchivalReorgDepth)
            );
            assert_eq!(
                ChainRules::new(net, Some(nz(7)), short()).map_err(|e| e.lever),
                Err(Lever::Difficulty),
                "both pulled: the difficulty is named first"
            );
        }
    }

    #[test]
    fn regtests_levers_apply_onto_its_own_set() {
        let fixed = ChainRules::new(Network::Regtest, Some(nz(7)), PRODUCTION).expect("permitted");
        let set = fixed.in_force(BlockHeight::from_raw(5));
        assert_eq!(set, RuleSet::fakechain(Some(nz(7)), PRODUCTION));
        assert_ne!(set, RuleSet::GENESIS, "same id, different set");
        assert_eq!(set.id(), RuleSet::GENESIS.id());
        // The schedule lever alone: the genesis target, a 512-block epoch.
        let scheduled = ChainRules::new(Network::Regtest, None, short()).expect("permitted");
        let set = scheduled.in_force(BlockHeight::from_raw(5));
        assert_eq!(set.settlement_schedule(), short().settlement());
        assert_eq!(set.reorg_cap(), BlockCount::from_raw(64));
        assert_eq!(set.id(), RuleSet::GENESIS.id());
        // A lever moves the rules, never the genesis.
        for rules in [fixed, scheduled] {
            assert_eq!(
                rules.trust(),
                Trust::full(GenesisPin::for_network(Network::Regtest))
            );
        }
    }

    #[test]
    fn only_a_harness_unpins_and_only_regtest_permits_the_replay_writes() {
        let rules = ChainRules::new(Network::Regtest, None, PRODUCTION).expect("regtest");
        assert_eq!(rules.unpinned().trust(), Trust::UNPINNED);
        assert_eq!(
            rules.unpinned().in_force(BlockHeight::ZERO),
            rules.in_force(BlockHeight::ZERO)
        );
        for net in Network::ALL {
            let rules = ChainRules::new(net, None, PRODUCTION).expect("no lever");
            for lever in [Lever::InjectServeCredit, Lever::IssueDraws] {
                assert_eq!(rules.permit(lever).is_some(), net == Network::Regtest);
            }
        }
    }

    #[test]
    fn the_refusal_names_the_lever() {
        let e = LeverRefused {
            network: Network::Testnet,
            lever: Lever::SettlementEpochBlocks,
        };
        assert_eq!(
            e.to_string(),
            "dev-settlement-epoch-blocks is a lever testnet's row does not permit \
             (NETWORK_IDENTITY.md NI-R6)"
        );
    }
}
