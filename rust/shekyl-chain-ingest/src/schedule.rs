// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which rules are in force at a height — the driver's half of RD-Q10,
//! and the home of `--fixed-difficulty` (RD-Q7).
//!
//! `connect` takes the in-force [`RuleSet`] by value and compares; it holds
//! no schedule and no `Network` (rule 71). Resolving *height → set* is
//! therefore the driver's, and this type is where it lives. Two sources:
//!
//! - a **public network**: `RuleSchedule::for_network(net).rules_at(h)`
//!   names an issued id, and `RuleSet::for_id` resolves it — every schedule
//!   the rules crate defines is `const`-asserted well-formed, so that
//!   resolution cannot fail;
//! - **regtest**, which `shekyl_address::Network` cannot name (slice 2 F10:
//!   no Fakechain variant): the genesis rules under the daemon's two
//!   regtest levers — the target **fixed** when `--fixed-difficulty n` is
//!   given, and the **settlement schedule** the daemon ran
//!   (`SHEKYL_SETTLEMENT_EPOCH_BLOCKS` / `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS`,
//!   a [`FakechainSchedule`] pair) — `RuleSet::fakechain(fixed, schedule)`,
//!   the one constructor of a non-issued set (DRS-E4 `ARW-15`: the
//!   schedule is rule-set data, so a chain mined under a 512-block epoch
//!   is judged under one). Without either lever a regtest run uses the
//!   genesis rules exactly, as `shekyld --regtest` does with
//!   `--fixed-difficulty` at its default `0` = not fixed and no schedule
//!   override armed.
//!
//! Both levers are **refused** off regtest at construction
//! ([`ChainRules::new`]): `for_network` cannot yield a fixed target or a
//! non-production schedule, and the refusal here is what makes that a
//! typed fact rather than a runtime surprise (§5's deviation row:
//! production nets refuse the levers by type).
//!
//! What is deliberately *not* here: a Fakechain seed-epoch override. The
//! validator derives the seed height with the mainnet constants at every
//! nettype and reads no environment (slice 2 F5, CEN-D3), so a driver that
//! claimed seeds on a faster schedule would earn `Stale::Seed` at every
//! block. The regtest daemon a corpus is harvested from must run without
//! `SEEDHASH_EPOCH_*` overrides (RD-F19). Under a **live** target such a
//! corpus is refused by CEN-D1 from the first block mined under the fast
//! schedule; under `--fixed-difficulty 1` every longhash satisfies the
//! target and nothing in the chain data can tell the two schedules apart —
//! which is why the exporter refuses to run with an override in its own
//! environment, and why the recipe states the daemon's.

use core::num::NonZeroU128;

use shekyl_address::Network;
use shekyl_chain_rules::{FakechainSchedule, ReleaseAnchors, RuleSchedule, RuleSet, Trust};
use shekyl_types::BlockHeight;

use crate::corpus::CorpusNet;

/// Where a run's chain is from, for rule-set purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    /// One of the three public networks.
    Public(Network),
    /// `shekyld --regtest`: genesis rules, optionally with a fixed target.
    Regtest,
}

impl From<CorpusNet> for Chain {
    /// The corpus's tag names the chain its blocks came from; the rules a
    /// run resolves are that chain's.
    fn from(net: CorpusNet) -> Self {
        match net {
            CorpusNet::Mainnet => Self::Public(Network::Mainnet),
            CorpusNet::Testnet => Self::Public(Network::Testnet),
            CorpusNet::Stagenet => Self::Public(Network::Stagenet),
            CorpusNet::Fakechain => Self::Regtest,
        }
    }
}

/// The regtest levers a run can pull — `shekyld --regtest`'s two ways of
/// running a chain a public network never would.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegtestLever {
    /// `--fixed-difficulty n`.
    FixedDifficulty,
    /// A settlement schedule other than the production one
    /// (`SHEKYL_SETTLEMENT_EPOCH_BLOCKS` / `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS`).
    SettlementSchedule,
}

impl core::fmt::Display for RegtestLever {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::FixedDifficulty => "--fixed-difficulty",
            Self::SettlementSchedule => "a non-production settlement schedule",
        })
    }
}

/// A regtest lever pulled somewhere it is not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{lever} is a regtest lever; {net:?} refuses it (its schedule cannot yield it)")]
pub struct RegtestLeverRefused {
    /// The public network the lever was pulled for.
    pub net: Network,
    /// Which lever.
    pub lever: RegtestLever,
}

/// The rules in force at each height of a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainRules {
    /// A public network's schedule.
    Scheduled(Network),
    /// Regtest: genesis rules under the daemon's levers — the target
    /// fixed at `n` when `Some`, and the settlement schedule the daemon
    /// ran ([`FakechainSchedule::PRODUCTION`] when nothing was armed).
    Regtest {
        /// `--fixed-difficulty n`, if given.
        fixed_difficulty: Option<NonZeroU128>,
        /// The `(SEB, cap)` pair the chain was mined under.
        schedule: FakechainSchedule,
    },
}

impl ChainRules {
    /// Build from the chain and the levers, refusing either lever off
    /// regtest. The production schedule is not a lever pulled: a public
    /// network with `FakechainSchedule::PRODUCTION` is simply scheduled.
    ///
    /// # Errors
    ///
    /// [`RegtestLeverRefused`] for `Public(_)` with a fixed difficulty or a
    /// schedule other than the production one — the difficulty named
    /// first when both are pulled.
    pub const fn new(
        chain: Chain,
        fixed_difficulty: Option<NonZeroU128>,
        schedule: FakechainSchedule,
    ) -> Result<Self, RegtestLeverRefused> {
        match chain {
            Chain::Regtest => Ok(Self::Regtest {
                fixed_difficulty,
                schedule,
            }),
            Chain::Public(net) if fixed_difficulty.is_some() => Err(RegtestLeverRefused {
                net,
                lever: RegtestLever::FixedDifficulty,
            }),
            Chain::Public(net) if !schedule.is_production() => Err(RegtestLeverRefused {
                net,
                lever: RegtestLever::SettlementSchedule,
            }),
            Chain::Public(net) => Ok(Self::Scheduled(net)),
        }
    }

    /// The rule set in force at `height`.
    #[must_use]
    pub fn in_force(&self, height: BlockHeight) -> RuleSet {
        match *self {
            Self::Scheduled(net) => {
                let id = RuleSchedule::for_network(net).rules_at(height);
                RuleSet::for_id(id)
                    .expect("every schedule the rules crate defines names only issued sets (const-asserted well_formed)")
            }
            // With no lever pulled this IS `RuleSet::GENESIS`
            // (`fakechain(None, PRODUCTION) == GENESIS`, pinned in the
            // rules crate): one arm, no special case to drift.
            Self::Regtest {
                fixed_difficulty,
                schedule,
            } => RuleSet::fakechain(fixed_difficulty, schedule),
        }
    }

    /// What this run takes on the release's word — `validate`'s `Trust`
    /// input (DRS-E6 slice 3; `PDM-Q5`). A public network's release-carried
    /// anchors, resolved by the same nettype the schedule is; regtest is
    /// unanchored — no release vouches for a regtest chain. Resolved here
    /// beside `in_force` because the two are the run's two chain-derived
    /// inputs to `validate` and the rules crate holds neither a schedule nor
    /// a `Network` (rule 71).
    #[must_use]
    pub const fn trust(&self) -> Trust {
        match *self {
            Self::Scheduled(net) => Trust::full(ReleaseAnchors::for_network(net)),
            Self::Regtest { .. } => Trust::UNANCHORED,
        }
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

    #[test]
    fn public_networks_resolve_their_schedule_and_refuse_the_levers() {
        for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            let rules = ChainRules::new(Chain::Public(net), None, PRODUCTION).expect("no lever");
            assert_eq!(rules.in_force(BlockHeight::from_raw(0)), RuleSet::GENESIS);
            assert_eq!(
                rules.in_force(BlockHeight::from_raw(1_000_000)),
                RuleSet::GENESIS
            );
            assert_eq!(
                ChainRules::new(Chain::Public(net), Some(nz(7)), PRODUCTION),
                Err(RegtestLeverRefused {
                    net,
                    lever: RegtestLever::FixedDifficulty
                })
            );
            assert_eq!(
                ChainRules::new(Chain::Public(net), None, short()),
                Err(RegtestLeverRefused {
                    net,
                    lever: RegtestLever::SettlementSchedule
                })
            );
            assert_eq!(
                ChainRules::new(Chain::Public(net), Some(nz(7)), short()).map_err(|e| e.lever),
                Err(RegtestLever::FixedDifficulty),
                "both pulled: the difficulty is named first"
            );
            // The release's anchors for that network — empty today, so
            // equal to UNANCHORED by value; the *resolution* is what this
            // pins (the first anchor entry moves the left side, not the
            // right).
            assert_eq!(rules.trust(), Trust::full(ReleaseAnchors::for_network(net)));
        }
    }

    #[test]
    fn regtest_is_genesis_without_a_lever_and_fakechain_with_one() {
        let plain = ChainRules::new(Chain::Regtest, None, PRODUCTION).expect("regtest");
        assert_eq!(plain.in_force(BlockHeight::from_raw(5)), RuleSet::GENESIS);
        let fixed = ChainRules::new(Chain::Regtest, Some(nz(7)), PRODUCTION).expect("regtest");
        let set = fixed.in_force(BlockHeight::from_raw(5));
        assert_eq!(set, RuleSet::fakechain(Some(nz(7)), PRODUCTION));
        assert_ne!(set, RuleSet::GENESIS, "same id, different set");
        assert_eq!(set.id(), RuleSet::GENESIS.id());
        // The schedule lever alone: the genesis target, a 512-block epoch.
        let scheduled = ChainRules::new(Chain::Regtest, None, short()).expect("regtest");
        let set = scheduled.in_force(BlockHeight::from_raw(5));
        assert_eq!(set.settlement_schedule(), short().settlement());
        assert_eq!(set.reorg_cap(), BlockCount::from_raw(64));
        assert_eq!(set.id(), RuleSet::GENESIS.id());
        // No release vouches for a regtest chain, lever or no lever.
        assert_eq!(plain.trust(), Trust::UNANCHORED);
        assert_eq!(fixed.trust(), Trust::UNANCHORED);
        assert_eq!(scheduled.trust(), Trust::UNANCHORED);
    }

    #[test]
    fn the_refusal_names_the_lever() {
        let e = RegtestLeverRefused {
            net: Network::Testnet,
            lever: RegtestLever::SettlementSchedule,
        };
        assert_eq!(
            e.to_string(),
            "a non-production settlement schedule is a regtest lever; Testnet refuses it \
             (its schedule cannot yield it)"
        );
    }
}
