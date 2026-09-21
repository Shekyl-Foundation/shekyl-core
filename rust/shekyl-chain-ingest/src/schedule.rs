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
//!   no Fakechain variant): the genesis rules, with the target **fixed**
//!   when `--fixed-difficulty n` is given — `RuleSet::fakechain(n)`,
//!   the one constructor of a non-issued set. Without the flag a regtest
//!   run uses the genesis LWMA rules, exactly as `shekyld --regtest` does
//!   with its `--fixed-difficulty` at the default `0` = not fixed.
//!
//! The flag is **refused** off regtest at construction
//! ([`ChainRules::new`]): `for_network` cannot yield a `Fixed` set, and the
//! refusal here is what makes that a typed fact rather than a runtime
//! surprise (§5's deviation row: production nets refuse the flag by type).
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
use shekyl_chain_rules::{RuleSchedule, RuleSet};
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

/// `--fixed-difficulty` given somewhere it is not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("--fixed-difficulty is a regtest lever; {net:?} refuses it (its schedule cannot yield a fixed target)")]
pub struct FixedDifficultyRefused {
    /// The public network the flag was given for.
    pub net: Network,
}

/// The rules in force at each height of a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainRules {
    /// A public network's schedule.
    Scheduled(Network),
    /// Regtest: genesis rules, the target fixed at `n` when `Some`.
    Regtest {
        /// `--fixed-difficulty n`, if given.
        fixed_difficulty: Option<NonZeroU128>,
    },
}

impl ChainRules {
    /// Build from the chain and the flag, refusing the flag off regtest.
    ///
    /// # Errors
    ///
    /// [`FixedDifficultyRefused`] for `Public(_)` with a fixed difficulty.
    pub const fn new(
        chain: Chain,
        fixed_difficulty: Option<NonZeroU128>,
    ) -> Result<Self, FixedDifficultyRefused> {
        match (chain, fixed_difficulty) {
            (Chain::Public(net), None) => Ok(Self::Scheduled(net)),
            (Chain::Public(net), Some(_)) => Err(FixedDifficultyRefused { net }),
            (Chain::Regtest, fixed_difficulty) => Ok(Self::Regtest { fixed_difficulty }),
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
            Self::Regtest {
                fixed_difficulty: Some(n),
            } => RuleSet::fakechain(n),
            Self::Regtest {
                fixed_difficulty: None,
            } => RuleSet::GENESIS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(n: u128) -> NonZeroU128 {
        NonZeroU128::new(n).expect("non-zero")
    }

    #[test]
    fn public_networks_resolve_their_schedule_and_refuse_the_flag() {
        for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            let rules = ChainRules::new(Chain::Public(net), None).expect("no flag");
            assert_eq!(rules.in_force(BlockHeight::from_raw(0)), RuleSet::GENESIS);
            assert_eq!(
                rules.in_force(BlockHeight::from_raw(1_000_000)),
                RuleSet::GENESIS
            );
            assert_eq!(
                ChainRules::new(Chain::Public(net), Some(nz(7))),
                Err(FixedDifficultyRefused { net })
            );
        }
    }

    #[test]
    fn regtest_is_genesis_without_the_flag_and_fakechain_with_it() {
        let plain = ChainRules::new(Chain::Regtest, None).expect("regtest");
        assert_eq!(plain.in_force(BlockHeight::from_raw(5)), RuleSet::GENESIS);
        let fixed = ChainRules::new(Chain::Regtest, Some(nz(7))).expect("regtest");
        let set = fixed.in_force(BlockHeight::from_raw(5));
        assert_eq!(set, RuleSet::fakechain(nz(7)));
        assert_ne!(set, RuleSet::GENESIS, "same id, different set");
        assert_eq!(set.id(), RuleSet::GENESIS.id());
    }
}
