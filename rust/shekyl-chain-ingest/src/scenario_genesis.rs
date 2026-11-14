// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A scenario chain that carries a network's identity (`CHAIN_FORGE.md`
//! §6, `CF-1a`).
//!
//! The driver's own chains mine their own block 0 and are held to no
//! genesis pin ([`super::RULES`], `Trust::UNPINNED`), so they sign under
//! the harness id and replay under no network's rules. A chain the forge
//! keeps is regtest's instead: its rules are [`ChainRules::new`] for
//! [`Network::Regtest`], whose pin is the table's genesis; its block 0 is
//! [`pinned_genesis`], the assembly the node connects, and it is connected
//! through the connector's door, where CEN-E1 holds it to the pin; its
//! miner is the wallet regtest derives from the harness seed
//! ([`MinerWallet::harness_regtest`]). Every network-bound signature the
//! chain's spends carry is then over regtest's id, which the spender reads
//! from [`Scenario::network_id`] (`Spender::on`).
//!
//! Nothing here mines block 0 or chooses its bytes. A change to the genesis
//! header or the table's coinbase moves this chain's block 0 with the
//! node's, because both call [`pinned_genesis`].

use core::num::NonZeroU128;

use shekyl_chain_rules::{Candidate, CappedEpoch, Substrate};
use shekyl_genesis_tool::builder::pinned_genesis;
use shekyl_harness_wallet::MinerWallet;
use shekyl_network::{Network, NetworkId};
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::Block;

use super::{MinerKeys, Scenario, StepOutcome};
use crate::schedule::ChainRules;

impl<P: Substrate + Send + Sync + 'static> Scenario<P>
where
    P::Fault: std::fmt::Debug + Send,
{
    /// A chain carrying regtest's identity at a fresh store named `name`:
    /// regtest at fixed difficulty one under `schedule`, held to regtest's
    /// table genesis, which is connected as block 0 before this returns
    /// (module docs). The genesis block is returned beside the scenario, for
    /// a spender to be fed from height 0 (`Spender::on`, through
    /// `shekyl_harness_spender::Linked`).
    ///
    /// # Panics
    ///
    /// If regtest's table genesis does not assemble, or does not connect
    /// under regtest's rules.
    pub async fn open_regtest(name: &str, pow: P, schedule: CappedEpoch) -> (Self, Block) {
        let rules = ChainRules::new(Network::Regtest, Some(NonZeroU128::MIN), schedule)
            .unwrap_or_else(|refused| panic!("regtest's row permits every lever: {refused}"));
        let mut scenario = Self::open_under(name, pow, rules);
        let miner = MinerWallet::harness_regtest();
        let recipient = miner.recipient();
        scenario.miner = MinerKeys {
            spend_public: recipient.spend_public,
            x25519_pk: recipient.x25519_pk,
            ml_kem_ek: recipient.ml_kem_ek.clone(),
        };
        scenario.wallet = miner;
        let genesis = pinned_genesis(Network::Regtest)
            .unwrap_or_else(|error| panic!("regtest's table genesis assembles: {error}"));
        let connected = scenario
            .offer_genesis(&genesis)
            .await
            .unwrap_or_else(|outcome| panic!("regtest's table genesis connects: {outcome}"));
        assert_eq!(
            connected,
            genesis.hash(),
            "the store holds the table's block 0"
        );
        (scenario, genesis)
    }

    /// Offer `block` as this chain's block 0: formed under the chain's own
    /// claims at height 0 and applied through the connector's door, the
    /// same form and apply a mined block takes. The rules judge it whole —
    /// CEN-E1 against the chain's genesis pin among them — and a refusal is
    /// returned with its row, not panicked: the identity test offers one
    /// network's genesis to another network's chain on purpose.
    ///
    /// # Errors
    ///
    /// [`StepOutcome::Refused`] with the row that refused the block, or the
    /// connector's fault.
    pub async fn offer_genesis(&mut self, block: &Block) -> Result<BlockHash, StepOutcome> {
        let height = BlockHeight::ZERO;
        let (seed, target) = self.claimed_seed_and_target(height).await?;
        // A genesis lists nothing, so it names no reference to claim.
        let formed = self.form_at(
            height,
            Candidate::new(block.clone(), Vec::new()),
            seed,
            target,
        )?;
        let applied = self.apply_formed(height, formed).await?;
        if let Some((_, refused)) = applied.refused {
            return Err(StepOutcome::Refused(refused));
        }
        self.record_header(height, block, target);
        let (_, hash) = applied.connected[0];
        Ok(hash)
    }

    /// The id of the network this chain is judged as: the one derived from
    /// its genesis pin (`NI-R10`), or the harness id for a chain that mines
    /// its own genesis. What every network-bound signature on it is over.
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        self.rules.trust().network_id()
    }
}
