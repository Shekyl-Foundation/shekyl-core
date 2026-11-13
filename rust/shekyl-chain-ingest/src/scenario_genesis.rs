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
//! that genesis, assembled from the table's coinbase under the fixed
//! genesis header the way the node assembles it (`shekyl-node`'s
//! `pinned_genesis`, through the same [`genesis_block`]) and connected
//! through the connector's door, where CEN-E1 holds it to the pin; its
//! miner is the wallet regtest derives from the harness seed
//! ([`MinerWallet::harness_regtest`]). Every network-bound signature the
//! chain's spends carry is then over regtest's id, which the spender reads
//! from [`Scenario::network_id`] (`Spender::on`).
//!
//! Nothing here mines block 0 or chooses its bytes: the table does, and a
//! change to the genesis header or the table's coinbase moves this chain's
//! block 0 with the node's.

use core::num::NonZeroU128;

use shekyl_chain_rules::Substrate;
use shekyl_chain_rules::{form, Candidate, CappedEpoch, FormAttempt, FormClaims, ReferenceClaims};
use shekyl_genesis_tool::builder::genesis_block;
use shekyl_harness_wallet::MinerWallet;
use shekyl_network::{Network, NetworkId};
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{Block, Transaction};

use super::{handler_error, MinerKeys, Scenario, StepOutcome};
use crate::connector::Apply;
use crate::schedule::ChainRules;

/// `network`'s genesis block as the node connects it: the table's coinbase
/// under the fixed genesis header ([`genesis_block`]), held to the hash the
/// table pins.
///
/// # Panics
///
/// If the table's coinbase does not decode or the assembled block is not
/// the pinned one: the build's genesis table and its header disagree, which
/// the node refuses at open too.
#[must_use]
pub(crate) fn table_genesis(network: Network) -> Block {
    let genesis = network.genesis();
    let bytes = hex::decode(genesis.tx_hex()).expect("the table's genesis coinbase is hex");
    let tx = Transaction::from_bytes(&bytes).expect("the table's genesis coinbase decodes");
    let block = genesis_block(tx).expect("the genesis block assembles");
    assert_eq!(
        block.hash(),
        BlockHash::from_bytes(genesis.hash()),
        "{network}'s assembled genesis is the block the table pins"
    );
    block
}

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
    /// If regtest's table genesis does not connect under regtest's rules.
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
        let genesis = table_genesis(Network::Regtest);
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
    /// claims at height 0 and applied through the connector's door, as the
    /// node offers its pinned genesis. The rules judge it whole — CEN-E1
    /// against the chain's genesis pin among them — and a refusal is
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
        let rule_set = self.rules.in_force(height);
        // A genesis lists nothing, so it names no reference to claim.
        let candidate = Candidate::new(block.clone(), Vec::new());
        self.substrate.pin_seed(&seed);
        let formed = form(
            candidate,
            &FormClaims {
                rule_set: &rule_set,
                seed,
                target,
                references: &ReferenceClaims::EMPTY,
                network: self.network_id(),
            },
            &self.substrate,
            FormAttempt::FIRST,
        )
        .expect("the driver's substrate does not fault")
        .map_err(StepOutcome::Refused)?;
        let applied = self
            .connector
            .ask(Apply(vec![(height, Ok(formed))]))
            .await
            .map_err(handler_error)
            .map_err(StepOutcome::Connector)?;
        if let Some((_, refused)) = applied.refused {
            return Err(StepOutcome::Refused(refused));
        }
        let (_, hash) = applied.connected[0];
        // Block 0's header joins the window every later claim reads.
        self.targets
            .extend(height, block, target)
            .unwrap_or_else(|corrupt| panic!("the scenario's chain is consistent: {corrupt}"));
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
