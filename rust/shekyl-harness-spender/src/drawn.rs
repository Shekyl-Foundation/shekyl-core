// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One spend bound to the seeds the caller already drew.
//!
//! [`Spender`] stays a wallet tree, shareable across the threads that build
//! a shard fill. The seeds are not on it. The planning thread calls
//! [`SpendPlan::next_spend`] once per spend, moves that [`SpendSeeds`] here,
//! and the worker builds that spend. Two threads that share a spender cannot
//! draw from one counter, so the bytes do not depend on which thread runs
//! first (`CHAIN_FORGE.md` §5.1, §5.3, seam T4).

use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::Transaction;

use crate::bond::PostedBond;
use crate::draw::SpendSeeds;
use crate::spender::Spender;
use crate::{MinerWallet, Recipient, Sourced};

/// A [`Spender`] and the seeds of exactly one spend.
///
/// Consumed by the build. A second spend is a second [`SpendPlan::next_spend`]
/// and a second `Drawn`, never this value reused.
pub struct Drawn<'a> {
    spender: &'a Spender,
    seeds: SpendSeeds,
}

impl Spender {
    /// This one spend, drawing its proofs and its spend-slot signatures from
    /// `seeds`. The persona's own signatures stay on
    /// [`crate::Persona::with_signing_seed`]: a post and a spend are different
    /// roles, and each brings the seed its role derived.
    #[must_use]
    pub fn drawing(&self, seeds: SpendSeeds) -> Drawn<'_> {
        Drawn {
            spender: self,
            seeds,
        }
    }
}

impl Drawn<'_> {
    /// [`Spender::spend_coinbase`] from this spend's seeds.
    #[must_use]
    pub fn spend_coinbase(
        self,
        wallet: &MinerWallet,
        height: BlockHeight,
        connecting: BlockHeight,
        fee: u64,
    ) -> Transaction {
        self.spender.spend_coinbase_to_drawn(
            Some(self.seeds),
            wallet,
            height,
            connecting,
            fee,
            None,
            wallet.recipient(),
        )
    }

    /// [`Spender::spend_coinbase_breaking_range_proof`] from this spend's seeds.
    #[must_use]
    pub fn spend_coinbase_breaking_range_proof(
        self,
        wallet: &MinerWallet,
        height: BlockHeight,
        connecting: BlockHeight,
        fee: u64,
    ) -> Transaction {
        self.spender.spend_coinbase_breaking_range_proof_drawn(
            Some(self.seeds),
            wallet,
            height,
            connecting,
            fee,
        )
    }

    /// [`Spender::spend_coinbase_referencing`] from this spend's seeds.
    #[must_use]
    pub fn spend_coinbase_referencing(
        self,
        wallet: &MinerWallet,
        height: BlockHeight,
        connecting: BlockHeight,
        fee: u64,
        reference: BlockHash,
    ) -> Transaction {
        self.spender.spend_coinbase_referencing_drawn(
            Some(self.seeds),
            wallet,
            height,
            connecting,
            fee,
            reference,
        )
    }

    /// [`Spender::spend_coinbase_posting_breaking_membership_proof`] from this
    /// spend's seeds. The bond slot signs with the persona's draw.
    #[must_use]
    pub fn spend_coinbase_posting_breaking_membership_proof(
        self,
        wallet: &MinerWallet,
        height: BlockHeight,
        connecting: BlockHeight,
        fee: u64,
        bond: Option<&PostedBond<'_>>,
    ) -> Transaction {
        self.spender
            .spend_coinbase_posting_breaking_membership_proof_drawn(
                Some(self.seeds),
                wallet,
                height,
                connecting,
                fee,
                bond,
            )
    }

    /// [`Spender::spend_coinbase_posting`] from this spend's seeds. The bond
    /// slot signs with the persona's draw.
    #[must_use]
    pub fn spend_coinbase_posting(
        self,
        wallet: &MinerWallet,
        height: BlockHeight,
        connecting: BlockHeight,
        fee: u64,
        bond: Option<&PostedBond<'_>>,
    ) -> Transaction {
        self.spender.spend_coinbase_to_drawn(
            Some(self.seeds),
            wallet,
            height,
            connecting,
            fee,
            bond,
            wallet.recipient(),
        )
    }

    /// [`Spender::spend_coinbase_to`] from this spend's seeds.
    #[must_use]
    pub fn spend_coinbase_to(
        self,
        wallet: &MinerWallet,
        height: BlockHeight,
        connecting: BlockHeight,
        fee: u64,
        bond: Option<&PostedBond<'_>>,
        recipient: &Recipient,
    ) -> Transaction {
        self.spender.spend_coinbase_to_drawn(
            Some(self.seeds),
            wallet,
            height,
            connecting,
            fee,
            bond,
            recipient,
        )
    }

    /// [`Spender::spend_owned`] from this spend's seeds.
    #[must_use]
    pub fn spend_owned(
        self,
        sourced: Vec<Sourced>,
        connecting: BlockHeight,
        fee: u64,
        recipient: &Recipient,
    ) -> Transaction {
        Spender::spend_owned_drawn(Some(self.seeds), sourced, connecting, fee, recipient)
    }

    /// [`Spender::spend_coinbases`] from this spend's seeds. One transaction,
    /// one draw: the inputs share the statement, so they share these seeds.
    #[must_use]
    pub fn spend_coinbases(
        self,
        wallet: &MinerWallet,
        heights: &[BlockHeight],
        connecting: BlockHeight,
        fee: u64,
    ) -> (Transaction, Vec<BlockHeight>) {
        self.spender
            .spend_coinbases_drawn(Some(self.seeds), wallet, heights, connecting, fee)
    }

    /// [`Spender::spend_coinbase_paying`] from this spend's seeds.
    #[must_use]
    pub fn spend_coinbase_paying(
        self,
        wallet: &MinerWallet,
        height: BlockHeight,
        connecting: BlockHeight,
        fee: u64,
        outputs: usize,
    ) -> Transaction {
        self.spender.spend_coinbase_paying_drawn(
            Some(self.seeds),
            wallet,
            height,
            connecting,
            fee,
            outputs,
        )
    }

    /// [`Spender::signed_under`] with the spend slots signed from this draw's
    /// sign seed. A re-sign is its own statement, so the caller draws a fresh
    /// [`SpendPlan::next_spend`] for it rather than reusing the spend's. The
    /// open half is not read: a re-sign does not prove. The bond slot signs
    /// with the persona's draw.
    #[must_use]
    pub fn signed_under(
        self,
        spent: &Transaction,
        wallet: &MinerWallet,
        height: BlockHeight,
        connecting: BlockHeight,
        bond: Option<&PostedBond<'_>>,
        network: &shekyl_network::NetworkId,
    ) -> Transaction {
        self.spender.signed_under_drawn(
            Some(&self.seeds),
            spent,
            wallet,
            height,
            connecting,
            bond,
            network,
        )
    }
}
