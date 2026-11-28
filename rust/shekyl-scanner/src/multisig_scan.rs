// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One member's receive step (`docs/PQC_MULTISIG.md` §8; R-35).
//!
//! The group's outputs are found by the group's view key, as a solo
//! wallet's are by its own. Each one is then received through
//! `shekyl-crypto-pq`'s group receive check
//! ([`receive_group_output`]), which recovers the output, checks it is the
//! group's, computes its key image and runs the member check, and returns a
//! receipt or a refusal only that crate can make. This step adds the
//! output's place on the chain and nothing else; a group wallet's ledger
//! builds its records from the two ([`shekyl_engine_state::GroupCoin`],
//! [`shekyl_engine_state::RefusedGroupOutput`]).

use zeroize::Zeroize;

use shekyl_crypto_pq::kem::HybridKemSecretKey;
use shekyl_crypto_pq::multisig_output::MultisigMemberView;
use shekyl_crypto_pq::multisig_receive::{
    receive_group_output, GroupEntryOnChain, GroupOutputOnChain, GroupReceived, GroupScanKeys,
};
use shekyl_types::{Timelock, TxHash};

use crate::scan::{timelock_from_unlock_time, OutputFields, Receive, ScanError, ScanKeys};

/// What one member of an Option E′ multisig group brings to a scan beyond
/// the group's view pair (`docs/PQC_MULTISIG.md` §8).
#[derive(Clone)]
pub struct MultisigMemberScan {
    member_index: u8,
    n_total: u8,
    m_required: u8,
    member_kem_secret: HybridKemSecretKey,
    network: [u8; 16],
}

impl MultisigMemberScan {
    /// A member's scan context: its index, the group's size and threshold,
    /// its own hybrid KEM secret, and the chain's network id (the key
    /// hashes bind it).
    #[must_use]
    pub fn new(
        member_index: u8,
        n_total: u8,
        m_required: u8,
        member_kem_secret: HybridKemSecretKey,
        network: [u8; 16],
    ) -> Self {
        Self {
            member_index,
            n_total,
            m_required,
            member_kem_secret,
            network,
        }
    }
}

impl Zeroize for MultisigMemberScan {
    fn zeroize(&mut self) {
        self.member_kem_secret.zeroize();
    }
}

/// One output a member's scan found paid to the group: what the receive
/// check returned, and where the output sits on the chain.
#[derive(Debug)]
pub struct GroupScannedOutput {
    received: GroupReceived,
    tx_hash: TxHash,
    global_index: u64,
    additional_timelock: Timelock,
}

impl GroupScannedOutput {
    /// What the receive check returned: a receipt or a refusal.
    #[must_use]
    pub fn received(&self) -> &GroupReceived {
        &self.received
    }
    /// The transaction that carries the output.
    #[must_use]
    pub fn tx_hash(&self) -> TxHash {
        self.tx_hash
    }
    /// The output's chain-wide index.
    #[must_use]
    pub fn global_index(&self) -> u64 {
        self.global_index
    }
    /// The output's own timelock, beyond the spendable age.
    #[must_use]
    pub fn additional_timelock(&self) -> Timelock {
        self.additional_timelock
    }
    /// The parts, for the ledger to build its record from.
    #[must_use]
    pub fn into_parts(self) -> (GroupReceived, TxHash, u64, Timelock) {
        (
            self.received,
            self.tx_hash,
            self.global_index,
            self.additional_timelock,
        )
    }
}

/// A block's group outputs, in chain order.
#[derive(Debug)]
pub struct GroupScanned(pub(crate) Vec<GroupScannedOutput>);

impl GroupScanned {
    /// The outputs, in chain order.
    #[must_use]
    pub fn into_inner(self) -> Vec<GroupScannedOutput> {
        self.0
    }
    /// The number of outputs found.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Whether the block paid the group nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Receive for MultisigMemberScan {
    type Item = GroupScannedOutput;

    fn receive(
        &self,
        keys: &ScanKeys<'_>,
        fields: &OutputFields<'_>,
    ) -> Result<Option<GroupScannedOutput>, ScanError> {
        let o = fields.o;
        let entry = fields
            .extra
            .pqc_multisig_entry(o)
            .map(|entry| GroupEntryOnChain {
                out_idx: entry.out_idx(),
                member_cts: entry
                    .member_cts()
                    .iter()
                    .map(|ct| (&ct.x25519, ct.ml_kem.as_slice()))
                    .collect(),
                enc_key_hashes: entry.enc_key_hashes(),
            });
        let output = GroupOutputOnChain {
            output_index: o as u64,
            output_key: &fields.output_key_bytes,
            commitment: &fields.commitment.0,
            enc_amount: &fields.enc_amount,
            amount_tag: fields.amount_tag,
            enc_label: &fields.enc_label,
            label_tag: fields.label_tag,
            view_tag: fields.view_tag,
            source_x25519_ct: fields.ct_x25519,
            source_ml_kem_ct: fields.ct_ml_kem,
            leaf_entry: fields.extra.pqc_leaf_entry(o),
            entry,
        };
        let member = MultisigMemberView {
            member_index: self.member_index,
            n_total: self.n_total,
            m_required: self.m_required,
            member_kem_secret: &self.member_kem_secret,
            network: &self.network,
        };
        let group_keys = GroupScanKeys {
            view_x25519: keys.pair.x25519_sk(),
            view_ml_kem: keys.pair.parsed_ml_kem_dk(),
            spend_key: &keys.primary_spend_compressed.0,
            b: keys.spend_secret,
        };
        let Some(received) = receive_group_output(&group_keys, &member, &output) else {
            return Ok(None);
        };
        Ok(Some(GroupScannedOutput {
            received,
            tx_hash: fields.tx_hash,
            global_index: fields.global_index()?,
            additional_timelock: timelock_from_unlock_time(fields.unlock_time),
        }))
    }
}
