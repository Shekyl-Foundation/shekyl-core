// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One member's receive check on top of the group's solo scan
//! (`docs/PQC_MULTISIG.md` §8).
//!
//! The group scans as a solo wallet would. For each output that matches,
//! this member opens the output's `0x0D` entry and checks that the published
//! leaf commits to the group's key hashes. That check replaces the solo leaf
//! comparison: a group output's leaf never commits to the solo per-output
//! key, which every member could derive.

use zeroize::{Zeroize, Zeroizing};

use shekyl_crypto_pq::multisig_output::{
    open_multisig_entry, MultisigEntryView, MultisigMemberView, MultisigReceiveError,
};
use shekyl_engine_state::UnspendableReason;

use crate::extra::Extra;

/// What one member of an Option E′ multisig group brings to a scan beyond
/// the group's view pair (`docs/PQC_MULTISIG.md` §8).
#[derive(Clone)]
pub struct MultisigMemberScan {
    member_index: u8,
    n_total: u8,
    m_required: u8,
    member_x25519_sk: Zeroizing<[u8; 32]>,
    member_ml_kem_dk: Zeroizing<Vec<u8>>,
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
        member_x25519_sk: Zeroizing<[u8; 32]>,
        member_ml_kem_dk: Zeroizing<Vec<u8>>,
        network: [u8; 16],
    ) -> Self {
        Self {
            member_index,
            n_total,
            m_required,
            member_x25519_sk,
            member_ml_kem_dk,
            network,
        }
    }

    /// The multisig verdict for one output the group's view pair matched.
    /// Each refusal is its own [`UnspendableReason`]: the ledger names the
    /// check that failed.
    pub(crate) fn verdict(
        &self,
        recovered: &shekyl_crypto_pq::output::RecoveredOutput,
        extra: &Extra,
        vout: usize,
    ) -> Option<UnspendableReason> {
        let Some(published) = extra.pqc_leaf_entry(vout) else {
            return Some(UnspendableReason::PqcLeafEntryAbsent);
        };
        // No 0x0D entry: paid to the group's keys as a solo output, whose
        // leaf commits to a key every member can derive. Not spendable
        // under the group's M-of-N rules.
        let Some(entry) = extra.pqc_multisig_entry(vout) else {
            return Some(UnspendableReason::MultisigEntryAbsent);
        };
        if entry.n() != self.n_total || self.member_index >= entry.n() {
            return Some(UnspendableReason::MultisigGroupSize);
        }
        let ct = &entry.member_cts()[usize::from(self.member_index)];
        let opened = open_multisig_entry(
            &recovered.combined_ss,
            vout as u64,
            &MultisigMemberView {
                member_index: self.member_index,
                n_total: self.n_total,
                m_required: self.m_required,
                member_x25519_sk: &self.member_x25519_sk,
                member_ml_kem_dk: &self.member_ml_kem_dk,
                network: &self.network,
            },
            &MultisigEntryView {
                out_idx: entry.out_idx(),
                n: entry.n(),
                own_x25519_ct: &ct.x25519,
                own_ml_kem_ct: &ct.ml_kem,
                enc_key_hashes: entry.enc_key_hashes(),
            },
            published,
        );
        match opened {
            Ok(_) => None,
            Err(err) => Some(persisted_reason(err)),
        }
    }
}

/// One persisted reason per receive-check failure. The match is total, so
/// a new [`MultisigReceiveError`] cannot collapse into a neighbour.
fn persisted_reason(err: MultisigReceiveError) -> UnspendableReason {
    match err {
        MultisigReceiveError::GroupSize => UnspendableReason::MultisigGroupSize,
        MultisigReceiveError::HashesUndecryptable => UnspendableReason::MultisigHashesUndecryptable,
        MultisigReceiveError::MemberDecap => UnspendableReason::MultisigMemberDecap,
        MultisigReceiveError::MemberKeyHash => UnspendableReason::MultisigMemberKeyHash,
        MultisigReceiveError::DuplicateKeyHash => UnspendableReason::MultisigDuplicateKeyHash,
        MultisigReceiveError::LeafMismatch => UnspendableReason::MultisigLeafMismatch,
    }
}

impl Zeroize for MultisigMemberScan {
    fn zeroize(&mut self) {
        self.member_x25519_sk.zeroize();
        self.member_ml_kem_dk.zeroize();
    }
}
