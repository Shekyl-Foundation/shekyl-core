// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bond-post observation — the single owner of "what counts as a cleartext
//! bond-post observation" in a scanned transaction.
//!
//! Two consumers read `Input::BondPost` from blocks in hand:
//!
//! - the **P-scan dual extractor** (`pscan::scan_step::run_dual_extractor`),
//!   which matches observations against the bonded-persona set and records
//!   [`BondPostMatch`](super::pscan::scan_step::BondPostMatch) rows into the
//!   sealed accrual evidence; and
//! - the **principal scan's bond watch** (SA-R-6 from-seed reconstruction):
//!   the refresh/rescan merge matches observations against the persisted
//!   probe-id cache (`StakingBlock::persona_id_cache`) to re-adopt bonds a
//!   restored wallet's record lost and raise the monotone `p_slot` cursor.
//!
//! Both must agree byte-for-byte on what an observation *is* — the id lift at
//! the wire→domain boundary and the post-kind byte — or the probe could sight
//! a bond the P-scan would later fail to corroborate (or vice versa), and the
//! sighting bridge in the open-time reconcile would wedge. Hence one free
//! function, no policy: matching (against which id set, with what refusals)
//! stays with each consumer.

use shekyl_types::PCanonicalId;
use shekyl_wire::transaction::{BondPostKind, Input, Transaction};

/// One cleartext bond-post observation lifted from a transaction input:
/// the posting persona's public canonical id and the wire post-kind byte.
/// Carries no height/tx context — the caller owns that pairing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct BondPostObservation {
    /// The posting persona's canonical id, lifted from the wire `[u8; 32]`
    /// once, at the wire→domain boundary.
    pub(crate) p_canonical_id: PCanonicalId,
    /// Wire post-kind byte (`0x00` = JoinMarket; otherwise the `Other` tag),
    /// via [`post_kind_byte`].
    pub(crate) post_kind: u8,
}

/// Iterate the bond-post observations in one transaction, in input order.
///
/// Pure read of public wire data — no secret is touched, nothing is cloned.
/// A transaction with no `Input::BondPost` yields nothing at the cost of an
/// input walk (inputs are few; bond posts are rare).
pub(crate) fn bond_post_observations(
    tx: &Transaction,
) -> impl Iterator<Item = BondPostObservation> + '_ {
    tx.prefix.inputs.iter().filter_map(|input| match input {
        Input::BondPost(bp) => Some(BondPostObservation {
            p_canonical_id: PCanonicalId::from_bytes(bp.p_canonical_id),
            post_kind: post_kind_byte(&bp.kind),
        }),
        _ => None,
    })
}

/// The wire post-kind byte (JoinMarket's dense tag is `0x00`,
/// `shekyl_wire::transaction` §9.11). Single-sourced from the wire crate's own
/// [`BOND_POST_KIND_JOINMARKET`](shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET)
/// so the recorded byte and the confirmation filter in
/// [`PScanAccrual`](super::pscan::accrual::PScanAccrual) cannot drift from the
/// wire definition.
pub(crate) fn post_kind_byte(kind: &BondPostKind) -> u8 {
    match kind {
        BondPostKind::JoinMarket { .. } => shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET,
        BondPostKind::Other(b) => *b,
    }
}
