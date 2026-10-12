// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! Which arm a bond post is, classified once.
//!
//! The sequence (`judge_bond_post`) and the fold (`Transition::apply_input`)
//! both ask that question. They used to answer it separately — the fold
//! through [`BondPostKind::from_u8`](shekyl_archival_retention::BondPostKind::from_u8),
//! the sequence through two raw kind bytes — so a kind no arm names could
//! pass the sequence and meet CEN-L7 only at the fold. One classifier means
//! the two cannot disagree about which arm a post is, or about there being
//! none.

use shekyl_archival_retention::BondPostKind as RetentionKind;
use shekyl_wire::transaction::{BondPost, BondPostKind as WireKind};

/// A bond post the retention crate has an arm for.
///
/// [`BondArm::of`] returns `None` for a post no arm names: `Other` carrying
/// one of JoinMarket's own tags (the decoder already reads wire `0` and `5`
/// as [`WireKind::JoinMarket`]), or a byte [`RetentionKind::from_u8`] does not
/// name. Both the sequence and the fold refuse that under CEN-L7, at the
/// post's vin. The fold's arm is the belt under the sequence's.
#[derive(Debug)]
pub(crate) enum BondArm<'a> {
    /// A JoinMarket: the credit that opens a record. The bond-spend key, the
    /// receipt key and the endpoint travel on the wire variant, not beside
    /// it. Wire kinds `0` and `5` are both this arm: `receipt_sign_pk` is
    /// `Some` on a kind-`5` post and `None` on a kind-`0` one, and nothing
    /// else about the arm differs.
    JoinMarket {
        post: &'a BondPost,
        bond_spend_pk: &'a [u8],
        receipt_sign_pk: Option<&'a [u8]>,
        endpoint: [u8; 32],
    },
    /// A Release: the debit that empties a record.
    Release { post: &'a BondPost },
    /// A Reinstate: the credit that closes an open bad interval.
    Reinstate { post: &'a BondPost },
}

impl<'a> BondArm<'a> {
    /// The arm `post` is, or `None` when no arm names its kind.
    pub(crate) fn of(post: &'a BondPost) -> Option<Self> {
        match &post.kind {
            WireKind::JoinMarket {
                bond_spend_pk,
                receipt_sign_pk,
                endpoint,
            } => Some(Self::JoinMarket {
                post,
                bond_spend_pk,
                receipt_sign_pk: receipt_sign_pk.as_deref(),
                endpoint: *endpoint,
            }),
            WireKind::Other(kind) => match RetentionKind::from_u8(*kind) {
                Ok(RetentionKind::Release) => Some(Self::Release { post }),
                Ok(RetentionKind::Reinstate) => Some(Self::Reinstate { post }),
                // `Other(0)` and `Other(5)` cannot come off the wire: the
                // decoder reads both JoinMarket tags as the variant. An
                // unknown byte is a post no fold applies.
                Ok(RetentionKind::JoinMarket | RetentionKind::JoinMarketReceipt) | Err(_) => None,
            },
        }
    }

    /// The post this arm was classified from.
    pub(crate) fn post(&self) -> &'a BondPost {
        match self {
            Self::JoinMarket { post, .. } | Self::Release { post } | Self::Reinstate { post } => {
                post
            }
        }
    }
}
