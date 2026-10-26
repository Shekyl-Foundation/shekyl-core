// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Section first, then each body, on one view (`SO-D12` increment 4a).
//!
//! [`judge_bundles`] is the queue's admission and the staged connect. It
//! computes nothing the section checker and [`super::verify_bundle`] do
//! not already compute.

use shekyl_archival_retention::{BundleBody, BundleRef};
use shekyl_types::BlockHeight;

use super::{
    check_section, verify_bundle, Admitted, BundleRefused, BundleView, SectionCheckFailed,
    SectionRefused, SectionStanding,
};
use crate::census::CenRow;
use crate::rule_set::RuleSet;

/// Why [`judge_bundles`] stopped. A section refusal is J29–J31; a bundle
/// refusal is the verifier's, at the reference it stopped on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionFault<F> {
    /// The section check refused the block before any bundle was opened.
    Section(SectionRefused),
    /// Some epoch's `D` is not on this view. A connected chain's view does
    /// not answer that way: a memo miss is [`Self::View`].
    Awaiting,
    /// [`BundleView`] faulted. A memo miss on the store view is this.
    View(F),
    /// Bundle `at` in section order was refused.
    Bundle {
        /// The reference's position.
        at: usize,
        /// The verifier's refusal.
        refused: BundleRefused<F>,
    },
}

impl<F> AdmissionFault<F> {
    /// The census row, when the fault is a verdict. A view fault and a
    /// body the reference does not name have none.
    #[must_use]
    pub fn row(&self) -> Option<CenRow> {
        match self {
            Self::Section(refused) => Some(refused.row()),
            Self::Bundle {
                refused: BundleRefused::Invalid(invalid),
                ..
            } => Some(invalid.row()),
            Self::Awaiting | Self::View(_) | Self::Bundle { .. } => None,
        }
    }
}

/// Section first, then each body in section order, stopping at the first
/// refusal (`SO-D12` increment 4a).
///
/// The block wire does not carry a section yet (4b), so the staged entry
/// takes the references and bodies the section will hold. Tests call this.
/// `form` and `validate` do not.
///
/// # Errors
///
/// The first section or bundle refusal, or the view's fault.
pub fn judge_bundles<V: BundleView>(
    refs: &[BundleRef],
    bodies: &[BundleBody],
    header_root: &[u8; 32],
    h_incl: BlockHeight,
    view: &V,
    rule_set: &RuleSet,
) -> Result<Vec<Admitted>, AdmissionFault<V::Fault>> {
    match check_section(refs, header_root, h_incl, view, rule_set) {
        Ok(SectionStanding::Admitted(_)) => {}
        Ok(SectionStanding::Awaiting(_)) => return Err(AdmissionFault::Awaiting),
        Err(SectionCheckFailed::Refused(refused)) => {
            return Err(AdmissionFault::Section(refused));
        }
        Err(SectionCheckFailed::View(fault)) => return Err(AdmissionFault::View(fault)),
    }
    if bodies.len() != refs.len() {
        return Err(AdmissionFault::Bundle {
            at: bodies.len().min(refs.len()),
            refused: BundleRefused::BodyNotReferenced,
        });
    }
    let mut admitted = Vec::with_capacity(refs.len());
    for (at, (reference, body)) in refs.iter().zip(bodies.iter()).enumerate() {
        match verify_bundle(reference, body, h_incl, view, rule_set) {
            Ok(one) => admitted.push(one),
            Err(refused) => return Err(AdmissionFault::Bundle { at, refused }),
        }
    }
    Ok(admitted)
}
