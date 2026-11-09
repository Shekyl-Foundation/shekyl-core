// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.B — CEN-B4, the block's root and its sidecar, as the switch's
//! second commit leaves them (`SO-D12` 4b, C2).
//!
//! The header's root is the **bundle root** (`ARCHIVAL_SERVE_CREDIT_SPEC.md`
//! §7.3, `SCS-P34`): it commits to the references of the bundles the block
//! admits. The references travel beside the block (§7.5), undecoded, in
//! [`Candidate::bundle_references`](crate::Candidate::bundle_references).
//! Admission is not live until C3, so a block admits no bundle: it carries
//! **no references**, and its root is [`empty_bundle_root`]. A block with
//! references is refused here until C3 replaces this half of the rule
//! with the section check (CEN-J29 onward) and the bundle verifier.
//!
//! The coinbase extra still parses here, and its attestation set (the
//! `0x0B` headers, with no witness beside them) must be empty: the header
//! commits to no record, so a record has nothing that binds it. CEN-I20's
//! coinbase grammar already admits no `0x0B` field.
//!
//! **Order.** After D1 and before the slot loop (`validate`): a coinbase
//! whose extra does not parse is refused **here**, not at CEN-I20 — the
//! row the census names for that extra is this one.

use shekyl_archival_retention::{empty_bundle_root, AttestationSet};
use shekyl_wire::tx_extra::{parse, TxExtraField};

use crate::census::CenRow;
use crate::fault::ViewRead;
use crate::rules::{BlockContext, BlockRule, Rule};
use crate::verdict::{Locus, Verdict};
use crate::view::ChainView;

/// CEN-B4: the coinbase extra parses, its attestation set is empty, the
/// block carries no bundle references, and the header's root is the empty
/// bundle root (module docs). Every refusal is this row at
/// [`Locus::Block`].
pub(crate) struct B4;

impl Rule for B4 {
    const ROW: CenRow = CenRow::B4;
}

impl B4 {
    /// The whole rule, and stateless: it reads no view, so `bind_body`
    /// runs it on a body before the block connects. An extra that does not
    /// parse is refused, never read as empty. `references` is the sidecar,
    /// empty when the block carries none.
    pub(crate) fn bind_root(extra: &[u8], references: &[Vec<u8>], root: &[u8; 32]) -> Verdict<()> {
        let refused = || Err(crate::verdict::InvalidBlock::new(Self::ROW, Locus::Block));
        let Ok(fields) = parse(extra) else {
            return refused();
        };
        let headers: &[u8] = fields
            .iter()
            .find_map(|field| match field {
                TxExtraField::ArchivalAttestation(blob) => Some(blob.as_slice()),
                _ => None,
            })
            .unwrap_or(&[]);
        let Ok(set) = AttestationSet::parse(headers, &[]) else {
            return refused();
        };
        if !set.records().is_empty() || !references.is_empty() || *root != empty_bundle_root() {
            return refused();
        }
        Ok(())
    }
}

impl BlockRule for B4 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        let candidate = cx.candidate();
        let references: &[Vec<u8>] = candidate
            .bundle_references
            .as_ref()
            .map_or(&[], |references| references.as_slice());
        Ok(Self::bind_root(
            &candidate.block.miner_transaction.prefix.extra,
            references,
            candidate.block.header.bundle_root.as_bytes(),
        ))
    }
}

#[cfg(test)]
#[path = "attestation_tests.rs"]
mod attestation_tests;
