// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.B — CEN-B4, the block's root and its attestation set, as the
//! switch's first commit leaves them (`SO-D12` 4b, C1).
//!
//! The header's root is the **bundle root** (`ARCHIVAL_SERVE_CREDIT_SPEC.md`
//! §7.3, `SCS-P34`): it commits to the references of the bundles the block
//! admits, not to pass records. Until blocks carry references (C2) every
//! block admits none, so the root is [`empty_bundle_root`] and this rule
//! holds the header to it. The attestation set beside the block still
//! parses here — the coinbase extra, its `0x0B` headers and the sidecar
//! witness — and must be empty: the header no longer commits to a record,
//! so a record has nothing that binds it. CEN-I20's coinbase grammar
//! already admitted no `0x0B` field, so no block that connected before
//! this commit carried one; the record arm that judged them, and its
//! anchor window, are gone with the root they were bound by. The bundle's
//! receipts (CEN-J37) are what a pass is judged by from C3.
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

/// CEN-B4: the coinbase extra parses, the attestation set it and the
/// sidecar witness make is empty, and the header's root is the empty
/// bundle root (module docs). Every refusal is this row at
/// [`Locus::Block`].
pub(crate) struct B4;

impl Rule for B4 {
    const ROW: CenRow = CenRow::B4;
}

impl B4 {
    /// The whole rule, and stateless: it reads no view, so `bind_body`
    /// runs it on a body before the block connects. An extra that does not
    /// parse is refused, never read as empty.
    pub(crate) fn bind_root(extra: &[u8], witness: &[u8], root: &[u8; 32]) -> Verdict<()> {
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
        let Ok(set) = AttestationSet::parse(headers, witness) else {
            return refused();
        };
        if !set.records().is_empty() || *root != empty_bundle_root() {
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
        let witness: &[u8] = candidate
            .attestation_witness
            .as_ref()
            .map_or(&[], |w| w.as_bytes());
        Ok(Self::bind_root(
            &candidate.block.miner_transaction.prefix.extra,
            witness,
            candidate.block.header.bundle_root.as_bytes(),
        ))
    }
}

#[cfg(test)]
#[path = "attestation_tests.rs"]
mod attestation_tests;
