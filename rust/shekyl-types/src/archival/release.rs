// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Release journal as consensus history (`SO-D12` increment 2): the
//! record a Release replaced, for the walk that rebuilds an epoch's
//! drawable set.

use crate::{BlockHeight, PCanonicalId};

use super::BondRecord;

/// `archival_release_journal[(height, persona)]` — one Release, as history:
/// the persona's bond record exactly as it stood before the Release arm
/// changed it.
///
/// A Release keeps the record and empties its holdings, so the record at
/// tip says what is held now and not what was held when an epoch opened.
/// The drawable set of `E` is the pairs held when `h_open(E)` connected
/// (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §4.1), and it is rebuilt at the slash
/// pass that settles `E`, two epochs later — past the reorg window the undo
/// log covers. This row is what that rebuild reads back, as the slash log
/// is for a slash (`ARCHIVAL_SETTLEMENT_WRITER.md` §16.6, `SO-D12b`).
///
/// The whole record, as ruled, and not the holdings alone. What a Release
/// loses at tip is the holdings and whether the bond was a complete tree;
/// the receipt key is not lost, since the record survives and the key never
/// changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasedRecord {
    /// The height the Release connected at.
    pub height: BlockHeight,
    /// The releasing persona.
    pub persona: PCanonicalId,
    /// The record before the Release.
    pub pre_image: BondRecord,
}
