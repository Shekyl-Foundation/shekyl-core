// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The kept per-record discriminant of an attestation header.
//!
//! The settlement fold that used to live here counted passes against an
//! issued count. Settlement now selects three of a pair's issued draws and
//! counts passes among them: [`crate::settlement_select::settle_pair`], with
//! the outcome and its threshold in `shekyl_types::archival`
//! (`ARCHIVAL_SETTLEMENT_WRITER.md` `SO-D10e`).

/// The kept per-record discriminant. `Pass` carried a countersignature (now
/// pruned); under the ruled mechanism a miss is never asserted on the wire
/// (expiry ⇒ miss), so `Miss` survives here only for the **interim** kept
/// headers the admission surface still parses — it retires with the format
/// round's deletion surface, not with this fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationKind {
    /// A countersigned pass: `P` served the read and signed the
    /// block-bound nonce.
    Pass,
    /// Interim kept-header miss record (see type-level note above).
    Miss,
}
