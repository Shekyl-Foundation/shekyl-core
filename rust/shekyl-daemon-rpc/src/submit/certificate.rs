// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The verification certificate — a **witness type**
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3.3, F33).

use shekyl_types::{BlockHash, BlockHeight, TxHash};

/// Witness that Phase C fully verified the transaction identified by
/// `txid` against `root` at `ref_height`.
///
/// Private fields; the **only** constructor is successful completion of
/// Phase C (`pub(crate)` — nothing outside the engine can mint one).
/// Possession ⇒ verification, by construction: the same shape as the
/// project's `RetirementWitness` / `ExitedConfirmed` pattern, so the F25
/// setter-enumeration audit collapses to "grep certificate construction =
/// grep Phase C completion."
///
/// Deliberately **not** `Clone` and **not** `Serialize` (rule 21's
/// reject-now shape: a copyable or persistable certificate would widen the
/// attestation choke point of §3.5; reopen only if a second legitimate
/// consumer of a single verification emerges, via a design-round amendment
/// to §3.5's write-site enumeration).
///
/// Certificate-blob binding falls out of F24 (§3.5 item 3): `commit_tx`
/// release-checks `C++(blob) == engine txid`, and the certificate is minted
/// for the engine txid — so a certificate cannot be replayed against a
/// different blob.
#[derive(Debug, PartialEq, Eq)]
pub struct VerificationCertificate {
    txid: TxHash,
    reference_block: BlockHash,
    ref_height: BlockHeight,
    root: [u8; 32],
}

impl VerificationCertificate {
    /// Mint the witness. `pub(crate)`: reachable only from Phase C's
    /// success path inside this crate.
    pub(crate) fn new(
        txid: TxHash,
        reference_block: BlockHash,
        ref_height: BlockHeight,
        root: [u8; 32],
    ) -> Self {
        Self {
            txid,
            reference_block,
            ref_height,
            root,
        }
    }

    /// The verified transaction's engine txid (§3.4: authoritative for the
    /// verdict path; release-checked against C++'s hash at commit).
    pub fn txid(&self) -> &TxHash {
        &self.txid
    }

    /// The reference-block hash the proof anchored.
    pub fn reference_block(&self) -> &BlockHash {
        &self.reference_block
    }

    /// The reference block's main-chain height at verification time.
    pub fn ref_height(&self) -> BlockHeight {
        self.ref_height
    }

    /// The curve-tree root the proof verified against.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }
}
