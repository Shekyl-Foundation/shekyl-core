// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One challenge read through the daemon's fetch scheduler
//! (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §5.1–§5.3).
//!
//! The read is the scheduler's ordinary nonce read: the same request
//! builder, header, stall and 400 moves, timeouts and outcome type every
//! caller has. What is the producer's own is the nonce, the persona the
//! draw named, and the key the receipt verifies under. The holder is named
//! under the **receipt key** from the bond record, as the verifier's step 8
//! opens it, so a verified read is a receipt and nothing else is.

use std::sync::Arc;

use shekyl_archival_fetch_sched::{
    DiscardTxs, FetchError, FetchScheduler, FetchTarget, Holder, HolderSource, NeedBudget,
    ReadFailure, ServingEndpoint, ShardFacts, SuppliedNonce,
};
use shekyl_archival_retention::BundleRecord;
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey;

use crate::outcome::{Answered, ReadOutcome};
use crate::producer::DueRead;

/// The holder a due read dials: the drawn persona, at its record's
/// endpoint, under its receipt key.
#[must_use]
pub fn receipt_holder(due: &DueRead) -> Holder<FnDsaHybridPublicKey> {
    Holder {
        id: due.persona,
        target: FetchTarget {
            endpoint: ServingEndpoint::from_record_bytes(due.endpoint),
            verifying_key: due.receipt_key.clone(),
        },
    }
}

/// Read `due` and say how it ended.
///
/// A verified body is a pass: the scheduler verified the receipt under
/// the draw's receipt key over the transcript with this read's nonce and
/// stream, which is the verifier's step 8 on the same bytes. The record
/// is that read's `attempt`, its header's anchor, the body's delivery
/// digest and the receipt.
pub async fn read_due<F: ShardFacts, H: HolderSource>(
    scheduler: &FetchScheduler<F, H>,
    due: &DueRead,
    budget: NeedBudget,
) -> ReadOutcome {
    match attempt_due(scheduler, due, budget).await {
        Ok(record) => ReadOutcome::Pass(Box::new(record)),
        Err(failure) => classify(&failure),
    }
}

/// [`read_due`], with the failure itself when the read did not pass: the
/// pass record, or what the scheduler reported. For a caller that logs why
/// a read ended (the ingest crate's task does, at debug).
///
/// # Errors
///
/// The scheduler's [`ReadFailure`]; a receipt of another width than the
/// record holds is a malformed envelope.
pub async fn attempt_due<F: ShardFacts, H: HolderSource>(
    scheduler: &FetchScheduler<F, H>,
    due: &DueRead,
    budget: NeedBudget,
) -> Result<BundleRecord, ReadFailure> {
    let nonce = SuppliedNonce {
        stream: due.key.stream,
        nonce: due.nonce,
    };
    let read = scheduler
        .read_from_nonce(
            &receipt_holder(due),
            due.shard,
            nonce,
            Arc::new(DiscardTxs),
            budget,
        )
        .await?;
    let receipt = read.shard.signature().to_canonical_bytes();
    let receipt = receipt.try_into().map_err(|_| ReadFailure::Exhausted {
        attempts: vec![shekyl_archival_fetch_sched::Attempt {
            holder: due.persona,
            error: FetchError::Malformed(shekyl_archival_fetch_sched::Malformed::Envelope),
        }],
    })?;
    Ok(BundleRecord {
        attempt: due.key.attempt,
        anchor_height: read.header.anchor_height(),
        delivery_digest: *read.shard.delivery_digest(),
        receipt,
    })
}

/// A failed read in the producer's two classes (§5.3).
///
/// The scheduler dials only the named persona on a nonce read, so the
/// attempts are that persona's, in order, and the last one is how the
/// read ended. A stall there is stall-class. Anything the requester could
/// not do before dialling — its own facts, its anchor — completed no
/// exchange either, and is read again the same way.
#[must_use]
pub fn classify(failure: &ReadFailure) -> ReadOutcome {
    match failure {
        ReadFailure::Exhausted { attempts } => match attempts.last().map(|a| &a.error) {
            Some(FetchError::Stall(_)) | None => ReadOutcome::Stall,
            Some(error) if other_scheme(error) => ReadOutcome::Answered(Answered::ServingScheme),
            Some(_) => ReadOutcome::Answered(Answered::Refused),
        },
        ReadFailure::Facts(_)
        | ReadFailure::Draw(_)
        | ReadFailure::Open { .. }
        | ReadFailure::NoAnchor { .. }
        | ReadFailure::NoHolders { .. } => ReadOutcome::Stall,
    }
}

/// Whether a refusal is an identity-scheme reply read under a receipt-key
/// target. The client reads it one of two ways, by the shard's size
/// (`FN_DSA_HYBRID.md` §9.3):
///
/// - The ceiling it holds a reply to is the frame's ceiling from the
///   requester's rows plus the receipt envelope. A reply that the wider
///   identity envelope takes past that ceiling declares more by at most
///   the difference between the two envelopes, and is refused from the
///   head (`Oversize`).
/// - A reply under the ceiling is read: the receipt-width envelope is the
///   tail of the identity signature, the whole frame parses, and exactly
///   the difference is left ahead of the envelope (`FrameLong`).
///
/// Any other excess is no envelope of either scheme: a refusal like any
/// other.
fn other_scheme(error: &FetchError) -> bool {
    use shekyl_archival_fetch_sched::{Malformed, IDENTITY_ENVELOPE_LEN, RECEIPT_ENVELOPE_LEN};
    let wider = u64::try_from(IDENTITY_ENVELOPE_LEN.saturating_sub(RECEIPT_ENVELOPE_LEN))
        .expect("an envelope width fits u64");
    match error {
        FetchError::Malformed(Malformed::Oversize { declared, max }) => declared
            .checked_sub(*max)
            .is_some_and(|excess| excess <= wider),
        FetchError::Malformed(Malformed::FrameLong { left }) => *left == wider,
        _ => false,
    }
}

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;
