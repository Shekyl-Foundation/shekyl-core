// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Session totals for one persona's loopback serve.
//!
//! Six aggregate monotone counters, and no per-request structure: served,
//! refused, lookup failures, sign failures, late sign failures, and accept
//! errors. Two handles share one set of slots.
//!
//! [`ServeCounterReader`] is the public read side. The endpoint stores one
//! and [`PServeEndpoint::counters`](crate::PServeEndpoint::counters) hands
//! it to a watcher; the endpoint's `*_count` getters forward here.
//! [`ServeCounterWriter`] is crate-private and increment-only. The accept
//! loop holds one and clones it into each connection task. A caller outside
//! this crate can sample a total and cannot move one.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The six slots. Private so the only way to move a total is a writer
/// method, and the only way to read one is a reader method.
#[derive(Clone, Debug)]
struct Slots {
    served: Arc<AtomicU64>,
    refused: Arc<AtomicU64>,
    lookup_failures: Arc<AtomicU64>,
    sign_failures: Arc<AtomicU64>,
    late_sign_failures: Arc<AtomicU64>,
    accept_errors: Arc<AtomicU64>,
}

impl Slots {
    fn zeroed() -> Self {
        Self {
            served: Arc::new(AtomicU64::new(0)),
            refused: Arc::new(AtomicU64::new(0)),
            lookup_failures: Arc::new(AtomicU64::new(0)),
            sign_failures: Arc::new(AtomicU64::new(0)),
            late_sign_failures: Arc::new(AtomicU64::new(0)),
            accept_errors: Arc::new(AtomicU64::new(0)),
        }
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// The read side of an endpoint's six session totals, detached from the
/// endpoint.
///
/// The accept loop and every connection task increment these; this handle
/// only reads them. It is `Clone` so a watcher can sample the totals on
/// its own task without borrowing the [`PServeEndpoint`](crate::PServeEndpoint)
/// — a reader that had to hold the endpoint (or the host that owns it)
/// could sample only when that owner was free, and the owner's refresh
/// awaits a store actor with no timeout. The totals stay readable after
/// the endpoint is dropped; they simply stop moving.
///
/// Aggregate and monotone: no per-request structure, no peer, no timing.
#[derive(Clone, Debug)]
pub struct ServeCounterReader {
    slots: Slots,
}

impl ServeCounterReader {
    pub(crate) fn zeroed() -> Self {
        Self {
            slots: Slots::zeroed(),
        }
    }

    /// The increment handle for these same totals.
    ///
    /// Cloning it shares the slots. It does not borrow `self`, so the
    /// accept loop can move the writer into its task and leave the reader
    /// on the endpoint.
    pub(crate) fn writer(&self) -> ServeCounterWriter {
        ServeCounterWriter {
            slots: self.slots.clone(),
        }
    }

    /// Shard responses fully written — an **aggregate**, no per-request
    /// structure. Exists so a harness can assert the endpoint served what
    /// it believes it served; it carries no path, no peer, no timing.
    #[must_use]
    pub fn served_count(&self) -> u64 {
        self.slots.served.load(Ordering::Relaxed)
    }

    /// Connections refused for exceeding [`MAX_INFLIGHT`](crate::MAX_INFLIGHT)
    /// — the operator signal that the carried placeholder cap is binding
    /// and wants its W₂-rig derivation.
    #[must_use]
    pub fn refused_count(&self) -> u64 {
        self.slots.refused.load(Ordering::Relaxed)
    }

    /// Store faults while answering a parsed shard read.
    ///
    /// The cases that fail before a byte is written are the 503, shared with
    /// a missing key, and the cases that fail after the head is out are a
    /// connection closed mid-body.
    ///
    /// Counted:
    ///
    /// * the tip the anchor gate needs could not be read, so the gate never
    ///   ran, or the shard could not be opened (I/O, or bytes pruned out
    ///   from under a serve-set that was not pinned) — the 503;
    /// * the body read failed part-way, ran past its frame, or ended short
    ///   of it — a response cut off mid-body.
    ///
    /// An invalid request (the 400) and an ordinary not-held answer (unknown
    /// id, unfrozen segment: the 404) are deliberate and **not** counted.
    /// A key that refuses its pre-flight is [`Self::sign_failure_count`];
    /// a signer that fails after the body is
    /// [`Self::late_sign_failure_count`].
    #[must_use]
    pub fn lookup_failure_count(&self) -> u64 {
        self.slots.lookup_failures.load(Ordering::Relaxed)
    }

    /// Valid requests for a held shard that the key refused at its
    /// pre-flight ([`PassKey::ready`](crate::countersign::PassKey::ready)):
    /// the 503, before any shard byte. This is the bucket a persona with no
    /// resident key accrues, and it costs the persona one shard open per
    /// request. An invalid request and an unheld shard never reach this
    /// counter.
    #[must_use]
    pub fn sign_failure_count(&self) -> u64 {
        self.slots.sign_failures.load(Ordering::Relaxed)
    }

    /// Responses whose whole body went out and whose signer then refused,
    /// or returned an envelope of the wrong length: a 200 whose envelope is
    /// the refusal trailer. Counted apart from [`Self::sign_failure_count`]
    /// because it is a different event at a different price: the pre-flight
    /// said yes, and a whole shard was read, hashed and sent for a response
    /// nobody can use. A persona that sees this move has a key whose
    /// pre-flight says yes to what its signer then refuses.
    #[must_use]
    pub fn late_sign_failure_count(&self) -> u64 {
        self.slots.late_sign_failures.load(Ordering::Relaxed)
    }

    /// `accept` failures. The loop backs off and retries rather than
    /// exiting, so without this a listener that has become permanently
    /// unusable — sustained FD exhaustion, a descriptor that will never
    /// accept again — looks exactly like a quiet epoch: the other
    /// counters simply stop moving. Aggregate and monotone like the rest;
    /// it names no peer and no time.
    #[must_use]
    pub fn accept_error_count(&self) -> u64 {
        self.slots.accept_errors.load(Ordering::Relaxed)
    }
}

/// Increment-only handle on one endpoint's session totals.
///
/// Crate-private: the accept loop and the connection tasks are the only
/// writers, and neither of them can read. Cloning shares the same slots
/// the [`ServeCounterReader`] samples.
#[derive(Clone, Debug)]
pub(crate) struct ServeCounterWriter {
    slots: Slots,
}

impl ServeCounterWriter {
    pub(crate) fn record_served(&self) {
        bump(&self.slots.served);
    }

    pub(crate) fn record_refused(&self) {
        bump(&self.slots.refused);
    }

    pub(crate) fn record_lookup_failure(&self) {
        bump(&self.slots.lookup_failures);
    }

    pub(crate) fn record_sign_failure(&self) {
        bump(&self.slots.sign_failures);
    }

    pub(crate) fn record_late_sign_failure(&self) {
        bump(&self.slots.late_sign_failures);
    }

    pub(crate) fn record_accept_error(&self) {
        bump(&self.slots.accept_errors);
    }
}
