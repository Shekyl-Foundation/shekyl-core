// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a node that produces bundles hands the service (`SO-D12` increment
//! 4c): the seat [`Follow::producer`](crate::service::Follow::producer)
//! holds.
//!
//! The type is in every `pipeline` build, so `Follow` has one shape
//! whatever features a build unifies (rule 125: a feature never changes a
//! public type's shape). The `producer` feature gates the code that builds
//! a seat ([`ProducerSeat::new`](crate::producer_seat::ProducerSeat::new))
//! and the task that runs one (`bundle_producer`): a build without it has
//! no way to hand the service a seat it would not run.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use shekyl_bundle_producer::{DueRead, ReadOutcome, WitnessRing};

/// One read through the daemon's fetch path: the due read in, its outcome
/// out. Built over the node's fetch scheduler by
/// `bundle_producer::read_through`.
pub type ReadFn =
    Arc<dyn Fn(DueRead) -> Pin<Box<dyn Future<Output = ReadOutcome> + Send>> + Send + Sync>;

/// What a node that produces bundles hands the service.
#[cfg_attr(
    not(feature = "producer"),
    expect(
        dead_code,
        reason = "only the producer feature builds a seat (`ProducerSeat::new`) and reads one"
    )
)]
pub struct ProducerSeat {
    /// The ring the node's templates draw from: the job seat's own.
    pub(crate) witness: Arc<WitnessRing>,
    /// The challenge read.
    pub(crate) read: ReadFn,
    /// The spread each read's start delay is drawn below:
    /// `shekyl_bundle_producer::READ_START_SPREAD` in the node, the value
    /// the read ceiling is derived with.
    pub(crate) start_spread: std::time::Duration,
}

impl ProducerSeat {
    /// A seat over `witness`, reading through `read`, each read's start
    /// delay drawn below `start_spread`.
    #[cfg(feature = "producer")]
    #[must_use]
    pub fn new(witness: Arc<WitnessRing>, read: ReadFn, start_spread: std::time::Duration) -> Self {
        Self {
            witness,
            read,
            start_spread,
        }
    }
}
