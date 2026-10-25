// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How one challenge read ended, in the producer's terms
//! (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §5.3).
//!
//! `SF-D6`'s taxonomy has two classes for the producer. **Stall-class** —
//! no exchange completed — is read again later with the next `attempt`.
//! A **completed exchange** is final: `P` answered, and a pass is the one
//! answer that files a record.

use shekyl_archival_retention::{BundleRecord, PassStream};
use shekyl_types::BlockHeight;

/// Which read this is: the block, the stream, the draw and the attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadKey {
    /// The block the draw is of.
    pub h: BlockHeight,
    /// Economy or support.
    pub stream: PassStream,
    /// The draw `j` within its stream.
    pub draw: u32,
    /// This read of the draw, from 0. Below `K` by the plan's construction.
    pub attempt: u8,
}

/// A completed exchange that is not a pass, by what `P` answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answered {
    /// The reply closed with a signature of another scheme than the
    /// receipt key's. Until the cutover (4b) the live serving host signs
    /// with its identity key, so this is every live read: the producer
    /// logs "no receipt scheme on the serving side yet" once for the
    /// block and files it with no passes.
    ServingScheme,
    /// Anything else `SF-D6` calls a completed exchange: a 404, a 503,
    /// the refusal trailer, a malformed or overlong reply, a bad
    /// countersignature, refused content, or a second 400.
    Refused,
}

/// How a read ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    /// A verified body under the draw's receipt key: the record to file.
    Pass(Box<BundleRecord>),
    /// No exchange completed. The draw is read again at its plan's next
    /// height, if the plan has one.
    Stall,
    /// `P` answered and it was not a pass. The draw is done.
    Answered(Answered),
}
