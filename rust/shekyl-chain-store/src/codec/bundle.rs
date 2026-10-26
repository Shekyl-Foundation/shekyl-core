// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle queue's two values (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.5,
//! `SO-D12` increment 4c).
//!
//! - [`QueuedBundle`] — `archival_bundle_queue[h]`: the reference (the
//!   bundle's kept bytes and the hash of its prunable bytes) and the tip
//!   the queue judged it against.
//! - [`QueuedBody`] — `archival_bundle_body[prunable_hash]`: the prunable
//!   bytes, the witness key, the witness signature and the records.
//!
//! Both are the retention crate's encodings carried whole. The codec
//! checks that the bytes are a reference or a body and re-encode to
//! themselves, and nothing about whether the bundle is valid: that is the
//! queue's admission, which ran before the row was written.

use shekyl_archival_retention::{BundleBody, BundleRef};
use shekyl_store_codec::reader::Reader;
use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::{BlockHash, BlockHeight};

/// What the queue holds for one `h`: the reference and the tip it was
/// admitted against.
///
/// # Layout
///
/// ```text
/// tip_height u64 ‖ tip_hash [32] ‖ reference (BundleRef::encode)
/// ```
///
/// The reference runs to the end of the row. Its own encoding fixes its
/// length from its count, so a row whose tail is not exactly one reference
/// is a codec error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedBundle {
    /// The reference: what a block will carry when references travel (4b).
    pub reference: BundleRef,
    /// The height of the tip the queue judged the bundle against.
    pub tip_height: BlockHeight,
    /// That tip's hash. After a reorg an entry whose tip is no longer on
    /// the chain is judged again.
    pub tip_hash: BlockHash,
}

impl Canonical for QueuedBundle {
    const NAME: &'static str = "queued_bundle";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.tip_height.to_raw().to_le_bytes());
        out.extend_from_slice(self.tip_hash.as_bytes());
        out.extend_from_slice(&self.reference.encode());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(Self::NAME, bytes);
        let tip_height = BlockHeight::from_raw(r.u64()?);
        let tip_hash = BlockHash::from_bytes(r.array::<32>("the tip hash")?);
        let rest = r.take(bytes.len() - 40, "the reference")?;
        let reference =
            BundleRef::decode(rest).map_err(|_| r.invalid("the tail is not a bundle reference"))?;
        if reference.encode() != rest {
            return Err(r.invalid("the reference does not re-encode to its own bytes"));
        }
        Ok(Self {
            reference,
            tip_height,
            tip_hash,
        })
    }
}

/// A bundle's prunable bytes, stored under their hash.
///
/// # Layout
///
/// The body's canonical bytes (`BundleBody::as_bytes`): the witness key,
/// the witness signature, and whole records. Any other length is a codec
/// error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedBody(pub BundleBody);

impl Canonical for QueuedBody {
    const NAME: &'static str = "queued_body";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.0.as_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let r = Reader::new(Self::NAME, bytes);
        BundleBody::decode(bytes)
            .map(Self)
            .map_err(|_| r.invalid("not a witness key, a witness signature and whole records"))
    }
}
