// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **corpus** as the replay driver's first [`Source`]
//! (`DRS_E2_REPLAY_DRIVER.md` RD-Q2, RD-F8, RD-F15).
//!
//! The artifact's format — its magic, layout version, records, and the
//! one writer and one reader that verify them — is `shekyl-corpus`'s
//! (`docs/design/CORPUS_CODEC.md`). This module turns its records into the
//! pipeline's events: an `extend` becomes [`IngestEvent::Extend`] carrying
//! the [`Candidate`] the validator consumes (the block, its listed bodies
//! in header order, and its bundle section), a `rewind` becomes
//! [`IngestEvent::Rewind`], and an `offer` becomes [`IngestEvent::Offer`]
//! carrying its candidate the same way, each stamped with the next
//! [`SequenceNo`].
//! Nothing here reads a byte of the file: a corpus that `shekyl-corpus`
//! refuses is refused here with the same [`CorpusFault`].

use std::io::BufRead;

use shekyl_chain_rules::Candidate;
use shekyl_corpus::{CorpusFault, CorpusReader, Record};
use shekyl_network::Network;
use shekyl_types::BlockHeight;

use crate::source::{IngestEvent, SequenceNo, Sequenced, Source};

/// A corpus read as a [`Source`], every record re-verified by
/// `shekyl-corpus`.
pub struct CorpusSource<R: BufRead> {
    reader: CorpusReader<R>,
    seq: SequenceNo,
}

impl<R: BufRead> CorpusSource<R> {
    /// Open a corpus: refuses a bad magic, a foreign layout version, or an
    /// unknown network tag before yielding anything.
    ///
    /// # Errors
    ///
    /// [`CorpusFault::BadMagic`], [`CorpusFault::UnsupportedVersion`],
    /// [`CorpusFault::UnknownNet`]; I/O.
    pub fn open(input: R) -> Result<Self, CorpusFault> {
        Ok(Self {
            reader: CorpusReader::open(input)?,
            seq: SequenceNo::FIRST,
        })
    }

    /// The chain the corpus was taken from.
    #[must_use]
    pub const fn net(&self) -> Network {
        self.reader.net()
    }

    /// The height of the first record (the header's `first_height`).
    #[must_use]
    pub const fn first_height(&self) -> BlockHeight {
        self.reader.first_height()
    }

    /// The header's record count.
    #[must_use]
    pub const fn declared(&self) -> u64 {
        self.reader.declared()
    }
}

impl<R: BufRead> Source for CorpusSource<R> {
    type Fault = CorpusFault;

    fn first_height(&self) -> BlockHeight {
        self.reader.first_height()
    }

    fn next(&mut self) -> Result<Option<Sequenced<IngestEvent>>, CorpusFault> {
        let Some(record) = self.reader.next_record()? else {
            return Ok(None);
        };
        let event = match record {
            Record::Extend(extend) => {
                let extend = *extend;
                IngestEvent::Extend(Box::new(
                    Candidate::new(extend.block, extend.transactions)
                        .with_bundle_references(extend.bundle_references)
                        .with_bundle_bodies(extend.bundle_bodies),
                ))
            }
            Record::Rewind { to } => IngestEvent::Rewind { to },
            Record::Offer(offer) => {
                let offer = *offer;
                IngestEvent::Offer(Box::new(
                    Candidate::new(offer.block, offer.transactions)
                        .with_bundle_references(offer.bundle_references)
                        .with_bundle_bodies(offer.bundle_bodies),
                ))
            }
        };
        let seq = self.seq;
        self.seq = seq.next();
        Ok(Some(Sequenced { seq, event }))
    }
}

#[cfg(test)]
#[path = "corpus_tests.rs"]
mod corpus_tests;
