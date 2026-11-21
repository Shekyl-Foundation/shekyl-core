// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one encoder.
//!
//! [`CorpusWriter`] verifies a record, then writes it as one buffer.
//! [`CorpusWriter::finish`] consumes the writer and patches the header
//! count, so append-after-finish is not a state the type can be in.

use std::io::{Seek, SeekFrom, Write};

use shekyl_network::Network;
use shekyl_types::BlockHeight;
use shekyl_wire::block::MAX_BLOCK_BLOB_SIZE;
use shekyl_wire::transaction::MAX_TX_SIZE;

use crate::cursor::{HeightCursor, LAST_HEIGHT};
use crate::fault::{CorpusFault, RecordAt};
use crate::lineage::{Lineage, Placed};
use crate::record::note_one_more;
use crate::verify::{parse_block, verified_block};
use crate::{header, tag, COUNT_OFFSET, MAX_SECTION_BLOB, REWIND_RECORD_LEN};

/// Writes a corpus, verifying every record before it lands (RD-F15).
pub struct CorpusWriter<W: Write + Seek> {
    out: W,
    cursor: HeightCursor,
    lineage: Lineage,
    count: u64,
}

impl<W: Write + Seek> CorpusWriter<W> {
    /// Start a corpus for `net` whose first record is at `first_height`.
    /// Writes the header with a zero count; [`finish`](Self::finish) fills
    /// it in.
    ///
    /// # Errors
    ///
    /// I/O.
    pub fn create(
        mut out: W,
        net: Network,
        first_height: BlockHeight,
    ) -> Result<Self, CorpusFault> {
        out.write_all(&header::encode(net, first_height, 0))?;
        Ok(Self {
            out,
            cursor: HeightCursor::starting_at(first_height),
            lineage: Lineage::starting_at(first_height),
            count: 0,
        })
    }

    /// Append `rewind { to }`: the reader will yield [`crate::Record::Rewind`]
    /// and expect the next block at `to + 1` (crate docs).
    ///
    /// # Errors
    ///
    /// [`CorpusFault::RewindNotBackward`], [`CorpusFault::RewindOutOfCorpus`],
    /// [`CorpusFault::RewindOnEmpty`]; I/O.
    pub fn rewind(&mut self, to: BlockHeight) -> Result<(), CorpusFault> {
        self.cursor.check_rewind(to)?;
        let mut record = Vec::with_capacity(REWIND_RECORD_LEN);
        record.push(tag::REWIND);
        record.extend_from_slice(&to.to_raw().to_le_bytes());
        self.out.write_all(&record)?;
        self.cursor.advance_past(to);
        self.lineage.rewind(to);
        self.count = note_one_more(self.count);
        Ok(())
    }

    /// Append the block at the next height with the bodies of its listed
    /// transactions, **as the source handed them** — this method does the
    /// verifying. A shortfall, a reorder or a foreign body is refused by
    /// height and nothing is written for it. The block follows the tip, or
    /// a block an earlier [`Self::offer`] carried, one height past it
    /// (`lineage` module); a block that follows neither is refused.
    ///
    /// # Errors
    ///
    /// [`CorpusFault::IncompleteBodies`] / [`CorpusFault::BodyMismatch`] /
    /// [`CorpusFault::Malformed`] for the record; [`CorpusFault::Oversized`]
    /// if a blob exceeds the wire cap; I/O.
    pub fn append(&mut self, block_blob: &[u8], tx_blobs: &[Vec<u8>]) -> Result<(), CorpusFault> {
        self.append_carrying(block_blob, tx_blobs, &[], &[])
    }

    /// [`Self::append`] for a block carrying a bundle section: its
    /// references and, in the same order, each one's body (crate docs).
    ///
    /// # Errors
    ///
    /// [`Self::append`]'s, and [`CorpusFault::BadSection`].
    pub fn append_carrying(
        &mut self,
        block_blob: &[u8],
        tx_blobs: &[Vec<u8>],
        references: &[Vec<u8>],
        bodies: &[Vec<u8>],
    ) -> Result<(), CorpusFault> {
        // Before any offer, a block can only follow the tip: an exhausted
        // cursor refuses it before its bytes are looked at.
        if !self.lineage.holds_offers() {
            self.cursor.next_extend()?;
        }
        let tip_next = self.cursor.next_extend();
        let named = *tip_next.as_ref().unwrap_or(&LAST_HEIGHT);
        let block = parse_block(RecordAt::Height(named), block_blob)?;
        let placed = self.lineage.place(&block, named)?;
        let height = match &placed {
            Placed::Tip => tip_next?,
            Placed::Offered { height, .. } => *height,
        };
        verified_block(
            RecordAt::Height(height),
            block_blob,
            tx_blobs,
            references,
            bodies,
        )?;
        // One buffer, one write: a verify failure writes nothing, and a
        // short write is the caller's I/O error with the cursor unmoved,
        // so the count still names only records that were written whole.
        let mut record = vec![tag::EXTEND];
        record.write_all(&height.to_raw().to_le_bytes())?;
        encode_block(&mut record, block_blob, tx_blobs, references, bodies)?;
        self.out.write_all(&record)?;
        self.cursor.advance_past(height);
        self.lineage.extend(placed, block.hash());
        self.count = note_one_more(self.count);
        Ok(())
    }

    /// Append an `offer`: a block that does not extend the tip, with its
    /// listed bodies and its bundle section, verified as
    /// [`Self::append_carrying`] verifies an `extend` (crate docs). The
    /// height cursor does not move.
    ///
    /// # Errors
    ///
    /// [`Self::append_carrying`]'s, each naming the record
    /// ([`RecordAt::Offer`]).
    pub fn offer(
        &mut self,
        block_blob: &[u8],
        tx_blobs: &[Vec<u8>],
        references: &[Vec<u8>],
        bodies: &[Vec<u8>],
    ) -> Result<(), CorpusFault> {
        let verified = verified_block(
            RecordAt::Offer { record: self.count },
            block_blob,
            tx_blobs,
            references,
            bodies,
        )?;
        let mut record = vec![tag::OFFER];
        encode_block(&mut record, block_blob, tx_blobs, references, bodies)?;
        if verified.block.number().is_none() {
            return Err(CorpusFault::OfferUnnumbered);
        }
        self.out.write_all(&record)?;
        self.lineage.offer(&verified.block)?;
        self.count = note_one_more(self.count);
        Ok(())
    }

    /// Patch the record count into the header and hand the writer back.
    /// Consumes the writer: there is no append-after-finish.
    ///
    /// # Errors
    ///
    /// I/O.
    pub fn finish(mut self) -> Result<W, CorpusFault> {
        let at = u64::try_from(COUNT_OFFSET).expect("the count field sits in the header");
        self.out.seek(SeekFrom::Start(at))?;
        self.out.write_all(&self.count.to_le_bytes())?;
        self.out.seek(SeekFrom::End(0))?;
        self.out.flush()?;
        Ok(self.out)
    }

    /// The bytes written so far, without patching the count.
    ///
    /// The unfinished-corpus test is the caller. Production ends at
    /// [`finish`](Self::finish), which is the only way a count is written.
    #[cfg(test)]
    pub(crate) fn into_unfinished(self) -> W {
        self.out
    }
}

/// The block, its bodies and its section as the on-disk layout, after a
/// record's tag (and an `extend`'s height): what `extend` and `offer` share
/// (crate docs).
fn encode_block(
    buf: &mut Vec<u8>,
    block_blob: &[u8],
    tx_blobs: &[Vec<u8>],
    references: &[Vec<u8>],
    bodies: &[Vec<u8>],
) -> Result<(), CorpusFault> {
    write_len(buf, "block", block_blob.len(), MAX_BLOCK_BLOB_SIZE)?;
    buf.write_all(block_blob)?;
    let tx_count = u32::try_from(tx_blobs.len()).map_err(|_| CorpusFault::Oversized {
        what: "transaction count",
        len: width_u64(tx_blobs.len()),
    })?;
    buf.write_all(&tx_count.to_le_bytes())?;
    for blob in tx_blobs {
        write_len(buf, "transaction", blob.len(), MAX_TX_SIZE)?;
        buf.write_all(blob)?;
    }
    // `verified_section` held the counts equal and under the section bound.
    let ref_count = u32::try_from(references.len()).map_err(|_| CorpusFault::Oversized {
        what: "bundle reference count",
        len: width_u64(references.len()),
    })?;
    buf.write_all(&ref_count.to_le_bytes())?;
    for blob in references {
        write_len(buf, "bundle reference", blob.len(), MAX_SECTION_BLOB)?;
        buf.write_all(blob)?;
    }
    for blob in bodies {
        write_len(buf, "bundle body", blob.len(), MAX_SECTION_BLOB)?;
        buf.write_all(blob)?;
    }
    Ok(())
}

/// A blob's length prefix ([`crate::LEN_PREFIX`] bytes), refused above `cap`.
fn write_len<W: Write>(
    out: &mut W,
    what: &'static str,
    len: usize,
    cap: usize,
) -> Result<(), CorpusFault> {
    if len > cap {
        return Err(CorpusFault::Oversized {
            what,
            len: width_u64(len),
        });
    }
    let len = u32::try_from(len).map_err(|_| CorpusFault::Oversized {
        what,
        len: width_u64(len),
    })?;
    out.write_all(&len.to_le_bytes())?;
    Ok(())
}

/// A length for [`CorpusFault::Oversized`]. A blob this process can hold
/// fits `u64` on every target the workspace builds.
fn width_u64(len: usize) -> u64 {
    u64::try_from(len).expect("a blob length fits u64")
}
