// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one decoder.
//!
//! [`CorpusReader::open`] refuses a foreign magic, version or network tag.
//! [`CorpusReader::next_record`] re-verifies each record and refuses a
//! count that does not match the header, including a file that ends inside
//! a record. A layout-4 corpus ([`crate::LAYOUT_4`]) is read with layout 4's
//! tags: an `offer` in it is an unknown tag.

use std::io::{BufRead, Read};

use shekyl_network::Network;
use shekyl_types::archival::MAX_SECTION_REFERENCES;
use shekyl_types::BlockHeight;
use shekyl_wire::block::MAX_BLOCK_BLOB_SIZE;
use shekyl_wire::transaction::MAX_TX_SIZE;

use crate::cursor::HeightCursor;
use crate::fault::{CorpusFault, RecordAt};
use crate::lineage::{Lineage, Placed};
use crate::record::{note_one_more, Record};
use crate::verify::{parse_block, verified_section, verified_tx, Verified};
use crate::{header, tag, CORPUS_FORMAT_VERSION, HEADER_LEN, LEN_PREFIX, MAX_SECTION_BLOB};

/// Reads a corpus, re-verifying every record.
pub struct CorpusReader<R: BufRead> {
    input: R,
    /// The header's layout: [`CORPUS_FORMAT_VERSION`] or [`crate::LAYOUT_4`].
    layout: u32,
    net: Network,
    cursor: HeightCursor,
    lineage: Lineage,
    declared: u64,
    read: u64,
}

impl<R: BufRead> CorpusReader<R> {
    /// Open a corpus: refuses a bad magic, a foreign layout version, or an
    /// unknown network tag before yielding anything.
    ///
    /// # Errors
    ///
    /// [`CorpusFault::BadMagic`], [`CorpusFault::UnsupportedVersion`],
    /// [`CorpusFault::UnknownNet`]; I/O.
    pub fn open(mut input: R) -> Result<Self, CorpusFault> {
        let mut bytes = [0u8; HEADER_LEN];
        input.read_exact(&mut bytes)?;
        // `declared` is a record count, not a height span (rewinds occupy
        // no height), so it says nothing about whether the heights fit;
        // `next_record` refuses an `extend` that would need a height past
        // `u64::MAX` once its tag is read, before its height.
        let header::Decoded {
            layout,
            net,
            first,
            declared,
        } = header::decode(&bytes)?;
        Ok(Self {
            input,
            layout,
            net,
            cursor: HeightCursor::starting_at(first),
            lineage: Lineage::starting_at(first),
            declared,
            read: 0,
        })
    }

    /// The header's layout version: [`CORPUS_FORMAT_VERSION`], or
    /// [`crate::LAYOUT_4`] for a corpus written before `offer`.
    #[must_use]
    pub const fn layout(&self) -> u32 {
        self.layout
    }

    /// The chain the corpus was taken from.
    #[must_use]
    pub const fn net(&self) -> Network {
        self.net
    }

    /// The height of the first record (the header's `first_height`).
    #[must_use]
    pub const fn first_height(&self) -> BlockHeight {
        self.cursor.first()
    }

    /// The header's record count.
    #[must_use]
    pub const fn declared(&self) -> u64 {
        self.declared
    }

    /// One record, re-verified, or `None` at the declared end. Refuses a
    /// record count that disagrees with the header, and a file that ends
    /// inside a record, as [`CorpusFault::CountMismatch`] naming the whole
    /// records present.
    ///
    /// # Errors
    ///
    /// Every [`CorpusFault`] a record can carry.
    pub fn next_record(&mut self) -> Result<Option<Record>, CorpusFault> {
        if self.read == self.declared {
            // The declared end. Anything past it is a count mismatch: read
            // one byte to tell "clean EOF" from "more records".
            let mut probe = [0u8; 1];
            return match self.input.read(&mut probe)? {
                0 => Ok(None),
                _ => Err(CorpusFault::CountMismatch {
                    declared: self.declared,
                    present: self.declared.saturating_add(1),
                }),
            };
        }
        match self.whole_record() {
            Err(CorpusFault::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                Err(CorpusFault::CountMismatch {
                    declared: self.declared,
                    present: self.read,
                })
            }
            other => other.map(Some),
        }
    }

    /// One record's bytes, tag first; an early end anywhere inside it is
    /// `Io(UnexpectedEof)`, which [`next_record`](Self::next_record)
    /// classifies.
    fn whole_record(&mut self) -> Result<Record, CorpusFault> {
        let mut tag_byte = [0u8; 1];
        self.input.read_exact(&mut tag_byte)?;
        match tag_byte[0] {
            tag::EXTEND => {}
            tag::REWIND => {
                let to = BlockHeight::from_raw(read_u64(&mut self.input)?);
                self.cursor.check_rewind(to)?;
                self.cursor.advance_past(to);
                self.lineage.rewind(to);
                self.read = note_one_more(self.read);
                return Ok(Record::Rewind { to });
            }
            tag::OFFER if self.layout == CORPUS_FORMAT_VERSION => {
                // An offer does not extend the tip: it carries no height,
                // and the cursor does not move.
                let at = RecordAt::Offer { record: self.read };
                let block = self.read_block(at)?;
                let offer = self.bodies_of(at, block)?.into_offer();
                self.lineage.offer(&offer.block)?;
                self.read = note_one_more(self.read);
                return Ok(Record::Offer(Box::new(offer)));
            }
            other => return Err(CorpusFault::UnknownTag(other)),
        }
        // The tag named an extend. Before any offer it can only follow the
        // tip, and there is no height past the last one, so an exhausted
        // cursor refuses here without reading the record's height: a
        // wrapped height cannot be a gap, and a file that ends on the tag
        // is this fault, not a short read.
        if !self.lineage.holds_offers() {
            self.cursor.next_extend()?;
        }
        let height = BlockHeight::from_raw(read_u64(&mut self.input)?);
        let at = RecordAt::Height(height);
        let block = self.read_block(at)?;
        // The height it must carry: the tip's next, or one past the offered
        // block it follows (`lineage` module).
        let placed = self.lineage.place(&block, height)?;
        let expected = match &placed {
            Placed::Tip => self.cursor.next_extend()?,
            Placed::Offered { height, .. } => *height,
        };
        if height != expected {
            return Err(CorpusFault::HeightGap {
                expected,
                found: height,
            });
        }
        let hash = block.hash();
        let extend = self.bodies_of(at, block)?.into_extend(height);
        self.cursor.advance_past(height);
        self.lineage.extend(placed, hash);
        self.read = note_one_more(self.read);
        Ok(Record::Extend(Box::new(extend)))
    }

    /// A record's block, read and parsed.
    fn read_block(&mut self, at: RecordAt) -> Result<shekyl_wire::Block, CorpusFault> {
        let block_blob = read_blob(&mut self.input, "block", MAX_BLOCK_BLOB_SIZE)?;
        parse_block(at, &block_blob)
    }

    /// `block`'s listed bodies and its bundle section, read and
    /// re-verified: what an `extend` (after its height and block) and an
    /// `offer` (after its block) carry.
    fn bodies_of(
        &mut self,
        at: RecordAt,
        block: shekyl_wire::Block,
    ) -> Result<Verified, CorpusFault> {
        // The header is the bound: the block was parsed before the file's
        // `tx_count` is trusted. `Block::read` caps the hash list at
        // `READ_LEN_CAP` and does not pre-allocate against it; a crafted
        // `tx_count = u32::MAX` must not `Vec::with_capacity` before this
        // check.
        let listed = block.transaction_hashes.len();
        let claimed = read_count(&mut self.input, "transaction count")?;
        if claimed != listed {
            return Err(CorpusFault::IncompleteBodies {
                at,
                listed,
                present: claimed,
            });
        }
        let mut transactions = Vec::with_capacity(listed);
        for (index, want) in block.transaction_hashes.iter().enumerate() {
            let blob = read_blob(&mut self.input, "transaction", MAX_TX_SIZE)?;
            transactions.push(verified_tx(at, index, *want, &blob)?);
        }
        let ref_count = read_count(&mut self.input, "bundle reference count")?;
        if ref_count > MAX_SECTION_REFERENCES {
            return Err(CorpusFault::BadSection { at });
        }
        let mut references = Vec::with_capacity(ref_count);
        for _ in 0..ref_count {
            references.push(read_blob(
                &mut self.input,
                "bundle reference",
                MAX_SECTION_BLOB,
            )?);
        }
        let mut bodies = Vec::with_capacity(ref_count);
        for _ in 0..ref_count {
            bodies.push(read_blob(&mut self.input, "bundle body", MAX_SECTION_BLOB)?);
        }
        let (bundle_references, bundle_bodies) = verified_section(at, &references, &bodies)?;
        Ok(Verified {
            block,
            transactions,
            bundle_references,
            bundle_bodies,
        })
    }
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, CorpusFault> {
    let mut b = [0u8; LEN_PREFIX];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64, CorpusFault> {
    let mut b = [0u8; crate::HEIGHT_LEN];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// A `u32` count as a `usize`, refused when it does not fit.
///
/// The count is bounded again by the caller before it sizes an allocation.
/// This conversion is only the lossless step the `as` cast would hide.
fn read_count<R: Read>(r: &mut R, what: &'static str) -> Result<usize, CorpusFault> {
    let raw = read_u32(r)?;
    usize::try_from(raw).map_err(|_| CorpusFault::Oversized {
        what,
        len: u64::from(raw),
    })
}

fn read_blob<R: Read>(r: &mut R, what: &'static str, cap: usize) -> Result<Vec<u8>, CorpusFault> {
    let raw = read_u32(r)?;
    let len = usize::try_from(raw).map_err(|_| CorpusFault::Oversized {
        what,
        len: u64::from(raw),
    })?;
    if len > cap {
        return Err(CorpusFault::Oversized {
            what,
            len: u64::from(raw),
        });
    }
    let mut blob = vec![0u8; len];
    r.read_exact(&mut blob)?;
    Ok(blob)
}
