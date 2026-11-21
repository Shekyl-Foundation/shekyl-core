// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **corpus** codec: a chain's blocks with their full transaction
//! bodies as one versioned artifact (`DRS_E2_REPLAY_DRIVER.md` RD-Q2,
//! RD-F8, RD-F15; `docs/design/CORPUS_CODEC.md`).
//!
//! This crate is the format and nothing else: the magic, the layout
//! version, and the one encoder ([`CorpusWriter`]) and one decoder
//! ([`CorpusReader`]) of its records. `shekyl-chain-ingest` reads a corpus
//! as its replay `Source` through a thin adapter over [`CorpusReader`]; the
//! chain store's tests read the same records without the pipeline, which
//! `shekyl-chain-ingest` cannot give them (it depends on the store).
//!
//! # Network-shaped only
//!
//! A record is what the validator consumes and nothing else: the block
//! blob and the bodies of its listed transactions in header order, and the
//! block's bundle section. No facts, no verdicts, no digests; those are the
//! **trace**'s (RD-Q2), and the two artifacts have different doors into the
//! pipeline so a comparison input can never be read as evidence.
//!
//! # The format is minted here, not inherited
//!
//! Round 0 defaulted to extending `blockchain_export`'s bootstrap file;
//! that container is Monero's, serialized with epee, and a Rust reader of
//! it would be a second parser of an inherited format (rule 16, RD-F9). So
//! this file: a fixed magic, a version constant, little-endian fixed-width
//! lengths, and one serializer shared by writer and reader. Changing the
//! layout bumps [`CORPUS_FORMAT_VERSION`] and the reader refuses the old
//! number — rebuild the artifact, never migrate it (rule 15) — with one
//! named exception, [`LAYOUT_4`] (`CF-R7`).
//!
//! ```text
//! header  = MAGIC(8) ‖ version u32 ‖ net u8 ‖ first_height u64 ‖ count u64
//! extend  = 0x01 ‖ height u64 ‖ block_len u32 ‖ block ‖ tx_count u32 ‖ (tx_len u32 ‖ tx)*
//!           ‖ ref_count u32 ‖ (ref_len u32 ‖ ref)* ‖ (body_len u32 ‖ body)^ref_count
//! rewind  = 0x02 ‖ to u64
//! offer   = 0x04 ‖ block_len u32 ‖ block ‖ tx_count u32 ‖ (tx_len u32 ‖ tx)*
//!           ‖ ref_count u32 ‖ (ref_len u32 ‖ ref)* ‖ (body_len u32 ‖ body)^ref_count
//! ```
//!
//! Tag `0x03` was version 3's out-of-band serve-credit `inject`. No layout
//! since carries an out-of-band write, and the reader refuses `0x03` as it
//! refuses any other unknown tag. Tag `0x04` is layout 5's: a layout-4
//! corpus that carries it is refused as an unknown tag.
//!
//! `count` counts records of every kind — a `rewind` occupies no height,
//! so it is a record count, not a height span — and is written at
//! [`CorpusWriter::finish`]; a file whose header count disagrees with its
//! records, or that ends inside one, was not finished and is refused.
//!
//! # Rewind — the reorg family's switch (RD-Q13, §7 commit 8c)
//!
//! `rewind { to }` is [`Record::Rewind`]: a replay pops to `to`, and the
//! next `extend` carries `to + 1`. `to` lies in `[first_height, tip)`: a
//! rewind to the tip pops nothing ([`CorpusFault::RewindNotBackward`]), one
//! below the first height would leave the next block chained to a block
//! the corpus does not hold ([`CorpusFault::RewindOutOfCorpus`]), and one
//! before any block has no tip ([`CorpusFault::RewindOnEmpty`]). Version 1
//! had no record tag and no rewind; the tag byte is the version-2 change.
//!
//! # A block's bundle section (version 4, the switch's C4)
//!
//! An `extend` carries the block's bundle references, as the block's
//! header root commits them, and each one's body, in section order: a
//! replay judges the section, and `validate` faults a block whose body it
//! does not have. A block that admits no bundle has `ref_count` 0. Writer
//! and reader both hold each body to its reference (length and hash,
//! §7.5) before the record is kept.
//!
//! # Offer — a block that arrived and does not extend the tip (layout 5)
//!
//! `offer` is [`Record::Offer`]: a block whose parent its own header names
//! (`prev_id`), a block of the chain or an earlier offer, carrying what an
//! `extend` carries. No record says *switch*: whether the chain switches
//! to an offered branch, and where, is the replay's fork choice, derived
//! and recorded in its trace, never declared here (`CHAIN_FORGE.md` §7.1).
//! An offer carries no height, so a fault in one names its place among the
//! records ([`RecordAt::Offer`]).
//!
//! # Which block an `extend` follows
//!
//! An `extend` follows the tip: its header names the last block the corpus
//! extended. From layout 5 it may instead follow a block an earlier
//! `offer` carried, at the height one past it, which is how a corpus goes
//! on after the chain switched to an offered branch; that branch is then
//! the chain it extends. An `extend` whose parent is neither is refused
//! ([`CorpusFault::ExtendUnfollowed`]). Whether the chain did switch is
//! still the replay's to derive: an `extend` on an offered block that did
//! not become the tip is refused there, its parent not being the tip.
//!
//! # Verified, not declared (RD-F15)
//!
//! The writer does not record what the source *said* about its bodies —
//! `block_list` names a discarded body per slot (`archived`, `PDM-Q10`),
//! and the fetch refuses that before it reaches the writer — it parses the
//! block and requires the bodies to match `block.transaction_hashes` in
//! **count, order and hash** before a height is written; a shortfall is
//! [`CorpusFault::IncompleteBodies`] naming the record. The reader
//! re-derives the same check on every record it yields, so an artifact
//! edited after writing is refused for the same reason. Completeness is a
//! property the artifact demonstrates on read, never a byte it asserts.
//!
//! # The corpus's `net` tag
//!
//! The network the blocks came from, as its code ([`shekyl_network::Network::code`]):
//! a replay resolves that network's schedule and genesis from it.
//!
//! # Where a layout change lands
//!
//! [`Record`] is the enum a new tag extends. The height cursor moves only
//! for a tag that moves the tip, and the lineage (which block an `extend`
//! may follow) only for a tag that records a block. Integrity checks, the writer and the
//! reader each have their own module, so the new tag is a variant and two
//! arms rather than another branch in one file.

#![deny(unsafe_code)]

mod cursor;
mod fault;
mod header;
mod lineage;
mod reader;
mod record;
mod verify;
mod writer;

pub use fault::{CorpusFault, RecordAt};
pub use reader::CorpusReader;
pub use record::{Extend, Offer, Record};
pub use writer::CorpusWriter;

/// Record tags (crate docs). A new layout adds a constant here and a
/// [`Record`] variant; the reader refuses any byte that is not one of these.
pub(crate) mod tag {
    /// `extend`: a block at the next height.
    pub const EXTEND: u8 = 0x01;
    /// `rewind`: pop to the height that follows.
    pub const REWIND: u8 = 0x02;
    /// `offer`: a block that does not extend the tip (layout 5).
    pub const OFFER: u8 = 0x04;
}

/// The artifact's magic: eight bytes no other Shekyl artifact starts with.
pub const CORPUS_MAGIC: [u8; 8] = *b"SHKCORPS";

/// The layout version this crate writes. A layout change bumps it; the
/// reader refuses every other value but [`LAYOUT_4`].
pub const CORPUS_FORMAT_VERSION: u32 = 5;

/// The one older layout the reader still reads: layout 4, which is layout 5
/// without `offer` (`CF-R7`). Migration code under rule 15's lifecycle.
/// **Deletion trigger:** the last layout-4 corpus is gone, the five
/// committed corpora under `shekyl-chain-ingest/tests/vectors/`, deleted by
/// `CF-5` when their last consumer has moved to a forged chain
/// (`CHAIN_FORGE.md` §12.1). That change deletes this constant and the
/// reader's arm for it.
pub const LAYOUT_4: u32 = 4;

/// Header and record field widths. Each is the width of the integer written,
/// so a change of integer width moves the offset with it.
pub(crate) const MAGIC_LEN: usize = CORPUS_MAGIC.len();
pub(crate) const VERSION_LEN: usize = core::mem::size_of::<u32>();
pub(crate) const NET_LEN: usize = core::mem::size_of::<u8>();
pub(crate) const HEIGHT_LEN: usize = core::mem::size_of::<u64>();
pub(crate) const COUNT_LEN: usize = core::mem::size_of::<u64>();
pub(crate) const TAG_LEN: usize = core::mem::size_of::<u8>();
/// A blob's length prefix: `len u32`.
pub(crate) const LEN_PREFIX: usize = core::mem::size_of::<u32>();

/// Where each header field starts. The next field starts where this one ends.
pub(crate) const VERSION_AT: usize = MAGIC_LEN;
pub(crate) const NET_AT: usize = VERSION_AT + VERSION_LEN;
pub(crate) const HEIGHT_AT: usize = NET_AT + NET_LEN;
/// Byte index of the header's `count` field.
pub(crate) const COUNT_OFFSET: usize = HEIGHT_AT + HEIGHT_LEN;
/// `MAGIC ‖ version ‖ net ‖ first_height ‖ count`.
pub(crate) const HEADER_LEN: usize = COUNT_OFFSET + COUNT_LEN;

/// A `rewind` record: tag ‖ `to`.
pub(crate) const REWIND_RECORD_LEN: usize = TAG_LEN + HEIGHT_LEN;

/// The largest reference or body a record allocates.
///
/// A body is the witness and one record per set bit (§7.4 of the
/// serve-credit spec). On the wire that body is read at the bundle-body
/// packet ceiling, `shekyl_levin::DEFAULT_MAX_PACKET_SIZE`: 100 MB base 10,
/// the bound command 2017 enforces. A length above it is not a section blob
/// this codec will allocate. The ingest adapter's corpus tests hold the two
/// ceilings equal, so neither can move alone.
pub const MAX_SECTION_BLOB: usize = 100 * 1_000_000;

#[cfg(test)]
mod tests;
