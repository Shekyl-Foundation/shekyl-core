// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pop journal's row codec (S-CHAIN-W, C2-R8 Q5).
//!
//! One [`UndoLog`] per connected height: the pre-images every declared
//! write recorded, in the order the writes happened. `pop` replays them in
//! **reverse** and the block is gone — no per-surface revert function, no
//! second journal with its own height base. What a write recorded is
//! decided by the verb, not by the caller ([`UndoEntry`]).
//!
//! Tables are named by [`TableOrdinal`], not by string: the ordinal is the
//! declaration index in `schema.rs`, and any change to that numbering — a
//! reorder, **or a removal, which renumbers everything declared after it**
//! — is a layout change that bumps `SCHEMA_VERSION` (schema module docs),
//! so a row never meets a numbering other than the one it was written
//! under. Rebuild-never-migrate makes the bump the whole resolution.
//!
//! # Layout
//!
//! ```text
//! UndoLog   := count:u32 LE, then `count` entries
//! UndoEntry := tag:u8, table:u32 LE, key:bytes, payload
//!   tag 1  Inserted       payload = ∅
//!   tag 2  MultiInserted  payload = value:bytes
//!   tag 3  Replaced       payload = 0x00 | 0x01 prior:bytes
//! bytes     := len:u32 LE, len raw bytes
//! ```
//!
//! Variable-width, so `FIXED_WIDTH` is `None`; strict as every codec here
//! is — a short buffer, a tag that names no variant, a `has_prior` byte
//! other than 0/1, or trailing bytes are each [`CodecError`], and the row
//! is then SI-7's (`undo_log` is a typed cell like any other).

use super::{Canonical, CodecError};
use crate::schema::TableOrdinal;

/// One journaled write's pre-image: what `pop` does to undo it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UndoEntry {
    /// An insert-once write landed on an absent key. Undo **removes** the
    /// key; the key must be present when it does.
    Inserted {
        /// The table, by declaration ordinal.
        table: TableOrdinal,
        /// The key's redb bytes (`Key::as_bytes`).
        key: Box<[u8]>,
    },
    /// A multimap write added a `(key, value)` member that was not
    /// present. Undo **removes** exactly that member; it must be present.
    MultiInserted {
        /// The table, by declaration ordinal.
        table: TableOrdinal,
        /// The key's redb bytes.
        key: Box<[u8]>,
        /// The member's redb bytes.
        value: Box<[u8]>,
    },
    /// A declared overwrite (`upsert`, `upsert_property`) replaced `prior`
    /// — or nothing, if the key was absent. Undo **restores** `prior`
    /// (re-inserting it) or removes the key; the key must be present when
    /// it does.
    Replaced {
        /// The table, by declaration ordinal.
        table: TableOrdinal,
        /// The key's redb bytes.
        key: Box<[u8]>,
        /// The displaced value's redb bytes, if there was one.
        prior: Option<Box<[u8]>>,
    },
}

impl UndoEntry {
    /// The table this entry replays into.
    #[must_use]
    pub const fn table(&self) -> TableOrdinal {
        match self {
            Self::Inserted { table, .. }
            | Self::MultiInserted { table, .. }
            | Self::Replaced { table, .. } => *table,
        }
    }

    const TAG_INSERTED: u8 = 1;
    const TAG_MULTI_INSERTED: u8 = 2;
    const TAG_REPLACED: u8 = 3;

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Inserted { table, key } => {
                out.push(Self::TAG_INSERTED);
                out.extend_from_slice(&table.index().to_le_bytes());
                bytes(out, key);
            }
            Self::MultiInserted { table, key, value } => {
                out.push(Self::TAG_MULTI_INSERTED);
                out.extend_from_slice(&table.index().to_le_bytes());
                bytes(out, key);
                bytes(out, value);
            }
            Self::Replaced { table, key, prior } => {
                out.push(Self::TAG_REPLACED);
                out.extend_from_slice(&table.index().to_le_bytes());
                bytes(out, key);
                match prior {
                    None => out.push(0),
                    Some(prior) => {
                        out.push(1);
                        bytes(out, prior);
                    }
                }
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let tag = r.u8()?;
        let table = TableOrdinal::from_index(r.u32()?);
        let key = r.bytes()?;
        match tag {
            Self::TAG_INSERTED => Ok(Self::Inserted { table, key }),
            Self::TAG_MULTI_INSERTED => {
                let value = r.bytes()?;
                Ok(Self::MultiInserted { table, key, value })
            }
            Self::TAG_REPLACED => {
                let prior = match r.u8()? {
                    0 => None,
                    1 => Some(r.bytes()?),
                    _ => return Err(invalid("has_prior byte is neither 0 nor 1")),
                };
                Ok(Self::Replaced { table, key, prior })
            }
            _ => Err(invalid("entry tag names no variant")),
        }
    }
}

/// The journal row for one height: every [`UndoEntry`] its `connect`
/// recorded, in write order. Replay walks it from the back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UndoLog(pub Vec<UndoEntry>);

impl Canonical for UndoLog {
    const NAME: &'static str = "undo_log";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        let count = u32::try_from(self.0.len()).expect("a block journals fewer than 2^32 writes");
        out.extend_from_slice(&count.to_le_bytes());
        for entry in &self.0 {
            entry.encode_into(out);
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader(bytes);
        let count = r.u32()?;
        let mut entries = Vec::with_capacity(
            usize::try_from(count).map_err(|_| invalid("entry count exceeds the address space"))?,
        );
        for _ in 0..count {
            entries.push(UndoEntry::decode(&mut r)?);
        }
        if !r.0.is_empty() {
            return Err(invalid("trailing bytes after the last entry"));
        }
        Ok(Self(entries))
    }
}

fn bytes(out: &mut Vec<u8>, b: &[u8]) {
    let len = u32::try_from(b.len()).expect("redb refuses values past 3 GiB; u32 is enough");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(b);
}

const fn invalid(reason: &'static str) -> CodecError {
    CodecError::Invalid {
        codec: UndoLog::NAME,
        reason,
    }
}

/// A strict cursor: every read is bounds-checked and a short buffer is a
/// [`CodecError::Invalid`] naming what ran out, never a panic.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&[u8], CodecError> {
        if self.0.len() < n {
            return Err(invalid(what));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        self.take(1, "buffer ends inside a tag or flag byte")
            .map(|b| b[0])
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        self.take(4, "buffer ends inside a u32 field")
            .map(|b| u32::from_le_bytes(b.try_into().expect("take(4) yields 4 bytes")))
    }

    fn bytes(&mut self) -> Result<Box<[u8]>, CodecError> {
        let len = usize::try_from(self.u32()?)
            .map_err(|_| invalid("byte length exceeds the address space"))?;
        self.take(len, "buffer ends inside a byte field")
            .map(Box::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<UndoEntry> {
        vec![
            UndoEntry::Inserted {
                table: TableOrdinal::from_index(0),
                key: Box::new([1, 2, 3]),
            },
            UndoEntry::MultiInserted {
                table: TableOrdinal::from_index(12),
                key: Box::new(7u64.to_le_bytes()),
                value: Box::new([0xaa; 5]),
            },
            UndoEntry::Replaced {
                table: TableOrdinal::from_index(19),
                key: Box::from(*b"total_burned"),
                prior: Some(Box::new(9u64.to_le_bytes())),
            },
            UndoEntry::Replaced {
                table: TableOrdinal::from_index(19),
                key: Box::from(*b"fresh"),
                prior: None,
            },
        ]
    }

    #[test]
    fn round_trips_every_variant_in_order() {
        let log = UndoLog(entries());
        let bytes = log.encode();
        assert_eq!(UndoLog::decode(&bytes), Ok(log));
        assert_eq!(
            UndoLog::decode(&UndoLog::default().encode()),
            Ok(UndoLog::default())
        );
    }

    #[test]
    fn refuses_a_truncated_row_at_every_boundary() {
        let bytes = UndoLog(entries()).encode();
        for cut in 0..bytes.len() {
            let err = UndoLog::decode(&bytes[..cut]).expect_err("truncated row decoded");
            assert!(
                matches!(
                    err,
                    CodecError::Invalid {
                        codec: "undo_log",
                        ..
                    }
                ),
                "cut {cut}: {err}"
            );
        }
    }

    #[test]
    fn refuses_trailing_bytes_a_bad_tag_and_a_bad_flag() {
        let mut bytes = UndoLog(entries()).encode();
        bytes.push(0);
        assert_eq!(
            UndoLog::decode(&bytes),
            Err(invalid("trailing bytes after the last entry"))
        );

        let mut one = UndoLog(entries()[..1].to_vec()).encode();
        one[4] = 9; // the first entry's tag
        assert_eq!(
            UndoLog::decode(&one),
            Err(invalid("entry tag names no variant"))
        );

        let mut replaced = UndoLog(entries()[3..].to_vec()).encode();
        let flag = replaced.len() - 1; // `prior: None` ends the row with its flag byte
        assert_eq!(replaced[flag], 0);
        replaced[flag] = 2;
        assert_eq!(
            UndoLog::decode(&replaced),
            Err(invalid("has_prior byte is neither 0 nor 1"))
        );
    }

    #[test]
    fn table_accessor_names_each_entry_s_target() {
        for (entry, want) in entries().iter().zip([0, 12, 19, 19]) {
            assert_eq!(entry.table().index(), want);
        }
    }
}
