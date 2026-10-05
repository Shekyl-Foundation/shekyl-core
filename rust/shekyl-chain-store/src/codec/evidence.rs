// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The evidence set `connect` stamps into the file's [`Provenance`]
//! (S-CHAIN-W commit 6b; `DRS_E1_SCHAIN_W.md` §3.2, §3.8; C2-R8 §9.4).
//!
//! `Provenance` began as *which archival applies some committed batch
//! skipped*. A second monotone set joins it here, in the same shape — a
//! union that only grows, widened inside the committing batch's own
//! transaction, and only ever **empty** when the file is parity evidence:
//!
//! - [`CoverageGaps`] — census rows some committed `connect` was handed a
//!   verdict for **without the row having been evaluated** (§9.4:
//!   *"persisted with anything it writes"*). A validator implementing 30
//!   rules and one implementing all of them produce different evidence;
//!   this is where the file remembers which it got.
//!
//! A third set — the `ConnectFacts` fields some `connect` recorded as
//! passed through rather than derived (SCW-1) — was stamped beside it until
//! E6 slice 7 wave B derived the last field on the verdict; see the note at
//! the top of the body.
//!
//! # Names, not indices
//!
//! The set encodes as **sorted, deduplicated ASCII names** —
//! `CenRow::as_str` (`"CEN-C1"`) — never as bitset slots: a slot shifts
//! when the census inserts a row, a name does not (the rules crate's own
//! `coverage.rs` says the same). In memory it is a small `Copy` bitset so
//! [`Provenance`] stays `Copy`. A name the running binary does not know
//! refuses to decode: a deleted row is a layout change and bumps
//! `SCHEMA_VERSION`, so such a cell is never met without the seal refusing
//! first — meeting one anyway is SI-7.
//!
//! [`Provenance`]: crate::provenance::Provenance

use shekyl_chain_rules::{CenRow, Row};

use super::{Canonical, CodecError};

// `FACT_FIELDS` and `PassedThroughFacts` lived here until E6 slice 7 wave B
// (2026-09-29): the `ConnectFacts` fields some committed `connect` recorded
// as passed through, encoded by name in declaration order. The vocabulary
// shrank as the rows landed — `cumulative_difficulty` (SCHEMA_VERSION 7),
// `root_after` (15), the two weights, the median and `coins_generated` (16)
// — and `burned`, the last, went with CEN-F17 / G11; with no field left to
// name, the cell left the layout (SCHEMA_VERSION 17; rule 42: rebuild,
// never migrate) and the type with it. The name framing both cells shared
// (`encode_names` / `decode_names`) stays with `CoverageGaps`.

/// Census rows some committed `connect` was handed a verdict for without
/// the row having been evaluated. Monotone; empty is the only parity state.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CoverageGaps {
    words: [u64; 4],
}

impl CoverageGaps {
    /// No gaps recorded — what a fresh file starts with.
    pub const NONE: Self = Self { words: [0; 4] };

    const fn slot(row: CenRow) -> (usize, u64) {
        let index = row.index();
        ((index / 64) as usize, 1 << (index % 64))
    }

    /// The gaps `rows` names.
    #[must_use]
    pub fn of(rows: impl IntoIterator<Item = CenRow>) -> Self {
        let mut gaps = Self::NONE;
        for row in rows {
            let (word, bit) = Self::slot(row);
            gaps.words[word] |= bit;
        }
        gaps
    }

    /// Whether `row` is a recorded gap.
    #[must_use]
    pub const fn contains(&self, row: CenRow) -> bool {
        let (word, bit) = Self::slot(row);
        self.words[word] & bit != 0
    }

    /// No row is a recorded gap.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.words[0] | self.words[1] | self.words[2] | self.words[3] == 0
    }

    /// The recorded gaps, in census order.
    pub fn iter(&self) -> impl Iterator<Item = CenRow> + '_ {
        CenRow::ALL
            .iter()
            .copied()
            .filter(move |row| self.contains(*row))
    }

    /// `self ∪ other`. Monotone: the result contains both.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            words: [
                self.words[0] | other.words[0],
                self.words[1] | other.words[1],
                self.words[2] | other.words[2],
                self.words[3] | other.words[3],
            ],
        }
    }
}

impl core::fmt::Debug for CoverageGaps {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_set().entries(self.iter().map(Row::as_str)).finish()
    }
}

impl core::fmt::Display for CoverageGaps {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for row in self.iter() {
            if !first {
                f.write_str(",")?;
            }
            first = false;
            f.write_str(row.as_str())?;
        }
        Ok(())
    }
}

impl Canonical for CoverageGaps {
    const NAME: &'static str = "rule_coverage_gaps";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_names(out, self.iter().map(Row::as_str));
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut gaps = Self::NONE;
        // `encode_into` emits names in census order; only that encoding is
        // accepted (`Canonical` promises one encoding per value), so the
        // position must strictly increase — which also refuses a repeat.
        let mut last: Option<usize> = None;
        decode_names(Self::NAME, bytes, |name| {
            let position = CenRow::ALL
                .iter()
                .position(|row| row.as_str() == name)
                .ok_or(CodecError::Invalid {
                    codec: Self::NAME,
                    reason: "names a census row this binary does not have",
                })?;
            if last.is_some_and(|prev| position <= prev) {
                return Err(CodecError::Invalid {
                    codec: Self::NAME,
                    reason: "rows are not in census order (repeated or out of order)",
                });
            }
            last = Some(position);
            let (word, bit) = Self::slot(CenRow::ALL[position]);
            gaps.words[word] |= bit;
            Ok(())
        })?;
        Ok(gaps)
    }
}

/// `count:u32 LE`, then `count` × (`len:u8`, `len` ASCII bytes). Names are
/// written in the caller's (census / declaration) order and must be
/// non-empty ASCII no longer than 255 bytes — every name here is a
/// compile-time literal, so the bound is an assertion, not a runtime path.
fn encode_names<'a>(out: &mut Vec<u8>, names: impl Iterator<Item = &'a str>) {
    let start = out.len();
    out.extend_from_slice(&0u32.to_le_bytes());
    let mut count: u32 = 0;
    for name in names {
        let len = u8::try_from(name.len()).expect("evidence names are short literals");
        assert!(
            len > 0 && name.is_ascii(),
            "evidence names are non-empty ASCII"
        );
        out.push(len);
        out.extend_from_slice(name.as_bytes());
        count += 1;
    }
    out[start..start + 4].copy_from_slice(&count.to_le_bytes());
}

fn decode_names(
    codec: &'static str,
    bytes: &[u8],
    mut each: impl FnMut(&str) -> Result<(), CodecError>,
) -> Result<(), CodecError> {
    let invalid = |reason| CodecError::Invalid { codec, reason };
    let (count, mut rest) = bytes
        .split_first_chunk::<4>()
        .ok_or(invalid("buffer ends inside the count"))?;
    for _ in 0..u32::from_le_bytes(*count) {
        let (&len, tail) = rest
            .split_first()
            .ok_or(invalid("buffer ends inside a length"))?;
        if len == 0 {
            return Err(invalid("a name is empty"));
        }
        let len = usize::from(len);
        if tail.len() < len {
            return Err(invalid("buffer ends inside a name"));
        }
        let (name, tail) = tail.split_at(len);
        let name = core::str::from_utf8(name)
            .ok()
            .filter(|n| n.is_ascii())
            .ok_or(invalid("a name is not ASCII"))?;
        each(name)?;
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(invalid("trailing bytes after the last name"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_gaps_round_trip_by_name_in_census_order_and_refuse_unknowns() {
        let gaps = CoverageGaps::of([CenRow::ALL[5], CenRow::ALL[0], CenRow::ALL[5]]);
        assert_eq!(gaps.iter().count(), 2, "deduplicated");
        let bytes = gaps.encode();
        assert_eq!(&bytes[0..4], &2u32.to_le_bytes(), "count first");
        assert_eq!(CoverageGaps::decode(&bytes), Ok(gaps));
        assert!(gaps.contains(CenRow::ALL[0]) && gaps.contains(CenRow::ALL[5]));
        assert!(!gaps.contains(CenRow::ALL[1]));
        assert_eq!(
            gaps.to_string(),
            format!("{},{}", CenRow::ALL[0], CenRow::ALL[5])
        );
        assert_eq!(
            CoverageGaps::decode(&CoverageGaps::NONE.encode()),
            Ok(CoverageGaps::NONE)
        );
        assert!(CoverageGaps::NONE.is_empty() && !gaps.is_empty());
        assert_eq!(gaps.union(CoverageGaps::NONE), gaps);

        let mut unknown = Vec::new();
        encode_names(&mut unknown, ["CEN-Z99"].into_iter());
        assert_eq!(
            CoverageGaps::decode(&unknown),
            Err(CodecError::Invalid {
                codec: "rule_coverage_gaps",
                reason: "names a census row this binary does not have",
            })
        );
        let mut twice = Vec::new();
        encode_names(&mut twice, [CenRow::ALL[0].as_str(); 2].into_iter());
        assert!(CoverageGaps::decode(&twice).is_err());
    }

    /// `Canonical::decode` accepts exactly one encoding per value: the
    /// names in census / declaration order. A row naming the same set out
    /// of order would normalise to the same bitset and is refused instead
    /// (PR #757 review) — a non-canonical evidence cell is SI-7.
    #[test]
    fn evidence_cells_refuse_names_out_of_canonical_order() {
        let mut out_of_order = Vec::new();
        encode_names(
            &mut out_of_order,
            [CenRow::ALL[5].as_str(), CenRow::ALL[0].as_str()].into_iter(),
        );
        assert_eq!(
            CoverageGaps::decode(&out_of_order),
            Err(CodecError::Invalid {
                codec: "rule_coverage_gaps",
                reason: "rows are not in census order (repeated or out of order)",
            })
        );
        // The canonical spelling round-trips, and is what `encode` emits.
        let set = CoverageGaps::of([CenRow::ALL[0], CenRow::ALL[5]]);
        let mut canonical = Vec::new();
        encode_names(
            &mut canonical,
            [CenRow::ALL[0].as_str(), CenRow::ALL[5].as_str()].into_iter(),
        );
        assert_eq!(CoverageGaps::decode(&canonical), Ok(set));
        assert_eq!(canonical, set.encode());
    }

    #[test]
    fn the_name_framing_is_strict() {
        let mut bytes = Vec::new();
        encode_names(&mut bytes, [CenRow::ALL[0].as_str()].into_iter());
        for cut in 0..bytes.len() {
            assert!(CoverageGaps::decode(&bytes[..cut]).is_err(), "cut {cut}");
        }
        bytes.push(0);
        assert_eq!(
            CoverageGaps::decode(&bytes),
            Err(CodecError::Invalid {
                codec: "rule_coverage_gaps",
                reason: "trailing bytes after the last name",
            })
        );
        let empty_name = [1, 0, 0, 0, 0];
        assert!(CoverageGaps::decode(&empty_name).is_err());
    }
}
