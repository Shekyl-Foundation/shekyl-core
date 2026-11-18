// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `blocks.txt`, a forged chain's KAT ledger (`CHAIN_FORGE.md` §7.2, §9).
//!
//! One line per block in corpus order: `height branch block_id`, the id in
//! lower-case hex. A rewind shows as a height that goes back. The file is
//! small (about 70 bytes a block) and diffs in a pull request, and the first
//! line that differs between two forgings is the first block that differs:
//! [`BlocksTxt::first_difference`] names it.

use core::fmt;

/// Which branch a block was written on. A layout-4 corpus writes every
/// block as it extends the chain (a reorg is a rewind, then the new
/// branch), so every line is [`Branch::Main`] until `CF-3` adds the
/// `offer` record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Branch {
    /// The chain the corpus extends.
    Main,
    /// The `n`-th alternative branch (`CF-3`).
    Alt(u32),
}

impl fmt::Display for Branch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Main => f.write_str("main"),
            Self::Alt(n) => write!(f, "alt:{n}"),
        }
    }
}

/// One block's line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    /// The block's height.
    pub height: u64,
    /// The branch it was written on.
    pub branch: Branch,
    /// The block's id.
    pub id: [u8; 32],
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.height,
            self.branch,
            hex::encode(self.id)
        )
    }
}

/// Why a `blocks.txt` did not parse.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LedgerFault {
    /// A line is not `height branch block_id`.
    #[error("blocks.txt line {line}: {reason}: {text:?}")]
    Malformed {
        /// One-based.
        line: usize,
        /// What was wrong.
        reason: &'static str,
        /// The line as read.
        text: String,
    },
}

/// The first place two ledgers differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difference {
    /// One-based line number.
    pub line: usize,
    /// This ledger's line there; `None` past its end.
    pub ours: Option<Line>,
    /// The other ledger's line there; `None` past its end.
    pub theirs: Option<Line>,
}

impl fmt::Display for Difference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let side = |line: &Option<Line>| line.map_or_else(|| "(end)".to_owned(), |l| l.to_string());
        write!(
            f,
            "blocks.txt line {}: {} != {}",
            self.line,
            side(&self.ours),
            side(&self.theirs)
        )
    }
}

/// A forged chain's `blocks.txt`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlocksTxt {
    lines: Vec<Line>,
}

impl BlocksTxt {
    /// An empty ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self { lines: Vec::new() }
    }

    /// Record the next block in corpus order.
    pub fn push(&mut self, line: Line) {
        self.lines.push(line);
    }

    /// The lines, in corpus order.
    #[must_use]
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

    /// The file's text: one line each, every line ending in `\n`.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(self.lines.len() * 72);
        for line in &self.lines {
            out.push_str(&line.to_string());
            out.push('\n');
        }
        out
    }

    /// Parse the file's text. Every line, the last included, ends in `\n`;
    /// nothing else is accepted, so one text has one ledger.
    ///
    /// # Errors
    ///
    /// [`LedgerFault::Malformed`] naming the first bad line.
    pub fn parse(text: &str) -> Result<Self, LedgerFault> {
        let mut lines = Vec::new();
        if text.is_empty() {
            return Ok(Self { lines });
        }
        let Some(body) = text.strip_suffix('\n') else {
            return Err(LedgerFault::Malformed {
                line: text.lines().count(),
                reason: "the last line does not end in a newline",
                text: text.lines().last().unwrap_or_default().to_owned(),
            });
        };
        for (i, raw) in body.split('\n').enumerate() {
            let malformed = |reason| LedgerFault::Malformed {
                line: i + 1,
                reason,
                text: raw.to_owned(),
            };
            let mut fields = raw.split(' ');
            let (Some(height), Some(branch), Some(id), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(malformed("not three fields"));
            };
            let spelled = height;
            let height: u64 = spelled.parse().map_err(|_| malformed("a height"))?;
            if height.to_string() != spelled {
                return Err(malformed("a height in its one spelling"));
            }
            let branch = match branch {
                "main" => Branch::Main,
                other => {
                    let n = other
                        .strip_prefix("alt:")
                        .and_then(|n| n.parse::<u32>().ok())
                        .filter(|n| other == format!("alt:{n}"))
                        .ok_or_else(|| malformed("a branch"))?;
                    Branch::Alt(n)
                }
            };
            if id.len() != 64 || id.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(malformed("a block id in 64 lower-case hex digits"));
            }
            let id: [u8; 32] = hex::decode(id)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| malformed("a block id in 64 lower-case hex digits"))?;
            lines.push(Line { height, branch, id });
        }
        Ok(Self { lines })
    }

    /// The first line where `self` and `other` differ, or `None` when they
    /// are the same ledger.
    #[must_use]
    pub fn first_difference(&self, other: &Self) -> Option<Difference> {
        let longest = self.lines.len().max(other.lines.len());
        (0..longest).find_map(|i| {
            let ours = self.lines.get(i).copied();
            let theirs = other.lines.get(i).copied();
            (ours != theirs).then_some(Difference {
                line: i + 1,
                ours,
                theirs,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(height: u64, byte: u8) -> Line {
        Line {
            height,
            branch: Branch::Main,
            id: [byte; 32],
        }
    }

    #[test]
    fn a_ledger_round_trips_its_text() {
        let mut ledger = BlocksTxt::new();
        ledger.push(line(0, 1));
        ledger.push(line(1, 2));
        ledger.push(Line {
            height: 1,
            branch: Branch::Alt(3),
            id: [9; 32],
        });
        let text = ledger.render();
        assert!(text.starts_with(&format!("0 main {}\n", "01".repeat(32))));
        assert_eq!(BlocksTxt::parse(&text), Ok(ledger));
        assert_eq!(BlocksTxt::parse(""), Ok(BlocksTxt::new()));
    }

    /// One text, one ledger: every other spelling of a line is refused.
    #[test]
    fn a_line_has_one_spelling() {
        let id = "ab".repeat(32);
        for bad in [
            format!("0 main {id}"),
            format!("00 main {id}\n"),
            format!("+0 main {id}\n"),
            format!("0 Main {id}\n"),
            format!("0 alt:01 {id}\n"),
            format!("0 main {}\n", id.to_uppercase()),
            format!("0 main {id} extra\n"),
            format!("0  main {id}\n"),
            format!("0 main {}\n", &id[2..]),
        ] {
            assert!(BlocksTxt::parse(&bad).is_err(), "{bad:?} parsed");
        }
    }

    /// The first differing line is the first differing block, and a ledger
    /// that ends early differs where the other goes on.
    #[test]
    fn the_first_difference_is_the_first_differing_block() {
        let mut a = BlocksTxt::new();
        let mut b = BlocksTxt::new();
        for h in 0..5 {
            a.push(line(h, 1));
            b.push(line(h, 1));
        }
        assert_eq!(a.first_difference(&b), None);
        b.push(line(5, 7));
        let diff = a.first_difference(&b).expect("b goes on");
        assert_eq!(
            (diff.line, diff.ours, diff.theirs),
            (6, None, Some(line(5, 7)))
        );
        a.push(line(5, 8));
        let diff = a.first_difference(&b).expect("block 5 differs");
        assert_eq!(diff.line, 6);
        assert!(diff.to_string().contains("line 6"));
    }
}
