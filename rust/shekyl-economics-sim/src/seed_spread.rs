// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Standard traffic's spread across the declared seeds, on demand
//! (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.35).
//!
//! The narration pins carry the canonical seed. This runs a narration at
//! every seed of [`HONEST_SEEDS`] and merges the texts: a line every seed
//! prints alike is printed once; a line whose words agree and whose figures
//! differ prints each differing figure as its median and `[its range]`; a
//! line whose words differ is printed once per seed, tagged. Nothing here
//! reads a fold: the merge is of the reports as printed.

use crate::chain_cursor::Traffic;
use crate::engine::SimParams;
use crate::rng::HONEST_SEEDS;

/// `render` at every declared seed, merged. `params` names the run; each
/// seed's run is `params` on standard traffic at that seed.
pub(crate) fn across_seeds(params: &SimParams, render: impl Fn(&SimParams) -> String) -> String {
    let runs: Vec<String> = HONEST_SEEDS
        .iter()
        .map(|&seed| {
            let mut at = params.clone();
            at.traffic = Traffic::Variable(seed);
            render(&at)
        })
        .collect();
    let seeds: Vec<String> = HONEST_SEEDS.iter().map(u64::to_string).collect();
    format!(
        "SEED SPREAD (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.35): the report at seeds {}; \
         each figure that differs prints as its median and [its range].\n{}",
        seeds.join(", "),
        merge(&HONEST_SEEDS, &runs)
    )
}

/// One printed figure or the words between figures.
#[derive(Debug, Clone, PartialEq)]
enum Piece<'a> {
    Words(&'a str),
    Figure(&'a str),
}

/// A line cut into words and figures. A figure is an optional `-`, digits,
/// and an optional `.` with digits after it. A `-` straight after a digit
/// joins two figures (a printed range, `0.10-1.08`), so it is a word, not
/// a sign.
fn pieces(line: &str) -> Vec<Piece<'_>> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < bytes.len() {
        let after_digit = i > 0 && bytes[i - 1].is_ascii_digit();
        let signed =
            bytes[i] == b'-' && !after_digit && bytes.get(i + 1).is_some_and(u8::is_ascii_digit);
        if bytes[i].is_ascii_digit() || signed {
            if start < i {
                out.push(Piece::Words(&line[start..i]));
            }
            let figure = i;
            i += usize::from(signed);
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i + 1 < bytes.len() && bytes[i] == b'.' && bytes[i + 1].is_ascii_digit() {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            out.push(Piece::Figure(&line[figure..i]));
            start = i;
        } else {
            i += 1;
        }
    }
    if start < bytes.len() {
        out.push(Piece::Words(&line[start..]));
    }
    out
}

/// Digits after the point, so the median and the range print as the
/// figures did.
fn decimals(figure: &str) -> usize {
    figure.split_once('.').map_or(0, |(_, frac)| frac.len())
}

/// The figures one position holds across the seeds: the figure itself
/// when every seed printed it alike, else the lower-middle median and the
/// range, at the most digits any seed printed.
fn spread(figures: &[&str]) -> String {
    if figures.iter().all(|f| f == &figures[0]) {
        return figures[0].to_string();
    }
    let places = figures.iter().map(|f| decimals(f)).max().unwrap_or(0);
    let mut values: Vec<f64> = figures
        .iter()
        .map(|f| f.parse().expect("a figure is a number"))
        .collect();
    values.sort_by(f64::total_cmp);
    let median = values[(values.len() - 1) / 2];
    let (low, high) = (values[0], values[values.len() - 1]);
    format!("{median:.places$} [{low:.places$}, {high:.places$}]")
}

/// The runs merged line by line (see the module's note). `seeds` tags a
/// line whose words differ; `runs[i]` is the report at `seeds[i]`.
fn merge(seeds: &[u64], runs: &[String]) -> String {
    let lines: Vec<Vec<&str>> = runs.iter().map(|run| run.lines().collect()).collect();
    let longest = lines.iter().map(Vec::len).max().unwrap_or(0);
    let mut out = String::new();
    for row in 0..longest {
        let at: Vec<Option<&str>> = lines.iter().map(|l| l.get(row).copied()).collect();
        if let Some(first) = at[0] {
            if at.iter().all(|line| *line == Some(first)) {
                out.push_str(first);
                out.push('\n');
                continue;
            }
        }
        let cut: Option<Vec<Vec<Piece<'_>>>> = at.iter().map(|l| l.map(pieces)).collect();
        let alike = cut.as_ref().is_some_and(|cut| {
            cut.iter().all(|p| {
                p.len() == cut[0].len()
                    && p.iter().zip(&cut[0]).all(|(a, b)| match (a, b) {
                        // A column's padding follows its figure's width, so
                        // words that differ only in spacing are alike.
                        (Piece::Words(a), Piece::Words(b)) => {
                            a.split_whitespace().eq(b.split_whitespace())
                                && a.starts_with(char::is_whitespace)
                                    == b.starts_with(char::is_whitespace)
                                && a.ends_with(char::is_whitespace)
                                    == b.ends_with(char::is_whitespace)
                        }
                        (Piece::Figure(_), Piece::Figure(_)) => true,
                        _ => false,
                    })
            })
        });
        if let (true, Some(cut)) = (alike, cut) {
            for (slot, piece) in cut[0].iter().enumerate() {
                match piece {
                    Piece::Words(words) => out.push_str(words),
                    Piece::Figure(_) => {
                        let figures: Vec<&str> = cut
                            .iter()
                            .map(|p| match p[slot] {
                                Piece::Figure(f) => f,
                                Piece::Words(_) => unreachable!("the pieces line up"),
                            })
                            .collect();
                        out.push_str(&spread(&figures));
                    }
                }
            }
            out.push('\n');
        } else {
            for (seed, line) in seeds.iter().zip(&at) {
                out.push_str(&format!("[seed {seed}] {}\n", line.unwrap_or("(no line)")));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_alike_prints_once_and_a_differing_figure_prints_its_spread() {
        let runs = [
            "head\nfee 0.50 SKL at y12, -3 blocks\n".to_string(),
            "head\nfee 0.48 SKL at y12, -1 blocks\n".to_string(),
            "head\nfee 0.55 SKL at y12, -2 blocks\n".to_string(),
        ];
        assert_eq!(
            merge(&[1, 2, 3], &runs),
            "head\nfee 0.50 [0.48, 0.55] SKL at y12, -2 [-3, -1] blocks\n"
        );
    }

    #[test]
    fn a_line_whose_words_differ_prints_once_per_seed() {
        let runs = [
            "tail era: not reached".to_string(),
            "tail era: 574 blocks".to_string(),
            "tail era: not reached".to_string(),
        ];
        assert_eq!(
            merge(&[1, 2, 3], &runs),
            "[seed 1] tail era: not reached\n[seed 2] tail era: 574 blocks\n[seed 3] tail era: not reached\n"
        );
    }

    #[test]
    fn a_missing_line_is_named() {
        let runs = ["a\nb".to_string(), "a".to_string(), "a\nb".to_string()];
        assert_eq!(
            merge(&[1, 2, 3], &runs),
            "a\n[seed 1] b\n[seed 2] (no line)\n[seed 3] b\n"
        );
    }

    /// A printed range keeps its two ends; the dash between them is a word.
    #[test]
    fn a_dash_after_a_digit_joins_a_range() {
        assert_eq!(
            pieces("range 0.10-1.08 x"),
            [
                Piece::Words("range "),
                Piece::Figure("0.10"),
                Piece::Words("-"),
                Piece::Figure("1.08"),
                Piece::Words(" x"),
            ]
        );
        let runs = [
            "r 0.10-1.08".to_string(),
            "r 0.10-1.07".to_string(),
            "r 0.10-1.08".to_string(),
        ];
        assert_eq!(merge(&[1, 2, 3], &runs), "r 0.10-1.08 [1.07, 1.08]\n");
    }

    /// A column padded to its figure's width at one seed and not another
    /// merges; the first seed's spacing is printed.
    #[test]
    fn padding_that_follows_a_figure_is_alike() {
        let runs = [
            "10%   3019   1120  4423.73".to_string(),
            "10%   2830    799  4151.77".to_string(),
            "10%   2418    896  3556.14".to_string(),
        ];
        assert_eq!(
            merge(&[1, 2, 3], &runs),
            "10%   2830 [2418, 3019]   896 [799, 1120]  4151.77 [3556.14, 4423.73]\n"
        );
    }

    #[test]
    fn the_pieces_keep_signs_points_and_words() {
        assert_eq!(
            pieces("y13.83 (+2.77) x-1 a.b"),
            [
                Piece::Words("y"),
                Piece::Figure("13.83"),
                Piece::Words(" (+"),
                Piece::Figure("2.77"),
                Piece::Words(") x"),
                Piece::Figure("-1"),
                Piece::Words(" a.b"),
            ]
        );
    }
}
