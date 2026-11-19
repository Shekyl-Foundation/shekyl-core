// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The order of a transaction's outputs, derived from its key (R-24).
//!
//! A wallet that wrote its change last, or its payees in the order it was
//! handed them, would tell an observer which output came back to it. So no
//! caller chooses a position: every transaction a wallet builds takes the
//! order [`TxKey::output_order`] derives, a permutation drawn from the
//! transaction key. A solo key is random, so its change lands at each
//! position with equal probability; a multisig key comes from the intent
//! ([`TxKey::from_intent_seed`]), so every member derives the same order.
//!
//! The draw is an unbiased Fisher–Yates shuffle (Durstenfeld's form) over a
//! stream expanded from the key:
//!
//! - **Stream.** HKDF-SHA-512 with no salt and the key's scalar bytes as
//!   IKM; block `b` is `expand(`[`LABEL_TX_OUTPUT_ORDER`]` ‖ u64_le(b), 64)`,
//!   for `b = 0, 1, …`. The stream is the blocks in order, read as
//!   little-endian `u32` words, sixteen to a block.
//! - **Shuffle.** Start from `recipient_at = [0, 1, …, n−1]`. For
//!   `i = n−1` down to `1`: draw `j` uniform in `[0, i]`, then swap
//!   `recipient_at[i]` and `recipient_at[j]`.
//! - **Uniform draw.** With `bound = i + 1`, a word `w` is accepted when
//!   `w < 2³² − (2³² mod bound)`, and then `j = w mod bound`; a refused word
//!   is skipped and the next one drawn. No modulo bias.
//!
//! The result reads both ways: `recipient_at[p]` is the recipient whose
//! output sits at position `p`, and [`OutputOrder::position_of`] is its
//! inverse, `π(recipient)`. The output at position `p` is built with
//! derivation index `p`, so a recipient's scan is unchanged.
//!
//! Pinned vectors: `docs/test_vectors/TX_OUTPUT_ORDER_V1.json`, written and
//! checked by the independent oracle `scripts/kat/tx_output_order_oracle.py`.

use std::fmt;

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::derivation::make_info;
use crate::tx_key::TxKey;

/// HKDF info prefix of the output-order stream's blocks.
pub const LABEL_TX_OUTPUT_ORDER: &[u8] = b"shekyl/tx-output-order-v1";

/// The length of one expanded block of the stream.
const BLOCK_LEN: usize = 64;
/// The length of one drawn word.
const WORD_LEN: usize = 4;
/// The number of word values, `2³²`.
const WORD_SPAN: u64 = 1 << 32;

/// The positions of a transaction's outputs: which recipient each position
/// holds. Made only by [`TxKey::output_order`]. Its `Debug` prints the
/// count and not the order, which would say which output is the change.
#[derive(Clone, PartialEq, Eq)]
pub struct OutputOrder {
    /// `recipient_at[p]`: the recipient whose output sits at position `p`.
    recipient_at: Vec<usize>,
}

impl OutputOrder {
    /// The number of outputs ordered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.recipient_at.len()
    }

    /// Whether the order holds no output.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recipient_at.is_empty()
    }

    /// The recipient whose output sits at `position`, or `None` past the
    /// last.
    #[must_use]
    pub fn recipient_at(&self, position: usize) -> Option<usize> {
        self.recipient_at.get(position).copied()
    }

    /// `π(recipient)`: the position of `recipient`'s output, or `None` for a
    /// recipient the order does not hold.
    #[must_use]
    pub fn position_of(&self, recipient: usize) -> Option<usize> {
        self.recipient_at.iter().position(|&r| r == recipient)
    }

    /// The recipients in position order: the first is the output at
    /// position 0.
    pub fn recipients(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        self.recipient_at.iter().copied()
    }
}

impl fmt::Debug for OutputOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OutputOrder({} outputs)", self.len())
    }
}

/// The key's stream of words (module docs).
struct Words {
    hk: Hkdf<Sha512>,
    block: Zeroizing<[u8; BLOCK_LEN]>,
    next_block: u64,
    offset: usize,
}

impl Words {
    fn of(tx_key: &TxKey) -> Self {
        Self {
            hk: Hkdf::<Sha512>::new(None, tx_key.ikm()),
            block: Zeroizing::new([0u8; BLOCK_LEN]),
            next_block: 0,
            offset: BLOCK_LEN,
        }
    }

    fn next(&mut self) -> u32 {
        if self.offset == BLOCK_LEN {
            self.hk
                .expand(
                    &make_info(LABEL_TX_OUTPUT_ORDER, self.next_block),
                    self.block.as_mut(),
                )
                .expect("64 bytes is a valid HKDF-SHA-512 output length");
            self.next_block += 1;
            self.offset = 0;
        }
        let word: [u8; WORD_LEN] = self.block[self.offset..self.offset + WORD_LEN]
            .try_into()
            .expect("a word is four bytes of the block");
        self.offset += WORD_LEN;
        u32::from_le_bytes(word)
    }
}

/// A draw uniform in `[0, bound)` from `next_word`, by rejection (module
/// docs): a word at or above the largest multiple of `bound` below `2³²` is
/// skipped.
fn uniform_below(mut next_word: impl FnMut() -> u32, bound: u64) -> u64 {
    let zone = WORD_SPAN - WORD_SPAN % bound;
    loop {
        let word = u64::from(next_word());
        if word < zone {
            return word % bound;
        }
    }
}

impl TxKey {
    /// The order of this transaction's `count` outputs (R-24; module docs):
    /// a permutation every holder of the key derives alike, and no one
    /// without it can predict.
    #[must_use]
    pub fn output_order(&self, count: usize) -> OutputOrder {
        let mut recipient_at: Vec<usize> = (0..count).collect();
        let mut words = Words::of(self);
        for i in (1..count).rev() {
            let bound = u64::try_from(i + 1).expect("an output count fits in a u64");
            let j = usize::try_from(uniform_below(|| words.next(), bound))
                .expect("a draw below an index fits");
            recipient_at.swap(i, j);
        }
        OutputOrder { recipient_at }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multisig_intent::IntentSeed;

    fn key(n: u32) -> TxKey {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&n.to_le_bytes());
        TxKey::from_intent_seed(&IntentSeed::new(&seed))
    }

    /// Every count from none to past the wire's output cap gets a
    /// permutation, read the same both ways.
    #[test]
    fn an_order_is_a_permutation_and_its_inverse() {
        const COUNTS_CHECKED: usize = 32;
        for count in 0..=COUNTS_CHECKED {
            let order = key(7).output_order(count);
            assert_eq!(order.len(), count);
            let mut seen: Vec<usize> = order.recipients().collect();
            seen.sort_unstable();
            assert_eq!(seen, (0..count).collect::<Vec<_>>());
            for position in 0..count {
                let recipient = order.recipient_at(position).unwrap();
                assert_eq!(order.position_of(recipient), Some(position));
            }
            assert_eq!(order.position_of(count), None);
            assert_eq!(order.recipient_at(count), None);
        }
    }

    /// One key gives one order: members holding one intent build one
    /// transaction. Another key gives another.
    #[test]
    fn one_key_is_one_order() {
        let a = key(11).output_order(9);
        assert_eq!(a, key(11).output_order(9));
        assert!((12..40).any(|n| key(n).output_order(9) != a));
    }

    /// The change, recipient 4 of five, lands at each position equally
    /// often over many keys: a chi-square bound on the counts. The keys are
    /// fixed, so the test cannot flake; the bound is the 0.999 quantile of
    /// chi-square with four degrees of freedom.
    #[test]
    fn the_change_lands_anywhere_with_equal_probability() {
        const OUTPUTS: u8 = 5;
        const KEYS: u32 = 10_000;
        const CHI_SQUARE_4_DF_0_999: f64 = 18.467;
        let mut counts = [0u32; OUTPUTS as usize];
        for n in 0..KEYS {
            let outputs = usize::from(OUTPUTS);
            let position = key(n)
                .output_order(outputs)
                .position_of(outputs - 1)
                .unwrap();
            counts[position] += 1;
        }
        let expected = f64::from(KEYS) / f64::from(OUTPUTS);
        let chi_square: f64 = counts
            .iter()
            .map(|&c| (f64::from(c) - expected).powi(2) / expected)
            .sum();
        assert!(
            chi_square < CHI_SQUARE_4_DF_0_999,
            "counts {counts:?}: chi-square {chi_square}"
        );
    }

    /// A word in the biased tail is skipped and the next one drawn: for a
    /// bound of 3, `2³² − 1` is the one refused word (`2³²` is one more than
    /// a multiple of 3).
    #[test]
    fn a_word_in_the_biased_tail_is_skipped() {
        let mut words = [u32::MAX, u32::MAX - 1, 5].into_iter();
        assert_eq!(
            uniform_below(|| words.next().unwrap(), 3),
            u64::from(u32::MAX - 1) % 3
        );
        assert_eq!(uniform_below(|| words.next().unwrap(), 3), 2);
        let mut words = [u32::MAX, 7].into_iter();
        assert_eq!(uniform_below(|| words.next().unwrap(), 3), 1);
    }

    /// The order prints its count only.
    #[test]
    fn an_order_never_prints_its_positions() {
        assert_eq!(
            format!("{:?}", key(3).output_order(4)),
            "OutputOrder(4 outputs)"
        );
    }
}
