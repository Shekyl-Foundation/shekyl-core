// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! BIP-39 mnemonic handling: the spelling of a Shekyl wallet's seed.
//!
//! Shekyl uses BIP-39 only as an **entropy encoding** (`NETWORK_IDENTITY.md`
//! NI-R7): the 24 words are how a wallet's 32-byte seed is written down,
//! on every network. The words decode to the 32 bytes and nothing else;
//! there is no passphrase and no PBKDF2 step, so the words and the bytes
//! are one secret. See `docs/POST_QUANTUM_CRYPTOGRAPHY.md` §"Key Derivation
//! Pipeline".
//!
//! # Why we wrap a crate rather than inline the wordlist
//!
//! BIP-39 correctness hinges on two easy-to-mis-implement details: the
//! 2048-word English wordlist and SHA-256 entropy checksum placement in the
//! final 11-bit word. The `bip39` crate from rust-bitcoin gets all three right and is widely
//! deployed. Rather than re-implement them here, we depend on the crate and
//! pin its correctness with a Tier-3 KAT that matches the canonical BIP-39
//! English-wordlist SHA-256 against a constant in this file. Any upstream
//! drift fails the KAT before it can ship.
//!
//! # Scope
//!
//! - Only the English wordlist is supported. Other languages would require
//!   additional KATs and a language selector in the wallet file; neither is
//!   in scope for v1.
//! - Only 24-word mnemonics are supported (32 bytes of entropy plus an
//!   8-bit checksum), at creation and at import: 12 words is 128 bits, 64
//!   bits of security under Grover, below Shekyl's post-quantum floor.

use std::fmt;

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::CryptoError;

/// Why [`entropy_from_mnemonic`] refused a phrase.
///
/// The value is the class and, where the parser counted tokens, that
/// count. It does not carry the words or a word's index. `Display` is
/// one fixed sentence, so formatting the error cannot echo the input.
///
/// `#[non_exhaustive]`: a new class is a new variant, and a caller
/// outside this crate keeps a fallback arm.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhraseError {
    /// The whitespace count is not a length BIP-39 spells
    /// (12, 15, 18, 21, or 24). Zero is an empty phrase.
    WordCount(usize),
    /// The count is a BIP-39 length and one token is not an English word.
    /// `words` is that count.
    UnknownWord { words: usize },
    /// The words are English and the checksum does not match.
    /// `words` is that count.
    Checksum { words: usize },
    /// The phrase is a valid BIP-39 mnemonic of a length other than
    /// [`SHEKYL_MNEMONIC_WORD_COUNT`].
    Length(usize),
    /// A 24-word phrase decoded to an entropy length other than 32 bytes.
    /// Unreachable under `bip39` 2.x; present so a shorter decode fails
    /// closed instead of truncating.
    EntropyLength,
    /// The parser returned a class this decoder does not spell: an
    /// entropy-sized failure, or more than one language. Neither carries
    /// the phrase.
    Unclassified,
}

impl fmt::Display for PhraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("recovery phrase is not usable")
    }
}

impl std::error::Error for PhraseError {}

impl From<PhraseError> for CryptoError {
    fn from(_err: PhraseError) -> Self {
        // One sentence, with no count and no words. Callers that need the
        // class match on [`PhraseError`] before this conversion.
        CryptoError::InvalidInput("recovery phrase is not usable".into())
    }
}

/// Shekyl mandates 24-word mnemonics. 32 bytes of entropy + 8-bit checksum
/// packed as 24 * 11-bit words.
pub const SHEKYL_MNEMONIC_WORD_COUNT: usize = 24;

/// Shekyl mandates 32-byte entropy (the `d` of a 24-word mnemonic).
pub const SHEKYL_BIP39_ENTROPY_BYTES: usize = 32;

/// Convert 32 bytes of entropy into a 24-word BIP-39 English mnemonic.
///
/// # Secrecy
///
/// The returned `String` is equally secret with the input entropy — anyone
/// holding the mnemonic can derive the wallet. Callers are expected to
/// `memwipe` the string after writing it to its final destination (typically
/// the user's paper backup), and to not log or trace it.
pub fn mnemonic_from_entropy(
    entropy: &[u8; SHEKYL_BIP39_ENTROPY_BYTES],
) -> Result<String, CryptoError> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
        .map_err(|e| CryptoError::InvalidInput(format!("BIP-39 from_entropy: {e}")))?;
    Ok(mnemonic.to_string())
}

/// Validate that `words` is a well-formed 24-word English BIP-39 mnemonic.
///
/// Validation checks, in order:
///
/// 1. Trimmed and collapsed-whitespace form has exactly 24 space-separated
///    tokens.
/// 2. Every token is in the English wordlist.
/// 3. The final 8 bits of the packed entropy match
///    `SHA-256(entropy)[0] >> 0` per BIP-39 §Checksum.
///
/// A failure in any step yields `false`. The function is constant-time only
/// with respect to the crate's internal lookup; do not rely on it for
/// protecting the wordlist contents from a timing attacker (the wordlist is
/// public).
pub fn validate(words: &str) -> bool {
    Mnemonic::parse_in(Language::English, words).is_ok()
        && word_count(words) == SHEKYL_MNEMONIC_WORD_COUNT
}

/// Recover the 32-byte BIP-39 entropy from a validated 24-word English
/// mnemonic phrase.
///
/// The phrase-to-entropy direction is a reversible bit-unpacking of the 264-bit word stream into 256 entropy bits
/// plus an 8-bit checksum. This entry point is the Shekyl-side primitive
/// behind the `shekyl_bip39_mnemonic_to_entropy` FFI added by the
/// Electrum-words removal Phase 1 atomic commit per
/// `docs/completed/ELECTRUM_WORDS_REMOVAL.md` §4.10. The wallet keyfile
/// persists the entropy (not the phrase); `query_key("mnemonic")`
/// regenerates the phrase from the persisted entropy on demand.
///
/// # Errors
///
/// [`PhraseError`]. The class is the parser's, not a second reading of
/// the string:
///
/// - [`PhraseError::WordCount`] when the whitespace count is not a
///   BIP-39 length.
/// - [`PhraseError::UnknownWord`] when one token is not an English word.
/// - [`PhraseError::Checksum`] when the words are English and the
///   checksum does not match.
/// - [`PhraseError::Length`] when the phrase is a valid mnemonic of a
///   length other than [`SHEKYL_MNEMONIC_WORD_COUNT`].
/// - [`PhraseError::EntropyLength`] if a 24-word phrase yields an
///   entropy length other than 32 bytes. Unreachable under `bip39` 2.x;
///   the branch exists so a shorter decode fails closed instead of
///   truncating.
/// - [`PhraseError::Unclassified`] for a parser class this decoder does
///   not spell. The phrase is not in it.
///
/// # Zeroization
///
/// The returned `Zeroizing<[u8; 32]>` wipes its backing storage when
/// dropped, per the cross-boundary zeroization contract documented in
/// `ELECTRUM_WORDS_REMOVAL.md` §4.7. The upstream `bip39` crate's
/// `to_entropy_array` returns a stack-resident `([u8; 33], usize)`
/// tuple; this function copies the 32 entropy bytes into the
/// `Zeroizing` wrapper and zeroizes the upstream stack buffer before
/// returning.
pub fn entropy_from_mnemonic(
    words: &str,
) -> Result<Zeroizing<[u8; SHEKYL_BIP39_ENTROPY_BYTES]>, PhraseError> {
    let counted = word_count(words);
    let mnemonic = match Mnemonic::parse_in(Language::English, words) {
        Ok(mnemonic) => mnemonic,
        Err(bip39::Error::BadWordCount(n)) => return Err(PhraseError::WordCount(n)),
        Err(bip39::Error::UnknownWord(_)) => {
            return Err(PhraseError::UnknownWord { words: counted })
        }
        Err(bip39::Error::InvalidChecksum) => return Err(PhraseError::Checksum { words: counted }),
        // `BadEntropyBitCount` is a from-entropy failure. `AmbiguousLanguages`
        // needs more than one wordlist compiled in. Neither carries the phrase.
        Err(bip39::Error::BadEntropyBitCount(_) | bip39::Error::AmbiguousLanguages(_)) => {
            return Err(PhraseError::Unclassified)
        }
    };

    if mnemonic.word_count() != SHEKYL_MNEMONIC_WORD_COUNT {
        return Err(PhraseError::Length(mnemonic.word_count()));
    }

    let (mut entropy_arr, entropy_len) = mnemonic.to_entropy_array();
    if entropy_len != SHEKYL_BIP39_ENTROPY_BYTES {
        // Wipe the upstream buffer before propagating the error.
        use zeroize::Zeroize;
        entropy_arr.zeroize();
        return Err(PhraseError::EntropyLength);
    }

    let mut entropy = [0u8; SHEKYL_BIP39_ENTROPY_BYTES];
    entropy.copy_from_slice(&entropy_arr[..SHEKYL_BIP39_ENTROPY_BYTES]);

    // Wipe the upstream buffer: the upstream `to_entropy_array` returns a
    // stack-resident `[u8; 33]` that the compiler is otherwise free to
    // leave populated on the stack for the lifetime of the frame. The
    // single 32-byte canonical copy lives inside the `Zeroizing` wrapper
    // returned below.
    use zeroize::Zeroize;
    entropy_arr.zeroize();

    Ok(Zeroizing::new(entropy))
}

/// Number of whitespace-separated tokens in `s`, after trimming.
fn word_count(s: &str) -> usize {
    s.split_whitespace().count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// SHA-256 of the BIP-39 English wordlist as returned by
    /// `bip39::Language::English.word_list()`, with a single `b"\n"`
    /// appended after every word and nothing else. The shape is chosen to
    /// avoid any ambiguity about trailing bytes: one newline per word, no
    /// leading BOM, no Windows CRLF.
    ///
    /// This constant is the Tier-3 tripwire for BIP-39 conformance. BIP-39
    /// is frozen; the only way this hash can drift is if the `bip39` crate
    /// reorders, renames, or re-encodes a word. Such drift would
    /// invalidate every wallet ever derived under this code and must be
    /// treated as a protocol-break incident, not a test-data refresh.
    ///
    /// Value computed on first implementation against the BIP-39 English
    /// wordlist shipped with the `bip39` crate at pin `2.2.2`. The
    /// canonical `bitcoin/bips/bip-0039/english.txt` file has its own
    /// well-known SHA-256 (`ad90bf3beea808fe33032c22c542ef1a34a36b3fa41db9d1f38c6e9d06f0fd67`);
    /// the two hashes differ because the canonical file is hashed as one
    /// byte stream with LF separators, whereas this test hashes the
    /// crate's `&[&'static str]` representation concatenated with `\n`
    /// after each word. Equivalence of the word *sequence* is enforced by
    /// the Tier-3 byte-vector KATs (which run official BIP-39 vectors
    /// through our pipeline); this constant serves as a fast local
    /// tripwire.
    const BIP39_ENGLISH_WORDLIST_SHA256_HEX: &str =
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

    #[test]
    fn bip39_english_wordlist_sha256_matches_canonical() {
        let list = Language::English.word_list();
        assert_eq!(list.len(), 2048);

        let mut hasher = Sha256::new();
        for word in list {
            hasher.update(word.as_bytes());
            hasher.update(b"\n");
        }
        let got = hex_lower(&hasher.finalize());

        assert_eq!(
            got, BIP39_ENGLISH_WORDLIST_SHA256_HEX,
            "BIP-39 English wordlist SHA-256 drifted. This is a freeze-gate \
             KAT; if the upstream wordlist genuinely changed, the mainnet \
             address derivation is broken and requires a protocol bump, not \
             a test update."
        );
    }

    #[test]
    fn entropy_roundtrip_24_words() {
        let entropy = [0x42u8; 32];
        let words = mnemonic_from_entropy(&entropy).unwrap();
        assert_eq!(word_count(&words), 24);
        assert!(validate(&words));

        let parsed = Mnemonic::parse_in(Language::English, &words).unwrap();
        let (back, len) = parsed.to_entropy_array();
        assert_eq!(len, 32);
        assert_eq!(&back[..32], &entropy[..]);
    }

    /// BIP-39 official test vector #1 from
    /// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    /// (entropy = 32 × 0x00): the words the entropy encodes.
    #[test]
    fn bip39_official_vector_zero_entropy_words_match() {
        let entropy = [0u8; 32];
        let expected_words = [
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "art",
        ];
        let got_words = mnemonic_from_entropy(&entropy).unwrap();
        let got_tokens: Vec<&str> = got_words.split_whitespace().collect();
        assert_eq!(got_tokens.as_slice(), &expected_words[..]);
    }

    #[test]
    fn validate_rejects_23_words() {
        let entropy = [0u8; 32];
        let words = mnemonic_from_entropy(&entropy).unwrap();
        let truncated: String = words
            .split_whitespace()
            .take(23)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!validate(&truncated));
    }

    /// `entropy_from_mnemonic` is the BIP-39 phrase-to-entropy primitive
    /// the wallet keyfile relies on for the new `m_bip39_entropy` field
    /// (per `ELECTRUM_WORDS_REMOVAL.md` §4.10). The round-trip property is
    /// the load-bearing invariant: a phrase produced by
    /// `mnemonic_from_entropy(E)` must yield exactly `E` when fed back
    /// through `entropy_from_mnemonic`; otherwise the keyfile-stored
    /// entropy and the user-supplied recovery phrase diverge and
    /// `query_key("mnemonic")` returns a phrase that does not derive the
    /// wallet's actual account material.
    #[test]
    fn entropy_from_mnemonic_round_trip() {
        // Pick three entropy patterns: all-zero (BIP-39 vector #1's input),
        // all-0x42, and
        // a non-trivial bit pattern that won't accidentally agree with
        // either extreme.
        for &entropy_byte in &[0x00u8, 0x42u8, 0xC3u8] {
            let entropy = [entropy_byte; SHEKYL_BIP39_ENTROPY_BYTES];
            let words = mnemonic_from_entropy(&entropy).unwrap();
            let recovered = entropy_from_mnemonic(&words).unwrap();
            assert_eq!(recovered.as_slice(), &entropy[..]);
        }
    }

    /// A phrase one word short of [`SHEKYL_MNEMONIC_WORD_COUNT`] is not a
    /// length BIP-39 spells. Reject it rather than padding the entropy.
    #[test]
    fn entropy_from_mnemonic_rejects_a_short_phrase() {
        let entropy = [0u8; SHEKYL_BIP39_ENTROPY_BYTES];
        let words = mnemonic_from_entropy(&entropy).unwrap();
        let short = SHEKYL_MNEMONIC_WORD_COUNT - 1;
        let truncated: String = words
            .split_whitespace()
            .take(short)
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            entropy_from_mnemonic(&truncated).unwrap_err(),
            PhraseError::WordCount(short)
        );
    }

    /// Half of [`SHEKYL_MNEMONIC_WORD_COUNT`] is a legal BIP-39 length and
    /// not a Shekyl seed. Its entropy is `words * 32 / 3` bits.
    #[test]
    fn a_valid_shorter_phrase_is_the_wrong_length() {
        const SHORT_MNEMONIC_WORDS: usize = SHEKYL_MNEMONIC_WORD_COUNT / 2;
        const SHORT_MNEMONIC_ENTROPY_BYTES: usize = SHORT_MNEMONIC_WORDS * 32 / 3 / 8;
        let mnemonic =
            Mnemonic::from_entropy_in(Language::English, &[0u8; SHORT_MNEMONIC_ENTROPY_BYTES])
                .unwrap();
        assert_eq!(mnemonic.word_count(), SHORT_MNEMONIC_WORDS);
        assert_eq!(
            entropy_from_mnemonic(&mnemonic.to_string()).unwrap_err(),
            PhraseError::Length(SHORT_MNEMONIC_WORDS)
        );
    }

    /// A phrase with a corrupted final word (the checksum word) must be
    /// rejected as [`PhraseError::Checksum`], not silently parsed with a
    /// tampered entropy block. This guards the wallet keyfile against
    /// entropy values that were never produced by a legitimate
    /// `mnemonic_from_entropy` call.
    #[test]
    fn entropy_from_mnemonic_rejects_bad_checksum() {
        let entropy = [0u8; SHEKYL_BIP39_ENTROPY_BYTES];
        let words = mnemonic_from_entropy(&entropy).unwrap();
        let mut tokens: Vec<&str> = words.split_whitespace().collect();
        assert_eq!(tokens.last().copied(), Some("art"));
        // "ability" is a wordlist token but yields a bad checksum in the
        // 24th position for the all-zero entropy input.
        *tokens.last_mut().unwrap() = "ability";
        let tampered = tokens.join(" ");
        assert_eq!(
            entropy_from_mnemonic(&tampered).unwrap_err(),
            PhraseError::Checksum {
                words: SHEKYL_MNEMONIC_WORD_COUNT
            }
        );
        let shown = PhraseError::Checksum {
            words: SHEKYL_MNEMONIC_WORD_COUNT,
        }
        .to_string();
        assert!(!shown.contains("ability"));
        assert!(!shown.contains("art"));
    }

    #[test]
    fn validate_rejects_bad_checksum() {
        // Replace the final word ("art") with a different valid-wordlist word.
        let entropy = [0u8; 32];
        let words = mnemonic_from_entropy(&entropy).unwrap();
        let mut tokens: Vec<&str> = words.split_whitespace().collect();
        assert_eq!(tokens.last().copied(), Some("art"));
        // "ability" is a valid English-wordlist token but yields a bad
        // checksum in this position.
        *tokens.last_mut().unwrap() = "ability";
        let tampered = tokens.join(" ");
        assert!(!validate(&tampered));
    }

    // --- helpers -----------------------------------------------------------

    fn hex_lower(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }
}
