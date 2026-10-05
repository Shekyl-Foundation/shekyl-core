// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The contract's canonical 32-byte hex spelling.
//!
//! One rule for every surface that accepts a tx hash: exactly 64
//! lowercase hex characters. Uppercase is a different string from the
//! one this wallet emits, so it is rejected here rather than folded —
//! a caller then says the value is not in canonical form, which is a
//! different fact from "no such transaction".

/// Characters in a canonical tx hash.
pub const HEX32_CHARS: usize = 64;

/// Bytes in a tx hash.
pub const HEX32_BYTES: usize = HEX32_CHARS / 2;

const NIBBLES_PER_BYTE: usize = 2;
const HIGH_NIBBLE_SHIFT: u32 = 4;
const DECIMAL_DIGIT_COUNT: u8 = 10;

/// Parse a canonical tx hash into its 32 bytes.
///
/// `None` for any other spelling, including uppercase and the wrong length.
#[must_use]
pub fn parse_lowercase_hex32(value: &str) -> Option<[u8; HEX32_BYTES]> {
    let digits = value.as_bytes();
    if digits.len() != HEX32_CHARS {
        return None;
    }
    let mut out = [0u8; HEX32_BYTES];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = hex_value(digits[index * NIBBLES_PER_BYTE])?;
        let low = hex_value(digits[index * NIBBLES_PER_BYTE + 1])?;
        *byte = (high << HIGH_NIBBLE_SHIFT) | low;
    }
    Some(out)
}

/// The stable invalid-params sentence for a tx-hash field.
///
/// `field` is the contract's parameter name (`txid` on proofs, `tx_hash`
/// on notes and abandon), so each surface names the field the caller sent.
#[must_use]
pub fn invalid_hex32_message(field: &str) -> String {
    format!("{field} must be {HEX32_CHARS} lowercase hex characters")
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + DECIMAL_DIGIT_COUNT),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_hex_round_trips() {
        let text = "0a".repeat(HEX32_CHARS / 2);
        let bytes = parse_lowercase_hex32(&text).expect("canonical");
        assert_eq!(bytes, [0x0a; HEX32_BYTES]);
        assert_eq!(hex_encode(&bytes), text);
    }

    #[test]
    fn uppercase_and_wrong_lengths_are_rejected() {
        assert!(parse_lowercase_hex32(&"0A".repeat(HEX32_BYTES)).is_none());
        assert!(parse_lowercase_hex32(&"0a".repeat(HEX32_BYTES - 1)).is_none());
        assert!(parse_lowercase_hex32(&"0a".repeat(HEX32_BYTES + 1)).is_none());
        assert!(parse_lowercase_hex32("").is_none());
        assert!(parse_lowercase_hex32(&format!("0g{}", "0a".repeat(HEX32_BYTES - 1))).is_none());
    }

    #[test]
    fn invalid_message_names_the_field_and_the_length() {
        assert_eq!(
            invalid_hex32_message("txid"),
            "txid must be 64 lowercase hex characters"
        );
        assert_eq!(
            invalid_hex32_message("tx_hash"),
            "tx_hash must be 64 lowercase hex characters"
        );
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
        const LOW_NIBBLE_MASK: u8 = 0x0f;
        let mut out = String::with_capacity(bytes.len() * NIBBLES_PER_BYTE);
        for byte in bytes {
            let high = usize::from(byte >> HIGH_NIBBLE_SHIFT);
            let low = usize::from(byte & LOW_NIBBLE_MASK);
            out.push(char::from(HEX_DIGITS[high]));
            out.push(char::from(HEX_DIGITS[low]));
        }
        out
    }
}
