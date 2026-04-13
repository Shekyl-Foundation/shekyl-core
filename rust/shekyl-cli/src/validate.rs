// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Input validation helpers for CLI arguments.
//!
//! These are pure functions suitable for property-based testing.

/// Validate a hex string (e.g. txid). Must be ASCII hex, even length, max 128 bytes decoded.
pub fn validate_hex(s: &str) -> Result<(), &'static str> {
    if s.is_empty() {
        return Err("empty hex string");
    }
    if s.len() > 256 {
        return Err("hex string too long (max 256 chars / 128 bytes)");
    }
    if s.len() % 2 != 0 {
        return Err("hex string has odd length");
    }
    if s.contains('\0') {
        return Err("hex string contains null byte");
    }
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("hex string contains non-hex character");
    }
    Ok(())
}

/// Validate a txid (exactly 64 hex characters = 32 bytes).
pub fn validate_txid(s: &str) -> Result<(), &'static str> {
    if s.len() != 64 {
        return Err("txid must be exactly 64 hex characters");
    }
    validate_hex(s)
}

/// Validate a Shekyl address (basic structural checks).
pub fn validate_address(s: &str) -> Result<(), &'static str> {
    if s.is_empty() {
        return Err("empty address");
    }
    if s.len() > 256 {
        return Err("address too long");
    }
    if s.contains('\0') {
        return Err("address contains null byte");
    }

    // Reject common Unicode confusables
    for ch in s.chars() {
        if !ch.is_ascii() {
            return Err("address contains non-ASCII character (possible Unicode confusable)");
        }
    }

    // Shekyl addresses should start with known prefix
    if !s.starts_with("skl1") && !s.starts_with("sklt") && !s.starts_with("skls") {
        return Err("address does not start with a valid Shekyl prefix (skl1/sklt/skls)");
    }

    Ok(())
}

/// Reject input strings that could cause OOM in JSON serialization.
pub fn validate_input_length(s: &str, max_bytes: usize) -> Result<(), &'static str> {
    if s.len() > max_bytes {
        return Err("input too large");
    }
    if s.contains('\0') {
        return Err("input contains null byte");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // -- parse_amount fuzz tests --

    proptest! {
        #[test]
        fn fuzz_parse_amount_never_panics(s in "\\PC{0,100}") {
            let _ = crate::commands::parse_amount(&s);
        }

        #[test]
        fn fuzz_parse_amount_embedded_nulls(s in "[0-9.]*\0[0-9.]*") {
            let result = crate::commands::parse_amount(&s);
            // Should return None for embedded nulls
            assert!(result.is_none(), "null bytes should be rejected: {s:?}");
        }

        #[test]
        fn fuzz_parse_amount_negative_signs(s in "-[0-9]{1,20}(\\.[0-9]{1,12})?") {
            let result = crate::commands::parse_amount(&s);
            assert!(result.is_none(), "negative amounts should be rejected: {s:?}");
        }

        #[test]
        fn fuzz_parse_amount_scientific_notation(s in "[0-9]{1,5}[eE][+-]?[0-9]{1,3}") {
            let result = crate::commands::parse_amount(&s);
            assert!(result.is_none(), "scientific notation should be rejected: {s:?}");
        }

        #[test]
        fn fuzz_parse_amount_oversized_decimals(
            whole in 0u64..1_000_000,
            frac in "[0-9]{13,30}"
        ) {
            let s = format!("{whole}.{frac}");
            let result = crate::commands::parse_amount(&s);
            assert!(result.is_none(), ">12 decimal places should be rejected: {s:?}");
        }
    }

    // -- hex validation fuzz tests --

    proptest! {
        #[test]
        fn fuzz_validate_hex_rejects_non_hex(s in "[g-zG-Z!@#$%]{1,100}") {
            assert!(validate_hex(&s).is_err());
        }

        #[test]
        fn fuzz_validate_hex_rejects_nulls(s in "[0-9a-f]*\0[0-9a-f]*") {
            assert!(validate_hex(&s).is_err());
        }

        #[test]
        fn fuzz_validate_txid_wrong_length(s in "[0-9a-f]{1,63}|[0-9a-f]{65,128}") {
            assert!(validate_txid(&s).is_err());
        }

        #[test]
        fn fuzz_validate_txid_correct(s in "[0-9a-f]{64}") {
            assert!(validate_txid(&s).is_ok());
        }
    }

    // -- address validation fuzz tests --

    proptest! {
        #[test]
        fn fuzz_validate_address_rejects_unicode(s in "[а-яА-Я]{1,100}") {
            // Cyrillic characters
            assert!(validate_address(&s).is_err());
        }

        #[test]
        fn fuzz_validate_address_rejects_zero_width(prefix in "skl1", zw in "[\u{200B}\u{200C}\u{200D}\u{FEFF}]", rest in "[a-z0-9]{10,50}") {
            let addr = format!("{prefix}{zw}{rest}");
            assert!(validate_address(&addr).is_err());
        }

        #[test]
        fn fuzz_validate_address_rejects_wrong_prefix(s in "[a-z]{1,4}[a-z0-9]{10,100}") {
            if !s.starts_with("skl1") && !s.starts_with("sklt") && !s.starts_with("skls") {
                assert!(validate_address(&s).is_err());
            }
        }
    }

    // -- oversized input rejection --

    #[test]
    fn test_validate_input_rejects_oversized() {
        let large = "a".repeat(1_048_577);
        assert!(validate_input_length(&large, 1_048_576).is_err());

        let ok = "a".repeat(1_048_576);
        assert!(validate_input_length(&ok, 1_048_576).is_ok());

        let with_null = format!("abc\0def");
        assert!(validate_input_length(&with_null, 1_048_576).is_err());
    }

    // -- split_whitespace argument parsing --

    #[test]
    fn test_proof_arg_counts() {
        // check_tx_key requires exactly 3 positional args
        let input = "check_tx_key txid123 key456 addr789";
        let parts: Vec<&str> = input.split_whitespace().collect();
        assert_eq!(parts.len(), 4); // cmd + 3 args

        // get_tx_proof requires 2-3 args
        let input2 = "get_tx_proof txid123 addr456";
        let parts2: Vec<&str> = input2.split_whitespace().collect();
        assert_eq!(parts2.len(), 3); // cmd + 2 args

        // check_tx_proof requires 3-4 args
        let input3 = "check_tx_proof txid addr sig msg";
        let parts3: Vec<&str> = input3.split_whitespace().collect();
        assert_eq!(parts3.len(), 5); // cmd + 4 args
    }
}
