// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The contract's transfer-id grammar.
//!
//! Incoming ids are `{tx_hash}:{output_index}`. Outgoing ids are a bare
//! tx hash. The two grammars are disjoint, so a well-formed id names
//! exactly one side of history. A string this wallet never emits is
//! [`None`]: the caller reports invalid params, not "unknown transfer".
//! Saying a send does not exist because its id was pasted in uppercase
//! is a wrong answer about a row that does exist.

use shekyl_types::TxHash;

use crate::canonical_hex::parse_lowercase_hex32;

const ID_SEPARATOR: char = ':';
const INDEX_ZERO: &str = "0";

/// Stable sentence for a `get_transfer_by_id` id this wallet never emits.
pub const LOOKUP_ID_GRAMMAR: &str = "id must be `{tx_hash}:{output_index}` for a receive, or a bare 64 lowercase-hex `{tx_hash}` for a send";

/// Which side of history a `get_transfer_by_id` id names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferLookupId {
    /// `{tx_hash}:{output_index}` — one received output.
    Incoming {
        /// Transaction the output belongs to.
        tx_hash: TxHash,
        /// Index of the output within that transaction.
        output_index: u64,
    },
    /// A bare tx hash — one send-journal row.
    Outgoing {
        /// Transaction the send is keyed by.
        tx_hash: TxHash,
    },
}

/// Parse an incoming transfer id.
///
/// Accepts exactly what a history row's id emitter writes:
/// [`HEX32_CHARS`](crate::canonical_hex::HEX32_CHARS) lowercase hex, a
/// colon, and a canonical decimal index (no sign, no leading zero).
#[must_use]
pub fn parse_transfer_id(id: &str) -> Option<(TxHash, u64)> {
    let (hash_hex, index_text) = id.split_once(ID_SEPARATOR)?;
    let bytes = parse_lowercase_hex32(hash_hex)?;
    if !canonical_index(index_text) {
        return None;
    }
    let output_index = index_text.parse().ok()?;
    Some((TxHash::from_bytes(bytes), output_index))
}

/// Parse a `get_transfer_by_id` id into the one side it names.
#[must_use]
pub fn parse_lookup_id(id: &str) -> Option<TransferLookupId> {
    if let Some((tx_hash, output_index)) = parse_transfer_id(id) {
        return Some(TransferLookupId::Incoming {
            tx_hash,
            output_index,
        });
    }
    parse_lowercase_hex32(id).map(|bytes| TransferLookupId::Outgoing {
        tx_hash: TxHash::from_bytes(bytes),
    })
}

fn canonical_index(index_text: &str) -> bool {
    !index_text.is_empty()
        && index_text.bytes().all(|byte| byte.is_ascii_digit())
        && !(index_text.len() > INDEX_ZERO.len() && index_text.starts_with('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::canonical_hex::HEX32_CHARS;

    fn hash_hex() -> String {
        "0a".repeat(HEX32_CHARS / 2)
    }

    #[test]
    fn canonical_incoming_id_parses() {
        let (hash, index) = parse_transfer_id(&format!("{}:7", hash_hex())).expect("canonical");
        assert_eq!(hash, TxHash::from_bytes([0x0a; 32]));
        assert_eq!(index, 7);
        let (_, zero) = parse_transfer_id(&format!("{}:0", hash_hex())).expect("index 0");
        assert_eq!(zero, 0);
    }

    #[test]
    fn non_canonical_incoming_ids_are_rejected() {
        let hash_hex = hash_hex();
        for bad in [
            String::new(),
            "no-colon".to_owned(),
            format!("{hash_hex}:"),
            format!("{hash_hex}:+7"),
            format!("{hash_hex}:07"),
            format!("{hash_hex}:1x"),
            format!("{}:1", "0A".repeat(HEX32_CHARS / 2)),
            format!("{}:1", "0a".repeat(HEX32_CHARS / 2 - 1)),
            format!("{}:1", "0a".repeat(HEX32_CHARS / 2 + 1)),
            format!("{hash_hex}:99999999999999999999"),
        ] {
            assert!(parse_transfer_id(&bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn lookup_routes_each_grammar_to_its_own_side() {
        let hash_hex = hash_hex();
        assert_eq!(
            parse_lookup_id(&format!("{hash_hex}:7")),
            Some(TransferLookupId::Incoming {
                tx_hash: TxHash::from_bytes([0x0a; 32]),
                output_index: 7,
            })
        );
        assert_eq!(
            parse_lookup_id(&hash_hex),
            Some(TransferLookupId::Outgoing {
                tx_hash: TxHash::from_bytes([0x0a; 32]),
            })
        );
    }

    #[test]
    fn lookup_rejects_ids_this_wallet_never_emits() {
        let hash_hex = hash_hex();
        for bad in [
            String::new(),
            "no-colon-not-hex".to_owned(),
            "0A".repeat(HEX32_CHARS / 2),
            "0a".repeat(HEX32_CHARS / 2 - 1),
            "0a".repeat(HEX32_CHARS / 2 + 1),
            format!("{hash_hex}:07"),
            format!("{hash_hex}:"),
        ] {
            assert!(parse_lookup_id(&bad).is_none(), "accepted {bad:?}");
        }
    }
}
