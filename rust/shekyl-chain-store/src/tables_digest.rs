// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **tables digest**: one 32-byte commitment to every table a store
//! holds, row for row (`CHAIN_FORGE.md` §8).
//!
//! `logical_state_digest_v0` ([`crate::digest_v0`]) commits to the chain,
//! the spent key images and the curve root, and leaves the archival, output
//! and alternative-chain tables out by design. A forged chain's snapshot is
//! read by tests of exactly those tables, so the trace carries this digest
//! at each indexed event instead, and a snapshot opened at an event is
//! held to it: a stale or edited row is refused, whatever else agrees.
//!
//! The input is [`ReadSnapshot::table_rows`](crate::store::ReadSnapshot::table_rows):
//! every catalogued table present in the file, by name, each table's rows
//! as stored bytes in key order. The preimage is unambiguous: every name,
//! key and value is length-prefixed and every table carries its row count,
//! so two different sets of rows cannot encode to the same bytes.
//!
//! ```text
//! preimage = for each table, in name order:
//!              name_len u64 ‖ name ‖ rows u64 ‖ (key_len u64 ‖ key ‖ value_len u64 ‖ value)*
//! digest   = cSHAKE256-32(TABLES_DIGEST_CUSTOMIZATION, preimage)
//! ```
//!
//! Not a consensus value: no rule reads it. It is a comparison a replay
//! and a snapshot's reader make against a trace, under its own version in
//! the customization string, so a change to the encoding is a new string
//! and every trace that carries the old one is re-baselined.

use std::collections::BTreeMap;

use shekyl_crypto_hash::cshake256_32;

use crate::store::RawRows;

/// The digest's domain (`docs/design/CRYPTO_DOMAIN_REGISTRY.tsv`).
pub const TABLES_DIGEST_CUSTOMIZATION: &[u8] = b"shekyl/chain-store/tables-digest/v1";

/// The tables digest of `tables` (module docs).
#[must_use]
pub fn tables_digest_v1(tables: &BTreeMap<&'static str, RawRows>) -> [u8; 32] {
    let mut preimage = Vec::new();
    for (name, rows) in tables {
        push_bytes(&mut preimage, name.as_bytes());
        preimage.extend_from_slice(&width(rows.len()).to_le_bytes());
        for (key, value) in rows {
            push_bytes(&mut preimage, key);
            push_bytes(&mut preimage, value);
        }
    }
    cshake256_32(TABLES_DIGEST_CUSTOMIZATION, &preimage)
}

/// `bytes`, length-prefixed.
fn push_bytes(preimage: &mut Vec<u8>, bytes: &[u8]) {
    preimage.extend_from_slice(&width(bytes.len()).to_le_bytes());
    preimage.extend_from_slice(bytes);
}

/// A length as the preimage writes it. Every length a process holds fits
/// `u64` on the targets the workspace builds.
fn width(len: usize) -> u64 {
    u64::try_from(len).expect("a length fits u64")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table by name, its rows as (key, value) pairs.
    type Table<'a> = (&'static str, &'a [(&'a [u8], &'a [u8])]);

    fn tables(rows: &[Table<'_>]) -> BTreeMap<&'static str, RawRows> {
        rows.iter()
            .map(|(name, rows)| {
                (
                    *name,
                    rows.iter()
                        .map(|(key, value)| (key.to_vec(), value.to_vec()))
                        .collect(),
                )
            })
            .collect()
    }

    #[test]
    fn the_digest_is_its_known_answer() {
        // Pinned: a change to the encoding or the domain moves it, and is a
        // new domain version (module docs). Computed outside this code, by
        // `scripts/kat/stdlib_cshake.py`'s `cshake256(preimage, 32, b"",
        // TABLES_DIGEST_CUSTOMIZATION)` over the preimage the module docs
        // define for these two tables (the sponge shares nothing with the
        // Rust).
        let digest = tables_digest_v1(&tables(&[
            ("alpha", &[(b"k1", b"v1"), (b"k2", b"")]),
            ("beta", &[]),
        ]));
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex, "a7db5e272829f1024830496931711e6450b7110040b7195e7159108682c510fc",
            "the tables digest's known answer"
        );
    }

    #[test]
    fn every_byte_of_every_table_moves_the_digest() {
        let base = tables(&[("alpha", &[(b"k1", b"v1")]), ("beta", &[(b"k", b"v")])]);
        let digest = tables_digest_v1(&base);
        let moved = [
            tables(&[("alpha", &[(b"k1", b"v2")]), ("beta", &[(b"k", b"v")])]),
            tables(&[("alpha", &[(b"k2", b"v1")]), ("beta", &[(b"k", b"v")])]),
            tables(&[("alphb", &[(b"k1", b"v1")]), ("beta", &[(b"k", b"v")])]),
            tables(&[("alpha", &[(b"k1", b"v1")])]),
            tables(&[("alpha", &[(b"k1", b"v1")]), ("beta", &[])]),
            // The boundary between a key and its value is in the preimage.
            tables(&[("alpha", &[(b"k1v", b"1")]), ("beta", &[(b"k", b"v")])]),
        ];
        for other in &moved {
            assert_ne!(tables_digest_v1(other), digest, "{other:?}");
        }
        assert_eq!(tables_digest_v1(&base), digest, "deterministic");
    }

    #[test]
    fn the_domain_is_its_own() {
        // Its own customization, not the store's other digest's.
        assert_ne!(
            TABLES_DIGEST_CUSTOMIZATION,
            crate::digest_v0::OUTER_CUSTOMIZATION
        );
    }
}
