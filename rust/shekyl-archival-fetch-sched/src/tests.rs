// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The urn and the span arithmetic, without a wire. The scheduler's moves
//! against a real endpoint are `tests/loopback.rs`.

use std::collections::BTreeSet;

use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_p_fetch::{FetchTarget, ServingEndpoint};
use shekyl_types::{BlockHeight, PCanonicalId};

use crate::draw::Urn;
use crate::facts::{BlockSpan, Holder};

/// A holder the urn can tell apart. Nothing here is dialled, so the key
/// is a placeholder shape, not a key.
fn holder(tag: u8) -> Holder {
    Holder {
        id: PCanonicalId::from_bytes([tag; 32]),
        target: FetchTarget {
            endpoint: ServingEndpoint::from_record_bytes([tag; 32]),
            verifying_key: HybridPublicKey {
                ed25519: [tag; 32],
                ml_dsa: Vec::new(),
            },
        },
    }
}

fn holders(n: u8) -> Vec<Holder> {
    (1..=n).map(holder).collect()
}

#[test]
fn the_urn_draws_every_holder_once() {
    let mut urn = Urn::new(holders(5));
    let mut seen = BTreeSet::new();
    while let Some(h) = urn.draw().unwrap() {
        assert!(seen.insert(h.id.to_bytes()[0]), "drawn twice");
    }
    assert_eq!(seen.len(), 5);
    assert_eq!(urn.len(), 0);
    assert!(urn.draw().unwrap().is_none());
}

#[test]
fn the_urn_is_uniform_across_needs() {
    // Memoryless: each need builds its own urn, and the first draw of 400
    // needs over 5 holders lands on every holder. Expected 80 each; a
    // holder under 30 is a 2^-20-class event, not a flaky test.
    let mut counts = [0u32; 5];
    for _ in 0..400 {
        let mut urn = Urn::new(holders(5));
        let first = urn.draw().unwrap().unwrap();
        counts[usize::from(first.id.to_bytes()[0] - 1)] += 1;
    }
    for (i, c) in counts.iter().enumerate() {
        assert!(*c >= 30, "holder {} drawn {c} times of 400", i + 1);
    }
}

#[test]
fn exclusion_removes_only_the_named_holder() {
    let mut urn = Urn::new(holders(3));
    urn.exclude(PCanonicalId::from_bytes([2; 32]));
    assert_eq!(urn.len(), 2);
    let mut rest = BTreeSet::new();
    while let Some(h) = urn.draw().unwrap() {
        rest.insert(h.id.to_bytes()[0]);
    }
    assert_eq!(rest, BTreeSet::from([1, 3]));
}

#[test]
fn span_arithmetic_is_inclusive_and_saturating() {
    let span = BlockSpan {
        first: BlockHeight::from_raw(100),
        last: BlockHeight::from_raw(100),
        first_timestamp: 1_000,
        last_timestamp: 900,
        coinbase_outputs: 1,
        tx_outputs: 7,
    };
    assert_eq!(span.block_count().to_raw(), 1);
    assert_eq!(span.time_range_seconds(), 0);
    let wide = BlockSpan {
        last: BlockHeight::from_raw(149),
        last_timestamp: 1_120,
        ..span
    };
    assert_eq!(wide.block_count().to_raw(), 50);
    assert_eq!(wide.time_range_seconds(), 120);
}
