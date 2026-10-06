// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Archival bodies the mutation family lists in duplicate.
//!
//! Each one is the rules harness's balanced shape with the vin the census
//! row collides on. They live beside [`crate::mutation`] rather than inside
//! it: the mutation enum is one exhaustive match, and these builders are
//! the fixtures that match feeds. Every `p` is a fixture-persona **tag**
//! (`fixture::persona`): the body carries the persona's derived keys and
//! the id those recompute to (CEN-J11), so a credit for `p` names the
//! record a join for `p` opened.

use shekyl_archival_retention::ArchivalServeCreditResponse;
use shekyl_chain_rules::harness::fixture;
use shekyl_wire::{Input, Transaction};

/// A **serve-credit-only** body (CEN-H20's shape, the harness's
/// `serve_credit_only`) whose one vin **parses** as the kept half of a pass
/// record for `(p, shard, epoch)` — the key CEN-G7 collides on. No
/// `pqc_auths`, no signature slot: the mutation family can twin it by
/// moving its `unlock_time` and the twin is still a valid body under every
/// landed row (the countersignature is CEN-J10's, pending).
pub fn serve_credit_body(p: [u8; 32], shard: u64, epoch: u64) -> Transaction {
    let kept = ArchivalServeCreditResponse {
        p_canonical_id: *fixture::persona(p).id.as_bytes(),
        shard_id: shard,
        settlement_epoch: epoch,
        ed25519_countersignature: [0x5c; 64],
    };
    let mut tx = fixture::serve_credit_only([0; 32]);
    tx.prefix.inputs = vec![Input::ServeCredit {
        canonical_bytes: kept.serialize().expect("a kept half serializes"),
    }];
    tx
}

/// A spend of `key_image` that posts `p`'s **JoinMarket** — the harness's
/// `join_market`, the body that opens the record a [`serve_credit_body`]
/// for `p` is judged against (CEN-J4 reads it off the view before the
/// credit's block, so the join lists in a block below the credit's).
/// Unanchored and unsigned like every body `chain_listing_with` places.
///
/// Two calls with two key images and one `p` are the pair CEN-G10 refuses:
/// each join alone passes the post rows over a view with no record for `p`
/// (CEN-J14 reads the record's absence, J13 the identity key), and G10
/// counts the second after the slot loop. Until slice 8 row 5 the family
/// twinned a **Release** here instead; with J16 landed a Release over no
/// record refuses on `RecordMissing` in the slot loop, before G10 — the
/// C++'s order too (`check_tx_inputs` runs per body ahead of the block's
/// duplicate-post pass), so the Release pair never reached G10 there.
pub fn join_body(key_image: [u8; 32], p: [u8; 32]) -> Transaction {
    fixture::join_market(key_image, p)
}
