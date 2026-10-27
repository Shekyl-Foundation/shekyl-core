// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The receipt key's shared test fixtures: one transcript, one pair of
//! slots, and the helpers every receipt-key test reaches for.
//!
//! The slot's tests (`held_receipt_key_tests.rs`), the capability's tests
//! (`serving/receipt_key.rs`) and the round trip through the real endpoint
//! (`serving/receipt_round_trip_tests.rs`) each defined these for
//! themselves. One definition here, so that a transcript or a slot named in
//! one of them is the one named in the others.

use std::sync::Arc;

use shekyl_archival_retention::{pass_countersignature_message, PASS_COUNTERSIGNATURE_MESSAGE_LEN};
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridPublicKey, FnDsaHybridSignature};
use shekyl_p_host::{PassKey, SignRefused};
use shekyl_types::BlockHeight;

use crate::engine::stake_engine::handle::StakeEngineHandle;
use crate::engine::stake_engine::persona::ReceiptKeyIsBuilt;
use crate::engine::stake_engine::serving::receipt_key::ResidentReceiptKey;
use crate::engine::stake_engine::test_fixtures::derive_bundle;
use crate::engine::stake_engine::types::PSlot;

/// The persona most tests sign as, and a second one beside it.
pub(crate) const SLOT: u32 = 3;
pub(crate) const OTHER_SLOT: u32 = 4;

/// The transcript's fields: one shard, one anchor, one request.
pub(crate) const SHARD: u64 = 7;
pub(crate) const ANCHOR: BlockHeight = BlockHeight::from_raw(1_000);
pub(crate) const NONCE: [u8; 32] = [0x11; 32];
pub(crate) const ANCHOR_HASH: [u8; 32] = [0x22; 32];
pub(crate) const DIGEST: [u8; 32] = [0x5a; 32];

/// A real transcript, from the consensus builder both ends agree on.
pub(crate) fn message() -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
    pass_countersignature_message(
        shekyl_archival_retention::PassStream::Economy,
        &NONCE,
        ANCHOR,
        &ANCHOR_HASH,
        SHARD,
        &DIGEST,
    )
}

/// The persona's public receipt key, from the derivation oracle the
/// actor's bundles came from. The actor is not asked: it has no message
/// that gives the key out, and none is added for a test.
pub(crate) fn receipt_pk(slot: u32) -> FnDsaHybridPublicKey {
    derive_bundle(slot).receipt_sign_pk.clone()
}

pub(crate) fn slot(raw: u32) -> PSlot {
    PSlot::from_raw(raw)
}

/// One receipt from the capability, on the blocking pool where the serve
/// loop asks for it: it parks on the actor's reply.
pub(crate) async fn sign(
    key: Arc<ResidentReceiptKey>,
    message: [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
) -> Result<FnDsaHybridSignature, SignRefused> {
    tokio::task::spawn_blocking(move || key.sign_pass(&message))
        .await
        .expect("blocking task")
}

/// Whether the actor's slot for `raw` holds a decoded key (`None` for an
/// unheld slot).
pub(crate) async fn is_built(stake: &StakeEngineHandle, raw: u32) -> Option<bool> {
    stake
        .actor
        .ask(ReceiptKeyIsBuilt { p_slot: slot(raw) })
        .await
        .expect("actor alive")
}

/// A bundle whose receipt secret does not decode. The corruption is the
/// scheme crate's test seam; this crate's tests reach it through the
/// `test-signer` edge the loopback tests already use.
pub(crate) fn bundle_with_a_corrupted_receipt_key(raw: u32) -> ArchivalPKeys {
    let mut bundle = derive_bundle(raw);
    bundle.receipt_sign_sk.corrupt_fn_dsa_half_for_tests();
    bundle
}
