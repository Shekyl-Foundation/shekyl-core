// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A relayed bundle's form, the body server, and the asker's acceptance
//! (`SO-D12` 4b-T). The server reads a real store; the bundles are bytes,
//! since neither side judges them here: admission is the queue's.
//!
//! Every test names the edit that turns it red.

use std::path::PathBuf;

use shekyl_archival_retention::{
    BodyRefused, BundleBody, BundleKept, BundleRecord, BundleRef, PassBitmap, BUNDLE_SIGNATURE_LEN,
    BUNDLE_WITNESS_KEY_LEN,
};
use shekyl_chain_rules::SettlementEpochBlocks;
use shekyl_chain_store::store::ChainStore;
use shekyl_levin::{
    HeldBundleBody, NewBundle, PortableMap, RequestBundleBodies, ResponseBundleBodies,
};
use shekyl_types::{BlockHash, BlockHeight};

use super::*;

const EPOCH: SettlementEpochBlocks = match SettlementEpochBlocks::new(10_000) {
    Some(epoch) => epoch,
    None => panic!("a positive epoch"),
};

fn tmp(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("shekyl-sync-bundles-{name}-{}", std::process::id()));
    let _fresh = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temp dir");
    dir.join("store.redb")
}

/// A bundle for `h` with `passes` set bits. The bytes are not a valid
/// bundle; nothing here judges one.
fn bundle(h: u64, passes: u32) -> (BundleRef, BundleBody) {
    let tag = u8::try_from(h % 251).expect("below 251");
    let kept = BundleKept {
        h: BlockHeight::from_raw(h),
        seed: [tag; 32],
        passes: PassBitmap::from_passes(passes.max(1), 0..passes).expect("in range"),
        support: PassBitmap::none(),
    };
    let records: Vec<BundleRecord> = (0..passes)
        .map(|j| BundleRecord {
            attempt: 0,
            anchor_height: BlockHeight::from_raw(u64::from(j)),
            delivery_digest: [tag; 32],
            receipt: [tag; BUNDLE_SIGNATURE_LEN],
        })
        .collect();
    let body = BundleBody::new(
        &[tag; BUNDLE_WITNESS_KEY_LEN],
        &[tag; BUNDLE_SIGNATURE_LEN],
        &records,
    );
    (BundleRef::of(&kept, &body), body)
}

fn store_holding(name: &str, bundles: &[(BundleRef, BundleBody)]) -> ChainStore {
    let store = ChainStore::create(tmp(name), EPOCH).expect("create");
    for (reference, body) in bundles {
        store
            .write(|batch| {
                batch.queue_bundle(
                    reference,
                    body,
                    BlockHeight::from_raw(500),
                    BlockHash::from_bytes([0x7A; 32]),
                    16,
                )
            })
            .expect("queued");
    }
    store
}

/// A relayed bundle is its reference and the body that reference names.
/// A body one byte long, or one that does not hash to the reference, is
/// the sender's form failure. Red edit: take the body without
/// `accept_body` — the flipped body is taken.
#[test]
fn a_relayed_bundle_is_taken_only_with_the_body_its_reference_names() {
    let (reference, body) = bundle(40, 2);
    let payload = |body: Vec<u8>| {
        NewBundle {
            reference: reference.encode(),
            body,
        }
        .store()
        .expect("store")
    };
    assert_eq!(
        relayed(&payload(body.as_bytes().to_vec())),
        Ok((reference.clone(), body.clone()))
    );
    let mut long = body.as_bytes().to_vec();
    long.push(0);
    assert!(matches!(
        relayed(&payload(long)),
        Err(RelayRefused::Body(BodyRefused::Length { .. }))
    ));
    let mut flipped = body.as_bytes().to_vec();
    flipped[0] ^= 1;
    assert_eq!(
        relayed(&payload(flipped)),
        Err(RelayRefused::Body(BodyRefused::Hash))
    );
    assert!(matches!(
        relayed(&[0xFF; 8]),
        Err(RelayRefused::Undecodable(_))
    ));
    // What leaves for a peer is what arrived.
    let Message::NewBundle(out) = relay_message(&reference, &body) else {
        panic!("a 2015");
    };
    assert_eq!(relayed(&out.store().expect("store")), Ok((reference, body)));
}

/// A body request against held bodies returns them, in the order asked,
/// each once, and leaves out a hash the store holds no body for. Red edit:
/// read the body by `h` — no hash request is then answered.
#[test]
fn a_body_request_is_answered_from_the_body_store() {
    let a = bundle(40, 1);
    let b = bundle(41, 3);
    let store = store_holding("serve", &[a.clone(), b.clone()]);
    let response = serve_bundle_bodies(
        &store,
        &RequestBundleBodies {
            hashes: vec![
                *b.0.prunable_hash(),
                [0xEE; 32],
                *a.0.prunable_hash(),
                *b.0.prunable_hash(),
            ],
        },
    )
    .expect("served");
    assert_eq!(
        response,
        ResponseBundleBodies {
            bodies: vec![
                HeldBundleBody {
                    hash: *b.0.prunable_hash(),
                    body: b.1.as_bytes().to_vec(),
                },
                HeldBundleBody {
                    hash: *a.0.prunable_hash(),
                    body: a.1.as_bytes().to_vec(),
                },
            ],
        }
    );
    // The asker accepts that answer against what it asked.
    let accepted = accept_bundle_bodies(&[a.0.clone(), b.0.clone()], &response).expect("accepted");
    assert_eq!(accepted, vec![(1, b.1), (0, a.1)]);
}

/// A response's body is refused at the wrong length and at the wrong hash,
/// and so is one for a hash not asked or one answered twice; any of them
/// refuses the whole response. Red edits: compare lengths with `<=`, skip
/// the hash, or drop the repeat check — the matching case below is taken.
#[test]
fn a_wrong_length_or_wrong_hash_body_response_is_refused() {
    let (reference, body) = bundle(40, 2);
    let hash = *reference.prunable_hash();
    let answer = |bytes: Vec<u8>| ResponseBundleBodies {
        bodies: vec![HeldBundleBody { hash, body: bytes }],
    };
    let asked = std::slice::from_ref(&reference);

    let short = body.as_bytes()[..body.as_bytes().len() - 1].to_vec();
    assert!(matches!(
        accept_bundle_bodies(asked, &answer(short)),
        Err(BodiesRefused::Body {
            refused: BodyRefused::Length { .. },
            ..
        })
    ));
    // A body of another bundle with fewer passes is a whole body, of a
    // length this reference does not fix.
    assert!(matches!(
        accept_bundle_bodies(asked, &answer(bundle(40, 1).1.as_bytes().to_vec())),
        Err(BodiesRefused::Body {
            refused: BodyRefused::Length { .. },
            ..
        })
    ));
    let mut flipped = body.as_bytes().to_vec();
    flipped[100] ^= 1;
    assert_eq!(
        accept_bundle_bodies(asked, &answer(flipped)),
        Err(BodiesRefused::Body {
            hash,
            refused: BodyRefused::Hash
        })
    );
    let unasked = ResponseBundleBodies {
        bodies: vec![HeldBundleBody {
            hash: [0xEE; 32],
            body: body.as_bytes().to_vec(),
        }],
    };
    assert_eq!(
        accept_bundle_bodies(asked, &unasked),
        Err(BodiesRefused::Unasked { hash: [0xEE; 32] })
    );
    let twice = ResponseBundleBodies {
        bodies: vec![
            HeldBundleBody {
                hash,
                body: body.as_bytes().to_vec(),
            },
            HeldBundleBody {
                hash,
                body: body.as_bytes().to_vec(),
            },
        ],
    };
    assert_eq!(
        accept_bundle_bodies(asked, &twice),
        Err(BodiesRefused::Repeated { hash })
    );
    assert_eq!(
        accept_bundle_bodies(asked, &answer(body.as_bytes().to_vec())),
        Ok(vec![(0, body)])
    );
}

/// After the first held body the response stays within the block body
/// budget, and the first is sent whatever its size. Red edit: apply the
/// budget to the first body — a lone large body is never served.
#[test]
fn a_body_response_stays_within_the_budget_after_its_first_body() {
    let per = usize::try_from(BODIES_RESPONSE_BYTES).expect("fits");
    // Enough passes that two bodies pass the budget.
    let passes = u32::try_from(per / 1_397 / 2 + 1).expect("fits");
    let a = bundle(40, passes);
    let b = bundle(41, passes);
    let c = bundle(42, passes);
    let store = store_holding("budget", &[a.clone(), b.clone(), c.clone()]);
    let response = serve_bundle_bodies(
        &store,
        &RequestBundleBodies {
            hashes: vec![
                *a.0.prunable_hash(),
                *b.0.prunable_hash(),
                *c.0.prunable_hash(),
            ],
        },
    )
    .expect("served");
    assert_eq!(response.bodies.len(), 1, "the second would pass the budget");
    assert_eq!(response.bodies[0].hash, *a.0.prunable_hash());
}
