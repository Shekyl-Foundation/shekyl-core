// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain-sync commands 2011–2014 (CS-Q3).
//!
//! Pins the encoded bytes, the cap checked before the codec runs, and the
//! body-response partition. The ids are not [`DefinedCommand`] arms.

use shekyl_levin::{
    body_budget_bytes, plan_bodies, BodiesFormFault, DefinedCommand, PayloadError, PortableMap,
    RequestBodies, RequestHeaders, ResponseBodies, ResponseHeaders, BODIES_RESPONSE_BYTES,
    CAP_REQUEST_BODIES, CAP_REQUEST_HEADERS, CAP_RESPONSE_BODIES, CAP_RESPONSE_HEADERS, HASH_SIZE,
    HEADERS_RESPONSE_BYTES, MIN_TX_SECTION_BYTES, NOTIFY_REQUEST_BODIES, NOTIFY_REQUEST_HEADERS,
    NOTIFY_RESPONSE_BODIES, NOTIFY_RESPONSE_HEADERS, RESPONSE_BODIES_MAX_OBJECTS,
    RESPONSE_BODIES_MAX_STRINGS, RESPONSE_HEADERS_MAX_STRINGS,
};
use shekyl_portable_storage::{store_to_binary, Array, Section, Value};
use shekyl_types::{ArchivalLength, PqcAuthHash, PrunableHash};
use shekyl_wire::transaction::{CT_TYPE_NULL, TAG_INPUT_GEN, TAG_OUTPUT_TAGGED_KEY};
use shekyl_wire::{Block, BlockBody, SkeletonTx, TxBody};

fn pin<T: PortableMap + PartialEq + std::fmt::Debug>(value: &T, expected_hex: &str) {
    let bytes = value.store().expect("store");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, expected_hex);
    assert_eq!(&T::load(&bytes).expect("load"), value);
}

fn over_cap(cap: u64, decode: impl Fn(&[u8]) -> Result<(), PayloadError>) {
    let cap = usize::try_from(cap).expect("cap fits");
    let bytes = vec![0u8; cap + 1];
    match decode(&bytes) {
        Err(PayloadError::OverCap { got, max }) => {
            assert_eq!(got, cap + 1);
            assert_eq!(max, cap);
        }
        other => panic!("one byte over the cap must be OverCap, got {other:?}"),
    }
}

/// A one-nonce coinbase block and its identity. The nonce is the only
/// difference, so each block is a distinct requested hash.
fn coined(nonce: u32) -> (Vec<u8>, [u8; HASH_SIZE]) {
    let mut bytes = Vec::new();
    bytes.push(0x01);
    bytes.push(0x00);
    bytes.push(0x00);
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.push(0x03);
    bytes.push(0x00);
    bytes.push(0x01);
    bytes.push(TAG_INPUT_GEN);
    bytes.push(0x00);
    bytes.push(0x01);
    bytes.push(0x00);
    bytes.push(TAG_OUTPUT_TAGGED_KEY);
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.push(0x00);
    bytes.push(0x00);
    bytes.push(CT_TYPE_NULL);
    bytes.extend_from_slice(&[0u8; 9]);
    bytes.extend_from_slice(&[0u8; 9]);
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.push(0x00);
    let block = Block::from_bytes(&bytes).expect("synthetic coinbase");
    let id = block.hash().to_bytes();
    (bytes, id)
}

fn carried(block: Vec<u8>) -> BlockBody {
    BlockBody {
        block,
        txs: Vec::new(),
        attestation_witness: Vec::new(),
    }
}

/// The new ids are named and are not dispatched. Ingress admits a command
/// for a handler, and none exists until the cutover.
#[test]
fn sync_commands_are_not_admitted_at_ingress() {
    assert_eq!(NOTIFY_REQUEST_HEADERS, 2011);
    assert_eq!(NOTIFY_RESPONSE_HEADERS, 2012);
    assert_eq!(NOTIFY_REQUEST_BODIES, 2013);
    assert_eq!(NOTIFY_RESPONSE_BODIES, 2014);
    for id in 2011..=2014 {
        assert_eq!(DefinedCommand::from_wire(id), None);
    }
}

/// A header request is the locator and nothing else, and its bytes are fixed.
#[test]
fn request_headers_bytes_are_pinned() {
    let msg = RequestHeaders {
        block_ids: vec![[0x11; HASH_SIZE]],
    };
    pin(
        &msg,
        "0111010101010201010409626c6f636b5f6964730a801111111111111111111111111111111111111111111111111111111111111111",
    );
    assert_eq!(
        RequestHeaders::decode(&msg.store().expect("store")).expect("decode"),
        msg
    );
}

/// A header response carries preimages, both halves of the claimed work,
/// and `more` even when it is false.
#[test]
fn response_headers_bytes_are_pinned() {
    let msg = ResponseHeaders {
        blobs: vec![vec![0xab; shekyl_wire::MIN_POW_BLOB_SIZE]],
        tip_work: (u128::from(0x9u64) << 64) | 0x4,
        more: false,
    };
    let bytes = msg.store().expect("store");
    let section_has_more = bytes.windows(4).any(|w| w == b"more");
    assert!(section_has_more, "more is stored even when false");
    pin(
        &msg,
        "0111010101010201011005626c6f62738a042102abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab046d6f72650b00087469705f776f726b0504000000000000000e7469705f776f726b5f746f703634050900000000000000",
    );
}

/// A body request is a hash list, pinned.
#[test]
fn request_bodies_bytes_are_pinned() {
    let msg = RequestBodies {
        hashes: vec![[0x22; HASH_SIZE]],
    };
    pin(
        &msg,
        "01110101010102010104066861736865730a802222222222222222222222222222222222222222222222222222222222222222",
    );
    assert_eq!(
        RequestBodies::decode(&msg.store().expect("store")).expect("decode"),
        msg
    );
}

/// A body response round-trips a full transaction and a skeleton, and the
/// bytes are fixed. `Debug` does not print a blob.
#[test]
fn response_bodies_bytes_are_pinned_and_debug_redacts_blobs() {
    let (block, _) = coined(1);
    let msg = ResponseBodies {
        bodies: vec![BlockBody {
            block,
            txs: vec![
                TxBody::Full(vec![0x0a, 0x0b]),
                TxBody::Skeleton(SkeletonTx {
                    unprunable: vec![0x0c],
                    prunable_hash: PrunableHash::from_bytes([0x33; 32]),
                    pqc_auth_hash: Some(PqcAuthHash::from_bytes([0x44; 32])),
                    archival_len: ArchivalLength::from_raw(7),
                }),
            ],
            attestation_witness: vec![0x0d],
        }],
        deferred: vec![[0x55; HASH_SIZE]],
        missed_ids: vec![[0x66; HASH_SIZE]],
    };
    let rendered = format!("{msg:?}");
    assert!(
        !rendered.contains("0a0b") && !rendered.contains("[10, 11]"),
        "{rendered}"
    );
    assert!(rendered.contains("Full"), "{rendered}");
    pin(&msg, "0111010101010201010c06626f646965738c040c136174746573746174696f6e5f7769746e6573730a040d05626c6f636b0a15030100000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000100000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000037478738c080804626c6f620a080a0b04666f726d0801140c617263686976616c5f6c656e05070000000000000004666f726d08020d7071635f617574685f686173680a8044444444444444444444444444444444444444444444444444444444444444440d7072756e61626c655f686173680a8033333333333333333333333333333333333333333333333333333333333333330a756e7072756e61626c650a040c0864656665727265640a8055555555555555555555555555555555555555555555555555555555555555550a6d69737365645f6964730a806666666666666666666666666666666666666666666666666666666666666666");
}

/// Each decoder refuses one byte over its encoded cap before the codec
/// would report a schema error.
#[test]
fn decoders_refuse_one_byte_over_the_cap() {
    over_cap(CAP_REQUEST_HEADERS, |bytes| {
        RequestHeaders::decode(bytes).map(|_| ())
    });
    over_cap(CAP_RESPONSE_HEADERS, |bytes| {
        ResponseHeaders::decode(bytes).map(|_| ())
    });
    over_cap(CAP_REQUEST_BODIES, |bytes| {
        RequestBodies::decode(bytes).map(|_| ())
    });
    over_cap(CAP_RESPONSE_BODIES, |bytes| {
        ResponseBodies::decode(bytes).map(|_| ())
    });
}

/// A header response whose preimages exceed the byte budget is refused,
/// including when the encoded payload is still under the packet cap.
#[test]
fn header_response_refuses_a_preimage_total_over_the_budget() {
    let mut section = Section::new();
    let blob = vec![0u8; usize::try_from(HEADERS_RESPONSE_BYTES).expect("budget") + 1];
    section.insert("blobs", Value::Array(Array::Bytes(vec![blob])));
    section.insert("tip_work", Value::UInt64(0));
    section.insert("tip_work_top64", Value::UInt64(0));
    section.insert("more", Value::Bool(false));
    let bytes = store_to_binary(&section).expect("encode");
    assert!(u64::try_from(bytes.len()).expect("len") <= CAP_RESPONSE_HEADERS);
    match ResponseHeaders::decode(&bytes) {
        Err(PayloadError::OverBudget { field, .. }) => assert_eq!(field, "blobs"),
        other => panic!("expected OverBudget, got {other:?}"),
    }
}

/// Preimages of 140 bytes fill the byte budget and still round-trip.
/// 140 is a PoW preimage or longer and still a two-byte length varint,
/// which is the case the allowance is sized for.
#[test]
fn a_budget_of_short_preimages_round_trips() {
    let each = 140;
    let count = usize::try_from(HEADERS_RESPONSE_BYTES).expect("budget") / each;
    let msg = ResponseHeaders {
        blobs: vec![vec![0u8; each]; count],
        tip_work: 1,
        more: false,
    };
    let bytes = msg
        .store()
        .expect("the allowance covers a 140-byte preimage");
    assert_eq!(ResponseHeaders::decode(&bytes).expect("decode"), msg);
}

/// A preimage shorter than a PoW preimage is refused at `store` and at
/// `decode`. The length-prefix allowance assumes every preimage is in the
/// two-byte band, and a shorter blob is not a header.
#[test]
fn a_preimage_shorter_than_a_block_is_refused_at_store_and_decode() {
    let msg = ResponseHeaders {
        blobs: vec![vec![0xab, 0xcd]],
        tip_work: 0,
        more: false,
    };
    match msg.store() {
        Err(PayloadError::PreimageTooShort { got, min }) => {
            assert_eq!(got, 2);
            assert_eq!(min, shekyl_wire::MIN_POW_BLOB_SIZE);
        }
        other => panic!("expected PreimageTooShort, got {other:?}"),
    }

    let mut section = Section::new();
    section.insert("blobs", Value::Array(Array::Bytes(vec![vec![0u8; 1]])));
    section.insert("tip_work", Value::UInt64(0));
    section.insert("tip_work_top64", Value::UInt64(0));
    section.insert("more", Value::Bool(false));
    let bytes = store_to_binary(&section).expect("encode");
    match ResponseHeaders::decode(&bytes) {
        Err(PayloadError::PreimageTooShort { got, min }) => {
            assert_eq!(got, 1);
            assert_eq!(min, shekyl_wire::MIN_POW_BLOB_SIZE);
        }
        other => panic!("expected PreimageTooShort, got {other:?}"),
    }
}

/// A response of small skeletons fits the byte budget and exceeds the
/// inherited Levin field and object ceilings. The cap is the ceiling, so
/// the response decodes.
#[test]
fn many_small_skeletons_round_trip() {
    let tx = TxBody::Skeleton(SkeletonTx {
        unprunable: vec![1],
        prunable_hash: PrunableHash::from_bytes([3u8; 32]),
        pqc_auth_hash: None,
        archival_len: ArchivalLength::from_raw(0),
    });
    let body = BlockBody {
        block: vec![0x11],
        txs: vec![tx; 90],
        attestation_witness: Vec::new(),
    };
    let msg = ResponseBodies {
        bodies: vec![body; 100],
        deferred: Vec::new(),
        missed_ids: Vec::new(),
    };
    let bytes = msg.store().expect("store");
    assert!(bytes.len() < usize::try_from(BODIES_RESPONSE_BYTES).expect("budget"));
    assert_eq!(ResponseBodies::decode(&bytes).expect("decode"), msg);
}

/// One hundred and one hashes fit under the encoded over-bound and are
/// still refused: the count is the request's cap.
#[test]
fn body_request_refuses_a_count_over_the_object_cap() {
    let msg = RequestBodies {
        hashes: vec![[0u8; HASH_SIZE]; 101],
    };
    match msg.store() {
        Err(PayloadError::OverCount { field, got, max }) => {
            assert_eq!(field, "hashes");
            assert_eq!(got, 101);
            assert_eq!(max, 100);
        }
        other => panic!("expected OverCount, got {other:?}"),
    }
}

fn response(ids: &[([u8; HASH_SIZE], Slot)]) -> (Vec<[u8; HASH_SIZE]>, ResponseBodies) {
    let mut requested = Vec::new();
    let mut bodies = Vec::new();
    let mut deferred = Vec::new();
    let mut missed_ids = Vec::new();
    for (id, slot) in ids {
        requested.push(*id);
        match slot {
            Slot::Sent => bodies.push(carried(id_block(id))),
            Slot::Deferred => deferred.push(*id),
            Slot::Missed => missed_ids.push(*id),
        }
    }
    (
        requested,
        ResponseBodies {
            bodies,
            deferred,
            missed_ids,
        },
    )
}

#[derive(Clone, Copy)]
enum Slot {
    Sent,
    Deferred,
    Missed,
}

fn id_block(id: &[u8; HASH_SIZE]) -> Vec<u8> {
    // The coined helper is the source of identities. Tests pass those ids.
    ID_BLOCKS.with(|blocks| {
        blocks
            .iter()
            .find(|(block_id, _)| block_id == id)
            .map(|(_, bytes)| bytes.clone())
            .unwrap_or_else(|| panic!("no block for {id:?}"))
    })
}

std::thread_local! {
    static ID_BLOCKS: Vec<([u8; HASH_SIZE], Vec<u8>)> = (1..=4).map(|n| {
        let (bytes, id) = coined(n);
        (id, bytes)
    }).collect();
}

fn ids(n: usize) -> Vec<[u8; HASH_SIZE]> {
    ID_BLOCKS.with(|blocks| blocks.iter().take(n).map(|(id, _)| *id).collect())
}

/// Every requested hash is sent. The partition holds.
#[test]
fn all_sent_bodies_pass_the_form() {
    let have = ids(2);
    let (requested, msg) = response(&[(have[0], Slot::Sent), (have[1], Slot::Sent)]);
    assert_eq!(msg.check_form(&requested), Ok(()));
}

/// A sent prefix and a deferred tail is the budget's shape.
#[test]
fn a_sent_prefix_with_a_deferred_tail_passes() {
    let have = ids(2);
    let (requested, msg) = response(&[(have[0], Slot::Sent), (have[1], Slot::Deferred)]);
    assert_eq!(msg.check_form(&requested), Ok(()));
}

/// Unavailable is not a fault, including when every block is unavailable.
#[test]
fn unavailable_blocks_pass_including_all_of_them() {
    let have = ids(3);
    let (requested, msg) = response(&[
        (have[0], Slot::Missed),
        (have[1], Slot::Sent),
        (have[2], Slot::Missed),
    ]);
    assert_eq!(msg.check_form(&requested), Ok(()));

    let (requested, msg) = response(&[
        (have[0], Slot::Missed),
        (have[1], Slot::Missed),
        (have[2], Slot::Missed),
    ]);
    assert_eq!(msg.check_form(&requested), Ok(()));
}

/// A requested hash in none of the three lists is a silent shortfall.
#[test]
fn an_unaccounted_hash_fails_the_form() {
    let have = ids(2);
    let (requested, mut msg) = response(&[(have[0], Slot::Sent), (have[1], Slot::Sent)]);
    msg.bodies.pop();
    assert_eq!(
        msg.check_form(&requested),
        Err(BodiesFormFault::Unaccounted)
    );
}

/// A hash in two lists is not a partition.
#[test]
fn a_hash_in_two_lists_fails_the_form() {
    let have = ids(1);
    let (requested, mut msg) = response(&[(have[0], Slot::Sent)]);
    msg.missed_ids.push(have[0]);
    assert_eq!(msg.check_form(&requested), Err(BodiesFormFault::Repeated));
}

/// A listed hash the request did not name is refused.
#[test]
fn an_unrequested_hash_fails_the_form() {
    let have = ids(2);
    let (requested, mut msg) = response(&[(have[0], Slot::Missed)]);
    msg.missed_ids.push(have[1]);
    assert_eq!(
        msg.check_form(&requested),
        Err(BodiesFormFault::Unrequested)
    );
}

/// In request order, a sent block after a deferred one is refused.
#[test]
fn a_sent_block_after_a_deferred_one_fails() {
    let have = ids(3);
    let (requested, msg) = response(&[
        (have[0], Slot::Sent),
        (have[1], Slot::Deferred),
        (have[2], Slot::Sent),
    ]);
    assert_eq!(
        msg.check_form(&requested),
        Err(BodiesFormFault::SentAfterDeferred)
    );
}

/// The first block the responder holds is sent, not deferred.
#[test]
fn a_deferred_first_held_block_fails() {
    let have = ids(2);
    let (requested, msg) = response(&[(have[0], Slot::Missed), (have[1], Slot::Deferred)]);
    assert_eq!(
        msg.check_form(&requested),
        Err(BodiesFormFault::FirstHeldDeferred)
    );
}

/// Sent bodies follow the request. A swap is a different response.
#[test]
fn sent_bodies_follow_request_order() {
    let have = ids(2);
    let (requested, mut msg) = response(&[(have[0], Slot::Sent), (have[1], Slot::Sent)]);
    msg.bodies.swap(0, 1);
    assert_eq!(msg.check_form(&requested), Err(BodiesFormFault::OutOfOrder));
}

/// The first held block is sent whatever its size. Later held blocks stop
/// at the budget. A block that is not held is missed and does not count.
#[test]
fn the_planner_sends_the_first_held_block_then_fits_the_budget() {
    assert_eq!(BODIES_RESPONSE_BYTES, 8 * 1024 * 1024);
    let budget = usize::try_from(BODIES_RESPONSE_BYTES).expect("budget");
    let have = ids(4);
    let over = sized_body(budget + 1);
    let one = sized_body(1);
    let plan = plan_bodies(&have, |hash| {
        match have.iter().position(|item| item == hash) {
            Some(0) | None => None,
            Some(1) => Some(&over),
            Some(_) => Some(&one),
        }
    });
    assert_eq!(plan.missed, vec![have[0]]);
    assert_eq!(plan.send, vec![have[1]]);
    assert_eq!(plan.deferred, vec![have[2], have[3]]);
    assert!(body_budget_bytes(&over) > budget);

    let small = sized_body(10);
    let plan = plan_bodies(&have[..3], |hash| {
        if hash == &have[2] {
            None
        } else {
            Some(&small)
        }
    });
    assert_eq!(plan.send, vec![have[0], have[1]]);
    assert_eq!(plan.missed, vec![have[2]]);
    assert!(plan.deferred.is_empty());
}

fn sized_body(block_len: usize) -> BlockBody {
    BlockBody {
        block: vec![0; block_len],
        txs: Vec::new(),
        attestation_witness: Vec::new(),
    }
}

/// The first sent body may pass the budget. A second that does not fit is
/// refused by `store` and by `decode`, measured the same way the planner
/// measures. The bytes of an over-budget response are built by hand:
/// `store` will not emit them.
#[test]
fn a_second_body_past_the_budget_is_refused_at_store_and_decode() {
    let budget = usize::try_from(BODIES_RESPONSE_BYTES).expect("budget");
    let two = ResponseBodies {
        bodies: vec![sized_body(budget), sized_body(1)],
        deferred: Vec::new(),
        missed_ids: Vec::new(),
    };
    match two.store() {
        Err(PayloadError::OverBudget { field, .. }) => assert_eq!(field, "bodies"),
        other => panic!("expected OverBudget, got {other:?}"),
    }
    let bytes = encode_bodies_unchecked(&[sized_body(budget), sized_body(1)]);
    match ResponseBodies::decode(&bytes) {
        Err(PayloadError::OverBudget { field, .. }) => assert_eq!(field, "bodies"),
        other => panic!("expected OverBudget, got {other:?}"),
    }
    let one = ResponseBodies {
        bodies: vec![sized_body(budget + 1)],
        deferred: Vec::new(),
        missed_ids: Vec::new(),
    };
    let stored = one
        .store()
        .expect("the first body is sent whatever its size");
    assert_eq!(ResponseBodies::decode(&stored).expect("decode"), one);
}

/// A body list the codec would refuse, encoded without the budget check.
fn encode_bodies_unchecked(bodies: &[BlockBody]) -> Vec<u8> {
    let objects = bodies
        .iter()
        .map(|body| {
            let mut section = Section::new();
            section.insert("block", Value::Bytes(body.block.clone()));
            section
        })
        .collect();
    let mut root = Section::new();
    root.insert("bodies", Value::Array(Array::Object(objects)));
    store_to_binary(&root).expect("encode")
}

/// A duplicate in the request is the caller's list, not the peer's response.
#[test]
fn a_repeated_request_hash_is_the_callers() {
    let have = ids(1);
    let (_requested, msg) = response(&[(have[0], Slot::Sent)]);
    let repeated = vec![have[0], have[0]];
    assert_eq!(
        msg.check_form(&repeated),
        Err(BodiesFormFault::RequestRepeated)
    );
}

fn body_of_total(id: &[u8; HASH_SIZE], total: usize) -> BlockBody {
    let block = id_block(id);
    assert!(
        total >= block.len(),
        "a coined block is {} bytes",
        block.len()
    );
    let extra = total - block.len();
    BlockBody {
        block,
        txs: if extra == 0 {
            Vec::new()
        } else {
            vec![TxBody::Full(vec![0; extra])]
        },
        attestation_witness: Vec::new(),
    }
}

fn response_from_plan(
    requested: &[[u8; HASH_SIZE]],
    held: &[Option<BlockBody>],
    plan: &shekyl_levin::BodyPlan,
) -> ResponseBodies {
    ResponseBodies {
        bodies: plan
            .send
            .iter()
            .map(|id| {
                let index = requested.iter().position(|hash| hash == id).expect("sent");
                held[index].clone().expect("a sent body is held")
            })
            .collect(),
        deferred: plan.deferred.clone(),
        missed_ids: plan.missed.clone(),
    }
}

/// A budget-sized body between two small ones defers the tail. The third
/// body would fit on its own after the first, and sending it is
/// `SentAfterDeferred`.
#[test]
fn a_large_body_between_small_ones_defers_the_rest() {
    let budget = usize::try_from(BODIES_RESPONSE_BYTES).expect("budget");
    let have = ids(3);
    let small_len = have
        .iter()
        .map(|id| id_block(id).len())
        .max()
        .expect("three blocks");
    let first = body_of_total(&have[0], small_len);
    let middle = body_of_total(&have[1], budget);
    let last = body_of_total(&have[2], small_len);
    let held = [Some(first), Some(middle), Some(last)];
    let plan = plan_bodies(&have, |hash| {
        let index = have.iter().position(|id| id == hash).expect("id");
        held[index].as_ref()
    });
    assert_eq!(plan.send, vec![have[0]]);
    assert_eq!(plan.deferred, vec![have[1], have[2]]);
    assert!(plan.missed.is_empty());
    assert_eq!(
        response_from_plan(&have, &held, &plan).check_form(&have),
        Ok(())
    );
}

/// How many random plans the property test builds. Each is a request of
/// one to four blocks, held at a size from the budget's edges or missing.
const PLAN_CASES: u32 = 48;

/// `check_form` accepts what `plan_bodies` produces, including a large
/// body between small ones.
#[test]
fn the_plan_is_a_form_the_receiver_accepts() {
    let budget = usize::try_from(BODIES_RESPONSE_BYTES).expect("budget");
    let have = ids(4);
    let mut state = 0x5eed_c0de_u64;
    let mut cases = 0u32;
    for len in 1..=4 {
        for pattern in 0..12 {
            cases += 1;
            let requested = have[..len].to_vec();
            let held: Vec<Option<BlockBody>> = requested
                .iter()
                .enumerate()
                .map(|(index, id)| {
                    let roll = if pattern % 8 == 0 {
                        // Small, then the budget, then small again.
                        if index == 1 {
                            3
                        } else {
                            1
                        }
                    } else {
                        (mix(&mut state) % 5) as usize
                    };
                    let block_len = id_block(id).len();
                    match roll {
                        0 => None,
                        1 => Some(body_of_total(id, block_len)),
                        2 => Some(body_of_total(id, block_len + 10)),
                        3 => Some(body_of_total(id, budget)),
                        _ => Some(body_of_total(id, budget + block_len)),
                    }
                })
                .collect();
            let plan = plan_bodies(&requested, |hash| {
                let index = requested.iter().position(|id| id == hash).expect("id");
                held[index].as_ref()
            });
            let mut deferring = false;
            for (index, hash) in requested.iter().enumerate() {
                if held[index].is_none() {
                    assert!(plan.missed.contains(hash));
                    continue;
                }
                if deferring {
                    assert!(plan.deferred.contains(hash));
                    assert!(!plan.send.contains(hash));
                } else if plan.deferred.contains(hash) {
                    deferring = true;
                }
            }
            assert_eq!(
                response_from_plan(&requested, &held, &plan).check_form(&requested),
                Ok(()),
                "plan {plan:?}"
            );
        }
    }
    assert_eq!(cases, PLAN_CASES);
}

fn mix(state: &mut u64) -> u64 {
    *state ^= state.wrapping_shl(13);
    *state ^= state.wrapping_shr(7);
    *state ^= state.wrapping_shl(17);
    *state
}

/// Portable-storage varint, the codec's own widths.
fn ps_varint(out: &mut Vec<u8>, val: usize) {
    let val = u64::try_from(val).expect("count");
    if val <= 63 {
        out.push(u8::try_from(val << 2).expect("small"));
    } else if val <= 16_383 {
        let packed = u16::try_from((val << 2) | 1).expect("mid");
        out.extend_from_slice(&packed.to_le_bytes());
    } else {
        let packed = u32::try_from((val << 2) | 2).expect("wide");
        out.extend_from_slice(&packed.to_le_bytes());
    }
}

/// One field `a` holding `count` empty sections, padded out to `cap`.
fn object_array_at_cap(count: usize, cap: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(&shekyl_portable_storage::HEADER);
    ps_varint(&mut out, 1);
    out.push(1);
    out.push(b'a');
    out.push(0x8c);
    ps_varint(&mut out, count);
    out.resize(out.len() + count, 0);
    assert!(out.len() <= cap, "the declared objects fit in the cap");
    out.resize(cap, 0);
    out
}

/// One field `a` holding `count` empty strings. `array_len` asks for two
/// bytes per string before it counts them, so the body is `2 * count`
/// bytes; the strings themselves are one byte each. Padded out to `cap`.
fn string_array_at_cap(count: usize, cap: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(&shekyl_portable_storage::HEADER);
    ps_varint(&mut out, 1);
    out.push(1);
    out.push(b'a');
    out.push(0x8a);
    ps_varint(&mut out, count);
    let body = count.checked_mul(2).expect("body");
    out.resize(out.len() + body, 0);
    assert!(out.len() <= cap, "the declared strings fit in the cap");
    out.resize(cap, 0);
    out
}

#[test]
fn the_crafted_array_matches_the_codec_for_one_element() {
    let mut objects = Section::new();
    objects.insert("a", Value::Array(Array::Object(vec![Section::new()])));
    assert_eq!(
        store_to_binary(&objects).expect("objects"),
        object_array_at_cap(1, store_to_binary(&objects).expect("len").len())
    );
}

#[test]
fn the_minimum_sections_are_the_sizes_the_limits_use() {
    let segment = vec![0u8; shekyl_wire::MIN_PRUNED_SEGMENT];
    let mut full = Section::new();
    full.insert("blob", Value::Bytes(segment.clone()));
    full.insert("form", Value::UInt8(1));
    let full_len =
        store_to_binary(&full).expect("full").len() - shekyl_portable_storage::HEADER.len();
    assert_eq!(full_len, MIN_TX_SECTION_BYTES);

    let mut skeleton = Section::new();
    skeleton.insert("archival_len", Value::UInt64(0));
    skeleton.insert("form", Value::UInt8(2));
    skeleton.insert("pqc_auth_hash", Value::Bytes(vec![0u8; 32]));
    skeleton.insert("prunable_hash", Value::Bytes(vec![0u8; 32]));
    skeleton.insert("unprunable", Value::Bytes(segment));
    let skeleton_len =
        store_to_binary(&skeleton).expect("skeleton").len() - shekyl_portable_storage::HEADER.len();
    assert!(skeleton_len > MIN_TX_SECTION_BYTES);
}

/// A cap-sized array of one-byte objects is refused before the decoder
/// allocates it. The count is one past the derived object limit.
#[test]
fn a_cap_of_one_byte_objects_is_too_many() {
    let cap = usize::try_from(CAP_RESPONSE_BODIES).expect("cap");
    let bytes = object_array_at_cap(RESPONSE_BODIES_MAX_OBJECTS + 1, cap);
    assert_eq!(bytes.len(), cap);
    match ResponseBodies::decode(&bytes) {
        Err(PayloadError::Storage(shekyl_portable_storage::Error::TooManyObjects { .. })) => {}
        other => panic!("expected TooManyObjects, got {other:?}"),
    }
}

/// A cap-sized array of empty strings is refused before the decoder
/// allocates it.
#[test]
fn a_cap_of_empty_strings_is_too_many() {
    let cap = usize::try_from(CAP_RESPONSE_HEADERS).expect("cap");
    let bytes = string_array_at_cap(RESPONSE_HEADERS_MAX_STRINGS + 1, cap);
    assert_eq!(bytes.len(), cap);
    match ResponseHeaders::decode(&bytes) {
        Err(PayloadError::Storage(shekyl_portable_storage::Error::TooManyStrings { .. })) => {}
        other => panic!("expected TooManyStrings, got {other:?}"),
    }
    let body_cap = usize::try_from(CAP_RESPONSE_BODIES).expect("cap");
    let bodies = string_array_at_cap(RESPONSE_BODIES_MAX_STRINGS + 1, body_cap);
    assert_eq!(bodies.len(), body_cap);
    match ResponseBodies::decode(&bodies) {
        Err(PayloadError::Storage(shekyl_portable_storage::Error::TooManyStrings { .. })) => {}
        other => panic!("expected TooManyStrings, got {other:?}"),
    }
}

/// One hundred bodies of minimum skeletons fill the body budget and still
/// decode. That is the honest maximum the derived limits have to admit.
#[test]
fn a_budget_of_minimum_skeletons_decodes() {
    let segment = {
        let tx = shekyl_wire::Transaction {
            prefix: shekyl_wire::TxPrefix {
                unlock_time: 0,
                inputs: Vec::new(),
                outputs: Vec::new(),
                extra: Vec::new(),
            },
            ct: shekyl_wire::Ct::Null(shekyl_wire::CtBase {
                enc_amounts: Vec::new(),
                enc_labels: Vec::new(),
                commitments: Vec::new(),
            }),
        };
        let bytes = tx.serialize();
        assert_eq!(bytes.len(), shekyl_wire::MIN_PRUNED_SEGMENT);
        bytes
    };
    let skeleton = TxBody::Skeleton(SkeletonTx {
        unprunable: segment,
        prunable_hash: PrunableHash::from_bytes([1u8; 32]),
        pqc_auth_hash: None,
        archival_len: ArchivalLength::from_raw(0),
    });
    let one = BlockBody {
        block: vec![0x11],
        txs: vec![skeleton.clone()],
        attestation_witness: Vec::new(),
    };
    let each = body_budget_bytes(&one) - one.block.len();
    let budget = usize::try_from(BODIES_RESPONSE_BYTES).expect("budget");
    let blocks = 100usize;
    let total = (budget - blocks) / each;
    assert!(
        total >= blocks,
        "a minimum skeleton is smaller than the budget"
    );
    let base = total / blocks;
    let extra = total % blocks;
    let bodies = (0..blocks)
        .map(|i| {
            let n = base + usize::from(i < extra);
            BlockBody {
                block: vec![0x11],
                txs: vec![skeleton.clone(); n],
                attestation_witness: Vec::new(),
            }
        })
        .collect::<Vec<_>>();
    let charged: usize = bodies.iter().map(body_budget_bytes).sum();
    assert!(charged <= budget);
    assert!(budget - charged < each);
    let msg = ResponseBodies {
        bodies,
        deferred: Vec::new(),
        missed_ids: Vec::new(),
    };
    let bytes = msg.store().expect("an honest maximum stores");
    assert_eq!(ResponseBodies::decode(&bytes).expect("and decodes"), msg);
}

/// The router's admission of 2011–2014 is its own set, beside the C++
/// ingress's: every id round-trips, each cap is the one its decoder uses,
/// and no other id is a chain-sync command.
#[test]
fn the_router_admits_exactly_the_four_sync_commands_with_their_caps() {
    use shekyl_levin::{
        SyncCommand, CAP_REQUEST_BODIES, CAP_REQUEST_HEADERS, CAP_RESPONSE_BODIES,
        CAP_RESPONSE_HEADERS,
    };
    for command in SyncCommand::ALL {
        assert_eq!(SyncCommand::from_wire(command.wire_id()), Some(command));
        assert_eq!(DefinedCommand::from_wire(command.wire_id()), None);
    }
    assert_eq!(
        SyncCommand::ALL.map(SyncCommand::payload_cap),
        [
            CAP_REQUEST_HEADERS,
            CAP_RESPONSE_HEADERS,
            CAP_REQUEST_BODIES,
            CAP_RESPONSE_BODIES
        ]
    );
    for id in [0, 1001, 1002, 2002, 2003, 2004, 2008, 2010, 2015] {
        assert_eq!(SyncCommand::from_wire(id), None, "{id}");
    }
}
