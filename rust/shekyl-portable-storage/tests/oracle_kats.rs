// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! C++ capture KATs and round-trips for `shekyl-portable-storage`.
//!
//! `two_keys` / `duplicate_key` are the gtest vectors in
//! `tests/unit_tests/epee_serialization.cpp`.

use shekyl_portable_storage::{
    load_from_binary, store_to_binary, Array, Error, Limits, Section, Value, HEADER,
};

const TWO_KEYS: &[u8] = &[
    0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x08, 0x01, b'a', 0x0b, 0x00, 0x01, b'b',
    0x0b, 0x00,
];

const DUPLICATE_KEY: &[u8] = &[
    0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x08, 0x01, b'a', 0x0b, 0x00, 0x01, b'a',
    0x0b, 0x00,
];

#[test]
fn cpp_two_keys() {
    let section = load_from_binary(TWO_KEYS, Limits::UNLIMITED).expect("two_keys");
    assert_eq!(section.get("a"), Some(&Value::Bool(false)));
    assert_eq!(section.get("b"), Some(&Value::Bool(false)));
    assert_eq!(store_to_binary(&section).expect("re-encode"), TWO_KEYS);
}

#[test]
fn cpp_duplicate_key() {
    assert_eq!(
        load_from_binary(DUPLICATE_KEY, Limits::UNLIMITED),
        Err(Error::DuplicateKey)
    );
}

#[test]
fn empty_section() {
    let mut expected = HEADER.to_vec();
    expected.push(0x00);
    let encoded = store_to_binary(&Section::new()).expect("empty");
    assert_eq!(encoded, expected);
    let decoded = load_from_binary(&encoded, Limits::UNLIMITED).expect("decode empty");
    assert!(decoded.is_empty());
}

#[test]
fn encode_order_is_lexicographic() {
    let mut section = Section::new();
    section.insert("b", Value::Bool(false));
    section.insert("a", Value::Bool(false));
    assert_eq!(store_to_binary(&section).expect("encode"), TWO_KEYS);
}

#[test]
fn string_howdy() {
    let mut section = Section::new();
    section.insert("q", Value::Bytes(b"Howdy".to_vec()));
    let bytes = store_to_binary(&section).expect("encode");
    let decoded = load_from_binary(&bytes, Limits::UNLIMITED).expect("decode");
    assert_eq!(decoded.get("q"), Some(&Value::Bytes(b"Howdy".to_vec())));
}

#[test]
fn uint32_and_nested() {
    let mut inner = Section::new();
    inner.insert(
        "unsigned_64bit_int",
        Value::UInt64(11_111_111_111_111_111_111),
    );
    inner.insert("double", Value::Double(-6.9));
    let mut root = Section::new();
    root.insert("signed_32bit_int", Value::Int32(20_140_418));
    root.insert("nested_section", Value::Object(inner));
    let bytes = store_to_binary(&root).expect("encode");
    let decoded = load_from_binary(&bytes, Limits::UNLIMITED).expect("decode");
    match decoded.get("signed_32bit_int") {
        Some(Value::Int32(v)) => assert_eq!(*v, 20_140_418),
        other => panic!("unexpected {other:?}"),
    }
    let nested = match decoded.get("nested_section") {
        Some(Value::Object(s)) => s,
        other => panic!("unexpected {other:?}"),
    };
    match nested.get("unsigned_64bit_int") {
        Some(Value::UInt64(v)) => assert_eq!(*v, 11_111_111_111_111_111_111),
        other => panic!("unexpected {other:?}"),
    }
    match nested.get("double") {
        Some(Value::Double(v)) => assert_eq!(v.to_bits(), (-6.9_f64).to_bits()),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn uint64_array_roundtrip() {
    let mut section = Section::new();
    section.insert("heights", Value::Array(Array::UInt64(vec![0, 1, 99])));
    let bytes = store_to_binary(&section).expect("encode");
    let decoded = load_from_binary(&bytes, Limits::UNLIMITED).expect("decode");
    assert_eq!(
        decoded.get("heights"),
        Some(&Value::Array(Array::UInt64(vec![0, 1, 99])))
    );
}

#[test]
fn object_array_and_collect_bytes() {
    let mut block = Section::new();
    block.insert("block", Value::Bytes(b"blob".to_vec()));
    let mut root = Section::new();
    root.insert("blocks", Value::Array(Array::Object(vec![block])));
    let bytes = store_to_binary(&root).expect("encode");
    let decoded = load_from_binary(&bytes, Limits::HTTP_BIN).expect("decode");
    assert_eq!(decoded.collect_bytes_named("block"), vec![b"blob".to_vec()]);
}

#[test]
fn bool_two_is_invalid() {
    let mut blob = HEADER.to_vec();
    blob.push(0x04); // one field
    blob.push(0x01);
    blob.push(b'a');
    blob.push(0x0b);
    blob.push(0x02);
    assert_eq!(
        load_from_binary(&blob, Limits::UNLIMITED),
        Err(Error::InvalidBool)
    );
}

#[test]
fn tag_13_is_hard_error() {
    let mut blob = HEADER.to_vec();
    blob.push(0x04);
    blob.push(0x01);
    blob.push(b'a');
    blob.push(13);
    assert_eq!(
        load_from_binary(&blob, Limits::UNLIMITED),
        Err(Error::UntypedArray)
    );
}

#[test]
fn trailing_bytes_ignored() {
    let mut blob = store_to_binary(&Section::new()).expect("empty");
    blob.extend_from_slice(&[0xff, 0xff]);
    load_from_binary(&blob, Limits::UNLIMITED).expect("trailing ok");
}

#[test]
fn get_o_indexes_request_shape() {
    let hash = [0x11u8; 32];
    let mut root = Section::new();
    root.insert("txid", Value::Bytes(hash.to_vec()));
    let bytes = store_to_binary(&root).expect("encode");
    let mut expected = HEADER.to_vec();
    expected.push(1 << 2);
    expected.push(4);
    expected.extend_from_slice(b"txid");
    expected.push(10);
    expected.push(32 << 2);
    expected.extend_from_slice(&hash);
    assert_eq!(bytes, expected);
}

#[test]
fn objects_limit_rejects_nested() {
    let mut inner = Section::new();
    inner.insert("x", Value::Bool(true));
    let mut root = Section::new();
    root.insert("n", Value::Object(inner));
    let bytes = store_to_binary(&root).expect("encode");
    let err = load_from_binary(
        &bytes,
        Limits {
            objects: 0,
            fields: 16,
            strings: 16,
        },
    )
    .expect_err("nested object");
    assert_eq!(err, Error::TooManyObjects { limit: 0 });
}

#[test]
fn header_only_is_truncated() {
    assert_eq!(
        load_from_binary(&HEADER, Limits::UNLIMITED),
        Err(Error::Truncated)
    );
}
