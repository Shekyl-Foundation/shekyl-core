// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed lookups against a decoded [`Section`]. Extra keys are ignored.

use shekyl_portable_storage::{Array, Section, Value};

use super::error::Error;

pub(crate) fn require<'a>(section: &'a Section, key: &'static str) -> Result<&'a Value, Error> {
    section.get(key).ok_or(Error::MissingField(key))
}

pub(crate) fn mismatch(field: &'static str, expected: &'static str) -> Error {
    Error::TypeMismatch { field, expected }
}

pub(crate) fn u8_val(section: &Section, key: &'static str) -> Result<u8, Error> {
    match require(section, key)? {
        Value::UInt8(v) => Ok(*v),
        _ => Err(mismatch(key, "uint8")),
    }
}

pub(crate) fn u16_val(section: &Section, key: &'static str) -> Result<u16, Error> {
    match require(section, key)? {
        Value::UInt16(v) => Ok(*v),
        _ => Err(mismatch(key, "uint16")),
    }
}

pub(crate) fn u32_val(section: &Section, key: &'static str) -> Result<u32, Error> {
    match require(section, key)? {
        Value::UInt32(v) => Ok(*v),
        _ => Err(mismatch(key, "uint32")),
    }
}

pub(crate) fn u64_val(section: &Section, key: &'static str) -> Result<u64, Error> {
    match require(section, key)? {
        Value::UInt64(v) => Ok(*v),
        _ => Err(mismatch(key, "uint64")),
    }
}

pub(crate) fn opt_u8(section: &Section, key: &'static str, default: u8) -> Result<u8, Error> {
    match section.get(key) {
        None => Ok(default),
        Some(Value::UInt8(v)) => Ok(*v),
        Some(_) => Err(mismatch(key, "uint8")),
    }
}

pub(crate) fn opt_u32(section: &Section, key: &'static str, default: u32) -> Result<u32, Error> {
    match section.get(key) {
        None => Ok(default),
        Some(Value::UInt32(v)) => Ok(*v),
        Some(_) => Err(mismatch(key, "uint32")),
    }
}

pub(crate) fn opt_i64(section: &Section, key: &'static str, default: i64) -> Result<i64, Error> {
    match section.get(key) {
        None => Ok(default),
        Some(Value::Int64(v)) => Ok(*v),
        Some(_) => Err(mismatch(key, "int64")),
    }
}

pub(crate) fn blob<const N: usize>(section: &Section, key: &'static str) -> Result<[u8; N], Error> {
    match require(section, key)? {
        Value::Bytes(b) => <[u8; N]>::try_from(b.as_slice()).map_err(|_| Error::InvalidLength {
            field: key,
            expected: N,
            got: b.len(),
        }),
        _ => Err(mismatch(key, "string")),
    }
}

pub(crate) fn bytes<'a>(section: &'a Section, key: &'static str) -> Result<&'a [u8], Error> {
    match require(section, key)? {
        Value::Bytes(b) => Ok(b.as_slice()),
        _ => Err(mismatch(key, "string")),
    }
}

pub(crate) fn utf8(section: &Section, key: &'static str) -> Result<String, Error> {
    let raw = bytes(section, key)?;
    String::from_utf8(raw.to_vec()).map_err(|_| Error::NotUtf8(key))
}

pub(crate) fn object<'a>(section: &'a Section, key: &'static str) -> Result<&'a Section, Error> {
    match require(section, key)? {
        Value::Object(inner) => Ok(inner),
        _ => Err(mismatch(key, "object")),
    }
}

pub(crate) fn insert_opt_u32(section: &mut Section, key: &'static str, value: u32, default: u32) {
    if value != default {
        section.insert(key, Value::UInt32(value));
    }
}

pub(crate) fn insert_opt_u8(section: &mut Section, key: &'static str, value: u8, default: u8) {
    if value != default {
        section.insert(key, Value::UInt8(value));
    }
}

pub(crate) fn insert_opt_i64(section: &mut Section, key: &'static str, value: i64, default: i64) {
    if value != default {
        section.insert(key, Value::Int64(value));
    }
}

pub(crate) fn opt_u64(section: &Section, key: &'static str, default: u64) -> Result<u64, Error> {
    match section.get(key) {
        None => Ok(default),
        Some(Value::UInt64(v)) => Ok(*v),
        Some(_) => Err(mismatch(key, "uint64")),
    }
}

pub(crate) fn opt_bool(section: &Section, key: &'static str, default: bool) -> Result<bool, Error> {
    match section.get(key) {
        None => Ok(default),
        Some(Value::Bool(v)) => Ok(*v),
        Some(_) => Err(mismatch(key, "bool")),
    }
}

pub(crate) fn opt_bytes(section: &Section, key: &'static str) -> Result<Vec<u8>, Error> {
    match section.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(mismatch(key, "string")),
    }
}

pub(crate) fn insert_opt_u64(section: &mut Section, key: &'static str, value: u64, default: u64) {
    if value != default {
        section.insert(key, Value::UInt64(value));
    }
}

pub(crate) fn insert_opt_bool(
    section: &mut Section,
    key: &'static str,
    value: bool,
    default: bool,
) {
    if value != default {
        section.insert(key, Value::Bool(value));
    }
}

pub(crate) fn insert_opt_bytes(section: &mut Section, key: &'static str, value: &[u8]) {
    if !value.is_empty() {
        section.insert(key, Value::Bytes(value.to_vec()));
    }
}

/// `crypto::hash` width (`KV_SERIALIZE_VAL_POD_AS_BLOB` / `CONTAINER_POD_AS_BLOB`).
pub const HASH_SIZE: usize = 32;

pub(crate) fn bytes_array(section: &Section, key: &'static str) -> Result<Vec<Vec<u8>>, Error> {
    match section.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(Array::Bytes(blobs))) => Ok(blobs.clone()),
        Some(_) => Err(mismatch(key, "array of string")),
    }
}

pub(crate) fn insert_bytes_array(section: &mut Section, key: &'static str, blobs: &[Vec<u8>]) {
    if !blobs.is_empty() {
        section.insert(key, Value::Array(Array::Bytes(blobs.to_vec())));
    }
}

pub(crate) fn object_array<'a>(
    section: &'a Section,
    key: &'static str,
) -> Result<Vec<&'a Section>, Error> {
    match section.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(Array::Object(secs))) => Ok(secs.iter().collect()),
        Some(_) => Err(mismatch(key, "array of object")),
    }
}

pub(crate) fn insert_object_array(section: &mut Section, key: &'static str, objs: Vec<Section>) {
    if !objs.is_empty() {
        section.insert(key, Value::Array(Array::Object(objs)));
    }
}

pub(crate) fn pod_hashes(
    section: &Section,
    key: &'static str,
) -> Result<Vec<[u8; HASH_SIZE]>, Error> {
    match section.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Bytes(b)) => split_pod(key, b, HASH_SIZE, |chunk| {
            let mut hash = [0u8; HASH_SIZE];
            hash.copy_from_slice(chunk);
            hash
        }),
        Some(_) => Err(mismatch(key, "string")),
    }
}

pub(crate) fn insert_pod_hashes(
    section: &mut Section,
    key: &'static str,
    hashes: &[[u8; HASH_SIZE]],
) {
    if hashes.is_empty() {
        return;
    }
    let mut out = Vec::with_capacity(hashes.len() * HASH_SIZE);
    for hash in hashes {
        out.extend_from_slice(hash);
    }
    section.insert(key, Value::Bytes(out));
}

pub(crate) fn pod_u64s(section: &Section, key: &'static str) -> Result<Vec<u64>, Error> {
    match section.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Bytes(b)) => split_pod(key, b, 8, |chunk| {
            u64::from_le_bytes(chunk.try_into().expect("chunk is 8"))
        }),
        Some(_) => Err(mismatch(key, "string")),
    }
}

pub(crate) fn insert_pod_u64s(section: &mut Section, key: &'static str, values: &[u64]) {
    if values.is_empty() {
        return;
    }
    let mut out = Vec::with_capacity(values.len() * 8);
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    section.insert(key, Value::Bytes(out));
}

fn split_pod<T, F>(
    field: &'static str,
    bytes: &[u8],
    element: usize,
    mut map: F,
) -> Result<Vec<T>, Error>
where
    F: FnMut(&[u8]) -> T,
{
    if !bytes.len().is_multiple_of(element) {
        return Err(Error::PodBlobLength {
            field,
            element,
            got: bytes.len(),
        });
    }
    Ok(bytes.chunks_exact(element).map(&mut map).collect())
}
