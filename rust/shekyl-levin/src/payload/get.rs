// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed lookups against a decoded [`Section`]. Extra keys are ignored.

use shekyl_portable_storage::{Section, Value};

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

pub(crate) fn opt_u16(section: &Section, key: &'static str, default: u16) -> Result<u16, Error> {
    match section.get(key) {
        None => Ok(default),
        Some(Value::UInt16(v)) => Ok(*v),
        Some(_) => Err(mismatch(key, "uint16")),
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

pub(crate) fn blob<const N: usize>(
    section: &Section,
    key: &'static str,
) -> Result<[u8; N], Error> {
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

pub(crate) fn insert_opt_u16(section: &mut Section, key: &'static str, value: u16, default: u16) {
    if value != default {
        section.insert(key, Value::UInt16(value));
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
