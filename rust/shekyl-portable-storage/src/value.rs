// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::collections::BTreeMap;

/// One portable_storage value. Arrays are typed; there is no array-of-array.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int64(i64),
    Int32(i32),
    Int16(i16),
    Int8(i8),
    UInt64(u64),
    UInt32(u32),
    UInt16(u16),
    UInt8(u8),
    Double(f64),
    /// `SERIALIZE_TYPE_STRING` — UTF-8 text or an opaque blob (POD-as-blob,
    /// hashes, tx bytes).
    Bytes(Vec<u8>),
    Bool(bool),
    Object(Section),
    Array(Array),
}

/// Homogeneous array. Encoded as `(inner_type | 0x80)` plus a varint count.
#[derive(Debug, Clone, PartialEq)]
pub enum Array {
    Int64(Vec<i64>),
    Int32(Vec<i32>),
    Int16(Vec<i16>),
    Int8(Vec<i8>),
    UInt64(Vec<u64>),
    UInt32(Vec<u32>),
    UInt16(Vec<u16>),
    UInt8(Vec<u8>),
    Double(Vec<f64>),
    Bytes(Vec<Vec<u8>>),
    Bool(Vec<bool>),
    Object(Vec<Section>),
}

impl Array {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Int64(v) => v.len(),
            Self::Int32(v) => v.len(),
            Self::Int16(v) => v.len(),
            Self::Int8(v) => v.len(),
            Self::UInt64(v) => v.len(),
            Self::UInt32(v) => v.len(),
            Self::UInt16(v) => v.len(),
            Self::UInt8(v) => v.len(),
            Self::Double(v) => v.len(),
            Self::Bytes(v) => v.len(),
            Self::Bool(v) => v.len(),
            Self::Object(v) => v.len(),
        }
    }
}

/// A section: lexicographic `BTreeMap` matching C++ `std::map<string, entry>`.
///
/// Encode walks keys in sorted order. Decode accepts any order and rejects
/// duplicates.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Section {
    entries: BTreeMap<String, Value>,
}

impl Section {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace `key`. Encode still rejects empty / overlong keys.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) {
        self.entries.insert(key.into(), value);
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.get(key)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub(crate) fn from_entries(entries: BTreeMap<String, Value>) -> Self {
        Self { entries }
    }

    /// Every `SERIALIZE_TYPE_STRING` (scalar or array element) whose field
    /// name is `name`, anywhere in the tree. Used by
    /// `get_blocks_by_height.bin` to collect `block` blobs.
    #[must_use]
    pub fn collect_bytes_named(&self, name: &str) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        collect_bytes(self, name, &mut out);
        out
    }
}

fn collect_bytes(section: &Section, name: &str, out: &mut Vec<Vec<u8>>) {
    for (key, value) in section.iter() {
        match value {
            Value::Bytes(b) if key == name => out.push(b.clone()),
            Value::Array(Array::Bytes(blobs)) if key == name => {
                out.extend(blobs.iter().cloned());
            }
            Value::Object(inner) => collect_bytes(inner, name, out),
            Value::Array(Array::Object(secs)) => {
                for inner in secs {
                    collect_bytes(inner, name, out);
                }
            }
            _ => {}
        }
    }
}
