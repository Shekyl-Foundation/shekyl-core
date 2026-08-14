// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::collections::BTreeMap;

use crate::error::Error;
use crate::limits::Limits;
use crate::value::{Array, Section, Value};
use crate::varint::read_varint;
use crate::{ty, HEADER, MAX_STRING_LEN_POSSIBLE, RECURSION_LIMIT, SERIALIZE_FLAG_ARRAY};

pub(crate) fn load_from_binary(bytes: &[u8], limits: Limits) -> Result<Section, Error> {
    if bytes.len() < HEADER.len() {
        return Err(Error::Truncated);
    }
    if bytes[..HEADER.len()] != HEADER {
        return Err(Error::BadHeader);
    }
    // C++ `throwable_buffer_reader` rejects a zero-length remainder.
    let rest = &bytes[HEADER.len()..];
    if rest.is_empty() {
        return Err(Error::Truncated);
    }
    let mut reader = Reader {
        rest,
        depth: 0,
        objects: 0,
        fields: 0,
        strings: 0,
        limits,
    };
    reader.read_section()
}

struct Reader<'a> {
    rest: &'a [u8],
    depth: usize,
    objects: usize,
    fields: usize,
    strings: usize,
    limits: Limits,
}

impl<'a> Reader<'a> {
    fn enter(&mut self) -> Result<(), Error> {
        self.depth += 1;
        if self.depth >= RECURSION_LIMIT {
            return Err(Error::RecursionLimit);
        }
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.rest.len() < n {
            return Err(Error::Truncated);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn varint(&mut self) -> Result<u64, Error> {
        read_varint(&mut self.rest)
    }

    fn usize_varint(&mut self) -> Result<usize, Error> {
        usize::try_from(self.varint()?).map_err(|_| Error::ArrayTooLarge)
    }

    fn read_section(&mut self) -> Result<Section, Error> {
        self.enter()?;
        let count = self.usize_varint()?;
        if count > self.limits.fields.saturating_sub(self.fields) {
            self.exit();
            return Err(Error::TooManyFields {
                limit: self.limits.fields,
            });
        }
        self.fields += count;
        let mut entries = BTreeMap::new();
        for _ in 0..count {
            let key = match self.read_key() {
                Ok(k) => k,
                Err(e) => {
                    self.exit();
                    return Err(e);
                }
            };
            if entries.contains_key(&key) {
                self.exit();
                return Err(Error::DuplicateKey);
            }
            let value = match self.read_entry() {
                Ok(v) => v,
                Err(e) => {
                    self.exit();
                    return Err(e);
                }
            };
            entries.insert(key, value);
        }
        self.exit();
        Ok(Section::from_entries(entries))
    }

    fn read_key(&mut self) -> Result<String, Error> {
        let len = self.byte()?;
        if len == 0 {
            return Err(Error::EmptyKey);
        }
        let bytes = self.take(usize::from(len))?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::KeyNotUtf8)
    }

    fn read_entry(&mut self) -> Result<Value, Error> {
        self.enter()?;
        let tag = match self.byte() {
            Ok(t) => t,
            Err(e) => {
                self.exit();
                return Err(e);
            }
        };
        let result = if tag & SERIALIZE_FLAG_ARRAY != 0 {
            self.read_array(tag & !SERIALIZE_FLAG_ARRAY)
                .map(Value::Array)
        } else {
            self.read_scalar(tag)
        };
        self.exit();
        result
    }

    fn read_scalar(&mut self, tag: u8) -> Result<Value, Error> {
        match tag {
            ty::INT64 => Ok(Value::Int64(i64::from_le_bytes(self.pod()?))),
            ty::INT32 => Ok(Value::Int32(i32::from_le_bytes(self.pod()?))),
            ty::INT16 => Ok(Value::Int16(i16::from_le_bytes(self.pod()?))),
            ty::INT8 => Ok(Value::Int8(i8::from_le_bytes(self.pod()?))),
            ty::UINT64 => Ok(Value::UInt64(u64::from_le_bytes(self.pod()?))),
            ty::UINT32 => Ok(Value::UInt32(u32::from_le_bytes(self.pod()?))),
            ty::UINT16 => Ok(Value::UInt16(u16::from_le_bytes(self.pod()?))),
            ty::UINT8 => Ok(Value::UInt8(self.pod::<1>()?[0])),
            ty::DOUBLE => Ok(Value::Double(f64::from_le_bytes(self.pod()?))),
            ty::BOOL => Ok(Value::Bool(self.read_bool()?)),
            ty::STRING => {
                self.bump_strings(1)?;
                Ok(Value::Bytes(self.read_bytes()?))
            }
            ty::OBJECT => {
                self.bump_objects(1)?;
                Ok(Value::Object(self.read_section()?))
            }
            ty::ARRAY => Err(Error::UntypedArray),
            other => Err(Error::UnknownType(other)),
        }
    }

    fn read_array(&mut self, inner: u8) -> Result<Array, Error> {
        match inner {
            ty::INT64 => self.read_pod_array(i64::from_le_bytes).map(Array::Int64),
            ty::INT32 => self.read_pod_array(i32::from_le_bytes).map(Array::Int32),
            ty::INT16 => self.read_pod_array(i16::from_le_bytes).map(Array::Int16),
            ty::INT8 => self.read_pod_array(i8::from_le_bytes).map(Array::Int8),
            ty::UINT64 => self.read_pod_array(u64::from_le_bytes).map(Array::UInt64),
            ty::UINT32 => self.read_pod_array(u32::from_le_bytes).map(Array::UInt32),
            ty::UINT16 => self.read_pod_array(u16::from_le_bytes).map(Array::UInt16),
            ty::UINT8 => self.read_pod_array(|b: [u8; 1]| b[0]).map(Array::UInt8),
            ty::DOUBLE => self.read_pod_array(f64::from_le_bytes).map(Array::Double),
            ty::BOOL => {
                let n = self.array_len(1)?;
                let mut out = Vec::with_capacity(n);
                for _ in 0..n {
                    out.push(self.read_bool()?);
                }
                Ok(Array::Bool(out))
            }
            ty::STRING => {
                let n = self.array_len(2)?;
                self.bump_strings(n)?;
                let mut out = Vec::with_capacity(n);
                for _ in 0..n {
                    out.push(self.read_bytes()?);
                }
                Ok(Array::Bytes(out))
            }
            ty::OBJECT => {
                let n = self.array_len(1)?;
                self.bump_objects(n)?;
                let mut out = Vec::with_capacity(n);
                for _ in 0..n {
                    out.push(self.read_section()?);
                }
                Ok(Array::Object(out))
            }
            ty::ARRAY => Err(Error::UntypedArray),
            other => Err(Error::UnknownType(other)),
        }
    }

    fn array_len(&mut self, min_bytes: usize) -> Result<usize, Error> {
        let n = self.usize_varint()?;
        let need = n.checked_mul(min_bytes).ok_or(Error::ArrayTooLarge)?;
        if need > self.rest.len() {
            return Err(Error::ArrayTooLarge);
        }
        Ok(n)
    }

    fn read_pod_array<const N: usize, T, F>(&mut self, parse: F) -> Result<Vec<T>, Error>
    where
        F: Fn([u8; N]) -> T,
    {
        let n = self.array_len(N)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(parse(self.pod()?));
        }
        Ok(out)
    }

    fn pod<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let b = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }

    fn read_bool(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidBool),
        }
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let len = self.varint()?;
        if len >= MAX_STRING_LEN_POSSIBLE {
            return Err(Error::StringTooLong);
        }
        let n = usize::try_from(len).map_err(|_| Error::StringTooLong)?;
        Ok(self.take(n)?.to_vec())
    }

    fn bump_objects(&mut self, n: usize) -> Result<(), Error> {
        if n > self.limits.objects.saturating_sub(self.objects) {
            return Err(Error::TooManyObjects {
                limit: self.limits.objects,
            });
        }
        self.objects += n;
        Ok(())
    }

    fn bump_strings(&mut self, n: usize) -> Result<(), Error> {
        if n > self.limits.strings.saturating_sub(self.strings) {
            return Err(Error::TooManyStrings {
                limit: self.limits.strings,
            });
        }
        self.strings += n;
        Ok(())
    }
}
