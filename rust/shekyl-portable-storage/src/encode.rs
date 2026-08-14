// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use crate::error::Error;
use crate::value::{Array, Section, Value};
use crate::varint::write_varint;
use crate::{ty, HEADER, SERIALIZE_FLAG_ARRAY};

pub(crate) fn store_to_binary(root: &Section) -> Result<Vec<u8>, Error> {
    let mut out = Vec::from(HEADER);
    write_section(&mut out, root)?;
    Ok(out)
}

fn write_section(out: &mut Vec<u8>, section: &Section) -> Result<(), Error> {
    write_varint(
        out,
        u64::try_from(section.len()).map_err(|_| Error::VarintTooLarge)?,
    )?;
    for (key, value) in section.iter() {
        write_key(out, key)?;
        write_value(out, value)?;
    }
    Ok(())
}

fn write_key(out: &mut Vec<u8>, key: &str) -> Result<(), Error> {
    if key.is_empty() {
        return Err(Error::EmptyKey);
    }
    if key.len() > 254 {
        return Err(Error::KeyTooLong);
    }
    let len = u8::try_from(key.len()).expect("len <= 254");
    out.push(len);
    out.extend_from_slice(key.as_bytes());
    Ok(())
}

fn write_value(out: &mut Vec<u8>, value: &Value) -> Result<(), Error> {
    match value {
        Value::Int64(v) => {
            write_pod(out, ty::INT64, &v.to_le_bytes());
            Ok(())
        }
        Value::Int32(v) => {
            write_pod(out, ty::INT32, &v.to_le_bytes());
            Ok(())
        }
        Value::Int16(v) => {
            write_pod(out, ty::INT16, &v.to_le_bytes());
            Ok(())
        }
        Value::Int8(v) => {
            write_pod(out, ty::INT8, &v.to_le_bytes());
            Ok(())
        }
        Value::UInt64(v) => {
            write_pod(out, ty::UINT64, &v.to_le_bytes());
            Ok(())
        }
        Value::UInt32(v) => {
            write_pod(out, ty::UINT32, &v.to_le_bytes());
            Ok(())
        }
        Value::UInt16(v) => {
            write_pod(out, ty::UINT16, &v.to_le_bytes());
            Ok(())
        }
        Value::UInt8(v) => {
            write_pod(out, ty::UINT8, &[*v]);
            Ok(())
        }
        Value::Double(v) => {
            write_pod(out, ty::DOUBLE, &v.to_le_bytes());
            Ok(())
        }
        Value::Bool(v) => {
            write_pod(out, ty::BOOL, &[u8::from(*v)]);
            Ok(())
        }
        Value::Bytes(v) => {
            out.push(ty::STRING);
            write_bytes(out, v)
        }
        Value::Object(section) => {
            out.push(ty::OBJECT);
            write_section(out, section)
        }
        Value::Array(array) => write_array(out, array),
    }
}

fn write_pod(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
    out.push(tag);
    out.extend_from_slice(bytes);
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    write_varint(
        out,
        u64::try_from(bytes.len()).map_err(|_| Error::VarintTooLarge)?,
    )?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn write_array(out: &mut Vec<u8>, array: &Array) -> Result<(), Error> {
    let tag = match array {
        Array::Int64(_) => ty::INT64,
        Array::Int32(_) => ty::INT32,
        Array::Int16(_) => ty::INT16,
        Array::Int8(_) => ty::INT8,
        Array::UInt64(_) => ty::UINT64,
        Array::UInt32(_) => ty::UINT32,
        Array::UInt16(_) => ty::UINT16,
        Array::UInt8(_) => ty::UINT8,
        Array::Double(_) => ty::DOUBLE,
        Array::Bytes(_) => ty::STRING,
        Array::Bool(_) => ty::BOOL,
        Array::Object(_) => ty::OBJECT,
    };
    out.push(tag | SERIALIZE_FLAG_ARRAY);
    write_varint(
        out,
        u64::try_from(array.len()).map_err(|_| Error::VarintTooLarge)?,
    )?;
    match array {
        Array::Int64(v) => {
            for x in v {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        Array::Int32(v) => {
            for x in v {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        Array::Int16(v) => {
            for x in v {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        Array::Int8(v) => {
            for x in v {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        Array::UInt64(v) => {
            for x in v {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        Array::UInt32(v) => {
            for x in v {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        Array::UInt16(v) => {
            for x in v {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        Array::UInt8(v) => out.extend_from_slice(v),
        Array::Double(v) => {
            for x in v {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        Array::Bytes(v) => {
            for s in v {
                write_bytes(out, s)?;
            }
        }
        Array::Bool(v) => {
            for x in v {
                out.push(u8::from(*x));
            }
        }
        Array::Object(v) => {
            for section in v {
                write_section(out, section)?;
            }
        }
    }
    Ok(())
}
