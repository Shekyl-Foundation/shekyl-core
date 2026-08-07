// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whole-message builders for the request / response / notification flows.
//! Each mirrors one `message_writer::finalize_*` shape from the C++ oracle
//! (`contrib/epee/src/levin_base.cpp`): header first, opaque payload after.

use crate::header::{BucketHead, Flags, HEADER_SIZE};

fn build(head: &BucketHead, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
    out.extend_from_slice(&head.write());
    out.extend_from_slice(payload);
    out
}

pub(crate) fn len_u64(payload: &[u8]) -> u64 {
    u64::try_from(payload.len()).expect("payload length fits in u64")
}

/// A one-way notification (`finalize_notify`): `Q` set, no response expected.
#[must_use]
pub fn notify(command: u32, payload: &[u8]) -> Vec<u8> {
    build(
        &BucketHead::make(command, len_u64(payload), Flags::REQUEST, false),
        payload,
    )
}

/// A request that expects a response (`finalize_invoke`): `Q` set,
/// `Expect Response` non-zero.
#[must_use]
pub fn invoke(command: u32, payload: &[u8]) -> Vec<u8> {
    build(
        &BucketHead::make(command, len_u64(payload), Flags::REQUEST, true),
        payload,
    )
}

/// A response to a prior request (`finalize_response`): `S` set, carrying the
/// command-specific return code.
#[must_use]
pub fn response(command: u32, return_code: i32, payload: &[u8]) -> Vec<u8> {
    let mut head = BucketHead::make(command, len_u64(payload), Flags::RESPONSE, false);
    head.return_code = return_code;
    build(&head, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::PROTOCOL_VERSION_1;

    #[test]
    fn notify_header_fields() {
        let msg = notify(2002, b"abc");
        let head = BucketHead::read(msg[..HEADER_SIZE].try_into().unwrap()).unwrap();
        assert_eq!(head.command, 2002);
        assert_eq!(head.payload_len, 3);
        assert!(!head.expects_response());
        assert_eq!(head.flags, Flags::REQUEST);
        assert_eq!(head.return_code, 0);
        assert_eq!(head.protocol_version, PROTOCOL_VERSION_1);
        assert_eq!(&msg[HEADER_SIZE..], b"abc");
    }

    #[test]
    fn invoke_sets_expect_response() {
        let msg = invoke(1001, &[]);
        let head = BucketHead::read(msg[..HEADER_SIZE].try_into().unwrap()).unwrap();
        assert!(head.expects_response());
        assert_eq!(head.flags, Flags::REQUEST);
    }

    #[test]
    fn response_carries_return_code() {
        let msg = response(1001, -4, b"x");
        let head = BucketHead::read(msg[..HEADER_SIZE].try_into().unwrap()).unwrap();
        assert_eq!(head.flags, Flags::RESPONSE);
        assert_eq!(head.return_code, -4);
        assert!(!head.expects_response());
    }
}
