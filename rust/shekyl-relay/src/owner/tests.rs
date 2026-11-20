// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner's pure pieces. The owner on live sessions is `tests/owner.rs`.

use super::connection_id;
use shekyl_p2p_session::SocketId;
use shekyl_relay_privacy::stem_map::ConnectionId;

#[test]
fn a_socket_id_names_a_connection_without_colliding_with_local() {
    let a = connection_id(SocketId::from_ffi(1).expect("one is an id"));
    let b = connection_id(SocketId::from_ffi(2).expect("two is an id"));
    assert_ne!(a, b);
    assert_ne!(a, ConnectionId::from_bytes([0; 16]), "nil is this node");
    assert_eq!(
        a.as_bytes()[..8],
        1u64.to_le_bytes(),
        "the socket id is the first eight bytes, little-endian"
    );
    assert!(a.as_bytes()[8..].iter().all(|b| *b == 0));
}

#[test]
fn the_same_socket_id_names_the_same_connection() {
    let id = SocketId::from_ffi(0x0102_0304_0506_0708).expect("an id");
    assert_eq!(connection_id(id), connection_id(id));
}
