// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The production dial path stamps what it observed (`DIALER_OUTAGE_EVIDENCE.md`
//! §8, step 2b): the hub's dial, over the real zone dialer and the real
//! connectors on localhost, ends with the connector's own table entry. This
//! is the result the dialer's attempt task awaits (`Hub::dial_channel_async`).

use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdListener, TcpStream as StdStream};
use std::thread;
use std::time::Duration;

use shekyl_seam::{Direction, Endpoint};
use shekyl_transport_layer::DialEnd;

use super::*;
use crate::inbound_ceiling_ffi::{ShekylInboundCeiling, SHEKYL_INBOUND_CEILING_UNLIMITED};
use crate::seam_ffi::{shekyl_seam_bind, shekyl_seam_set_ceiling, ShekylSeamObserved};

unsafe extern "C" fn discard(
    _ctx: *mut c_void,
    _id: u64,
    _kind: u32,
    _observed: *const ShekylSeamObserved,
    _bytes: *const u8,
    _len: usize,
    _cause: *const CloseCause,
) {
}

/// The hub's dial to `endpoint`, awaited off the host's runtime. A dial
/// that was admitted has no end yet; this test wants every dial to fail.
fn dial_end(hub: &Hub, endpoint: Endpoint) -> DialEnd {
    let waiter = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    waiter.block_on(async {
        match tokio::time::timeout(Duration::from_secs(10), hub.dial_channel_async(&endpoint)).await
        {
            Ok(Err(end)) => end,
            Ok(Ok(_)) => panic!("{endpoint:?} was admitted"),
            Err(_) => panic!("{endpoint:?} did not end"),
        }
    })
}

fn clearnet_at(port: u16) -> Endpoint {
    Endpoint::Clearnet {
        ip: Ipv4Addr::LOCALHOST.into(),
        port,
        direction: Direction::Outbound,
    }
}

/// A listener on localhost that hands each connection it takes to `serve`.
fn listening(serve: impl Fn(StdStream) + Send + 'static) -> u16 {
    let listener = StdListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            serve(stream);
        }
    });
    port
}

/// A SOCKS5 server that takes the no-auth greeting and answers every
/// CONNECT with `reply`.
fn socks_replying(reply: u8) -> SocketAddr {
    let listener = StdListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    let at = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut greeting = [0u8; 3];
            if stream.read_exact(&mut greeting).is_err() || greeting != [0x05, 1, 0x00] {
                continue;
            }
            drop(stream.write_all(&[0x05, 0x00]));
            let mut head = [0u8; 5];
            if stream.read_exact(&mut head).is_err() || head[3] != 0x03 {
                continue;
            }
            let mut rest = vec![0u8; usize::from(head[4]) + 2];
            if stream.read_exact(&mut rest).is_err() {
                continue;
            }
            drop(stream.write_all(&[0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        }
    });
    at
}

/// A key whose onion address the Tor connector dials: a valid ed25519
/// point.
fn onion_key() -> [u8; 32] {
    (1u8..=255)
        .map(|n| [n; 32])
        .find(|key| shekyl_onion_v3::v3_pubkey(&shekyl_onion_v3::v3_onion_hostname(key)).is_some())
        .expect("a valid key")
}

/// Each failure the production path observes ends with its connector's own
/// row: clearnet's refused port, broken handshake and silent listener, and
/// each scripted Tor reply. `0x06` at the window is the reply's stamp here;
/// whether it ends its test is the dialer's reading of the attempt's run time
/// (the attempts tests). The edit that makes this red is a drive or the zone
/// dialer building an end itself instead of reading the connector's table.
#[test]
fn the_production_dial_path_ends_with_the_connectors_own_row() {
    let _bind = crate::seam_ffi::seam_bind_lock().lock();
    let mut executor = 0u8;
    let ceiling = ShekylInboundCeiling {
        kind: SHEKYL_INBOUND_CEILING_UNLIMITED,
        ceiling: 0,
        soft_limit: 0,
        held: 0,
    };
    let bound = unsafe {
        shekyl_seam_bind(
            std::ptr::addr_of_mut!(executor).cast::<c_void>(),
            Some(discard),
        )
    };
    assert_eq!(bound, 0);
    assert_eq!(unsafe { shekyl_seam_set_ceiling(&raw const ceiling) }, 0);
    let network_id = [13u8; 16];
    start_clearnet(
        &[SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
        None,
        true,
        network_id,
    )
    .expect("clearnet starts");
    let hub = crate::seam_ffi::hub().expect("bound");

    let refusing = {
        let listener = StdListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
        listener.local_addr().expect("addr").port()
    };
    assert_eq!(
        dial_end(&hub, clearnet_at(refusing)),
        shekyl_clearnet::Observed::ConnectRefused.end(),
        "a refusing port"
    );
    let breaking = listening(drop);
    assert_eq!(
        dial_end(&hub, clearnet_at(breaking)),
        shekyl_clearnet::Observed::HandshakeBroken.end(),
        "a peer that breaks the handshake"
    );
    let silent = listening(|stream| {
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(5));
            drop(stream);
        });
    });
    assert_eq!(
        dial_end(&hub, clearnet_at(silent)),
        shekyl_clearnet::Observed::HandshakeDeadline.end(),
        "a listener that never answers"
    );

    for reply in [0x05u8, 0x06, 0xF0, 0x03] {
        dial_through_tor(
            shekyl_socks::Proxy::unauthenticated(socks_replying(reply)),
            network_id,
        )
        .expect("the proxy install");
        let onion = Endpoint::Tor {
            key: onion_key(),
            port: 18080,
        };
        assert_eq!(
            dial_end(&hub, onion),
            shekyl_tor::reply_end(u16::from(reply)),
            "tor reply {reply:#x}"
        );
    }

    shutdown();
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None);
    }
}
