// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A connection refused before its channel exists ends with FIN, never RST
//! (D10.2). A peer refused at accept has usually sent its first flight
//! already, and Linux answers a close with unread bytes queued with RST. The
//! far side tells the two apart: after an RST that follows the FIN, its
//! socket error is set.

use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::net::Shutdown;
use std::net::{TcpListener as StdListener, TcpStream as StdStream};
use std::time::{Duration, Instant};

use shekyl_p2p_transport::INITIATOR_FLIGHT_LEN;

use super::close_before_channel;

/// A connected pair whose server side holds `sent` bytes unread in its
/// receive queue.
fn pair_with_unread(sent: usize) -> (StdStream, StdStream) {
    let listener = StdListener::bind("127.0.0.1:0").expect("bind");
    let mut client = StdStream::connect(listener.local_addr().expect("addr")).expect("connect");
    client.write_all(&vec![0x5a; sent]).expect("the flight");
    let (server, _) = listener.accept().expect("accept");
    let mut peek = vec![0u8; sent];
    let start = Instant::now();
    while sent > 0 && server.peek(&mut peek).expect("peek") < sent {
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the flight arrives"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    (client, server)
}

/// What the far side saw: the read's result, then its socket error once
/// anything the close sent has had time to arrive.
fn far_side(mut client: StdStream) -> (std::io::Result<usize>, Option<std::io::Error>) {
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let mut buf = [0u8; 16];
    let read = client.read(&mut buf);
    std::thread::sleep(Duration::from_millis(50));
    (read, client.take_error().expect("socket error"))
}

fn refuse(server: StdStream) {
    server.set_nonblocking(true).expect("nonblocking");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        close_before_channel(tokio::net::TcpStream::from_std(server).expect("tokio stream")).await;
    });
}

/// The instrument can see an RST: a socket shut for writing and dropped with
/// a flight unread resets the far side. This is the kernel's behaviour, not
/// ours, pinned so the test below cannot pass by being blind.
#[cfg(target_os = "linux")]
#[test]
fn the_far_side_sees_a_reset_when_a_flight_is_left_unread() {
    let (client, server) = pair_with_unread(INITIATOR_FLIGHT_LEN);
    server.shutdown(Shutdown::Write).expect("fin");
    drop(server);
    let (read, error) = far_side(client);
    let reset = matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset)
        || error.is_some();
    assert!(reset, "read {read:?}, socket error {error:?}");
}

#[test]
fn a_refusal_with_a_flight_unread_ends_with_fin_not_rst() {
    let (client, server) = pair_with_unread(INITIATOR_FLIGHT_LEN);
    refuse(server);
    let (read, error) = far_side(client);
    assert_eq!(
        read.expect("an orderly end, not a reset"),
        0,
        "zero bytes written"
    );
    assert!(error.is_none(), "an RST followed the FIN: {error:?}");
}

#[test]
fn a_refusal_before_any_byte_arrives_ends_with_fin() {
    let (client, server) = pair_with_unread(0);
    refuse(server);
    let (read, error) = far_side(client);
    assert_eq!(read.expect("an orderly end"), 0);
    assert!(error.is_none(), "{error:?}");
}
