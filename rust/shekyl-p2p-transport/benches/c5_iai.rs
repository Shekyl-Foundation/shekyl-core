// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! C5's cells as instruction counts (`BENCHMARK_ALIGNMENT.md` BA-T24's
//! per-PR arm): what `c5.rs` times with criterion, each call counted on
//! its own.
//!
//! - **The handshake**, a step a row: the initiator's message 1, the
//!   responder's read of it and its message 2, and the initiator's read of
//!   message 2.
//! - **One record** of the interim framer, sealed (`SendHalf::seal`) and
//!   opened (`RecvHalf::open_one`): the two calls every byte a session
//!   sends or receives passes through today. A record is an encrypted
//!   two-byte length and an encrypted body, so each call is two AEAD
//!   operations. Two body sizes: a kilobyte, and the largest body a record
//!   carries, which a block response fills.
//! - **One window** sealed and opened on the raw directions: one AEAD
//!   operation each, as a fixed-window record is (`P2P_TRANSPORT_LAYER.md`
//!   D14 item 4). The window size is not ruled: the sizes are step 7's
//!   candidates, the same nine `c5.rs` times.
//! - **One rekey**: the HKDF a direction runs every `REKEY_NONCES` nonces.
//!
//! Every session is a whole handshake run in memory in setup, so its keys
//! differ run to run. The AEAD does the same work for any key, and each
//! row uses a session's first nonces, far from the rekey boundary. The
//! handshake rows generate keys inside the measured call and their counts
//! move with the draw; the manifest records the spread.
//!
//! `c5.rs` stays: it is the instrument a floor run times with. A count
//! here is the CI runner's x86 and never a floor figure (rule 76).

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use shekyl_p2p_transport::c5_bench::{self, OpenInit, Session, Windows};
use shekyl_p2p_transport::{RecvHalf, SendHalf};

/// The largest body one record carries.
const MAX_BODY: usize = 65_535;

/// `len` bytes that are not all one value.
fn body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[library_benchmark]
fn crypto_bench_noise_handshake_message1() -> (OpenInit, Vec<u8>) {
    black_box(OpenInit::message1())
}

fn message1() -> Vec<u8> {
    OpenInit::message1().1
}

#[library_benchmark]
#[bench::responder(setup = message1)]
fn crypto_bench_noise_handshake_message2(message1: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let message2 = black_box(c5_bench::responder_message2(black_box(&message1)));
    (message1, message2)
}

fn answered() -> (OpenInit, Vec<u8>) {
    let (initiator, message1) = OpenInit::message1();
    (initiator, c5_bench::responder_message2(&message1))
}

#[library_benchmark]
#[bench::initiator(setup = answered)]
fn crypto_bench_noise_handshake_finish((initiator, message2): (OpenInit, Vec<u8>)) -> Vec<u8> {
    initiator.finish(black_box(&message2));
    message2
}

fn before_seal(len: usize) -> (SendHalf, Vec<u8>) {
    (Session::connected().into_halves().0, body(len))
}

/// A receiving half and the one record its peer sealed for it.
fn before_open(len: usize) -> (RecvHalf, Vec<u8>, usize) {
    let (mut send, recv) = Session::connected().into_halves();
    let wire = send.seal(&body(len)).expect("the record seals");
    (recv, wire, len)
}

#[library_benchmark]
#[bench::body_1024(args = (1024), setup = before_seal)]
#[bench::body_65535(args = (MAX_BODY), setup = before_seal)]
fn crypto_bench_noise_record_seal(
    (mut send, body): (SendHalf, Vec<u8>),
) -> (SendHalf, Vec<u8>, Vec<u8>) {
    let wire = black_box(send.seal(black_box(&body)).expect("the record seals"));
    (send, body, wire)
}

#[library_benchmark]
#[bench::body_1024(args = (1024), setup = before_open)]
#[bench::body_65535(args = (MAX_BODY), setup = before_open)]
fn crypto_bench_noise_record_open(
    (mut recv, wire, len): (RecvHalf, Vec<u8>, usize),
) -> (RecvHalf, Vec<u8>, Vec<u8>) {
    let (body, used) = black_box(recv.open_one(black_box(&wire)).expect("the record opens"));
    assert_eq!((body.len(), used), (len, wire.len()));
    (recv, wire, body)
}

fn window_before_seal(len: usize) -> (Windows, Vec<u8>) {
    (Windows::connected(), body(len))
}

/// A direction pair and the one window sealed on it.
fn window_before_open(len: usize) -> (Windows, Vec<u8>, usize) {
    let mut windows = Windows::connected();
    let sealed = windows.seal(&body(len));
    (windows, sealed, len)
}

#[library_benchmark]
#[bench::w_256(args = (256), setup = window_before_seal)]
#[bench::w_512(args = (512), setup = window_before_seal)]
#[bench::w_1024(args = (1_024), setup = window_before_seal)]
#[bench::w_1400(args = (1_400), setup = window_before_seal)]
#[bench::w_2048(args = (2_048), setup = window_before_seal)]
#[bench::w_4096(args = (4_096), setup = window_before_seal)]
#[bench::w_8192(args = (8_192), setup = window_before_seal)]
#[bench::w_16384(args = (16_384), setup = window_before_seal)]
#[bench::w_65535(args = (MAX_BODY), setup = window_before_seal)]
fn crypto_bench_noise_window_seal(
    (mut windows, window): (Windows, Vec<u8>),
) -> (Windows, Vec<u8>, Vec<u8>) {
    let sealed = black_box(windows.seal(black_box(&window)));
    (windows, window, sealed)
}

#[library_benchmark]
#[bench::w_256(args = (256), setup = window_before_open)]
#[bench::w_512(args = (512), setup = window_before_open)]
#[bench::w_1024(args = (1_024), setup = window_before_open)]
#[bench::w_1400(args = (1_400), setup = window_before_open)]
#[bench::w_2048(args = (2_048), setup = window_before_open)]
#[bench::w_4096(args = (4_096), setup = window_before_open)]
#[bench::w_8192(args = (8_192), setup = window_before_open)]
#[bench::w_16384(args = (16_384), setup = window_before_open)]
#[bench::w_65535(args = (MAX_BODY), setup = window_before_open)]
fn crypto_bench_noise_window_open(
    (mut windows, sealed, len): (Windows, Vec<u8>, usize),
) -> (Windows, Vec<u8>, Vec<u8>) {
    let window = black_box(windows.open(black_box(&sealed)));
    assert_eq!(window.len(), len);
    (windows, sealed, window)
}

#[library_benchmark]
fn crypto_bench_noise_rekey() {
    c5_bench::rekey_once();
}

library_benchmark_group!(
    name = c5_group;
    benchmarks =
        crypto_bench_noise_handshake_message1,
        crypto_bench_noise_handshake_message2,
        crypto_bench_noise_handshake_finish,
        crypto_bench_noise_record_seal,
        crypto_bench_noise_record_open,
        crypto_bench_noise_window_seal,
        crypto_bench_noise_window_open,
        crypto_bench_noise_rekey
);

main!(library_benchmark_groups = c5_group);
