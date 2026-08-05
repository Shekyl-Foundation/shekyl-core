// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Levin p2p **framing** layer — the Shekyl-owned Rust skeleton of the wire
//! protocol specified in `docs/LEVIN_PROTOCOL.md`.
//!
//! # Scope (framing only, inert until wired)
//!
//! This crate owns the bottom layer of the p2p stack: the 33-byte bucket
//! header, the five message flows (notification / request / response /
//! fragmented / dummy), noise-shaped fragmentation for the white-noise
//! feature, the optional zstd `COMPRESSED` path, and an incremental
//! stream reader ([`BucketReader`]) that demultiplexes socket bytes into
//! complete messages.
//!
//! Deliberate **non-goals** of this crate:
//!
//! - the epee `portable_storage` payload codec and the p2p/cryptonote
//!   command schemas (handshake bodies, peerlist entries, …) — payloads
//!   here are opaque bytes;
//! - connection management, peerlists, timeouts, and invoke/response
//!   correlation (the `async_protocol_handler` layer);
//! - any daemon wiring or FFI. The C++ path in `contrib/epee` stays the
//!   live implementation until the scheduled p2p cutover.
//!
//! # Parity oracle
//!
//! The byte-level oracle is the C++ implementation:
//! `epee::levin::{make_header, make_noise_notify, make_fragmented_notify,
//! try_compress_message}` (`contrib/epee/src/levin_base.cpp`) and the
//! read-side state machine in
//! `contrib/epee/include/net/levin_protocol_handler_async.h`
//! (`handle_recv`). The tests mirror the `tests/unit_tests/levin.cpp`
//! gtest expectations byte for byte. Three **documented divergences**
//! (inner-signature verify, inner-length trim, logical-header response
//! classification) — see [`reader`] module docs.

mod compress;
mod error;
mod fragment;
mod header;
mod message;
mod reader;

pub use compress::{
    decompress_payload, is_compression_available, try_compress_message, COMPRESSION_MIN_PAYLOAD,
    DECOMPRESSED_MAX_SIZE, ZSTD_COMPRESSION_LEVEL,
};
pub use error::Error;
pub use fragment::{fragmented_notify, noise_notify};
pub use header::{
    BucketHead, Flags, DEFAULT_MAX_PACKET_SIZE, HEADER_SIZE, INITIAL_MAX_PACKET_SIZE,
    LEVIN_SIGNATURE, PROTOCOL_VERSION_1,
};
pub use message::{invoke, notify, response};
pub use reader::{BucketReader, Received};
