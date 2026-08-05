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
//! gtest expectations byte for byte, and a CI gate
//! (`.github/workflows/levin-constant-parity.yml`) fails the build if any
//! wire constant here stops matching its C++ definition.
//!
//! # Divergence census (authoritative)
//!
//! **This list is the single source of truth.** The README, the changelog,
//! `docs/LEVIN_PROTOCOL.md` and the `IMPLEMENTATION_INDEX` LV row point here
//! rather than restating it, because a second copy drifts and then lies.
//!
//! Every entry is *stricter* than the oracle — none accepts something the
//! C++ rejects. All but one are also unreachable for a conforming sender
//! (nothing `make_fragmented_notify` emits trips any of them); **divergence
//! 4 is the exception, and its reachable window is stated there.** Adding a
//! blanket "no conforming sender" to this list without checking each entry
//! is precisely the kind of unverified claim this census exists to stop.
//!
//! Read side ([`BucketReader`]):
//!
//! 1. **inner-signature verify** — the reassembled inner fragment header's
//!    signature is checked; the C++ `memcpy`s it without checking.
//! 2. **inner-length trim** — the inner header's `length` must fit the
//!    reassembled bytes and the delivered payload is trimmed to it; the C++
//!    forwards the fragment zero-padding to the command handler and relies
//!    on the payload parser ignoring trailing bytes.
//! 3. **logical-header classification** — response classification uses the
//!    delivered message's `protocol_version` (the inner header after
//!    reassembly). The C++ sticky `m_oponent_protocol_ver` is refreshed only
//!    on outer-header parse, so a crafted fragment train can disagree with
//!    this crate on whether a reassembled bucket is a response. Conforming
//!    outer fragment headers always carry version 1 and the protocol's
//!    fragment emitters only produce notifications.
//! 4. **post-inflate limit** — a decompressed payload is bounded by the same
//!    `min(packet limit, per-command limit)` its header was checked against.
//!    The C++ bounds the inflated size only by `DECOMPRESSED_MAX_SIZE`
//!    (128 MiB), which is larger than `LEVIN_DEFAULT_MAX_PACKET_SIZE` and
//!    512× the pre-handshake limit, so a compressed bucket there can deliver
//!    a payload far past the limit the connection is enforcing.
//!
//!    **This one has a reachable interop window** — the only entry that
//!    does, and it is stated rather than papered over. `COMPRESSED` is only
//!    ever set by `make_payload_send_txs` on `NOTIFY_NEW_TRANSACTIONS`,
//!    whose effective limit is `min(100 MB packet, 128 MB per-command)` =
//!    100 MB (`connection_context.cpp`, whose own comment notes the packet
//!    limit binds first). Nothing bounds the *uncompressed* relay batch on
//!    the sender side, so a batch inflating to 100–128 MB is accepted by a
//!    C++ receiver and rejected here: a ~34 MB window, needing on the order
//!    of 670 weight-limit transactions in one batch. The limit this reader
//!    enforces is the one the C++ table declares — the C++ misses it only
//!    because it never re-checks after inflating — and leaving it unchecked
//!    is a memory-exhaustion surface (a few KB of frame forcing a 128 MiB
//!    allocation per connection). Confirming the window is unreachable in
//!    real traffic, or widening the bound to `DECOMPRESSED_MAX_SIZE` for
//!    this one command, is an LV-3 cutover item: it needs a mixed C++/Rust
//!    network to measure against, which does not exist while this crate is
//!    unwired. Recorded in the FOLLOWUPS "Levin p2p migration" LV-3 entry.
//! 5. **error latch** — a framing error poisons the reader
//!    ([`Error::Poisoned`] on every later call). In the C++ the guard and
//!    the consequence are one statement — `handle_recv` returning `false`
//!    *is* the disconnect — so the question cannot arise there; here they
//!    are separate, and the latch keeps a caller that logs and continues
//!    from keeping a malformed peer alive.
//!
//! Emit side. [`BucketHead::write`], [`notify`] / [`invoke`] / [`response`],
//! [`noise_notify`] and [`fragmented_notify`] are byte-identical to the C++,
//! pinned assertion-for-assertion by `tests/oracle_kats.rs`. Two caveats,
//! neither of which those KATs cover:
//!
//! 6. **`try_compress_message` refuses malformed input** — a buffer whose
//!    header signature does not verify, whose `length` disagrees with the
//!    bytes after it (i.e. is not exactly one message), or which is the
//!    noise/fragment class comes back unchanged instead of being re-framed.
//!    The C++ `memcpy`s the header unchecked and would compress all three.
//!    See [`try_compress_message`] for why each matters.
//! 7. **compressed payload bytes are not pinned, and cannot be** — for a
//!    well-formed message the *framing* `try_compress_message` produces is
//!    byte-identical (same header, same `COMPRESSED` bit, same `length`
//!    discipline), but the compressed bytes themselves are whatever the
//!    linked libzstd emits at [`ZSTD_COMPRESSION_LEVEL`]. This crate and the
//!    C++ do not necessarily link the same libzstd — see the note on the
//!    `zstd` dependency in `Cargo.toml` — and zstd does not guarantee
//!    byte-stable output across versions. What is guaranteed is what
//!    actually matters on the wire: the frame format is stable, so either
//!    side decodes the other's. A byte-pinned KAT here would pin the codec
//!    build, not the protocol, and would break on a routine dependency
//!    bump.

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
