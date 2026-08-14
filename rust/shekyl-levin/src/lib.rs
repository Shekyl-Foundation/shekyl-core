// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Levin p2p **framing** layer — the Shekyl-owned Rust skeleton of the wire
//! protocol specified in `docs/LEVIN_PROTOCOL.md`.
//!
//! # Scope (framing only)
//!
//! This crate owns the bottom layer of the p2p stack: the 33-byte bucket
//! header, the five message flows (notification / request / response /
//! fragmented / dummy), noise-shaped fragmentation for the white-noise
//! feature, the optional zstd `COMPRESSED` path, and an incremental
//! stream reader ([`BucketReader`]) that demultiplexes socket bytes into
//! complete messages.
//!
//! **Wiring status (2026-08-13):** the **entire emit side and the
//! compression path are production-live** through the `shekyl_levin_*` FFI
//! (`rust/shekyl-ffi/src/levin_ffi.rs`):
//!
//! - compression (2026-08-06): whole-message [`compress_message`] out,
//!   frame-level [`inflated_size`] + [`decompress_into`] in; the
//!   Rust-pinned libzstd is the binary's single zstd and no compression
//!   policy is left in C++;
//! - white-noise emit (2026-08-13): [`noise_notify`] and
//!   [`fragmented_notify`] back `epee::levin::make_noise_notify` /
//!   `make_fragmented_notify`, so the fragment-padding algorithm — the
//!   privacy-load-bearing emit logic — has exactly one implementation,
//!   and the byte-exact `make_fragment.*` gtests exercise this crate live.
//!
//! Still inert until LV-3: the read side ([`BucketReader`]) and the plain
//! notification/request/response builders (the C++ `message_writer` keeps
//! the hot finalize path).
//!
//! Deliberate **non-goals** of this crate:
//!
//! - the epee `portable_storage` **codec** — that is
//!   `shekyl-portable-storage` (LV-2a). This crate owns the typed Levin
//!   maps on top of it (LV-2b): handshake / timed-sync / ping /
//!   support-flags (1001 / 1002 / 1003 / 1007), `network_address`, and
//!   notifies 2001–2004 / 2006–2010. Cryptonote blobs stay opaque bytes
//!   (`shekyl-wire`); RPC maps stay out. Live `shekyld` dual-stack is
//!   the named remaining of `LV2_PORTABLE_STORAGE.md` §12 step 4 (no
//!   daemon in crate unit tests).
//! - connection management, timeouts, and invoke/response correlation
//!   (the `async_protocol_handler` layer).
//!
//! # Parity oracle
//!
//! The remaining C++-side oracles are `epee::levin::make_header` (the hot
//! `message_writer::finalize` path, still C++) and the read-side state
//! machine in `contrib/epee/include/net/levin_protocol_handler_async.h`
//! (`handle_recv`). `make_noise_notify` / `make_fragmented_notify` are
//! forwarding shims over this crate and are no longer an independent
//! implementation: the byte-level oracle for those emitters is the gtest
//! *expectations* in `tests/unit_tests/levin.cpp` (`make_noise.*` /
//! `make_fragment.*`), which now execute through the FFI. A CI gate
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
//! C++ rejects — and each is unreachable for a conforming sender today.
//! Two entries (4 and 6) stopped being divergences at the 2026-08-06
//! compression cut and are kept as the record of how they closed; that is
//! deliberate, because "the difference went away" is exactly the kind of
//! claim that rots into folklore once the entry is deleted. Adding a
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
//! 4. **post-inflate limit** — *resolved 2026-08-06; no longer a
//!    divergence.* A decompressed payload is bounded by the same
//!    `min(packet limit, per-command limit)` its header was checked
//!    against, and since the compression-shim cut the C++ receiver
//!    enforces the identical bound at its decompress site
//!    (`levin_protocol_handler_async.h`, `max_decompressed`), closing what
//!    was a ~34 MB accept-window on `NOTIFY_NEW_TRANSACTIONS` (C++
//!    previously bounded inflation only by the 128 MiB
//!    `DECOMPRESSED_MAX_SIZE`, 512× the pre-handshake packet limit — a
//!    memory-exhaustion surface where a few KB of frame forced a 128 MiB
//!    allocation per connection). Both implementations now agree; the
//!    entry stays in the census as the record that the bound is deliberate
//!    on both sides.
//! 5. **error latch** — a framing error poisons the reader
//!    ([`Error::Poisoned`] on every later call). In the C++ the guard and
//!    the consequence are one statement — `handle_recv` returning `false`
//!    *is* the disconnect — so the question cannot arise there; here they
//!    are separate, and the latch keeps a caller that logs and continues
//!    from keeping a malformed peer alive.
//!
//! Emit side. [`BucketHead::write`], [`notify`] / [`invoke`] / [`response`],
//! [`noise_notify`] and [`fragmented_notify`] are pinned assertion-for-
//! assertion by `tests/oracle_kats.rs` and, for the wired emitters, by the
//! `make_noise.*` / `make_fragment.*` gtests which now execute through the
//! FFI. Three caveats, none of which those KATs cover:
//!
//! 6. **`try_compress_message` refuses malformed input** — *resolved
//!    2026-08-06; no longer a divergence.* A buffer whose header signature
//!    does not verify, whose `length` disagrees with the bytes after it
//!    (i.e. is not exactly one message), or which is the noise/fragment
//!    class comes back unchanged instead of being re-framed. The C++ used
//!    to `memcpy` the header unchecked and would have compressed all three
//!    — the noise case being the one that mattered, since shortening a
//!    dummy makes cover traffic distinguishable from real traffic on the
//!    wire. The compression cut deleted that copy: `epee::levin::
//!    try_compress_message` now forwards to [`compress_message`], so these
//!    guards are the emit path rather than a difference from it. See
//!    [`try_compress_message`] for why each matters.
//! 7. **compressed payload bytes are not pinned, and cannot be** — for a
//!    well-formed message the *framing* `try_compress_message` produces is
//!    byte-identical (same header, same `COMPRESSED` bit, same `length`
//!    discipline), but the compressed bytes themselves are whatever the
//!    linked libzstd emits at [`ZSTD_COMPRESSION_LEVEL`]. Since the
//!    compression-shim cut (2026-08-06) the C++ reaches *this crate's*
//!    libzstd through the FFI, so today the bytes trivially agree — but
//!    zstd does not guarantee byte-stable output across versions, and a
//!    byte-pinned KAT would pin the codec build, not the protocol,
//!    breaking on a routine dependency bump. What is guaranteed is what
//!    actually matters on the wire: the frame format is stable, so any
//!    zstd decodes any other's frames.
//! 8. **emit refuses an oversize bucket** — [`noise_notify`] /
//!    [`fragmented_notify`] reject when the bucket they would write has
//!    `m_cb` above [`DEFAULT_MAX_PACKET_SIZE`] (the payload limit the
//!    reader already enforces). Detected before any allocation. The
//!    deleted C++ allocated first and left the peer to drop it. The bound
//!    is on each on-wire body's `m_cb`, not on the inner payload that
//!    fragmentation exists to split. Unreachable for a conforming sender
//!    (production noise is 3 KiB).

mod compress;
mod error;
mod fragment;
mod header;
mod message;
mod payload;
mod reader;

pub use compress::{
    compress_message, compress_payload, decompress_into, decompress_payload, inflated_size,
    is_compression_available, try_compress_message, COMPRESSION_MIN_PAYLOAD, DECOMPRESSED_MAX_SIZE,
    ZSTD_COMPRESSION_LEVEL,
};
pub use error::Error;
pub use fragment::{fragmented_notify, noise_notify};
pub use header::{
    BucketHead, Flags, DEFAULT_MAX_PACKET_SIZE, HEADER_SIZE, INITIAL_MAX_PACKET_SIZE,
    LEVIN_SIGNATURE, PROTOCOL_VERSION_1,
};
pub use message::{invoke, notify, response};
pub use payload::Error as PayloadError;
pub use payload::{
    BasicNodeData, BlockCompleteEntry, CoreSyncData, GetTxpoolComplement, HandshakeRequest,
    HandshakeResponse, NetworkAddress, NewBlock, NewFluffyBlock, NewTransactions, PeerlistEntry,
    PingRequest, PingResponse, PortableMap, RequestChain, RequestFluffyMissingTx,
    RequestGetObjects, ResponseChainEntry, ResponseGetObjects, SupportFlagsRequest,
    SupportFlagsResponse, TimedSyncRequest, TimedSyncResponse, TxBlobEntry, ADDR_I2P, ADDR_IPV4,
    ADDR_IPV6, ADDR_TOR, ATTESTATION_WITNESS_MAX_BYTES, COMMAND_HANDSHAKE, COMMAND_PING,
    COMMAND_REQUEST_SUPPORT_FLAGS, COMMAND_TIMED_SYNC, HASH_SIZE, NOTIFY_GET_TXPOOL_COMPLEMENT,
    NOTIFY_NEW_BLOCK, NOTIFY_NEW_FLUFFY_BLOCK, NOTIFY_NEW_TRANSACTIONS, NOTIFY_REQUEST_CHAIN,
    NOTIFY_REQUEST_FLUFFY_MISSING_TX, NOTIFY_REQUEST_GET_OBJECTS, NOTIFY_RESPONSE_CHAIN_ENTRY,
    NOTIFY_RESPONSE_GET_OBJECTS, PING_OK,
};
pub use reader::{BucketReader, Received};
