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
//! **Wiring status (2026-08-06):** the compression half is
//! **production-live** — the C++ `epee::levin` compression path is a
//! marshaling shim over the `shekyl_levin_*` FFI
//! (`rust/shekyl-ffi/src/levin_ffi.rs`), and the Rust-pinned libzstd is the
//! binary's single zstd (the system-libzstd link and `HAVE_ZSTD` gate are
//! gone). The seam is whole-message on the way out
//! ([`compress_message`], which `epee::levin::try_compress_message`
//! forwards to) and frame-level on the way in ([`inflated_size`] +
//! [`decompress_into`], which `epee::levin::decompress_payload` forwards
//! to). No compression policy is left in C++.
//!
//! The framing half — builders and [`BucketReader`] — stays inert until the
//! LV-3 cutover; the C++ path in `contrib/epee` remains the live framing
//! implementation.
//!
//! Deliberate **non-goals** of this crate:
//!
//! - the epee `portable_storage` payload codec and the p2p/cryptonote
//!   command schemas (handshake bodies, peerlist entries, …) — payloads
//!   here are opaque bytes until LV-2b. The codec decision is
//!   `docs/design/LV2_PORTABLE_STORAGE.md` (first-party `shekyl-portable-storage`,
//!   LV-2a); this crate grows typed command structs on top of that, it
//!   does not absorb the codec;
//! - connection management, peerlists, timeouts, and invoke/response
//!   correlation (the `async_protocol_handler` layer).
//!
//! # Parity oracle
//!
//! The byte-level oracle is the C++ implementation:
//! `epee::levin::{make_header, make_noise_notify, make_fragmented_notify}`
//! (`contrib/epee/src/levin_base.cpp`) and the read-side state machine in
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
//! [`noise_notify`] and [`fragmented_notify`] are byte-identical to the C++,
//! pinned assertion-for-assertion by `tests/oracle_kats.rs`. Two caveats,
//! neither of which those KATs cover:
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

mod compress;
mod error;
mod fragment;
mod header;
mod message;
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
pub use reader::{BucketReader, Received};
