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
//! This crate owns the bottom layer of the p2p stack: the 29-byte bucket
//! header, the five message flows (notification / request / response /
//! fragmented / dummy), noise-shaped fragmentation for the white-noise
//! feature, and an incremental stream reader ([`BucketReader`]) that
//! demultiplexes socket bytes into complete messages.
//!
//! The protocol has no compression (Rick, 2026-10-19,
//! `docs/benchmarks/zstd_ruzstd_levin_20261020.md`): a bucket carrying the
//! old `0x10` flag bit is refused at ingress like any undefined bit.
//!
//! **Wiring status.** Since the p2p remnant cutover
//! (`P2P_3_REMNANT_CUTOVER_BRIEF.md`) this crate is the only Levin
//! implementation in the tree: `shekyl-p2p-session` reads every socket
//! through [`BucketReader`] and writes every message through [`notify`] /
//! [`invoke`] / [`response`], and the ingress policy (PWD-B3 / PWD-B3a /
//! PWD-B4, [`ingress_payload_cap`]) runs in the session's reader. The epee
//! Levin stack (`levin_base`, `levin_protocol_handler_async`) and the
//! `shekyl_levin_*` FFI shims over this crate were deleted with the C++
//! host. *Records-was (2026-08-13 to 2026-11-05):* the emit side was live
//! through the FFI from 2026-08-13 and the read side inert until LV-3; the
//! C++ `handle_recv` called `shekyl_levin_ingress_admit`.
//!
//! Deliberate **non-goals** of this crate:
//!
//! - the epee `portable_storage` **codec** — that is
//!   `shekyl-portable-storage` (LV-2a). This crate owns the typed Levin
//!   maps on top of it (LV-2b): handshake / timed-sync (1001 / 1002),
//!   `network_address`, and
//!   notifies 2002–2004 / 2006–2010. Cryptonote blobs stay opaque bytes
//!   (`shekyl-wire`); RPC maps stay out.
//! - connection management, timeouts, and invoke/response correlation
//!   (`shekyl-p2p-session`).
//!
//! # Parity oracle
//!
//! There is no C++ oracle any more. The byte-level pins are
//! `tests/oracle_kats.rs`, whose expectations were transcribed assertion
//! for assertion from the deleted gtests (`tests/unit_tests/levin.cpp`,
//! `make_noise.*` / `make_fragment.*`) and from `docs/LEVIN_PROTOCOL.md`'s
//! byte layout; the wire constants are this crate's own, pinned there.
//! The LV-1 constant-parity gate (`check_levin_constant_parity.sh`) was
//! deleted with the C++ definitions it compared against.
//!
//! # Divergence census (authoritative)
//!
//! **This list is the single source of truth.** The README, the changelog,
//! `docs/LEVIN_PROTOCOL.md` and the `IMPLEMENTATION_INDEX` LV row point here
//! rather than restating it, because a second copy drifts and then lies.
//!
//! Every entry is *stricter* than the deleted C++ oracle was — none accepts
//! something it rejected — and each is unreachable for a conforming sender
//! today. The entries are kept as the record of where this crate's
//! behaviour was chosen over the inherited one.
//! One entry (6) closed at the 2026-09-09 PWD-B3/B3a/B4 ingress cut; it is
//! kept as the record of how it closed. That is deliberate, because "the
//! difference went away" is exactly the kind of claim that rots into
//! folklore once the entry is deleted. Adding a
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
//! 4. **error latch** — a framing error poisons the reader
//!    ([`Error::Poisoned`] on every later call). In the C++ the guard and
//!    the consequence are one statement — `handle_recv` returning `false`
//!    *is* the disconnect — so the question cannot arise there; here they
//!    are separate, and the latch keeps a caller that logs and continues
//!    from keeping a malformed peer alive.
//!
//! Emit side. [`BucketHead::write`], [`notify`] / [`invoke`] / [`response`],
//! [`noise_notify`] and [`fragmented_notify`] are pinned assertion-for-
//! assertion by `tests/oracle_kats.rs`. One caveat, which those KATs do
//! not cover:
//!
//! 5. **emit refuses an oversize bucket** — [`noise_notify`] /
//!    [`fragmented_notify`] reject when the bucket they would write has
//!    `m_cb` above [`DEFAULT_MAX_PACKET_SIZE`] (the payload limit the
//!    reader already enforces). Detected before any allocation. The
//!    deleted C++ allocated first and left the peer to drop it. The bound
//!    is on each on-wire body's `m_cb`, not on the inner payload that
//!    fragmentation exists to split. Unreachable for a conforming sender
//!    (production noise is 3 KiB).
//! 6. **unknown flags / unknown dispatch commands rejected at ingress** —
//!    *resolved 2026-09-09; no longer a divergence.* Both sides apply
//!    [`ingress_payload_cap`]: unknown flag bits are fatal on every bucket;
//!    a Q/S-flagged command that is not a [`Command`] is fatal; a
//!    noise/fragment bucket (neither Q nor S) is bounded only by the packet
//!    limit so cover traffic with command 0 is not an unknown command. The
//!    codec still round-trips unknown bits (PWC-A6); ingress is what
//!    refuses to process them.

mod error;
mod fragment;
mod header;
mod ingress;
mod message;
mod payload;
mod reader;

pub use error::Error;
pub use fragment::{fragmented_notify, noise_notify};
pub use header::{
    AfterFrame, BucketHead, Flags, FrameHeads, HandshakeFrame, HandshakeKind,
    DEFAULT_MAX_PACKET_SIZE, HEADER_SIZE, INITIAL_MAX_PACKET_SIZE, LEVIN_SIGNATURE,
    PROTOCOL_VERSION_1,
};
pub use ingress::{
    ingress_payload_cap, Command, BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT, FLAGS_DEFINED,
    HANDSHAKE_FIXED_MAX_BYTES, MAX_OBJECT_REQUEST_COUNT, PEERLIST_ENTRY_MAX_ENCODED_BYTES,
};
pub use message::{invoke, notify, response};
pub use payload::Error as PayloadError;
pub use payload::{body_budget_bytes, plan_bodies, BodiesFormFault, BodyPlan, BodyPlanner};
pub use payload::{
    BasicNodeData, BlockCompleteEntry, CoreSyncData, GetTxpoolComplement, HandshakeRequest,
    HandshakeResponse, NetworkAddress, NewCompactBlock, NewTransactions, PeerlistEntry,
    PortableMap, RequestBodies, RequestCompactMissingTx, RequestHeaders, ResponseBodies,
    ResponseHeaders, SyncCommand, TimedSyncRequest, TimedSyncResponse, TxBlobEntry, ADDR_IPV4,
    ADDR_IPV6, ADDR_TOR, ATTESTATION_WITNESS_MAX_BYTES, BODIES_RESPONSE_BYTES, CAP_REQUEST_BODIES,
    CAP_REQUEST_HEADERS, CAP_RESPONSE_BODIES, CAP_RESPONSE_HEADERS, COMMAND_HANDSHAKE,
    COMMAND_TIMED_SYNC, HASH_SIZE, HEADERS_RESPONSE_BYTES, MIN_TX_SECTION_BYTES,
    NOTIFY_GET_TXPOOL_COMPLEMENT, NOTIFY_NEW_COMPACT_BLOCK, NOTIFY_NEW_TRANSACTIONS,
    NOTIFY_REQUEST_BODIES, NOTIFY_REQUEST_COMPACT_MISSING_TX, NOTIFY_REQUEST_HEADERS,
    NOTIFY_RESPONSE_BODIES, NOTIFY_RESPONSE_HEADERS, RESPONSE_BODIES_MAX_FIELDS,
    RESPONSE_BODIES_MAX_OBJECTS, RESPONSE_BODIES_MAX_STRINGS, RESPONSE_BODIES_MAX_TXS,
    RESPONSE_HEADERS_MAX_STRINGS,
};
pub use reader::{BucketReader, Received};
