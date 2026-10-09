// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `shekyl-p-fetch` — the daemon's shard-fetch client, the other half of
//! the protocol whose server is `shekyl-p-serve`.
//!
//! One client, two callers, one request. The challenge caller (a miner
//! answering a `D`-draw against `CHALLENGE_RESPONSE_BLOCKS`) and the
//! organic caller (a pruned daemon's fill scheduler reconstructing set-B)
//! enter the same [`PFetchClient::fetch`] (each naming its shard as an
//! [`ExpectedShard`] built from its own retained rows), take a slot from
//! the same [`MAX_INFLIGHT`] admission path, and put the same bytes on the
//! wire — so a serving `P` has no request-level way to tell which it is
//! answering (`SF-D1`, `SF-D7`). Schedulers name `P`; the HTTP path names
//! only `s`.
//!
//! # What one fetch is
//!
//! 1. Take an in-flight slot (wait if all [`MAX_INFLIGHT`] are held; there
//!    is no queue behind it — `SF-D7`).
//! 2. Dial `P`'s onion through the daemon's tor-zone SOCKS5 proxy, handing
//!    the proxy the `.onion` **name** to resolve (SOCKS5h). This crate never
//!    resolves anything (`SF-D2`, `SF-D3`).
//! 3. Write `GET /shard/{id}` with the one required header — the caller's
//!    72-byte [`RequestHeader`] `nonce ‖ anchor_height ‖ anchor_hash`, hex on
//!    the wire (`SF-D5`).
//! 4. Read a complete head. `200` → continue; `404` → [`FetchError::Miss`];
//!    `400` → [`FetchError::Rejected`]; `503` →
//!    [`FetchError::Unavailable`]; anything else complete →
//!    [`FetchError::Malformed`]; no complete head → [`FetchError::Stall`]
//!    (`SF-D6`, `RF-R1`).
//! 5. Bound the body from `content-length` **before** reading it — against
//!    [`ExpectedShard::max_response_len`], which the requester's own rows
//!    fix — then stream it: the `shekyl_wire::shard_frame` body over the
//!    shard's archival good (`SF-D8` amendment 2026-10-08), one transaction
//!    resident at a time. Each entry's declared lengths are checked against
//!    its retained row before its segments are read; each entry's segments
//!    are hashed against `txs_pqc_auth_hash` / `txs_prunable_hash`, folded
//!    into the shard's view hash, and handed to the caller's [`TxSink`],
//!    then dropped. The frame must end exactly where the fixed-width
//!    countersignature envelope begins. `P` sends the envelope last, so
//!    holding it means the whole body arrived; an envelope that is the
//!    refusal trailer is [`FetchError::Unsigned`]. A body that stops short
//!    of its declared length is a stall, wherever it stops.
//! 6. Verify `P`'s
//!    [`HybridSignature`](shekyl_crypto_pq::signature::HybridSignature)
//!    over `nonce ‖ anchor_height ‖ anchor_hash ‖ shard_id_le ‖ delivery_digest`
//!    under the bond-record key the caller supplied (`SF-D8`, `SF-D13`),
//!    the digest recomputed over every body byte under this request's own
//!    nonce and never taken from the response.
//! 7. Return the [`VerifiedShard`] — digest, signature, view hash, counts —
//!    or, if the content did not match the expectation under a signature
//!    that **did** verify, [`FetchError::ContentRefused`] naming the
//!    transaction `P` got wrong.
//!
//! # What this crate deliberately is not
//!
//! **It is not leaf-aware.** The unit is the `W`-shard's transaction range
//! (`SHT-Q2`) and nothing older: no leaf type, no segment geometry, no
//! tx/leaf polymorphism. One appearing here means the retired geometry
//! leaked back (`SHARD_VIEW_FETCH.md` §4).
//!
//! **It reads no chain state and holds no key.** Every input a fetch
//! needs — endpoint, verifying key, the shard's rows, anchor — arrives
//! typed in [`FetchTarget`], [`ExpectedShard`] and [`RequestHeader`],
//! obtained by the caller from local chain state and never from a
//! response. The types carry the provenance obligation the crate cannot
//! check itself (`SF-D7` amendment).
//!
//! **It does not retry.** The taxonomy in [`FetchError`] tells the
//! scheduler what happened and [`FetchError::next_move`] what to do about
//! this `P`; when to give up is the scheduler's (`SF-D6`: the axis is the
//! caller's).
//!
//! Dependency cut (`SF-D4`): `shekyl-curve-tree` for the shared route
//! grammar, `shekyl-wire` for the shared frame grammar and the `txid_parts`
//! row, `shekyl-crypto-pq` for the key and signature types,
//! `shekyl-archival-retention` for the transcript, its verifier and the
//! view-hash fold, and nothing from the serving side.
//! `scripts/ci/check_p_fetch_dep_cut.py` holds the edges.

pub mod client;
pub mod error;
pub mod header;
pub mod target;

pub use client::{PFetchClient, Timeouts, MAX_INFLIGHT, SIGNATURE_ENVELOPE_LEN};
pub use error::{FetchError, Malformed, NextMove, Stall};
pub use header::RequestHeader;
/// The content and grammar verdicts a fetch carries, re-exported so a
/// scheduler can match on them without naming the codec crate.
pub use shekyl_wire::shard_frame::{ContentMismatch, FrameError};
pub use target::{
    DiscardTxs, ExpectationError, ExpectedShard, FetchTarget, ServingEndpoint, TxSink,
    VerifiedShard, VerifiedTx,
};

#[cfg(test)]
mod client_tests;
