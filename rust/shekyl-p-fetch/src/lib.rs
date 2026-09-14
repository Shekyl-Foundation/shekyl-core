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
//! enter the same [`PFetchClient::fetch`] (each plugging its
//! [`ContentVerify`] hole for that shard), take a slot from the same
//! [`MAX_INFLIGHT`] admission path, and put the same bytes on the wire — so
//! a serving `P` has no request-level way to tell which it is answering
//! (`SF-D1`, `SF-D7`). Schedulers name `P`; the HTTP path names only `s`.
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
//!    anything else complete → [`FetchError::Malformed`]; no complete head
//!    → [`FetchError::Stall`] (`SF-D6`, `RF-R1`).
//! 5. Bound the body from `content-length` **before** reading it, read
//!    exactly that many bytes, and split the fixed-width countersignature
//!    envelope off the front.
//! 6. Verify `P`'s [`HybridSignature`](shekyl_crypto_pq::signature::HybridSignature)
//!    over the decoded header ‖ `shard_id_le` under the bond-record key
//!    the caller supplied (`SF-D8`, `SF-D13`).
//! 7. Hand the remaining bytes — a `Vec<u8>`, nothing more shaped than that
//!    — to the caller's [`ContentVerify`] hole.
//!
//! # What this crate deliberately is not
//!
//! **It is not unit-aware.** The body is bytes. Sub-PR 1 lands the
//! transport and the transport-authenticity check (the countersignature);
//! what those bytes *are* — today an `RF-D4` frame over a leaf shard,
//! tomorrow whatever `PDM-Q6` rules — is sub-PR 2's, behind
//! [`ContentVerify`]. A leaf type, a frame parse, or a tx/leaf polymorphism
//! appearing in this crate means the split leaked
//! (`docs/FOLLOWUPS.md`, "Implement the daemon shard-fetch client"). The
//! one place the leaf figure appears is [`max_body_bytes`], the provisional
//! resource ceiling, and it says so.
//!
//! **It reads no chain state and holds no key.** Every input a fetch
//! needs — endpoint, verifying key, shard id, anchor — arrives typed in
//! [`FetchTarget`] and [`RequestHeader`], obtained by the caller from local
//! chain state and never from a response. The types carry the provenance
//! obligation the crate cannot check itself (`SF-D7` amendment).
//!
//! **It does not retry.** The taxonomy in [`FetchError`] tells the
//! scheduler what happened; whom to name next and when to give up is the
//! scheduler's (`SF-D6`: the axis is the caller's).
//!
//! Dependency cut (`SF-D4`): `shekyl-curve-tree` for the shared route
//! grammar, `shekyl-crypto-pq` for the key and signature types,
//! `shekyl-archival-retention` for the transcript and its verifier, and
//! nothing from the serving side. `scripts/ci/check_p_fetch_dep_cut.py`
//! holds the edges.

pub mod client;
pub mod error;
pub mod header;
pub mod target;

pub use client::{max_body_bytes, PFetchClient, Timeouts, MAX_INFLIGHT, SIGNATURE_ENVELOPE_LEN};
pub use error::{FetchError, Malformed, Stall};
pub use header::RequestHeader;
pub use target::{ContentRefused, ContentVerify, FetchTarget, ServingEndpoint, VerifiedShard};

#[cfg(test)]
mod client_tests;
