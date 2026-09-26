// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persona serving loop — the production half of the archival inbound
//! path (`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.5 item 3).
//!
//! A bonded persona `P` answers shard reads over its onion rendezvous: a
//! witness pulls the **entire shard** and verifies the bytes against the
//! chain-committed sub-root `R_k` (§2) — the response is
//! **self-authenticating by content** — and, since `SF-D8` (§9.1 step
//! (a), landed here), **bound to the request** by the persona's
//! countersignature over the decoded request header
//! `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖ shard_id_le[8]`
//! under `BondPost.hybrid_public_key`. The signature is produced by the
//! host's [`PassSigner`]; this crate still holds no key. The verifier the
//! daemon runs is step (a0)'s,
//! `shekyl_archival_retention::verify_pass_transcript`.
//!
//! # This crate's place in the §9.5 item-3 arc
//!
//! | Slice | Surface | This crate |
//! |----|---------|------------|
//! | **PR-A (here)** | Loopback serve + store serving read | owns |
//! | **PR-B** | `WalletTorControl` `ADD_ONION` / `DEL_ONION` + derived-bundle custody (§7.2(iii)) | no surface here |
//! | **VG-1…VG-3** | Native full-vanguards path selection | no surface here |
//! | **SH-1** | The composition: endpoint + onion + record-derived serve-set, one lifetime | consumer of [`PServeEndpoint::addr`] + [`StoreShardProvider`] |
//!
//! Dropping [`PServeEndpoint`] aborts the accept loop (test-friendly);
//! `shekyl-p-host` owns coordinated persona lifecycle (pin serve-set →
//! bind → publish onion → tear down) and did not need to grow this
//! crate's privacy contract to do it.
//!
//! # Request contract (`RF-R1`) — `GET /shard/{shard_id}`
//!
//! The route, status line, and header set are
//! `docs/design/ARCHIVAL_SERVING_ROUTE.md`. §9.5 of
//! `ARCHIVAL_CHALLENGE_MECHANISM.md` still excludes this HTTP shape from
//! the **format** round — that exclusion stands — and `RF-R1` is the
//! successor it lacked. Citing `/shard/` in a design doc is not a bug;
//! citing it as a format-round candidate still is.
//!
//! **The body is a different matter as of `RF-D4` (2026-08-20), and the two
//! must not be confused.** The response *payload* now carries the ruled
//! served frame — [`shekyl_curve_tree::served_frame::ServedFrameHeader`],
//! `leaf_count ‖ padding_len ‖ segment_bytes ‖ padding_bytes` — which **is**
//! genesis-frozen. The request half is the status line, the header set and
//! the route; the framed half is everything after `\r\n\r\n`. This crate
//! *emits* that frame, it does not define it: the definition lives in
//! `shekyl-curve-tree` because any fetcher already depends on that crate to
//! recompute `R_k`, and a format owned by the server would make every reader
//! depend on the writer.
//!
//! # What this crate is, and is not
//!
//! **Is:** the loopback listener ([`PServeEndpoint`]) and the store-backed
//! shard lookup ([`StoreShardProvider`]) — pure transport plus a read,
//! plus the [`PassSigner`] seam through which the host countersigns. The
//! endpoint binds `127.0.0.1:0` only; reachability comes from the
//! `ADD_ONION` mapping `shekyl-p-host` wires in. This crate holds no key
//! material — the signer is the host's object, and the serve loop sees
//! only the signature it returns — and, since [`StoreShardProvider`] is
//! built from a read-only `ServingReader`, it cannot write to the store
//! either.
//!
//! **Is not:** a pass-record builder, a key holder, the *definition* of a
//! wire format (it emits `RF-D4`'s frame; `shekyl-curve-tree` owns it), a
//! consensus surface, onion registration, or the W₂ rig. The rig extends
//! this loop with the concurrent-batch measurement shape (§9); the
//! placeholder [`serve::MAX_INFLIGHT`] (SPIKE-PIN-2) is derived there on
//! the provisioning-floor hardware (rule 76).
//!
//! # Privacy invariants (carried from the SP-T3 spike as tests, not memories)
//!
//! - loopback-only bind, enforced at bind and again at the `ADD_ONION`
//!   target (`shekyl_tor_control_wallet`'s `OnionPort::loopback`, on the host side);
//! - two personas served from one wallet are byte-identical at the header
//!   level ([`serve::RESPONSE_HEADER_NAMES`] is the complete set);
//! - every **complete-head** non-servable outcome — wrong path, wrong
//!   method, malformed route/id, missing / duplicate / malformed request
//!   header, out-of-gate anchor, **unknown shard, unfrozen shard, store
//!   failure, signer refusal** — renders one identical 404, so neither the
//!   route table nor store health nor key residency is probeable by
//!   **response bytes**;
//! - incomplete heads (oversized, mid-head EOF, read timeout) and
//!   over-capacity arrivals are **closed** with no HTTP bytes — the same
//!   class as ordinary circuit death, not a status-code oracle;
//! - which response a complete head gets is settled **before any byte is
//!   written**, so no miss can leak as a truncated `200`; the one residual
//!   ([`serve`], "the residual") is a body cut short by a stalled peer or a
//!   store fault, and is named rather than assumed away;
//! - no request logging at any level: the only observables are five
//!   aggregate monotone counters — served, refused, lookup failures, sign
//!   failures, and accept failures — none of which carries per-request
//!   structure.
//!
//! **Timing.** Byte identity is the invariant for complete-head misses.
//! Micro-timing differences between a wrong path (no store read) and a
//! valid-route miss (store read via `spawn_blocking`) are out of scope for
//! this loopback listener: the serving host places it behind onion RTT
//! noise, and
//! holdings/freeze progress are already chain-public. Do not invent
//! equalising delays here — they would not survive the onion path and
//! would only obscure local diagnostics.

#![forbid(unsafe_code)]

pub mod countersign;
pub mod provider;
pub mod serve;

#[cfg(any(test, feature = "test-signer"))]
pub use countersign::TestKeySigner;
pub use countersign::{
    anchor_within_gate, sign_pass_transcript, PassKey, PassSigner, SignRefused,
    SIGNATURE_ENVELOPE_LEN,
};
pub use provider::{ProviderError, ShardBody, ShardProvider, StoreShardProvider};
pub use serve::{
    PServeEndpoint, CONTENT_TYPE, MAX_INFLIGHT, MAX_REQUEST_BYTES, REQUEST_HEADER_NAME,
    RESPONSE_HEADER_NAMES, ROUTE_PREFIX,
};
pub use shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN;
