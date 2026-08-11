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
//! **self-authenticating by content**, which is why this crate signs
//! nothing. The two inputs a countersignature would need — the session
//! nonce construction and the signing key (attestation-leg-is-onion-key
//! vs sibling + proof-of-possession) — are both open format-round forks;
//! building either here would prejudge the fork, so the pass-record axis
//! lands with the format round, not with this loop.
//!
//! # `x-provisional/v0` — THROWAWAY framing, no vote in the format round
//!
//! The route is `GET /x-provisional/v0/shard/{shard_id}`. §9.5 records the
//! discipline verbatim: *"the provisional framing is THROWAWAY and gets no
//! vote in the format round."* The frozen response format is a
//! genesis-irreversible decision made on its own merits (including
//! resumability, which is a *format property* — the serving loop writes in
//! bounded chunks precisely so a future resumable format is a change of
//! framing, not a rewrite of the loop). Nothing about these bytes is a
//! proposal; a reviewer who finds `x-provisional/v0` cited in a design doc
//! should treat that as a bug.
//!
//! # What this crate is, and is not
//!
//! **Is:** the loopback listener ([`PServeEndpoint`]) and the store-backed
//! shard lookup ([`StoreShardProvider`]) — pure transport plus a read.
//! The endpoint binds `127.0.0.1:0` only; reachability comes from the
//! `ADD_ONION` mapping the daemon wires in (`shekyl-tor`), which is a
//! separate PR precisely because it carries the key-custody boundary
//! (§7.2(iii): the serving host receives **derived bundles only**, never
//! the master seed). This crate touches no key material at all.
//!
//! **Is not:** a pass-record builder, a countersigner, a wire format, or a
//! consensus surface. It is also not the W₂ rig — the rig extends this
//! loop with the concurrent-batch measurement shape (§9), and the two
//! placeholder pins carried here ([`serve::MAX_INFLIGHT`], inherited from
//! SPIKE-PIN-2) are derived there, on the provisioning-floor hardware.
//!
//! # Privacy invariants (carried from the SP-T3 spike as tests, not memories)
//!
//! - loopback-only bind, enforced at bind and again at the `ADD_ONION`
//!   target ([`shekyl_tor` `OnionPort::loopback`] on the daemon side);
//! - two personas served from one wallet are byte-identical at the header
//!   level ([`serve::RESPONSE_HEADER_NAMES`] is the complete set);
//! - every **complete-head** non-servable outcome — wrong path, wrong
//!   method, malformed route/id, **unknown shard, unfrozen shard, store
//!   failure** — renders one identical 404, so neither the route table
//!   nor store health is probeable;
//! - incomplete heads (oversized, mid-head EOF, read timeout) and
//!   over-capacity arrivals are **closed** with no HTTP bytes — the same
//!   class as ordinary circuit death, not a status-code oracle;
//! - no request logging at any level: the only observables are aggregate
//!   monotone counters.

#![forbid(unsafe_code)]

pub mod provider;
pub mod serve;

pub use provider::{ProviderError, ServeSetPin, ShardBody, ShardProvider, StoreShardProvider};
pub use serve::PServeEndpoint;
