// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The peer lists (`docs/design/P2P_3_SLICE_1_PEERLIST_BRIEF.md`).
//!
//! Two lists per connector and one door between them. **Gray** is every
//! address that arrived and has not been confirmed: gossip, a peerlist a
//! neighbour sent, an inbound peer, `--add-peer`, every address reloaded
//! from disk. **White** is an address this node confirmed by dialling it:
//! the only way in is a uniform gray draw that the dialer then reports as
//! `SessionAccepted` or `Confirmed` (brief §2), or a Foundation-fleet
//! harvest (§3). Nothing else writes white — not an inbound session, not a
//! transcript, not an operator assertion — and that is a type fact here:
//! there is no exported white type, and the only function that writes a
//! white seat is [`Peerlist::apply`].
//!
//! An address has one seat. An outstanding draw is still gray: it counts
//! toward gray, the snapshot names it gray, and the file keeps it. It is
//! not also white, and eviction does not take it.
//!
//! Lists are partitioned by connector, derived from the address type
//! through the transport layer's declaration ([`connector_for`]) at every
//! admit and never stored (ruled 2026-09-25). No entry crosses: a draw, a
//! sample, an eviction and a reload each work inside one partition.
//!
//! The 2026-10-09 rulings this crate carries: **D3** — the disclosure
//! sample is [`DISCLOSE_COUNT`] (12) addresses, a protocol constant on
//! every node and connector, drawn uniformly once per connector per
//! 24-hour window and sent unchanged to every requester in the window;
//! **D4** — a ban demotes a white entry to gray at the next white read and
//! never removes it; **D-S1** — gray intake is capped at
//! [`SESSION_INTAKE_CAP`] distinct addresses per session in any 24-hour
//! span. Each constant is labelled `Assumption` in
//! `DAEMON_RELAY_PRIVACY.md` §97 and is derived on the Rust path after the
//! slice 3 cutover.
//!
//! This crate is data. It holds no socket, dials nothing, and has no FFI.
//! The dialer (P2P-3 slice 3) is the consumer of every draw and the only
//! caller of [`Peerlist::apply`]; the C++ peer list it replaces is deleted
//! at the cutover (brief §13, increment 3).
//!
//! The white type is not exported, so no caller can build a white entry
//! (brief §11.1):
//!
//! ```compile_fail,E0432
//! use shekyl_peerlist::White;
//! ```

#![deny(unsafe_code)]

mod index;
mod outcome;
mod partition;
mod peerlist;
mod sample;

#[cfg(feature = "conformance")]
pub mod conformance;

pub use outcome::{DialOutcome, ListName, Refusal, Source};

pub use peerlist::{BanQuery, NoBans, Peerlist, Snapshot};
pub use shekyl_net_address::NetworkAddress;
/// A daemon connection. The type is `shekyl_relay_privacy::ConnectionId`;
/// re-exported so a peerlist session and a stem source are one id. F4 moves
/// that vocabulary; this re-export does not.
pub use shekyl_relay_privacy::ConnectionId;
pub use shekyl_timing_engine::Tick;
pub use shekyl_transport_layer::{connector_for, ConnectorId};

/// `DISCLOSE_COUNT`: how many white addresses one disclosure sample
/// carries, and the most a received message may carry (D3, Rick,
/// 2026-10-09). A protocol constant: the same on every node and every
/// connector, not tied to the outbound target. Replaces
/// `P2P_DEFAULT_PEERS_IN_HANDSHAKE` and `P2P_MAX_PEERS_IN_HANDSHAKE`
/// (both 250, `cryptonote_config.h:193` to `:194`).
///
/// **Assumption** (`DAEMON_RELAY_PRIVACY.md` §97): the interim outbound
/// target carried over, derived on the Rust path after PR-3 from intake
/// diversity, honest fill and per-reply exposure.
pub const DISCLOSE_COUNT: usize = 12;

/// The most distinct addresses one session may put into gray in any
/// 24-hour span (D-S1, Rick, 2026-10-09): twice the sample, so an honest
/// peer's cached sample cannot reach it. The same on every connector,
/// inbound and outbound sessions alike. Exceeding it is
/// [`Refusal::PeerlistRefused`].
///
/// **Assumption** (§97): the multiple is not derived.
pub const SESSION_INTAKE_CAP: usize = 2 * DISCLOSE_COUNT;

/// The interim multiple that stands in for the white diversity floor's
/// derivation (brief §2, 2026-10-08).
///
/// **Assumption** (§97).
pub const INTERIM_WHITE_DIVERSITY_MULTIPLE: usize = 4;

/// The white diversity floor: the eligible white count below which a
/// connector discloses nothing (brief §2, §5a). 48 today.
#[must_use]
pub const fn white_diversity_floor() -> usize {
    INTERIM_WHITE_DIVERSITY_MULTIPLE * DISCLOSE_COUNT
}

/// The refill line: white below this, and the dialer's fill runs (brief
/// §2). Above the floor by one sample of headroom — a window's worth of
/// confirmations before the floor is reached — so the node is not probing
/// stale gray entries once connectivity has already thinned. 60 today.
///
/// **Assumption** (§97): RULED as D-PR2-2 (brief §16.3, Rick 2026-10-09),
/// re-derived on the Rust path after PR-3 with the floor.
pub const WHITE_REFILL_LINE: usize = white_diversity_floor() + DISCLOSE_COUNT;

/// Gray capacity per connector. The C++ value
/// (`P2P_LOCAL_GRAY_PEERLIST_LIMIT`, `cryptonote_config.h:183`), moved
/// with the crate and not re-derived (brief §2, §14).
pub const GRAY_CAP: usize = 5000;

/// White capacity per connector. The C++ value
/// (`P2P_LOCAL_WHITE_PEERLIST_LIMIT`, `cryptonote_config.h:182`), moved
/// with the crate and not re-derived.
pub const WHITE_CAP: usize = 1000;

/// Nanoseconds in one hour.
const HOUR_NANOS: u64 = 60 * 60 * 1_000_000_000;

/// The white expiry: a white address with no contact this node initiated
/// for this long returns to gray (brief §2, `EXPIRATION_PERIOD`). In
/// nanoseconds, the unit of [`Tick`].
pub const EXPIRATION_PERIOD_NANOS: u64 = 24 * HOUR_NANOS;

/// The disclosure window: one cached sample per connector for this long
/// (D3). The same 24 hours as the expiry.
pub const DISCLOSE_WINDOW_NANOS: u64 = 24 * HOUR_NANOS;

/// The span over which a session's distinct admitted addresses are
/// counted against [`SESSION_INTAKE_CAP`] (D-S1).
pub const INTAKE_SPAN_NANOS: u64 = 24 * HOUR_NANOS;
