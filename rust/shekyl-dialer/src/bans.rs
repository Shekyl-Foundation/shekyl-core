// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transport layer's bans, asked through the seam hub.
//!
//! The peer lists take a [`BanQuery`]. The hub is where the bans live.
//! Neither crate depends on the other, so the dialer — which holds both —
//! is the adapter. The FFI reads the same one.

use std::net::IpAddr;

use shekyl_peerlist::{BanQuery, Tick};
use shekyl_seam::Hub;

/// Bans as the hub currently holds them. The tick is the lists' clock;
/// the hub answers against its own.
pub struct HubBans<'a>(pub &'a Hub);

impl BanQuery for HubBans<'_> {
    fn is_banned(&mut self, host: IpAddr, _now: Tick) -> bool {
        self.0.is_banned(host)
    }
}
