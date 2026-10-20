// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handshake's deadlines, measured rather than assumed (`RPC_CHANNEL.md`
//! §4.3, ruled 2026-10-20).
//!
//! Both run on the daemon's clock from the instant its `accept` returns, and
//! both come from RT-P9: round trips on an onion leg to the floor device, 300
//! connections, each on its own Tor circuit
//! (`docs/benchmarks/rt_p9_handshake_round_trips_20261020.md`). Each is
//! twice the onion leg's 99th percentile, rounded up to a whole second (the
//! rule confirmed 2026-10-20). One
//! deadline has to serve an onion client, so the LAN figures (0.7 ms and
//! 8.6 ms at the 99th percentile) are reported beside them and bound nothing.
//!
//! The listener that enforces them is RT-W10's. A client retries a timed-out
//! handshake once before reporting it ([`crate::retry`]).

use std::time::Duration;

/// From `accept` to the whole of message 1 received: twice RT-P9's onion
/// 99th percentile of 1,803.4 ms, rounded up. One of RT-P9's 300 onion
/// connections took longer (4,488.8 ms).
pub const MESSAGE1_DEADLINE: Duration = Duration::from_secs(4);

/// From `accept` to the client's first record opened, which ends the
/// handshake: twice RT-P9's onion 99th percentile of 5,231.9 ms, rounded up.
/// None of RT-P9's 300 onion connections took longer (the slowest,
/// 7,791.1 ms).
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(11);

// Message 1 is part of the handshake, so its deadline cannot be the later of
// the two.
const _: () = assert!(MESSAGE1_DEADLINE.as_secs() < HANDSHAKE_DEADLINE.as_secs());
