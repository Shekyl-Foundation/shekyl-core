// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The network row (`DAEMON_CONFIG_CUTOVER.md` §2.6): the network table's
//! one type (`shekyl_network`, `NETWORK_IDENTITY.md` NI-Q3). The network
//! selects data, never control flow (rule 71): its name, ports, data
//! subdirectory and address prefixes are its row's, regtest's included.

pub use shekyl_network::Network;
