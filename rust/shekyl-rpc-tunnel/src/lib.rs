// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `shekyl-rpc-tunnel` (`docs/design/RPC_CHANNEL.md` §8, RT-W11): a small
//! Shekyl binary on a consumer's host. It holds that host's channel key,
//! reaches a node over the channel, and serves the node's RPC to local
//! consumers in plaintext on a loopback listener or a socket only its
//! account can enter.
//!
//! - [`table`]: its options (`INPUT_GRAMMAR.md` IG-Q108…IG-Q111).
//! - [`config`]: the command line and the file, resolved as the daemon
//!   resolves its own.
//! - [`serve`]: the listener, the pool of sessions, and a request carried
//!   whole; a revocation ends the tunnel.

#![deny(unsafe_code)]

pub mod config;
pub mod serve;
pub mod table;
