// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! What every Noise transport in the workspace shares: the symmetric
//! primitives, the handshake's symmetric state, and the record layer that
//! runs after `Split`.
//!
//! Two transports use it. The P2P handshake (`shekyl-p2p-transport`) and the
//! RPC channel's (`shekyl-rpc-channel`) each bring their own pattern, their
//! own protocol name and their own tokens. Neither carries a copy of what is
//! here (`docs/design/RPC_CHANNEL.md` section 4.4).
//!
//! This crate has no handshake of its own and reads no socket.
//!
//! # The `test-support` feature
//!
//! It exposes raw keys and lets a test set a nonce, so that a handshake's
//! tests can pin the key schedule across the crate boundary. It is for
//! `[dev-dependencies]` only. `scripts/ci/check_noise_test_support.py` fails
//! the build if any other kind of dependency turns it on.

pub mod aead;
pub mod channel;
pub mod symmetric;

pub use channel::{RecordError, RecvHalf, SendHalf};
pub use symmetric::{SplitKeys, SymmetricError, SymmetricState};
