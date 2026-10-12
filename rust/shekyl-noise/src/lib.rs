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
//! RPC channel each bring their own pattern, their own protocol name and
//! their own tokens. Neither carries a copy of what is here
//! (`docs/design/RPC_CHANNEL.md` section 4.4).
//!
//! A handshake drives [`SymmetricState`] and finishes with
//! [`SymmetricState::into_halves`]. That is the only way from the handshake
//! into the record layer. The hash, HKDF and AEAD stay in this crate.
//!
//! This crate has no handshake of its own and reads no socket.
//!
//! # The `test-support` feature
//!
//! It exposes raw keys and lets a test set a nonce, so that a handshake's
//! tests can pin the key schedule across the crate boundary. It is for
//! `[dev-dependencies]` only. `scripts/ci/check_test_only_features.py` holds
//! it there: CI fails if any other kind of dependency turns it on, and a
//! second CI lane lints this crate with the feature off, as a release build
//! compiles it.
//!
//! # The `rekey-timing` feature
//!
//! It exposes one rekey HKDF so the P2P transport's C5 bench can time that
//! derivation apart from a session. `shekyl-p2p-transport`'s `c5-bench`
//! feature is the only thing that turns it on.

pub(crate) mod aead;
pub mod channel;
pub mod symmetric;

#[cfg(feature = "rekey-timing")]
pub use aead::rekey_hkdf;
pub use aead::{HASH_LEN, TAG_LEN};
pub use channel::{RecordError, RecvHalf, SendHalf};
pub use symmetric::{SplitRole, SymmetricError, SymmetricState};
