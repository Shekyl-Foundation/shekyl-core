// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! What every Noise transport in the workspace shares: the symmetric
//! primitives, the handshake's symmetric state, and [`Direction`], the one
//! nonce stream a framer seals with.
//!
//! Two transports use it. The P2P handshake (`shekyl-p2p-transport`) and the
//! RPC channel each bring their own pattern, their own protocol name, their
//! own tokens and their own framer. Neither carries a copy of what is here
//! (`docs/design/RPC_CHANNEL.md` section 4.4).
//!
//! A handshake drives [`SymmetricState`] and finishes with
//! [`SymmetricState::into_directions`]. That is the only way out of the
//! handshake. The hash, HKDF and AEAD stay in this crate, and no raw key
//! leaves it.
//!
//! This crate has no handshake of its own, no record framer and no socket.
//! The length-prefixed framer the clearnet seam speaks stays in
//! `shekyl-p2p-transport`.
//!
//! # The `rekey-timing` feature
//!
//! It runs one rekey HKDF so the P2P transport's C5 bench can time that
//! derivation apart from a session. The derived keys stay in this crate.
//! `shekyl-p2p-transport`'s `c5-bench` feature is the only thing that turns
//! it on.

pub(crate) mod aead;
pub mod direction;
pub mod symmetric;

#[cfg(feature = "rekey-timing")]
pub use aead::rekey_hkdf;
pub use aead::{HASH_LEN, TAG_LEN};
pub use direction::{Direction, DirectionError, KeyEpoch, REKEY_NONCES};
pub use symmetric::{SplitRole, SymmetricError, SymmetricState};
