// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Test-only cross-check of the RPC channel's handshake against `clatter`
//! (`docs/design/RPC_CHANNEL.md` §4.1; RT-O11, RT-O12).
//!
//! This crate exports nothing and nothing may depend on it. Its tests do two
//! things:
//!
//! - hold clatter's classical XK to the community vector, so the harness and
//!   the external anchor are known to agree before anything else is trusted;
//! - drive clatter's `hybridXK` from seeded randomness with the channel's
//!   real prologue, and hold the result to the vectors committed under
//!   `docs/test_vectors/RPC_CHANNEL_HYBRIDXK_V1/`.
//!
//! Slice RT-W8 pins those vectors. Slice RT-W9 implements Shekyl's handshake
//! against them. Until RT-W9 lands, the vectors say what clatter does, not
//! that Shekyl's code agrees.
