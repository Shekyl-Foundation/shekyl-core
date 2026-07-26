// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Propagation / privacy measurement suite for `shekyl-relay-privacy`.
//!
//! Modules are split by instrument family. Run with:
//!
//! ```text
//! cargo test -p shekyl-relay-privacy --all-features --test propagation_measurement -- --nocapture
//! ```

#![allow(clippy::cast_precision_loss)]

mod adversary;
mod common;
mod embargo_survival;
mod fluff_delay;
mod reshape;
mod selection;
mod transport;
