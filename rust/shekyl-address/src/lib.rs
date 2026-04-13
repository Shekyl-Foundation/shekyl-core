// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Network-aware Bech32m address encoding for Shekyl.
//!
//! This crate provides the `ShekylAddress` type with segmented Bech32m
//! encoding (classical + PQC segments), network-aware HRPs, and the
//! `Network` enum for distinguishing mainnet/testnet/stagenet.
//!
//! # Examples
//!
//! ```
//! use shekyl_address::{ShekylAddress, Network};
//!
//! let addr = ShekylAddress::new(
//!     Network::Mainnet,
//!     [0xaa; 32],  // spend key
//!     [0xbb; 32],  // view key
//!     vec![0xcc; 1184],  // ML-KEM-768 encap key
//! );
//! let encoded = addr.encode().unwrap();
//! assert!(encoded.starts_with("shekyl1"));
//!
//! let decoded = ShekylAddress::decode(&encoded).unwrap();
//! assert_eq!(decoded.network, Network::Mainnet);
//! assert_eq!(decoded.spend_key, [0xaa; 32]);
//! ```

pub mod network;
pub mod address;

pub use address::{
    AddressError, ShekylAddress, ADDRESS_VERSION_V1, CLASSICAL_PAYLOAD_LEN, PQC_PAYLOAD_LEN,
    SEGMENT_SEPARATOR,
};
pub use network::Network;
