// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wallet contract's vocabulary, in one place for every surface that
//! speaks it.
//!
//! The contract is [`docs/api/wallet_rpc.yaml`](../../docs/api/wallet_rpc.yaml).
//! Its error codes, and the mapping from each engine error onto the code and
//! message that name its remedy, live here rather than in the RPC server, so
//! the server (`shekyl-wallet-rpc`) and an embedder of the engine (the GUI
//! wallet) answer the same failure with the same code. A second copy of the
//! mapping would drift; this crate is the one owner.
//!
//! [`error::WalletRpcError`] is the mapping's target, and
//! [`error::WalletRpcErrorCode::name`] the contract's spelling of each code.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod canonical_hex;
pub mod error;
mod message_sig_errors;
mod proof_errors;
pub mod shard_view;
pub mod transfer_id;
mod transfer_state;

pub use transfer_state::{outgoing_transfer_state_of, TransferState};
