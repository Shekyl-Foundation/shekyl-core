// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's built-in miner loop in Rust (`DRS_X_STORE_FLIP.md` DX-Q4,
//! PR 3). **Staged:** built and tested here, connected by the flip. The
//! C++ miner (`src/cryptonote_basic/miner.cpp`) keeps mining until then and
//! is deleted with the core it calls.
//!
//! # A crate, not a daemon module
//!
//! The loop's threads hash with RandomX for as long as mining runs, and the
//! only other RandomX caller in the daemon is the validator's substrate.
//! Here they share one [`CacheStore`](shekyl_pow_randomx::CacheStore) —
//! the daemon's one RandomX budget, handed in — and nothing else: the
//! miner has no RPC, store or p2p dependency, and the RPC crate gains no
//! hashing threads. PR 2's composition root wires the two ends.
//!
//! # Inputs are values
//!
//! - **The template** arrives on a [`JobBoard`]: the producer (the template
//!   builder over the tip, PR 2) [`publish`](JobBoard::publish)es a [`Job`]
//!   — the block, its height, its seed and its target — and each publish
//!   supersedes the last. [`withdraw`](JobBoard::withdraw) leaves nothing
//!   to mine (a node behind its peers).
//! - **The address** is a [`MiningAddress`], decoded by `shekyl-address` and
//!   refused when it is not this network's, or carries no KEM key a coinbase
//!   can pay.
//! - **The thread count** is a [`NonZeroUsize`](std::num::NonZeroUsize).
//!
//! # The loop
//!
//! Each worker owns a disjoint range of the 32-bit nonce space — worker `i`
//! of `n` the `i`-th of `n` equal slices, the last taking the remainder —
//! and writes each nonce into the job's PoW preimage at the header's
//! [`nonce_offset`](shekyl_wire::BlockHeader::nonce_offset), so an attempt
//! is one RandomX hash and no serialization. It checks the board's
//! generation before every hash: a superseded job stops at once. The
//! comparison is the validator's (`check_hash`, CEN-D1b).
//!
//! **One solution per job.** The first worker to find a nonce claims the
//! job's generation on the board and sends the block to the
//! [`FoundBlocks`] sink; every worker then parks until the board posts a
//! newer job. A second solution for the same height could only become an
//! alternative block of this node's own making, so none is searched for.
//! A worker that exhausts its range also parks.
//!
//! # Below the daemon
//!
//! Every worker is its own `shekyl-thread-ledger` row ([`spawn_dedicated`]
//! (shekyl_thread_ledger::spawn_dedicated), named `sk-miner`) and lowers
//! its own CPU priority as it starts (`SH-3`'s mechanism,
//! `shekyl-thread-priority`: nice 19 on Linux, never `SCHED_IDLE`). A
//! platform that refuses leaves the worker at normal priority, counted in
//! [`MinerStatus::not_lowered`]; mining is never refused for it.
//!
//! # One mode
//!
//! There is one mining mode. There is no background mode, no idle or
//! battery detection, and no setting that changes how the loop runs: a
//! node mines with the threads it was given or it does not mine.
//!
//! # The rate is the verifier's
//!
//! The hash is `shekyl_pow_randomx::compute_hash` over the cache — the
//! light, cache-only mode the validator verifies with. The crate has no
//! dataset mode (`RANDOMX_V2_RUST.md` §9, measure-first; `RD-F11`), so the
//! rate [`MinerStatus`] reports is that mode's, over the window it states.

mod address;
mod found;
mod job;
mod miner;
mod rate;

pub use address::{MiningAddress, MiningAddressRefused};
pub use found::{found_blocks, Found, FoundBlocks};
pub use job::{Generation, Job, JobBoard};
pub use miner::{Miner, MinerConfig, MinerStatus};
pub use rate::{HashRate, RATE_WINDOW};
