// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The writer halt as the store reports it (`DAEMON_REDB_STORE.md` §3.6.2;
//! S-CHAIN-W commit 7).
//!
//! A `StoreInvariantViolated` on `connect`, `pop`, or a branded
//! `chain_view` read (the production validation path, which runs before
//! `connect` can) means the file's coherence is in doubt at that height: a
//! validator hole let something through a belt, a journal stopped
//! describing its tables, or a typed cell stopped decoding. Every later
//! write would build on it, so the writer halts for the life of the handle;
//! reads stay open so the operator (and the wallets refreshing against this
//! daemon) can see the chain as it stands and the row that caught the hole.
//!
//! The halt is **in memory** and re-derived on restart, never persisted: a
//! durable latch would refuse a file the operator has since repaired, and
//! the belts that set it rerun on the next connect anyway. The wire form is
//! `shekyl-rpc-types::chain::ConnectState`, which carries the register's
//! stable row *number* rather than this crate's enum, so a wallet decodes a
//! tip without linking the store (PR #751 disposition); the two are joined
//! at the daemon when the Rust store serves `get_info` (cutover).

use shekyl_types::BlockHeight;

use super::error::StoreInvariant;

/// Whether the store's writer is live or halted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectState {
    /// Connects and pops are accepted.
    Live,
    /// A connect, pop, or branded-view read hit a store invariant; writes
    /// are refused until restart.
    Halted {
        /// The height the halting connect, pop, or validation read was
        /// working at.
        at_height: BlockHeight,
        /// The belt that caught it — resolve against
        /// `STORE_INVARIANT_REGISTER.md` by [`StoreInvariant::row`].
        row: StoreInvariant,
    },
}

impl ConnectState {
    /// Whether writes are accepted.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }
}
