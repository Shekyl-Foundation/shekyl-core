// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay owner: transaction relay's seat on the session layer's
//! dispatch table (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1, §7.5).
//!
//! Two commands are this owner's. **2002** (`NewTransactions`): the batch
//! is admitted to the pool, then the arrival is recorded with the zone and
//! the admitted transactions are stemmed or fluffed as the batch's flag
//! says. **2010** (`GetTxpoolComplement`): served from the pool. Both reach
//! the owner through [`Port`], the session layer's `RelayOwner`, from the
//! session's own task, holding that session's `Taken`.
//!
//! Everything the C++ `levin_notify.cpp` hosted around `shekyl-relay`'s
//! zone is one task here, [`actor`]: the dispatch (`dandelionpp_notify`),
//! the effects a poll releases (`on_stem`, `on_fluff`, `on_noise`), the
//! carrier verdicts, the floor watch, the published reads. The callbacks
//! are direct calls; the connection registry is the owner's own map from
//! [`ConnectionId`] to `Established`; the wake is a timing-engine owner
//! under `OwnerClass::Relay` (brief §2 rule 7), armed at the zone's
//! `next_wake`. The task owns every piece of relay state (rule 5): the
//! port touches none of it, it posts.
//!
//! What the owner needs from the node is [`PoolDoor`], the four pool verbs
//! relay uses, implemented by the node over its mempool; and the node's
//! sync watch, read at each batch and at each plan.
//!
//! [`ConnectionId`]: crate::graph::ConnectionId

mod actor;
mod pool;
mod port;
mod rng;
mod snapshot;

pub use actor::{
    connection_id, start, RelayConfig, RelayHandle, RelayParts, RelayStartError, Started,
};
pub use pool::{Admit, PoolDoor};
pub use port::Port;
pub use rng::SecureRelayRng;
pub use snapshot::RelaySnapshot;

#[cfg(test)]
mod tests;
