// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sort that `Connection` is built from.
//!
//! This is the design. The struct is the next commit. C++ keeps
//! `p2p_connection_context` through this step. Nothing here changes a
//! session.
//!
//! The test for each member is who asserted it
//! (`LV3_CONNECTION_OBJECT.md`, the step-a table).
//!
//! # Observed, write-once at adoption
//!
//! `m_connection_id`, the connected address, the direction, the
//! connector, and `m_started`. The seam measured these when the row was
//! adopted. They do not change. Eviction, admission, the protection set,
//! and the operator view read only this bin.
//!
//! The byte counters (`m_last_recv`, `m_last_send`, the counts, the
//! speeds) are observed too, and they advance. They are not write-once,
//! and they are not this step's fields. The socket is what moves them.
//! A claim does not.
//!
//! # Claimed
//!
//! `m_remote_blockchain_height`, `m_last_known_hash`, `support_flags`,
//! and the handshake's advertised port and address. The peer asserted
//! them. `Claimed<T>` is the type so a reader cannot treat one as a
//! measurement. Sync may use a claim as a hypothesis. Nothing that
//! decides who stays connected may.
//!
//! # The one promotion
//!
//! The advertised port and address stay claimed. A re-dial that answers
//! is a new `Observed` endpoint. It does not write the claim. That is
//! the gray-to-white rule on this object: the claim and the observation
//! do not share a representation.
//!
//! # Local
//!
//! The sync driver's bookkeeping: `m_state`, the three lists this node
//! built, the request timers, `m_in_timedsync`, `sent_addresses`, and
//! `m_remote_height_source`. They stay on the C++ context until that
//! driver moves. This step does not copy them into a second store.
//!
//! # Not fields
//!
//! `m_ssl` is not a field. p2p SSL was deleted in #909. It comes back
//! only if that protocol does.
//!
//! `m_score` is not a field. §2.7.2: a score a peer can improve by what
//! it asserts is the self-selection trap. The C++ field stays where it
//! is; deleting it would change who gets dropped, and this step changes
//! no behavior. A later round may add a counter whose inputs are
//! measurements this node made — idle time, a check it ran — and not
//! the peer's claims. A claim is not that measurement.
