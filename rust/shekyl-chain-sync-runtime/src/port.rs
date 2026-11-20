// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sync owner's seat on the session layer's dispatch table
//! (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1, §7.2).
//!
//! The session layer calls [`SyncOwner`] from each session's own task. The
//! owner is one task on its own runtime row, so the trait's job here is
//! to hand each call over as one [`Inbound`], in the order the session
//! made them, and return. The [`Taken`] a message arrives with rides in
//! the `Inbound`: the owner drops it when the message has been taken
//! into its state, and the session reads its next frame only then.
//!
//! This replaces the seam's router (CS-3 §4.2) and its claim tap (CS-Q10):
//! the handshake and the timed sync are the session layer's, and the
//! peer's sync payload reaches the owner already decoded, as a claim.

use shekyl_p2p_session::{
    ClaimCarrier, CoreSyncData, Established, SessionFacts, SyncInbound, SyncOwner, Taken,
};
use tokio::sync::mpsc;

/// What the session layer hands the sync owner, one per trait call.
#[derive(Debug)]
pub enum Inbound {
    /// A session completed its handshake. Precedes every other `Inbound`
    /// of that session.
    Established(Established),
    /// A peer's sync payload: its claim.
    Claim {
        /// The session.
        session: Established,
        /// The payload, decoded.
        sync: CoreSyncData,
        /// Which message carried it.
        carrier: ClaimCarrier,
        /// The session's permit for the frame (module docs): its next frame
        /// is read once the owner has taken the claim.
        taken: Taken,
    },
    /// One of the owner's nine commands, still encoded under its arm.
    Message {
        /// The session.
        session: Established,
        /// The message.
        message: SyncInbound,
        /// The session's permit for it (module docs).
        taken: Taken,
    },
    /// The session is gone.
    Closed(SessionFacts),
}

/// The owner's seat: the session layer's [`SyncOwner`], forwarding into
/// the owner task's inbox.
#[derive(Clone, Debug)]
pub struct Port {
    inbox: mpsc::UnboundedSender<Inbound>,
}

/// A port and the inbox it feeds. The inbox goes to
/// [`crate::owner::OwnerParts::inbound`]; the port goes to the session
/// layer's `Owners::sync`.
#[must_use]
pub fn port() -> (Port, mpsc::UnboundedReceiver<Inbound>) {
    let (inbox, received) = mpsc::unbounded_channel();
    (Port { inbox }, received)
}

impl Port {
    fn hand(&self, inbound: Inbound) {
        // The owner has ended: the daemon is stopping on that end, and the
        // session layer closes with it. Nothing to do here.
        let _gone = self.inbox.send(inbound);
    }
}

impl SyncOwner for Port {
    fn claim(
        &self,
        session: &Established,
        sync: CoreSyncData,
        carrier: ClaimCarrier,
        taken: Taken,
    ) {
        self.hand(Inbound::Claim {
            session: session.clone(),
            sync,
            carrier,
            taken,
        });
    }

    fn message(&self, session: &Established, message: SyncInbound, taken: Taken) {
        self.hand(Inbound::Message {
            session: session.clone(),
            message,
            taken,
        });
    }

    fn on_established(&self, session: &Established) {
        self.hand(Inbound::Established(session.clone()));
    }

    fn on_closed(&self, facts: &SessionFacts, _end: shekyl_p2p_session::DialEnd) {
        self.hand(Inbound::Closed(*facts));
    }
}
