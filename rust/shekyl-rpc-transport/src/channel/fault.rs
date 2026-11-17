// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Why a channel call did not complete, in the words its reader can act on.

use shekyl_rpc_channel::SESSIONS_PER_CLIENT;

/// Why the channel did not carry a call. Each variant is one thing the
/// person reading it can act on (§4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelFault {
    /// Nothing accepted the connection at the leg.
    Unreachable {
        /// The leg, as the person named it.
        at: String,
        /// What the operating system or the proxy said.
        cause: String,
    },
    /// The node closed the connection after message 1 without answering:
    /// it does not hold this client's copy of its key, is on another
    /// network, or speaks another channel version. The node's log says
    /// which.
    NotRecognised {
        /// The leg.
        at: String,
    },
    /// Message 2 did not come from the node whose bundle this client holds.
    /// Not retried.
    NotTheDaemon {
        /// The leg.
        at: String,
    },
    /// The node answered and closed after message 3: this key is not
    /// enrolled there.
    NotEnrolled {
        /// This client's fingerprint, for the operator's `rpc client add`.
        fingerprint: [u8; 32],
    },
    /// The node revoked this client: a session it held was closed and the
    /// next one was refused at message 3. The pool does not dial again.
    Revoked,
    /// The handshake did not finish within its deadline, retried once.
    TimedOut,
    /// The node answered busy until the handshake deadline.
    Busy,
    /// No session came free within the handshake deadline: this client
    /// already holds `SESSIONS_PER_CLIENT`, each busy.
    PoolFull,
    /// The node's first answer was `bound.sessions`: this key already
    /// holds `SESSIONS_PER_CLIENT` sessions there, so this one was not
    /// admitted. The connection is closed.
    SessionCap,
    /// The connection closed under a call.
    Closed,
    /// This client's own state failed: its key, or randomness.
    Local(String),
}

impl std::fmt::Display for ChannelFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { at, cause } => {
                write!(f, "No Shekyl node answered at {at}: {cause}.")
            }
            Self::NotRecognised { at } => write!(
                f,
                "The node at {at} closed the connection without answering. It does not \
                 recognise this client's copy of its key, is on a different network, or runs \
                 a different version. The node's log records which."
            ),
            Self::NotTheDaemon { at } => write!(
                f,
                "Something answered at {at} that is not the node you enrolled with. Do not \
                 connect; check the address."
            ),
            Self::NotEnrolled { fingerprint } => write!(
                f,
                "The node answered but has not enrolled this client. Enrol it on the node \
                 with: shekyl-cli rpc client add {} --ceiling GRANTS",
                hex::encode(fingerprint)
            ),
            Self::Revoked => f.write_str("The node revoked this client's enrolment."),
            Self::TimedOut => f.write_str("The node did not complete the handshake in time."),
            Self::Busy => f.write_str(
                "The node is busy and did not accept the connection in time. Try again shortly.",
            ),
            Self::PoolFull => f.write_str(
                "Every connection this client may hold to the node is busy; none came free in \
                 time.",
            ),
            Self::SessionCap => write!(
                f,
                "This client already holds {SESSIONS_PER_CLIENT} connections to the node, the \
                 most one client may hold."
            ),
            Self::Closed => f.write_str("The node closed the connection."),
            Self::Local(why) => write!(f, "This client could not use the channel: {why}."),
        }
    }
}

impl std::error::Error for ChannelFault {}
