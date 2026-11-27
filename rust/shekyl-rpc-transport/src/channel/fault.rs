// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Why a channel call did not complete, in the words its reader can act on.

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
    Revoked {
        /// The key to enroll again.
        fingerprint: [u8; 32],
    },
    /// The handshake did not finish within its deadline, retried once.
    TimedOut,
    /// The call's own bound elapsed. The request is not sent again, and the
    /// pool does not dial to decide whether the key was revoked.
    Budget,
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

impl ChannelFault {
    /// The operator sentence. The leg and the operating-system cause stay in
    /// [`Self::place`]: one catalog, shared with the wallet wire.
    #[must_use]
    pub fn wallet_fault(&self) -> shekyl_rpc_client::WalletChannelFault {
        use shekyl_rpc_client::WalletChannelFault as Wallet;
        match self {
            Self::NotEnrolled { fingerprint } => Wallet::NotEnrolled(*fingerprint),
            Self::Revoked { fingerprint } => Wallet::Revoked(*fingerprint),
            Self::NotTheDaemon { .. } => Wallet::NotTheDaemon,
            Self::NotRecognised { .. } => Wallet::NotRecognised,
            Self::Unreachable { .. } => Wallet::Unreachable,
            Self::TimedOut => Wallet::TimedOut,
            Self::Budget => Wallet::Budget,
            Self::Busy => Wallet::Busy,
            Self::PoolFull => Wallet::PoolFull,
            Self::SessionCap => Wallet::SessionCap,
            Self::Closed => Wallet::Closed,
            Self::Local(_) => Wallet::Local,
        }
    }

    /// Where this failure happened, when the sentence does not already say.
    /// A log records this beside [`Self::wallet_fault`].
    #[must_use]
    pub fn place(&self) -> Option<String> {
        match self {
            Self::Unreachable { at, cause } => Some(format!("{at}: {cause}")),
            Self::NotRecognised { at } | Self::NotTheDaemon { at } => Some(at.clone()),
            Self::Local(why) => Some(why.clone()),
            Self::NotEnrolled { .. }
            | Self::Revoked { .. }
            | Self::TimedOut
            | Self::Budget
            | Self::Busy
            | Self::PoolFull
            | Self::SessionCap
            | Self::Closed => None,
        }
    }

    /// The exchange built nothing and wrote nothing, so the session can be lent again.
    pub(super) fn keeps_session(&self) -> bool {
        matches!(self, Self::Local(_))
    }

    /// The daemon has named this key's admission. The pool stops, and the
    /// caller hears this fault rather than a close.
    pub(super) fn admission_stop(&self) -> bool {
        matches!(
            self,
            Self::Revoked { .. }
                | Self::NotEnrolled { .. }
                | Self::NotTheDaemon { .. }
                | Self::NotRecognised { .. }
        )
    }
}

impl std::fmt::Display for ChannelFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sentence = self.wallet_fault();
        match self.place() {
            Some(place) => write!(f, "{sentence} ({place})"),
            None => write!(f, "{sentence}"),
        }
    }
}

impl From<ChannelFault> for shekyl_rpc_client::RpcError {
    fn from(fault: ChannelFault) -> Self {
        let detail = fault.place().unwrap_or_default();
        let kind = fault.wallet_fault();
        Self::Channel(kind, detail)
    }
}

impl std::error::Error for ChannelFault {}
