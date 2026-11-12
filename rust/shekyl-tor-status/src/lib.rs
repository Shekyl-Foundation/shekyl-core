// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Tor status as it crosses the wire, and the one renderer that turns it
//! into words (`docs/design/TOR_STATUS_CRATE.md`).
//!
//! The shape and every name are `INPUT_GRAMMAR.md` §23 as amended by Part G
//! (IG-Q95…IG-Q101). Each closed set has an `Unknown { tag }` arm: a
//! keyword this build does not know decodes into it, so a newer node's
//! reply is read whole, and [`render`] says that the node reports something
//! this version does not know.
//!
//! An unknown keyword never reads as the node hiding its address: the one
//! accessor a send decision reads, [`TorStatus::own_tx_hides_address`],
//! fails closed.
//!
//! Every duration is whole seconds of awake time (IG-Q93, IG-Q96). No clock
//! reading crosses.

#![deny(unsafe_code)]

use std::fmt;

use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

mod render;

pub use render::{held_at_start_sentence, install_sentence, render, UNKNOWN_SENTENCE};

/// A closed set of keywords, with an arm for a keyword this build does not
/// know. Serialized as the keyword; a keyword not in the set decodes as
/// `Unknown { tag }`.
macro_rules! keywords {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident = $word:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
            /// A keyword this build does not know.
            Unknown {
                /// The keyword as it arrived.
                tag: String,
            },
        }

        impl $name {
            /// Every keyword this build knows, in declaration order: what a
            /// schema lists for the set.
            pub const KEYWORDS: &'static [&'static str] = &[$($word),+];

            /// The keyword on the wire.
            #[must_use]
            pub fn keyword(&self) -> &str {
                match self {
                    $(Self::$variant => $word,)+
                    Self::Unknown { tag } => tag,
                }
            }

            /// Every variant this build knows.
            #[must_use]
            pub fn known() -> Vec<Self> {
                vec![$(Self::$variant),+]
            }

            fn of(word: &str) -> Self {
                match word {
                    $($word => Self::$variant,)+
                    other => Self::Unknown { tag: other.to_owned() },
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.keyword())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct Word;
                impl Visitor<'_> for Word {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("a keyword")
                    }
                    fn visit_str<E: de::Error>(self, word: &str) -> Result<$name, E> {
                        Ok($name::of(word))
                    }
                }
                deserializer.deserialize_str(Word)
            }
        }
    };
}

keywords! {
    /// The `tor` setting (`posture.tor`).
    TorSetting {
        /// A Tor this node runs and supervises.
        Managed = "managed",
        /// A Tor the operator runs.
        Operator = "operator",
        /// No Tor.
        Off = "off",
    }
}

keywords! {
    /// The `clearnet` setting (`posture.clearnet`).
    Clearnet {
        /// Clearnet on.
        On = "on",
        /// Clearnet off.
        Off = "off",
    }
}

keywords! {
    /// What happens to the node's own transactions (IG-Q68).
    Origination {
        /// They leave on a session that hides this node's address.
        AddressHiding = "address-hiding",
        /// Tor is on and no session hides this node's address yet: held.
        Connecting = "connecting",
        /// A session hides this node's address and the epoch's origin pin is
        /// exhausted: held.
        Rebuilding = "rebuilding",
        /// The operator set Tor off and clearnet on.
        ClearnetOnly = "clearnet-only",
        /// Tor off and clearnet off.
        Offline = "offline",
    }
}

keywords! {
    /// A connector the node syncs over (`sync_connector`).
    Connector {
        /// Clearnet.
        Clearnet = "clearnet",
        /// Tor.
        Tor = "tor",
    }
}

keywords! {
    /// The managed Tor's state (§4.3, IG-Q69).
    TorState {
        /// Starting again after a process fault.
        Restarting = "restarting",
        /// Waiting out the cap: a pin, a missing bundle, no managed Tor here.
        Waiting = "waiting",
        /// Not yet a usable outbound link.
        Bootstrapping = "bootstrapping",
        /// The outbound link is usable.
        Usable = "usable",
        /// Tor is up and something is wrong.
        Impaired = "impaired",
    }
}

keywords! {
    /// A fix the operator may apply to an install cause.
    Fix {
        /// Stay managed and restore a Tor that passes the check.
        RestoreManaged = "restore-managed",
        /// Use a Tor the operator runs.
        Operator = "operator",
        /// Turn clearnet on and keep Tor managed.
        ClearnetOn = "clearnet-on",
        /// Turn Tor off and send over clearnet.
        ClearnetOnly = "clearnet-only",
    }
}

keywords! {
    /// What the Tor link still carries (IG-Q100).
    Carriage {
        /// The outbound link carries the node's traffic.
        Carries = "carries",
        /// Only connections already open still carry it.
        OpenOnly = "open-only",
        /// Nothing the earlier link held carries anything.
        Gone = "gone",
    }
}

keywords! {
    /// The onion's state (IG-Q96).
    OnionState {
        /// Published, and no probe has come back yet.
        Publishing = "publishing",
        /// The last probe came back.
        Reachable = "reachable",
        /// Peers cannot reach it.
        Unreachable = "unreachable",
    }
}

keywords! {
    /// How a bootstrap is going, as the supervisor reads it (IG-Q98).
    Pace {
        /// The percent moved within the window.
        Advancing = "advancing",
        /// The percent held and bytes arrived: a slow directory mirror.
        Slow = "slow",
        /// A full window in which nothing arrived.
        Stalled = "stalled",
        /// The percent held, and the bytes cannot be read.
        Held = "held",
    }
}

/// Serialize a one-key object: `{key: payload}`.
fn one_key<S: Serializer, P: Serialize + ?Sized>(
    serializer: S,
    key: &str,
    payload: &P,
) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(1))?;
    map.serialize_entry(key, payload)?;
    map.end()
}

/// Read a one-key object: its key, then the payload `read` takes for that
/// key, or `None` for a key it does not know, whose payload is skipped.
/// A second key is refused: the variant is the one key (IG-Q70).
fn read_one_key<'de, A, T>(
    mut map: A,
    read: impl FnOnce(&str, &mut A) -> Result<Option<T>, A::Error>,
    unknown: impl FnOnce(String) -> T,
) -> Result<T, A::Error>
where
    A: MapAccess<'de>,
{
    let Some(key) = map.next_key::<String>()? else {
        return Err(de::Error::custom(
            "an empty object where one key was expected",
        ));
    };
    let value = match read(&key, &mut map)? {
        Some(value) => value,
        None => {
            map.next_value::<IgnoredAny>()?;
            unknown(key)
        }
    };
    if map.next_key::<IgnoredAny>()?.is_some() {
        return Err(de::Error::custom(
            "more than one key where one was expected",
        ));
    }
    Ok(value)
}

/// A visitor for one one-key set: `what` names it for a refusal, `read`
/// maps a known key to its value (reading the payload), `unknown` keeps a
/// key it does not know.
macro_rules! one_key_visitor {
    ($visitor:ident, $ty:ty, $what:literal, |$key:ident, $map:ident| $read:block, $unknown:expr) => {
        struct $visitor;
        impl<'de> Visitor<'de> for $visitor {
            type Value = $ty;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($what)
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<$ty, A::Error> {
                read_one_key(map, |$key: &str, $map: &mut A| $read, $unknown)
            }
        }
    };
}

/// Tor's figure for the clock (IG-Q95): signed seconds, negative behind the
/// network.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Skew {
    /// Tor measured the offset (`SKEW=`).
    Measured(i64),
    /// Tor gave a lower bound (`MIN_SKEW=`).
    Minimum(i64),
    /// A key this build does not know.
    Unknown {
        /// The key as it arrived.
        tag: String,
    },
}

impl Serialize for Skew {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Measured(seconds) => one_key(serializer, "measured", seconds),
            Self::Minimum(seconds) => one_key(serializer, "minimum", seconds),
            Self::Unknown { tag } => one_key(serializer, tag, &()),
        }
    }
}

one_key_visitor!(
    SkewVisit,
    Skew,
    "a clock figure",
    |key, map| {
        Ok(match key {
            "measured" => Some(Skew::Measured(map.next_value()?)),
            "minimum" => Some(Skew::Minimum(map.next_value()?)),
            _ => None,
        })
    },
    |tag| Skew::Unknown { tag }
);

impl<'de> Deserialize<'de> for Skew {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(SkewVisit)
    }
}

/// Why Tor's data directory could not be used (IG-Q97).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Unusable {
    /// The pre-spawn check found too little space.
    Exhausted {
        /// Free space there, in bytes.
        free: u64,
        /// The space Tor needs there, in bytes.
        needed: u64,
    },
    /// The account cannot write the directory.
    Unwritable,
    /// A key this build does not know.
    Unknown {
        /// The key as it arrived.
        tag: String,
    },
}

#[derive(Serialize, Deserialize)]
struct Space {
    free: u64,
    needed: u64,
}

impl Serialize for Unusable {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Exhausted { free, needed } => one_key(
                serializer,
                "exhausted",
                &Space {
                    free: *free,
                    needed: *needed,
                },
            ),
            Self::Unwritable => one_key(serializer, "unwritable", &()),
            Self::Unknown { tag } => one_key(serializer, tag, &()),
        }
    }
}

one_key_visitor!(
    UnusableVisit,
    Unusable,
    "a storage hold",
    |key, map| {
        Ok(match key {
            "exhausted" => {
                let Space { free, needed } = map.next_value()?;
                Some(Unusable::Exhausted { free, needed })
            }
            "unwritable" => {
                map.next_value::<()>()?;
                Some(Unusable::Unwritable)
            }
            _ => None,
        })
    },
    |tag| Unusable::Unknown { tag }
);

impl<'de> Deserialize<'de> for Unusable {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(UnusableVisit)
    }
}

/// The managed Tor's cause: null on the wire when there is none, else one
/// object with one key (§23, Part G).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TorCause {
    /// This machine cannot reach the Tor network.
    OutboundBlocked,
    /// No directory Tor knows answered.
    DirectoryUnreachable,
    /// The clock: Tor's figure, or `None` when Tor stated none (relays'
    /// certificates read as out of date) (IG-Q95).
    ClockSkew(Option<Skew>),
    /// Tor reached the open-file limit; how many it reported open.
    DescriptorLimit(u64),
    /// The process ended; its exit code when the reap reported one.
    Exited(Option<i32>),
    /// A control reply missed its bound.
    Unanswered,
    /// A launch that passed the pin did not come up.
    LaunchFailed,
    /// The pin refused the Tor it found; it was not executed. The file and
    /// the reason are in the daemon's log, not on the wire (Rick,
    /// 2026-11-12: the status holds no daemon-authored free text).
    InstallDefect,
    /// Discovery found no Tor.
    Missing,
    /// This release has no managed Tor for this platform.
    Unavailable,
    /// Tor's data directory could not be used; `None` for any failure that
    /// is neither of [`Unusable`]'s (IG-Q97).
    Unusable(Option<Unusable>),
    /// Tor refused to publish the onion again, and the remedy escalated to
    /// a respawn (IG-Q101).
    OnionRefused,
    /// A bootstrap stranded after a clock jump (IG-Q101).
    Stranded,
    /// A key this build does not know.
    Unknown {
        /// The key as it arrived.
        tag: String,
    },
}

impl TorCause {
    /// Whether the fixes offered for it are the install list.
    #[must_use]
    pub fn is_install(&self) -> bool {
        matches!(
            self,
            Self::InstallDefect | Self::Missing | Self::Unavailable
        )
    }
}

impl Serialize for TorCause {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::OutboundBlocked => one_key(serializer, "outbound-blocked", &()),
            Self::DirectoryUnreachable => one_key(serializer, "directory-unreachable", &()),
            Self::ClockSkew(skew) => one_key(serializer, "clock-skew", skew),
            Self::DescriptorLimit(open) => one_key(serializer, "descriptor-limit", open),
            Self::Exited(code) => one_key(serializer, "exited", code),
            Self::Unanswered => one_key(serializer, "unanswered", &()),
            Self::LaunchFailed => one_key(serializer, "launch-failed", &()),
            Self::InstallDefect => one_key(serializer, "install-defect", &()),
            Self::Missing => one_key(serializer, "missing", &()),
            Self::Unavailable => one_key(serializer, "unavailable", &()),
            Self::Unusable(kind) => one_key(serializer, "unusable", kind),
            Self::OnionRefused => one_key(serializer, "onion-refused", &()),
            Self::Stranded => one_key(serializer, "stranded", &()),
            Self::Unknown { tag } => one_key(serializer, tag, &()),
        }
    }
}

one_key_visitor!(
    CauseVisit,
    TorCause,
    "a Tor cause",
    |key, map| {
        let null = |map: &mut A| map.next_value::<()>();
        Ok(Some(match key {
            "outbound-blocked" => {
                null(map)?;
                TorCause::OutboundBlocked
            }
            "directory-unreachable" => {
                null(map)?;
                TorCause::DirectoryUnreachable
            }
            "clock-skew" => TorCause::ClockSkew(map.next_value()?),
            "descriptor-limit" => TorCause::DescriptorLimit(map.next_value()?),
            "exited" => TorCause::Exited(map.next_value()?),
            "unanswered" => {
                null(map)?;
                TorCause::Unanswered
            }
            "launch-failed" => {
                null(map)?;
                TorCause::LaunchFailed
            }
            "install-defect" => {
                null(map)?;
                TorCause::InstallDefect
            }
            "missing" => {
                null(map)?;
                TorCause::Missing
            }
            "unavailable" => {
                null(map)?;
                TorCause::Unavailable
            }
            "unusable" => TorCause::Unusable(map.next_value()?),
            "onion-refused" => {
                null(map)?;
                TorCause::OnionRefused
            }
            "stranded" => {
                null(map)?;
                TorCause::Stranded
            }
            _ => return Ok(None),
        }))
    },
    |tag| TorCause::Unknown { tag }
);

impl<'de> Deserialize<'de> for TorCause {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(CauseVisit)
    }
}

/// Why the onion is unreachable (IG-Q96).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OnionCause {
    /// The probe did not come back within its bound.
    ProbeMissed,
    /// More than half of the latest round's directories refused the upload.
    UploadsRefused,
    /// The directories the uploads reached no longer had the descriptor.
    DescriptorMissing,
    /// This computer's clock is behind the consensus by at least this many
    /// seconds.
    ClockBehind(u64),
    /// A key this build does not know.
    Unknown {
        /// The key as it arrived.
        tag: String,
    },
}

impl Serialize for OnionCause {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::ProbeMissed => one_key(serializer, "probe-missed", &()),
            Self::UploadsRefused => one_key(serializer, "uploads-refused", &()),
            Self::DescriptorMissing => one_key(serializer, "descriptor-missing", &()),
            Self::ClockBehind(seconds) => one_key(serializer, "clock-behind", seconds),
            Self::Unknown { tag } => one_key(serializer, tag, &()),
        }
    }
}

one_key_visitor!(
    OnionCauseVisit,
    OnionCause,
    "an onion cause",
    |key, map| {
        Ok(Some(match key {
            "probe-missed" => {
                map.next_value::<()>()?;
                OnionCause::ProbeMissed
            }
            "uploads-refused" => {
                map.next_value::<()>()?;
                OnionCause::UploadsRefused
            }
            "descriptor-missing" => {
                map.next_value::<()>()?;
                OnionCause::DescriptorMissing
            }
            "clock-behind" => OnionCause::ClockBehind(map.next_value()?),
            _ => return Ok(None),
        }))
    },
    |tag| OnionCause::Unknown { tag }
);

impl<'de> Deserialize<'de> for OnionCause {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(OnionCauseVisit)
    }
}

/// The quiet line (IG-Q99), under every `tor` setting.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TorQuiet {
    /// The dialer's census holds no Tor peer.
    Empty,
    /// Peers are known, and none has answered through Tor for this many
    /// seconds of awake time.
    Failing {
        /// How long, in seconds.
        age: u64,
    },
    /// A key this build does not know.
    Unknown {
        /// The key as it arrived.
        tag: String,
    },
}

#[derive(Serialize, Deserialize)]
struct Failing {
    age: u64,
}

impl Serialize for TorQuiet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Empty => one_key(serializer, "empty", &()),
            Self::Failing { age } => one_key(serializer, "failing", &Failing { age: *age }),
            Self::Unknown { tag } => one_key(serializer, tag, &()),
        }
    }
}

one_key_visitor!(
    QuietVisit,
    TorQuiet,
    "a quiet line",
    |key, map| {
        Ok(Some(match key {
            "empty" => {
                map.next_value::<()>()?;
                TorQuiet::Empty
            }
            "failing" => {
                let Failing { age } = map.next_value()?;
                TorQuiet::Failing { age }
            }
            _ => return Ok(None),
        }))
    },
    |tag| TorQuiet::Unknown { tag }
);

impl<'de> Deserialize<'de> for TorQuiet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(QuietVisit)
    }
}

/// The node's connector settings (IG-Q68).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Posture {
    /// The `tor` setting.
    pub tor: TorSetting,
    /// The `clearnet` setting.
    pub clearnet: Clearnet,
}

/// The onion's reachability (IG-Q96).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Onion {
    /// Its state.
    pub state: OnionState,
    /// How long the state has stood, in seconds of awake time; for
    /// `reachable`, since the last probe came back.
    pub age: u64,
    /// Why it is unreachable; `None` unless `unreachable`.
    pub cause: Option<OnionCause>,
}

/// How a bootstrap is going (IG-Q98).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Bootstrap {
    /// The supervisor's reading.
    pub pace: Pace,
    /// How long the percent has not moved, in seconds.
    pub unchanged: u64,
    /// Bytes that arrived in the window; `None` when they cannot be read.
    pub download: Option<u64>,
    /// The window, in seconds.
    pub window: u64,
}

/// The managed Tor (§23).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ManagedTor {
    /// The §4.3 state.
    pub state: TorState,
    /// The cause, one variant, or `None`.
    pub cause: Option<TorCause>,
    /// How long the state has stood, in seconds of awake time.
    pub age: u64,
    /// Respawns since the daemon started.
    pub respawn_count: u32,
    /// The last bootstrap percent whenever the bootstrap is spoken, and
    /// `None` otherwise (§23 as amended 2026-11-12). The renderer speaks
    /// the bootstrap exactly when this is `Some`. 0 is a sample (RK-D23), so
    /// `None` never reads as 0%.
    pub progress: Option<u8>,
    /// The consensus does not recommend this Tor.
    pub flagged: bool,
    /// The fixes for an install cause; empty otherwise.
    pub fix: Vec<Fix>,
    /// The onion; `None` when none is offered.
    pub onion: Option<Onion>,
    /// The bootstrap's reading; `None` before the first window.
    pub bootstrap: Option<Bootstrap>,
    /// What the link still carries.
    pub carriage: Carriage,
}

impl ManagedTor {
    /// Whether any value in it is a keyword this build does not know.
    #[must_use]
    pub fn has_unknown(&self) -> bool {
        let cause = matches!(
            &self.cause,
            Some(
                TorCause::Unknown { .. }
                    | TorCause::ClockSkew(Some(Skew::Unknown { .. }))
                    | TorCause::Unusable(Some(Unusable::Unknown { .. }))
            )
        );
        let onion = self.onion.as_ref().is_some_and(|onion| {
            matches!(onion.state, OnionState::Unknown { .. })
                || matches!(onion.cause, Some(OnionCause::Unknown { .. }))
        });
        cause
            || onion
            || matches!(self.state, TorState::Unknown { .. })
            || matches!(self.carriage, Carriage::Unknown { .. })
            || self
                .fix
                .iter()
                .any(|fix| matches!(fix, Fix::Unknown { .. }))
            || self
                .bootstrap
                .as_ref()
                .is_some_and(|bootstrap| matches!(bootstrap.pace, Pace::Unknown { .. }))
    }
}

/// The node's Tor status: `daemon_status`'s Status-level Tor fields (§23).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TorStatus {
    /// The settings in force.
    pub posture: Posture,
    /// What happens to the node's own transactions.
    pub origination: Origination,
    /// The connectors the node syncs over now.
    pub sync_connector: Vec<Connector>,
    /// The quiet line, when it stands.
    pub tor_quiet: Option<TorQuiet>,
    /// The managed Tor; `None` unless `posture.tor` is `managed`.
    pub tor: Option<ManagedTor>,
}

impl TorStatus {
    /// Whether any value in the reply is a keyword this build does not know.
    /// A client says so once, and reads the rest as usual.
    #[must_use]
    pub fn has_unknown(&self) -> bool {
        matches!(self.posture.tor, TorSetting::Unknown { .. })
            || matches!(self.posture.clearnet, Clearnet::Unknown { .. })
            || matches!(self.origination, Origination::Unknown { .. })
            || self
                .sync_connector
                .iter()
                .any(|connector| matches!(connector, Connector::Unknown { .. }))
            || matches!(self.tor_quiet, Some(TorQuiet::Unknown { .. }))
            || self.tor.as_ref().is_some_and(ManagedTor::has_unknown)
    }

    /// Whether the node's own transactions leave on a session that hides
    /// its address now: the one read a send decision makes, and the only
    /// accessor that answers it. It fails closed: an unknown origination, a
    /// `tor` or `clearnet` setting this build does not know, or Tor off, is
    /// not that, and the send holds (Rick, 2026-11-12).
    #[must_use]
    pub fn own_tx_hides_address(&self) -> bool {
        matches!(self.posture.tor, TorSetting::Managed | TorSetting::Operator)
            && matches!(self.posture.clearnet, Clearnet::On | Clearnet::Off)
            && matches!(self.origination, Origination::AddressHiding)
    }
}

#[cfg(test)]
mod tests;
