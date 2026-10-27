// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the supervisor says, and when.
//!
//! The cap limits repeats of one announcement. A change of shown state or
//! cause kind is said at once (`TSR-F11`). A suppressed [`Cadence::Once`]
//! is a different debt from that repeat: a spawn or a pin check drops the
//! repeat and does not drop the once (`TOR_SUPERVISOR.md` §4.4).

use super::{Cause, Shown};

/// When an announcement is said.
///
/// A recovery is [`Cadence::Now`]. A phase that repeats its sentence is
/// [`Cadence::Due`]. A loss of the origin verdict is [`Cadence::Once`]: one
/// announcement under the cap, including while the phase is quiet. Under
/// every cadence a change of what is said (the projection or the cause's
/// kind) is said at once (`TSR-F11`): the cap limits repeats only.
#[derive(Clone, Copy)]
pub(super) enum Cadence {
    /// Say now. Arm the next period only while the phase repeats.
    Now,
    /// Say when the cap has elapsed. Arm a suppressed repeat only while
    /// the phase repeats.
    Due,
    /// Say once, when the cap has elapsed. A suppressed say is still
    /// armed, so a quiet phase does not swallow it.
    Once,
}

/// The shown state and the cause's kind. Detail inside one kind is not a
/// change (§4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SayKey {
    shown: Shown,
    cause: std::mem::Discriminant<Cause>,
}

impl SayKey {
    pub(super) fn new(shown: Shown, cause: &Cause) -> Self {
        Self {
            shown,
            cause: std::mem::discriminant(cause),
        }
    }
}

/// An announcement armed for one cap after the last thing said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PendingSay {
    /// The phase's sentence again. Drop it when the phase stops repeating,
    /// and when a pin check is due in the same tick.
    Repeat { at: u64 },
    /// A [`Cadence::Once`] that missed the cap. A spawn or a pin check
    /// does not drop it.
    Once { at: u64 },
}

impl PendingSay {
    fn at(self) -> u64 {
        match self {
            Self::Repeat { at } | Self::Once { at } => at,
        }
    }
}

/// The last thing said, and the one debt armed on the cap.
#[derive(Debug)]
pub(super) struct Announcements {
    last: Option<u64>,
    said: Option<SayKey>,
    pending: Option<PendingSay>,
}

impl Announcements {
    pub(super) const fn new() -> Self {
        Self {
            last: None,
            said: None,
            pending: None,
        }
    }

    /// The armed debt. The pin-tick test reads it: a repeat dropped there is
    /// gone, and an announcement count of zero does not say which.
    #[cfg(test)]
    pub(super) fn pending(&self) -> Option<PendingSay> {
        self.pending
    }

    /// When the armed debt is due.
    pub(super) fn due(&self) -> Option<u64> {
        self.pending.map(PendingSay::at)
    }

    /// Drop an armed debt. A stop does not say it later.
    pub(super) fn disarm(&mut self) {
        self.pending = None;
    }

    /// The deadline fired. A due [`PendingSay::Once`] is said. A due
    /// [`PendingSay::Repeat`] is said only while `repeats` and this tick
    /// has no pin check; otherwise the repeat is dropped.
    pub(super) fn on_deadline(
        &mut self,
        now: u64,
        key: SayKey,
        cap: u64,
        repeats: bool,
        pin_due: bool,
    ) -> bool {
        let Some(pending) = self.pending else {
            return false;
        };
        if now < pending.at() {
            return false;
        }
        match pending {
            PendingSay::Once { .. } => self.say(now, Cadence::Due, key, cap, repeats),
            PendingSay::Repeat { .. } if repeats && !pin_due => {
                self.say(now, Cadence::Due, key, cap, repeats)
            }
            PendingSay::Repeat { .. } => {
                self.pending = None;
                false
            }
        }
    }

    /// Say `key` under `cadence`, or arm the debt the cap still owes.
    /// `true` when the driver should announce.
    pub(super) fn say(
        &mut self,
        now: u64,
        cadence: Cadence,
        key: SayKey,
        cap: u64,
        repeats: bool,
    ) -> bool {
        let due = self.last.is_none_or(|then| now.saturating_sub(then) >= cap);
        let changed = self.said != Some(key);
        if !matches!(cadence, Cadence::Now) && !changed && !due {
            self.arm_suppressed(cadence, cap, repeats);
            return false;
        }
        self.last = Some(now);
        self.said = Some(key);
        self.pending = repeats.then_some(PendingSay::Repeat {
            at: now.saturating_add(cap),
        });
        true
    }

    /// A suppressed say. A [`Cadence::Once`] replaces a repeat. A repeat
    /// suppress leaves an owed once in place: that debt is not the phase's
    /// sentence.
    fn arm_suppressed(&mut self, cadence: Cadence, cap: u64, repeats: bool) {
        let Some(last) = self.last else {
            return;
        };
        let at = last.saturating_add(cap);
        let owed_once = matches!(cadence, Cadence::Once)
            || matches!(self.pending, Some(PendingSay::Once { .. }));
        if owed_once {
            self.pending = Some(PendingSay::Once { at });
        } else if repeats {
            self.pending = Some(PendingSay::Repeat { at });
        }
    }
}
