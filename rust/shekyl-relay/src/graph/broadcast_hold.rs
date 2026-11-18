// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hold before a broadcast that ends a stem (`CVR-R10`; Rick,
//! 2026-11-18).
//!
//! Every path on which this node ends a transaction's stem phase holds the
//! transaction first: the ordinary fluff decision (a fluffing epoch, no
//! successor), a stem that cannot get a window, an embargo with no live
//! alternate, and a node that relays no stems. The hold is
//! [`carrier::BROADCAST_HOLD_WINDOWS`] draws of the carrier cadence, drawn
//! from the window schedule and from nothing about the transaction; its
//! derivation and the ambiguity it buys are at that constant. When it ends
//! the broadcast is queued as before, with the per-peer delays
//! (`FLUFF_AVERAGE_*`) unchanged.
//!
//! A transaction that arrives already broadcast is not held: its stem phase
//! ended elsewhere.

use shekyl_draw_rng::RelayRng;
use shekyl_relay_privacy::params::carrier;
use shekyl_relay_privacy::schedule::{Millis, NoiseCadence};
use shekyl_relay_privacy::stem_map::ConnectionId;

use super::{Relay, TxBlob};
use crate::stem_watch::TxId;

/// Transactions held before their broadcast starts.
#[derive(Debug, Default)]
pub(super) struct BroadcastHolds {
    held: Vec<Held>,
}

#[derive(Debug)]
struct Held {
    release_at: Millis,
    txs: Vec<(TxId, TxBlob)>,
    source: Option<ConnectionId>,
}

/// A held broadcast whose hold has ended: queue it for fluff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Broadcast {
    /// The transactions, with the hashes the pool knows them by.
    pub txs: Vec<(TxId, TxBlob)>,
    /// The session the stem arrived on, excluded from the broadcast as
    /// before; `None` for none.
    pub source: Option<ConnectionId>,
}

/// One hold: [`carrier::BROADCAST_HOLD_WINDOWS`] draws of the carrier
/// cadence, summed.
fn hold_ms<R: RelayRng + ?Sized>(rng: &mut R) -> Millis {
    let cadence = NoiseCadence::shipped();
    (0..carrier::BROADCAST_HOLD_WINDOWS).fold(0, |at, _| cadence.next_send(at, rng))
}

impl Relay {
    /// Hold `txs` before the broadcast that ends their stem phase starts
    /// (`CVR-R10`). The hold is drawn now, from the window schedule alone.
    pub fn hold_broadcast<R: RelayRng + ?Sized>(
        &mut self,
        txs: &[(TxId, TxBlob)],
        source: Option<ConnectionId>,
        now: Millis,
        rng: &mut R,
    ) {
        if txs.is_empty() {
            return;
        }
        let release_at = now.saturating_add(hold_ms(rng));
        self.broadcast_holds.held.push(Held {
            release_at,
            txs: txs.to_vec(),
            source,
        });
    }

    /// The earliest held broadcast's release, or `None` when none is held.
    #[must_use]
    pub fn broadcast_hold_deadline(&self) -> Option<Millis> {
        self.broadcast_holds
            .held
            .iter()
            .map(|held| held.release_at)
            .min()
    }

    /// Every held broadcast whose hold has ended by `now`, in release order.
    pub fn due_broadcasts(&mut self, now: Millis) -> Vec<Broadcast> {
        let (mut due, held): (Vec<Held>, Vec<Held>) =
            std::mem::take(&mut self.broadcast_holds.held)
                .into_iter()
                .partition(|held| held.release_at <= now);
        self.broadcast_holds.held = held;
        due.sort_by_key(|held| held.release_at);
        due.into_iter()
            .map(|held| Broadcast {
                txs: held.txs,
                source: held.source,
            })
            .collect()
    }

    /// Transactions held before a broadcast, for tests.
    #[cfg(test)]
    pub(crate) fn held_broadcasts(&self) -> usize {
        self.broadcast_holds
            .held
            .iter()
            .map(|held| held.txs.len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_draw_rng::SplitMix64;

    /// The hold is `BROADCAST_HOLD_WINDOWS` cadence draws: its mean is that
    /// many cadence means, and its spread is a sum's (coefficient of
    /// variation `1/√n`), not one draw's.
    ///
    /// Red edits: hold for one draw (the mean falls fivefold), or for a fixed
    /// span (the spread collapses).
    #[test]
    fn the_hold_is_the_cadence_drawn_hold_windows_times() {
        const DRAWS: u32 = 20_000;
        let mut rng = SplitMix64::new(0x0010);
        let (mut sum, mut sum_sq) = (0.0_f64, 0.0_f64);
        for _ in 0..DRAWS {
            #[allow(clippy::cast_precision_loss)]
            let hold = hold_ms(&mut rng) as f64;
            sum += hold;
            sum_sq += hold * hold;
        }
        let n = f64::from(DRAWS);
        let mean = sum / n;
        let cv = (sum_sq / n - mean * mean).sqrt() / mean;
        let want = f64::from(carrier::BROADCAST_HOLD_WINDOWS) * f64::from(carrier::MEAN_CADENCE_MS);
        assert!(
            (mean - want).abs() < want * 0.02,
            "mean hold {mean} ms against {want}"
        );
        let want_cv = 1.0 / f64::from(carrier::BROADCAST_HOLD_WINDOWS).sqrt();
        assert!((cv - want_cv).abs() < 0.03, "spread {cv} against {want_cv}");
    }
}
