// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Own-edge capture over the hidden pool.
//!
//! This instrument does not build the two-class graph. It draws `h`
//! sessions, labels each a spy with probability `p_h`, and asks whether
//! the stem-map pin — and the frozen walk after churn — landed on a spy.
//! The one-draw reference is `p_h^h`. The refill is [`StemMap::update`]:
//! the source walks the peers it pinned, and a peer that joined after
//! that pin is not a candidate.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use crate::params::StemGraph;
use crate::rng::RelayRng;
use crate::stem_map::StemMap;

use super::super::util::{bernoulli_unit, usize_from};
use super::{bounded_uniform_len, node_of, peer_id};

/// Own-edge capture: the whole hidden pool, and the pinned session under churn.
///
/// `drawn_all_sessions` checks `p_h^h` by labelling each hidden session
/// independently. The epoch arms follow [`StemMap`]: a churn drops the
/// pinned peer and [`StemMap::update`] refills the slot, but the source
/// walks its frozen set and does not take the new peer. Across epochs the
/// map is rebuilt, which is the refill that can hand the attacker a new pin.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OwnEdgeCapture {
    /// `p_h^h`.
    pub closed_form: f64,
    /// Fraction of draws in which every hidden session was a spy.
    pub drawn_all_sessions: f64,
    /// Fraction of epochs whose pinned own-edge was a spy, before churn.
    pub pin_is_spy: f64,
    /// Fraction of epochs in which the frozen walk after churn still sat on a spy.
    pub frozen_after_churn: f64,
    /// Fraction of windows in which any epoch's initial pin was a spy.
    /// The post-churn fallback is [`Self::frozen_after_churn`] and is not
    /// folded into this chance.
    pub ever_across_epochs: f64,
}

/// Measure [`OwnEdgeCapture`].
///
/// `epochs` is the window. Each epoch rebuilds the stem map. Inside an
/// epoch, `churns` peers are dropped, the dropped one first being the pin,
/// and the map is updated from the survivors plus a refill peer that is a
/// spy with probability `p_h`. The frozen pin does not move onto that refill.
/// `churns == 0` leaves the pin in place and does not refill.
///
/// # Panics
///
/// Panics if `trials` or `epochs` is zero, `hidden_out` is zero, or `p_h`
/// is outside `[0, 1]`.
#[must_use]
pub fn simulate_own_edge_capture<R: RelayRng + ?Sized>(
    hidden_out: usize,
    p_h: f64,
    epochs: usize,
    churns: usize,
    trials: usize,
    rng: &mut R,
) -> OwnEdgeCapture {
    assert!(trials > 0 && epochs > 0, "need trials and epochs");
    assert!((0.0..=1.0).contains(&p_h), "p_h must be in [0, 1]");
    assert!(hidden_out >= 1, "capture is over the hidden pool");
    let closed_form = p_h.powf(hidden_out as f64);
    let mut all_hits = 0_usize;
    let mut pin_hits = 0_usize;
    let mut frozen_hits = 0_usize;
    let mut ever_hits = 0_usize;
    let epoch_total = trials * epochs;
    for _ in 0..trials {
        let mut ever = false;
        for _ in 0..epochs {
            let spies: Vec<bool> = (0..hidden_out).map(|_| bernoulli_unit(rng, p_h)).collect();
            if spies.iter().all(|s| *s) {
                all_hits += 1;
            }
            let ids: Vec<_> = (0..hidden_out).map(peer_id).collect();
            let width = StemGraph::QuasiFourRegular.stem_count().min(hidden_out);
            let mut map = StemMap::new(ids.clone(), width, rng);
            let Some(pin) = map.stem_for(None, rng) else {
                continue;
            };
            let pin_node = node_of(pin);
            let pin_spy = spies[pin_node];
            if pin_spy {
                pin_hits += 1;
                ever = true;
            }
            let frozen_spy = if churns == 0 {
                let after = map.stem_for(None, rng);
                after.is_some_and(|id| node_of(id) == pin_node) && pin_spy
            } else {
                // Drop `churns` peers, the pin first. Update refills from
                // whoever remains. The source's next stem_for walks the
                // frozen set.
                let mut live = ids.clone();
                live.retain(|id| *id != pin);
                for _ in 1..churns {
                    if live.is_empty() {
                        break;
                    }
                    let drop = usize_from(bounded_uniform_len(rng, live.len()));
                    live.swap_remove(drop);
                }
                // The refill always joins the live set. It is a spy with
                // probability p_h, and it is not in the frozen set, so the
                // source's next stem must not be that peer. Its id sits
                // outside `0..hidden_out`, so it is not one of the labelled
                // sessions.
                let refill = peer_id(hidden_out);
                let refill_spy = bernoulli_unit(rng, p_h);
                live.push(refill);
                let _change = map.update(live, rng);
                let after = map.stem_for(None, rng);
                assert_ne!(
                    after,
                    Some(refill),
                    "the frozen walk took the refill (spy {refill_spy})"
                );
                after.is_some_and(|id| {
                    let n = node_of(id);
                    n < hidden_out && spies[n]
                })
            };
            if frozen_spy {
                frozen_hits += 1;
            }
        }
        if ever {
            ever_hits += 1;
        }
    }
    OwnEdgeCapture {
        closed_form,
        drawn_all_sessions: all_hits as f64 / epoch_total as f64,
        pin_is_spy: pin_hits as f64 / epoch_total as f64,
        frozen_after_churn: frozen_hits as f64 / epoch_total as f64,
        ever_across_epochs: ever_hits as f64 / trials as f64,
    }
}
