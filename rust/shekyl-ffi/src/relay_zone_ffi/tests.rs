// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use std::cell::RefCell;

// The "C++ side", simulated: recording callbacks that capture exactly what
// crosses the boundary. This is the Effect seam test §18.4a asks for, and it
// runs without a daemon build — which is what lets the transparency check
// gate the expensive oracle rather than trail it.
#[derive(Default)]
struct Recorder {
    fluffed: Vec<([u8; 16], Vec<Vec<u8>>)>,
    slots: Vec<Vec<[u8; 16]>>,
}

thread_local! {
    static REC: RefCell<Recorder> = RefCell::new(Recorder::default());
}

extern "C" fn rec_fluff(_: *mut c_void, peer: *const u8, blobs: *const ShekylRelayBlob, n: usize) {
    let mut p = [0u8; 16];
    unsafe { p.copy_from_slice(slice::from_raw_parts(peer, 16)) };
    let batch = unsafe { slice::from_raw_parts(blobs, n) }
        .iter()
        .map(|b| unsafe { slice::from_raw_parts(b.ptr, b.len) }.to_vec())
        .collect();
    REC.with(|r| r.borrow_mut().fluffed.push((p, batch)));
}

extern "C" fn rec_slots(_: *mut c_void, slots: *const u8, count: usize) {
    let flat = unsafe { slice::from_raw_parts(slots, count * 16) };
    let list = (0..count)
        .map(|i| {
            let mut s = [0u8; 16];
            s.copy_from_slice(&flat[i * 16..i * 16 + 16]);
            s
        })
        .collect();
    REC.with(|r| r.borrow_mut().slots.push(list));
}

// The outbound-gather side of `poll`, simulated. `poll` pulls the connection
// set through this callback only when a wake crosses an epoch boundary, so
// `calls` is the witness for the lazy contract: it must stay 0 on a
// fluff-release wake and tick to 1 on a rollover.
#[derive(Default)]
struct GatherState {
    calls: usize,
    /// The ids the next call hands back.
    supply: Vec<[u8; 16]>,
    /// Backing store the returned pointer borrows; a field so it outlives the
    /// `poll` call, as the `OutboundCb` "valid until poll returns" contract asks.
    pool: Vec<u8>,
}

thread_local! {
    static GATHER: RefCell<GatherState> = RefCell::new(GatherState::default());
}

extern "C" fn rec_gather(_: *mut c_void, out_n: *mut usize) -> *const u8 {
    GATHER.with(|g| {
        let mut g = g.borrow_mut();
        g.calls += 1;
        g.pool = g.supply.concat();
        unsafe { *out_n = g.supply.len() };
        if g.pool.is_empty() {
            std::ptr::null()
        } else {
            g.pool.as_ptr()
        }
    })
}

fn reset() {
    REC.with(|r| *r.borrow_mut() = Recorder::default());
    GATHER.with(|g| *g.borrow_mut() = GatherState::default());
}

fn id(byte: u8) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = byte;
    b
}

#[test]
fn fluff_effects_cross_with_peer_and_payload_intact() {
    reset();
    unsafe {
        let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
        shekyl_relay_zone_on_handshake(h, id(1).as_ptr(), true);
        let blob = [0xAB, 0xCD, 0xEF];
        let batch = [ShekylRelayBlob {
            ptr: blob.as_ptr(),
            len: blob.len(),
        }];
        assert_eq!(
            shekyl_relay_zone_queue_fluff(h, 0, batch.as_ptr(), 1, std::ptr::null()),
            1,
            "the one connected peer took the batch"
        );
        shekyl_relay_zone_force_fluff(h, 0, std::ptr::null_mut(), rec_fluff);
        shekyl_relay_zone_free(h);
    }
    REC.with(|r| {
        let rec = r.borrow();
        assert_eq!(rec.fluffed.len(), 1, "one batch to one peer");
        assert_eq!(rec.fluffed[0].0, id(1), "peer id crossed intact");
        assert_eq!(
            rec.fluffed[0].1,
            vec![vec![0xAB, 0xCD, 0xEF]],
            "payload intact"
        );
    });
}

#[test]
fn a_peers_batch_crosses_as_one_call_sorted_and_deduplicated() {
    // Two properties the daemon depends on, neither visible to a test that
    // only checks the transactions arrived:
    //
    // 1. **One call per peer.** The batch becomes a single levin
    //    notification carrying every transaction. Delivered blob-by-blob it
    //    would become N notifications — same bytes on the wire, N times the
    //    messages, and a per-peer message count that leaks how many
    //    transactions were batched together.
    // 2. **Sorted and de-duplicated**, which the inherited code did at the
    //    send site under the comment "don't leak receive order". Receive
    //    order is an observable: it is the order a relaying node saw
    //    transactions arrive, and forwarding it hands that ordering to
    //    every peer downstream.
    reset();
    unsafe {
        let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
        shekyl_relay_zone_on_handshake(h, id(1).as_ptr(), true);
        // Offered high-to-low, with a repeat: order and duplication both
        // have to be removed for the assertion below to hold.
        let raw = [[0x33u8], [0x11], [0x22], [0x11]];
        let batch: Vec<ShekylRelayBlob> = raw
            .iter()
            .map(|b| ShekylRelayBlob {
                ptr: b.as_ptr(),
                len: 1,
            })
            .collect();
        shekyl_relay_zone_queue_fluff(h, 0, batch.as_ptr(), batch.len(), std::ptr::null());
        shekyl_relay_zone_force_fluff(h, 0, std::ptr::null_mut(), rec_fluff);
        shekyl_relay_zone_free(h);
    }
    REC.with(|r| {
        let rec = r.borrow();
        assert_eq!(rec.fluffed.len(), 1, "one call carries the whole batch");
        assert_eq!(
            rec.fluffed[0].1,
            vec![vec![0x11], vec![0x22], vec![0x33]],
            "sorted ascending with the duplicate removed — not receive order"
        );
    });
}

/// **Sole witness — do not delete as redundant. Read this before touching it.**
///
/// This is the only test in the tree asserting that the stem-slot snapshot
/// crosses the boundary in **index order with nils in position**. Nothing
/// else covers it, and in particular the 33 `levin_notify` gtests do not:
/// they assert **counts** (`EXPECT_EQ(2u, sent)`, `connections_filled`) and
/// that a stem lands on an *outbound* peer — never that noise channel `i` is
/// bound to stem slot `i` (`DAEMON_RELAY_PRIVACY.md` §18.4b, finding 2).
/// Count assertions look like coverage and are not.
///
/// The property is contract 3 (§16.1): `update_channels::post` computes
/// `i = id - begin()` and posts to `channels[i]`, so a snapshot that
/// compacted a nil away or reordered slots would silently bind covert
/// channels to the wrong connections — no crash, no failing count, wrong
/// peers.
///
/// **RP-3b is the round that consumes this positionally**, and it is also
/// the round where the inherited names are least trustworthy (`run_stems`
/// cancels noise timers). So the reader most likely to consider this test
/// redundant is the one porting the covert path, looking at count-asserting
/// gtests, three commits deep. If the property ever becomes genuinely
/// covered elsewhere, delete this test *in the commit that adds that
/// coverage* and say so — not before.
///
/// **Negative-controlled.** Two bugs were injected into `dispatch` and both
/// fail this test: compacting the nil away, and reversing slot order. That
/// check is the reason the body looks the way it does — an earlier version
/// carried this same docstring while never producing a nil at all, and
/// caught neither bug. A seal that says "sole witness" over a body that does
/// not test the property is worse than no test, because it tells the next
/// reader the coverage already exists.
#[test]
fn stem_slots_cross_in_index_order_with_nils_in_position() {
    // Ground truth is read from the zone directly, NOT from the pushed
    // snapshot, and that is load-bearing. An earlier version of this test
    // derived which peer to keep from the pushed array — which made a
    // *reversal* self-consistent and undetectable, because the expectation
    // travelled through the very transform under test. A marshalling test
    // whose expected value is computed from the marshalled output can only
    // ever check that the output equals itself.
    fn truth(h: *const RelayZoneHandle) -> Vec<[u8; 16]> {
        // `as_ref` is the checked deref: `None` for null, so a construction
        // regression surfaces as a panic here rather than a read of an invalid
        // pointer (which is also what keeps CodeQL's invalid-pointer query quiet).
        unsafe { h.as_ref() }
            .expect("live zone handle")
            .driver
            .zone()
            .stem_slots()
            .iter()
            .map(|s| s.map_or(NIL, |id| *id.as_bytes()))
            .collect()
    }

    reset();
    let (filled, after) = unsafe {
        let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
        let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
        shekyl_relay_zone_force_epoch(h, 0, peers.as_ptr(), 3, std::ptr::null_mut(), rec_slots);
        let filled = REC.with(|r| r.borrow().slots[0].clone());
        assert_eq!(
            filled,
            truth(h),
            "the pushed snapshot must be the zone's slots, in the zone's order"
        );

        // Now empty a slot and offer no replacement: re-offer ONLY the peer
        // in slot 1. Slot 0's peer is gone with nothing to backfill it, so
        // the map holds a hole — which is the state this test exists for,
        // and which a snapshot of three-candidates-into-two-slots never
        // reaches. `dispatch` maps `None` to nil via `map_or`; swap that for
        // anything that skips instead and the hole compacts, silently
        // shifting slot 1's peer onto covert channel 0.
        let keep = filled[1];
        shekyl_relay_zone_update_stems(h, keep.as_ptr(), 1, std::ptr::null_mut(), rec_slots);
        let after = REC.with(|r| r.borrow().slots.last().cloned());
        if let Some(after) = &after {
            assert_eq!(
                *after,
                truth(h),
                "with a hole in it, the pushed snapshot must still be the \
                 zone's slots in the zone's order"
            );
        }
        shekyl_relay_zone_free(h);
        (filled, after)
    };

    assert_eq!(filled.len(), 2, "width preserved across the boundary");
    for s in &filled {
        assert_ne!(*s, NIL, "both slots filled from three candidates");
    }

    let after = after.expect("emptying a slot changes the set, so it pushes");
    assert_eq!(
        after.len(),
        2,
        "the span keeps its width when a slot empties"
    );
    assert_eq!(
        after[0], NIL,
        "the emptied slot stays nil IN POSITION — if this is the surviving \
         peer, the hole was compacted away and every covert channel after it \
         is now bound to the wrong connection"
    );
    assert_eq!(
        after[1], filled[1],
        "the surviving stem keeps slot 1 rather than sliding to slot 0"
    );
}

#[test]
fn live_stems_atomic_tracks_the_derived_value_after_every_mutation() {
    // The one deliberate cache. Single writer is what makes it honest, so
    // this asserts the published value equals the derived one after each
    // kind of mutation — a second writer, or a missed publish, shows here.
    unsafe {
        let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
        let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
        assert_eq!(shekyl_relay_zone_live_stems(h), 0, "fresh zone");

        shekyl_relay_zone_on_handshake(h, id(1).as_ptr(), false);
        assert_eq!(shekyl_relay_zone_live_stems(h), 0, "no stems drawn yet");

        shekyl_relay_zone_force_epoch(h, 0, peers.as_ptr(), 3, std::ptr::null_mut(), rec_slots);
        assert_eq!(
            shekyl_relay_zone_live_stems(h),
            h.as_ref().expect("live zone").driver.zone().live_stems(),
            "published value must equal the derived one after an epoch"
        );
        assert_eq!(shekyl_relay_zone_live_stems(h), 2);

        shekyl_relay_zone_on_close(h, id(1).as_ptr());
        assert_eq!(
            shekyl_relay_zone_live_stems(h),
            h.as_ref().expect("live zone").driver.zone().live_stems(),
            "published value must track a close"
        );
        shekyl_relay_zone_free(h);
    }
}

#[test]
fn the_three_plan_outcomes_stay_distinct_across_the_boundary() {
    // The C++ caller branches three ways on this code: send, refresh-and-
    // retry, or fluff. Collapsing any two of them here is invisible to the
    // 33 gtests as a *routing* failure — the transaction still goes
    // somewhere — but it changes which `relay_method` event is emitted and
    // whether a recoverable stem is abandoned.
    unsafe {
        let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
        let mut out = [0u8; 16];

        assert_eq!(
            shekyl_relay_zone_plan_relay(h, std::ptr::null(), true, out.as_mut_ptr()),
            SHEKYL_RELAY_PLAN_NO_ROUTE,
            "no slots populated yet: transient, and a refresh may fix it"
        );
        assert_eq!(out, NIL, "no successor to report");

        // Refresh, exactly as `dandelionpp_notify`'s retry does.
        let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
        shekyl_relay_zone_update_stems(h, peers.as_ptr(), 3, std::ptr::null_mut(), rec_slots);

        // Drive to a fluff epoch. The role is drawn from OS entropy, so it
        // is reached by re-drawing rather than by construction; at q = 20%
        // the loop bound is astronomically slack.
        let mut rolls = 0;
        while !h.as_ref().expect("live zone").driver.zone().is_fluffing() {
            shekyl_relay_zone_force_epoch(h, 0, peers.as_ptr(), 3, std::ptr::null_mut(), rec_slots);
            rolls += 1;
            assert!(rolls < 10_000, "no fluff epoch in 10k draws");
        }

        assert_eq!(
            shekyl_relay_zone_plan_relay(h, id(7).as_ptr(), false, out.as_mut_ptr()),
            SHEKYL_RELAY_PLAN_FLUFF_EPOCH,
            "a relayed tx in a fluff epoch is settled — retrying is wasted work"
        );
        assert_eq!(
            shekyl_relay_zone_plan_relay(h, std::ptr::null(), true, out.as_mut_ptr()),
            SHEKYL_RELAY_PLAN_STEM,
            "RD-4 across the boundary: the origin stems even in a fluff epoch"
        );
        assert_ne!(out, NIL, "a stem plan must carry its successor");
        shekyl_relay_zone_free(h);
    }
}

#[test]
fn the_nil_uuid_means_locally_originated_which_is_what_cpp_actually_sends() {
    // The encoding production depends on, and — until this test — the one
    // encoding nothing exercised. `levin_notify` never passes a null
    // `source`: it passes `uuid_bytes(source_)`, a real 16-byte uuid that is
    // *nil-valued* when the node originated the transaction. Every other
    // seam test here reaches "local origin" through the null pointer
    // instead, so `read_id`'s `(b != NIL)` check — the line that turns those
    // bytes into `None` — had no coverage at all.
    //
    // Delete that check and nothing failed: a local transaction would become
    // "sourced from connection nil", get pinned in the stem map under a peer
    // id that does not exist, and share one slot with every other local
    // transaction for the epoch. Routing changes, no test notices.
    //
    // So this asserts the two encodings agree, on the axis RD-4 turns on:
    // nil-source + local_origin must stem during a fluff epoch exactly as
    // the null-source path does.
    unsafe {
        let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
        let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
        shekyl_relay_zone_update_stems(h, peers.as_ptr(), 3, std::ptr::null_mut(), rec_slots);

        let mut rolls = 0;
        while !h.as_ref().expect("live zone").driver.zone().is_fluffing() {
            shekyl_relay_zone_force_epoch(h, 0, peers.as_ptr(), 3, std::ptr::null_mut(), rec_slots);
            rolls += 1;
            assert!(rolls < 10_000, "no fluff epoch in 10k draws");
        }

        let mut from_nil = [0u8; 16];
        let mut from_null = [0u8; 16];
        let nil_plan = shekyl_relay_zone_plan_relay(h, NIL.as_ptr(), true, from_nil.as_mut_ptr());
        let null_plan =
            shekyl_relay_zone_plan_relay(h, std::ptr::null(), true, from_null.as_mut_ptr());

        assert_eq!(
            nil_plan, SHEKYL_RELAY_PLAN_STEM,
            "a nil source IS local origin — RD-4 stems it even in a fluff epoch"
        );
        assert_eq!(
            nil_plan, null_plan,
            "the two spellings of \"no source\" must not route differently"
        );
        // Same source, so the epoch's pinning must send both to one slot.
        assert_eq!(from_nil, from_null, "both pin to the same stem successor");
        shekyl_relay_zone_free(h);
    }
}

#[test]
fn polling_at_the_reported_wake_time_releases_the_batch() {
    // The production path, and the only test of it anywhere: the daemon
    // arms its timer on `next_wake()` and calls `poll()` when it fires. The
    // 33 gtests never reach this — their `io_service_.poll()` runs only
    // *ready* handlers, and the wake deadline is seconds to minutes out, so
    // every gtest drives the zone through `force_fluff`/`force_epoch`
    // instead. Without this, `next_wake` could report a time `poll` did not
    // agree was due and nothing in the tree would notice.
    reset();
    unsafe {
        let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
        shekyl_relay_zone_on_handshake(h, id(1).as_ptr(), true);

        let blob = [0x5Au8];
        let batch = [ShekylRelayBlob {
            ptr: blob.as_ptr(),
            len: 1,
        }];
        // Queue at a nonzero clock so `due == QUEUED_AT` is distinguishable
        // from "no wake". The contract under test is wake/poll AGREEMENT —
        // poll at the reported wake releases, poll before it does not — NOT
        // strict futurity: the fluff table is a discrete geometric with
        // genuine mass at zero ticks, so a same-tick flush (`due ==
        // QUEUED_AT`) is a legitimate ~5%-probability outcome of the shipped
        // distribution, and asserting `due > QUEUED_AT` was a flake
        // (CI, PR #378). Do not "fix" this back by shifting the draw's
        // support instead — the delay tables are a pinned, measured
        // relay-privacy surface (survival quantiles, F-1); changing the
        // distribution is that lane's design decision, not a test repair.
        const QUEUED_AT: u64 = 1_000;
        shekyl_relay_zone_queue_fluff(h, QUEUED_AT, batch.as_ptr(), 1, std::ptr::null());

        let due = shekyl_relay_zone_next_wake(h);
        assert!(
            due >= QUEUED_AT,
            "a queued batch must report a wake at or after the queue time"
        );

        if due > QUEUED_AT {
            shekyl_relay_zone_poll(
                h,
                due - 1,
                std::ptr::null_mut(),
                rec_gather,
                rec_fluff,
                rec_slots,
            );
            REC.with(|r| assert!(r.borrow().fluffed.is_empty(), "not due yet"));
        }

        shekyl_relay_zone_poll(
            h,
            due,
            std::ptr::null_mut(),
            rec_gather,
            rec_fluff,
            rec_slots,
        );
        shekyl_relay_zone_free(h);
    }
    REC.with(|r| {
        let rec = r.borrow();
        assert_eq!(
            rec.fluffed.len(),
            1,
            "the batch releases at the wake it reported"
        );
        assert_eq!(rec.fluffed[0].1, vec![vec![0x5Au8]]);
    });
    // The wake was a fluff release, not an epoch boundary, so poll must not have
    // reached for the outbound set — the lazy-gather contract, across the FFI.
    GATHER.with(|g| {
        assert_eq!(
            g.borrow().calls,
            0,
            "a fluff-release wake must not gather the outbound set"
        )
    });
}

#[test]
fn polling_across_the_epoch_boundary_gathers_and_rebuilds() {
    // The other half of the lazy-gather contract, and the reason it is safe to
    // skip the scan on a fluff wake: a wake that *does* cross the epoch deadline
    // must still pull the outbound set — through the callback, exactly once —
    // and rebuild the stem map from it. With no batch queued, `next_wake` is the
    // epoch deadline, so polling there is a rollover.
    reset();
    unsafe {
        let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
        assert!(!h.is_null(), "these params build a zone");

        // The set the rollover will draw its two slots from.
        GATHER.with(|g| g.borrow_mut().supply = vec![id(1), id(2), id(3)]);

        let due = shekyl_relay_zone_next_wake(h);
        shekyl_relay_zone_poll(
            h,
            due,
            std::ptr::null_mut(),
            rec_gather,
            rec_fluff,
            rec_slots,
        );

        GATHER.with(|g| {
            assert_eq!(
                g.borrow().calls,
                1,
                "a wake that crosses the epoch boundary gathers the set exactly once"
            )
        });
        assert_eq!(
            shekyl_relay_zone_live_stems(h),
            2,
            "the rollover rebuilt the map from the gathered peers"
        );
        shekyl_relay_zone_free(h);
    }
    REC.with(|r| {
        assert_eq!(
            r.borrow().slots.len(),
            1,
            "the rebuilt slots are pushed outward"
        );
    });
}

#[test]
fn a_zone_that_would_spin_is_refused_rather_than_built() {
    // A zero epoch expires at every wake, so the daemon's relay timer would
    // re-arm in the past forever. Refusing construction turns a silent
    // busy-loop in the p2p reactor into a loud startup failure.
    assert!(
        shekyl_relay_zone_new(0, 2, 0, 30, false).is_null(),
        "zero epoch"
    );
    assert!(
        shekyl_relay_zone_new(0, usize::MAX, 600, 30, false).is_null(),
        "unrepresentable stem width"
    );
}

#[test]
fn a_null_handle_is_a_safe_no_op_on_every_export() {
    reset();
    unsafe {
        let null: *mut RelayZoneHandle = std::ptr::null_mut();
        shekyl_relay_zone_on_handshake(null, id(1).as_ptr(), true);
        shekyl_relay_zone_on_close(null, id(1).as_ptr());
        assert_eq!(shekyl_relay_zone_live_stems(null), 0);
        assert_eq!(shekyl_relay_zone_next_wake(null), 0);
        let mut out = [0u8; 16];
        assert_eq!(
            shekyl_relay_zone_plan_relay(null, id(1).as_ptr(), true, out.as_mut_ptr()),
            SHEKYL_RELAY_PLAN_NO_ROUTE,
            "nothing routes through a zone that does not exist"
        );
        assert_eq!(
            shekyl_relay_zone_plan_relay_with_refresh(
                null,
                id(1).as_ptr(),
                true,
                std::ptr::null(),
                0,
                out.as_mut_ptr(),
                std::ptr::null_mut(),
                rec_slots,
            ),
            SHEKYL_RELAY_PLAN_NO_ROUTE,
        );
        shekyl_relay_zone_update_stems(null, std::ptr::null(), 0, std::ptr::null_mut(), rec_slots);
        shekyl_relay_zone_poll(
            null,
            0,
            std::ptr::null_mut(),
            rec_gather,
            rec_fluff,
            rec_slots,
        );
        shekyl_relay_zone_free(null);
    }
    REC.with(|r| assert!(r.borrow().fluffed.is_empty(), "no effects from a null zone"));
}

#[test]
fn plan_relay_with_refresh_fills_an_empty_map_and_pushes_slots() {
    // Production notify path: empty public zone, first plan is NoRoute, one
    // refresh populates the map and re-plans — without C++ owning that loop.
    reset();
    unsafe {
        let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
        let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
        let mut out = [0u8; 16];
        let plan = shekyl_relay_zone_plan_relay_with_refresh(
            h,
            std::ptr::null(),
            true,
            peers.as_ptr(),
            3,
            out.as_mut_ptr(),
            std::ptr::null_mut(),
            rec_slots,
        );
        assert_eq!(
            plan, SHEKYL_RELAY_PLAN_STEM,
            "local origin stems after refresh"
        );
        assert_ne!(out, NIL, "successor written");
        assert_eq!(shekyl_relay_zone_live_stems(h), 2);
        shekyl_relay_zone_free(h);
    }
    REC.with(|r| {
        assert_eq!(
            r.borrow().slots.len(),
            1,
            "first population must push the stem-slot snapshot"
        );
    });
}

#[test]
fn queue_fluff_rejects_a_null_ptr_with_nonzero_len() {
    // Contract: empty blobs may pass a null ptr; non-empty must not. Fail
    // closed on the whole batch so a bad span cannot drop a sibling silently.
    unsafe {
        let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
        shekyl_relay_zone_on_handshake(h, id(1).as_ptr(), true);
        let bad = [ShekylRelayBlob {
            ptr: std::ptr::null(),
            len: 4,
        }];
        assert_eq!(
            shekyl_relay_zone_queue_fluff(h, 0, bad.as_ptr(), 1, std::ptr::null()),
            0,
            "invalid span rejects the batch"
        );
        assert!(
            h.as_ref()
                .expect("live zone")
                .driver
                .zone()
                .peer(&ConnectionId::from_bytes(id(1)))
                .map(|p| p.queued.is_empty())
                .unwrap_or(false),
            "nothing was queued"
        );
        // Empty is still accepted.
        let empty = [ShekylRelayBlob {
            ptr: std::ptr::null(),
            len: 0,
        }];
        assert_eq!(
            shekyl_relay_zone_queue_fluff(h, 0, empty.as_ptr(), 1, std::ptr::null()),
            1,
            "empty blob with null ptr is valid"
        );
        shekyl_relay_zone_free(h);
    }
}
