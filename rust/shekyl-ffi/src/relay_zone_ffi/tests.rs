// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use std::cell::RefCell;

/// Zone byte for the cases that do not exercise the per-zone parameter split.
/// Spelled out rather than `1` so a change to the discriminant cannot silently
/// re-point every fixture at a different transport.
const PUBLIC: u8 = RelayZone::Public.as_u8();
/// A noise carrier only exists on an encrypted zone, so covert fixtures build
/// on tor rather than on the cleartext default. Both flags travel together for
/// the same reason: the pair is what production forms at `make_relay_zone`.
const TOR: u8 = RelayZone::Tor.as_u8();
const NOISE_ON_ENCRYPTED: u32 =
    SHEKYL_RELAY_ZONE_NOISE_ENABLED | SHEKYL_RELAY_ZONE_OUTBOUND_FLUFF_ONLY;

// The "C++ side", simulated: recording callbacks that capture exactly what
// crosses the boundary. This is the Effect seam test §18.4a asks for, and it
// runs without a daemon build — which is what lets the transparency check
// gate the expensive oracle rather than trail it.
#[derive(Default)]
struct Recorder {
    fluffed: Vec<([u8; 16], Vec<Vec<u8>>)>,
    unbinds: Vec<usize>,
    /// `(channel, peer)` — peer bytes are the marshalling half of CV-2.
    noise: Vec<(usize, [u8; 16])>,
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

extern "C" fn rec_unbind(_: *mut c_void, channel: usize) {
    REC.with(|r| r.borrow_mut().unbinds.push(channel));
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

extern "C" fn rec_noise(_: *mut c_void, channel: usize, peer: *const u8) {
    let mut p = [0u8; 16];
    unsafe { p.copy_from_slice(slice::from_raw_parts(peer, 16)) };
    REC.with(|r| r.borrow_mut().noise.push((channel, p)));
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
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
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
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
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

/// A due channel with an unbound slot crosses as a `NoiseUnbind` at its own
/// channel index, at every due tick — the marshalling half of the property
/// whose decision half lives in `shekyl-relay`'s
/// `a_due_channel_with_an_unbound_slot_clears_at_every_tick`.
///
/// This is the FFI-layer successor of the retired RP-3a seal
/// (`stem_slots_cross_in_index_order_with_nils_in_position`): there is no
/// pushed array left to check for compaction or reordering, so what remains to
/// witness at this layer is that the channel **index survives `dispatch`
/// intact**, on the poll path production actually drives. Ground truth is
/// read from the zone directly, never from the recorded emission — the
/// sourcing discipline the seal established.
///
/// Negative-controlled: an off-by-one injected into `dispatch`'s
/// `NoiseUnbind` arm (`unbind(ctx, channel + 1)`) fails the index assertion.
#[test]
fn an_unbound_slots_due_ticks_cross_as_noise_unbind_at_its_index() {
    reset();
    unsafe {
        let peers: Vec<u8> = [id(1), id(2)].concat();
        let h = shekyl_relay_zone_new(0, TOR, 2, 600, 30, NOISE_ON_ENCRYPTED);
        shekyl_relay_zone_on_handshake(h, id(1).as_ptr(), false);
        shekyl_relay_zone_on_handshake(h, id(2).as_ptr(), false);
        shekyl_relay_zone_update_stems(h, peers.as_ptr(), 2);

        // Ground truth from the owning structure: which peer holds slot 1.
        let zone = h.as_ref().expect("live zone").driver.zone();
        assert!(
            zone.stem_slots().iter().all(Option::is_some),
            "fixture: both slots bound"
        );
        let keep = *zone.stem_slots()[1].expect("slot 1 bound").as_bytes();
        let gone = *zone.stem_slots()[0].expect("slot 0 bound").as_bytes();

        // The hole recipe: close slot 0's peer AND re-offer only the survivor,
        // so nothing backfills.
        shekyl_relay_zone_on_close(h, gone.as_ptr());
        shekyl_relay_zone_update_stems(h, keep.as_ptr(), 1);
        let zone = h.as_ref().expect("live zone").driver.zone();
        assert_eq!(
            zone.stem_slots()[0],
            None,
            "fixture: the hole is at index 0"
        );

        // Poll at the reported wakes until both kinds have crossed. Twelve
        // covert ticks at 10–15 s sit far inside the 600 s epoch minimum; the
        // gather-call count is asserted zero below to prove no rollover
        // rewrote the fixture mid-drive.
        for _ in 0..12 {
            let done = REC.with(|r| {
                let r = r.borrow();
                2 <= r.unbinds.len() && !r.noise.is_empty()
            });
            if done {
                break;
            }
            let due = shekyl_relay_zone_next_wake(h);
            shekyl_relay_zone_poll(
                h,
                due,
                std::ptr::null_mut(),
                rec_gather,
                rec_fluff,
                rec_unbind,
                rec_noise,
            );
        }
        shekyl_relay_zone_free(h);

        // `keep` must outlive the recorder check below.
        REC.with(|r| {
            let rec = r.borrow();
            assert!(
                2 <= rec.unbinds.len(),
                "the unbound channel's clear crosses at EVERY due tick — zero \
                 means it never crossed, one means the emission became \
                 transition-shaped and lossy"
            );
            assert!(
                rec.unbinds.iter().all(|&c| c == 0),
                "every unbind names the unbound channel's own index — 1 in \
                 {:?} is the off-by-one defect",
                rec.unbinds
            );
            assert!(
                !rec.noise.is_empty(),
                "the bound channel really sent — liveness"
            );
            for &(channel, peer) in &rec.noise {
                assert_eq!(
                    (channel, peer),
                    (1, keep),
                    "NoiseSend must cross with the slot's own peer at its own \
                     index — a wrong peer slice is invisible if only the \
                     channel index is recorded"
                );
            }
        });
    }
    GATHER.with(|g| {
        assert_eq!(
            g.borrow().calls,
            0,
            "fixture: no epoch rollover rewrote the slots mid-drive"
        )
    });
}

#[test]
fn live_stems_atomic_tracks_the_derived_value_after_every_mutation() {
    // The one deliberate cache. Single writer is what makes it honest, so
    // this asserts the published value equals the derived one after each
    // kind of mutation — a second writer, or a missed publish, shows here.
    unsafe {
        let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
        assert_eq!(shekyl_relay_zone_live_stems(h), 0, "fresh zone");

        shekyl_relay_zone_on_handshake(h, id(1).as_ptr(), false);
        assert_eq!(shekyl_relay_zone_live_stems(h), 0, "no stems drawn yet");

        shekyl_relay_zone_force_epoch(h, 0, peers.as_ptr(), 3);
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
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
        let mut out = [0u8; 16];

        assert_eq!(
            shekyl_relay_zone_plan_relay(h, std::ptr::null(), true, out.as_mut_ptr()),
            SHEKYL_RELAY_PLAN_NO_ROUTE,
            "no slots populated yet: transient, and a refresh may fix it"
        );
        assert_eq!(out, NIL, "no successor to report");

        // Refresh, exactly as `dandelionpp_notify`'s retry does.
        let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
        shekyl_relay_zone_update_stems(h, peers.as_ptr(), 3);

        // Drive to a fluff epoch. The role is drawn from OS entropy, so it
        // is reached by re-drawing rather than by construction; at q = 20%
        // the loop bound is astronomically slack.
        let mut rolls = 0;
        while !h.as_ref().expect("live zone").driver.zone().is_fluffing() {
            shekyl_relay_zone_force_epoch(h, 0, peers.as_ptr(), 3);
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
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
        shekyl_relay_zone_update_stems(h, peers.as_ptr(), 3);

        let mut rolls = 0;
        while !h.as_ref().expect("live zone").driver.zone().is_fluffing() {
            shekyl_relay_zone_force_epoch(h, 0, peers.as_ptr(), 3);
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
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
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
                rec_unbind,
                rec_noise,
            );
            REC.with(|r| assert!(r.borrow().fluffed.is_empty(), "not due yet"));
        }

        shekyl_relay_zone_poll(
            h,
            due,
            std::ptr::null_mut(),
            rec_gather,
            rec_fluff,
            rec_unbind,
            rec_noise,
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
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
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
            rec_unbind,
            rec_noise,
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
}

#[test]
fn a_zone_that_would_spin_is_refused_rather_than_built() {
    // A zero epoch expires at every wake, so the daemon's relay timer would
    // re-arm in the past forever. Refusing construction turns a silent
    // busy-loop in the p2p reactor into a loud startup failure.
    assert!(
        shekyl_relay_zone_new(0, PUBLIC, 2, 0, 30, 0).is_null(),
        "zero epoch"
    );
    assert!(
        shekyl_relay_zone_new(0, PUBLIC, usize::MAX, 600, 30, 0).is_null(),
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
            ),
            SHEKYL_RELAY_PLAN_NO_ROUTE,
        );
        let mut carrier = 0xFFu8;
        let mut channel = 0xFFFF_FFFFu32;
        out.fill(0xAA);
        assert_eq!(
            shekyl_relay_zone_plan_dispatch_with_refresh(
                null,
                id(1).as_ptr(),
                true,
                std::ptr::null(),
                0,
                out.as_mut_ptr(),
                &raw mut carrier,
                &raw mut channel,
            ),
            SHEKYL_RELAY_PLAN_NO_ROUTE,
        );
        assert_eq!(out, NIL, "null handle must nil-write out_dest");
        assert_eq!(
            carrier, SHEKYL_RELAY_CARRIER_ORDINARY,
            "null handle must not leave a stale covert carrier"
        );
        assert_eq!(channel, 0, "null handle must not leave a stale slot");
        shekyl_relay_zone_update_stems(null, std::ptr::null(), 0);
        shekyl_relay_zone_force_epoch(null, 0, std::ptr::null(), 0);
        shekyl_relay_zone_poll(
            null,
            0,
            std::ptr::null_mut(),
            rec_gather,
            rec_fluff,
            rec_unbind,
            rec_noise,
        );
        shekyl_relay_zone_free(null);
    }
    REC.with(|r| assert!(r.borrow().fluffed.is_empty(), "no effects from a null zone"));
}

#[test]
fn plan_relay_with_refresh_fills_an_empty_map() {
    // Production notify path: empty public zone, first plan is NoRoute, one
    // refresh populates the map and re-plans — without C++ owning that loop.
    reset();
    unsafe {
        let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
        let mut out = [0u8; 16];
        let plan = shekyl_relay_zone_plan_relay_with_refresh(
            h,
            std::ptr::null(),
            true,
            peers.as_ptr(),
            3,
            out.as_mut_ptr(),
        );
        assert_eq!(
            plan, SHEKYL_RELAY_PLAN_STEM,
            "local origin stems after refresh"
        );
        assert_ne!(out, NIL, "successor written");
        assert_eq!(shekyl_relay_zone_live_stems(h), 2);
        shekyl_relay_zone_free(h);
    }
}

/// The dispatch crossing is additive: same plan as `plan_relay_with_refresh`,
/// plus a carrier. Covert-on + local origin (RD-4: always stems) so the
/// epoch cannot make this vacuous. This bites against a seam that starts
/// re-deciding the phase, and against a covert-on stem that forgets to
/// name a slot inside the stem width.
#[test]
fn dispatch_with_refresh_attaches_a_carrier_without_redeciding_the_plan() {
    reset();
    unsafe {
        let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
        let h = shekyl_relay_zone_new(0, TOR, 2, 600, 30, NOISE_ON_ENCRYPTED);
        assert!(
            shekyl_relay_zone_noise_enabled(h),
            "fixture must actually have covert on or the carrier cell is vacuous"
        );

        let mut dest_plan = [0u8; 16];
        let via_plan = shekyl_relay_zone_plan_relay_with_refresh(
            h,
            std::ptr::null(),
            true,
            peers.as_ptr(),
            3,
            dest_plan.as_mut_ptr(),
        );

        shekyl_relay_zone_free(h);
        let h = shekyl_relay_zone_new(0, TOR, 2, 600, 30, NOISE_ON_ENCRYPTED);
        let mut dest_dispatch = [0u8; 16];
        let mut carrier = 0xFFu8;
        let mut channel = 0xFFFF_FFFFu32;
        let via_dispatch = shekyl_relay_zone_plan_dispatch_with_refresh(
            h,
            std::ptr::null(),
            true,
            peers.as_ptr(),
            3,
            dest_dispatch.as_mut_ptr(),
            &raw mut carrier,
            &raw mut channel,
        );

        assert_eq!(
            via_dispatch, via_plan,
            "dispatch must not re-decide the phase"
        );
        assert_eq!(via_dispatch, SHEKYL_RELAY_PLAN_STEM, "RD-4: origin stems");
        assert_eq!(
            carrier, SHEKYL_RELAY_CARRIER_NOISE,
            "covert is on and this is a stem"
        );
        assert!(
            (channel as usize) < 2,
            "channel is the stem slot (§20.3); {channel} is outside the width"
        );
        shekyl_relay_zone_free(h);
    }
}

#[test]
fn queue_fluff_rejects_a_null_ptr_with_nonzero_len() {
    // Contract: empty blobs may pass a null ptr; non-empty must not. Fail
    // closed on the whole batch so a bad span cannot drop a sibling silently.
    unsafe {
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
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

/// The zone-flag bits do not transpose, and the covert bit round-trips.
///
/// This test is the *reason* [`SHEKYL_RELAY_ZONE_NOISE_ENABLED`] is a named bit
/// rather than a second `bool` parameter, so it must be able to fail if the two
/// bits were ever swapped. It is written as a **negative control on
/// transposition**: each bit is set *alone*, so a swap flips both assertions
/// rather than cancelling out — which a both-bits-set case would not catch.
///
/// Why the stakes justify a dedicated test: transposing these two swaps the
/// i2p/tor outbound-only fluff rule with the covert enable, which is exactly the
/// regression RP-3a's first pass shipped. That one survived only because eight
/// `private_*` gtests happened to cover the fluff side; nothing covered this
/// side, and the C++ header is hand-written, so no codegen would catch a
/// mismatched declaration either.
#[test]
fn zone_flag_bits_do_not_transpose() {
    // **The ABI pin, and the reason it comes first.** A first version of this
    // test set a flag and read it back through the *same constant*, which made
    // swapping both definitions a consistent relabelling — it passed under the
    // very transposition it claimed to catch, because the expectation travelled
    // through the transform under test. Verified by doing the swap: it stayed
    // green.
    //
    // The real hazard was never a Rust-internal swap. It is these values
    // drifting from the `#define`s in the hand-written `shekyl_ffi.h`, which no
    // codegen checks. So the load-bearing assertion is on the **numbers**, which
    // are the actual ABI contract; the round-trip cases below are then
    // meaningful because these are pinned.
    assert_eq!(
        SHEKYL_RELAY_ZONE_OUTBOUND_FLUFF_ONLY, 1,
        "ABI value; `shekyl_ffi.h` hardcodes 1u"
    );
    assert_eq!(
        SHEKYL_RELAY_ZONE_NOISE_ENABLED, 2,
        "ABI value; `shekyl_ffi.h` hardcodes 2u"
    );

    unsafe {
        /* Covert bit ALONE. This is now a REFUSED configuration, not a
        readback: covert without outbound-fluff-only is a noise carrier on
        a cleartext zone, which `Zone::new` rejects (ruling of 2026-08-19).

        The negative control survives the change and is strictly sharper.
        Under a transposition this call would decode as *fluff-only*, which
        is a perfectly ordinary zone and would build — so a swap turns this
        null into a handle, and the assertion flips. The refusal is the
        observation; a readback is no longer available here because the
        zone does not exist to be read. */
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, SHEKYL_RELAY_ZONE_NOISE_ENABLED);
        assert!(
            h.is_null(),
            "covert bit set alone is a noise carrier on a cleartext zone and \
             must be refused; a handle here means the bits are transposed and \
             this decoded as the harmless fluff-only zone"
        );

        // Fluff bit ALONE. A swap makes this read the covert bit → refused,
        // so the handle would be null and BOTH assertions below would fail.
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, SHEKYL_RELAY_ZONE_OUTBOUND_FLUFF_ONLY);
        assert!(
            !h.is_null(),
            "an outbound-fluff-only zone is ordinary and builds"
        );
        assert!(
            !shekyl_relay_zone_noise_enabled(h),
            "outbound-fluff bit set alone must NOT enable covert; \
             reading true here means the bits are transposed"
        );
        shekyl_relay_zone_free(h);

        // Neither, and both — the two ends, so an always-true or always-false
        // decode cannot pass the set above by accident.
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
        assert!(!shekyl_relay_zone_noise_enabled(h), "no flags ⇒ no covert");
        shekyl_relay_zone_free(h);

        /* Both flags, on an ENCRYPTED zone — the only configuration a noise
        carrier is allowed in. Swap-blind by construction (both bits set),
        so it is the positive readback and not part of the control. */
        let h = shekyl_relay_zone_new(0, TOR, 2, 600, 30, NOISE_ON_ENCRYPTED);
        assert!(
            shekyl_relay_zone_noise_enabled(h),
            "both flags on an encrypted zone ⇒ covert on"
        );
        shekyl_relay_zone_free(h);

        /* An OUT-OF-DOMAIN zone byte with noise flags — refused. The two
        fail-safe directions point opposite ways on purpose: an unknown zone
        draws the *anonymity* parameters (the longer embargo, the safe
        direction there), but it is not presumed *encrypted*, so it earns no
        noise. Pinned because an asymmetry that is not stated reads as an
        accident, and the next reader "fixing" it would silently hand a
        noise carrier to a link nobody could identify. */
        let h = shekyl_relay_zone_new(0, 0xFF, 2, 600, 30, NOISE_ON_ENCRYPTED);
        assert!(
            h.is_null(),
            "an unknown link is not presumed encrypted and earns no noise"
        );

        /* Both flags on a CLEARTEXT zone — refused. This pins the axis split
        the flags used to hide: outbound-only fluff does not imply an
        encrypted link. It is a real configuration (§25.5 keeps
        outbound-only fluff on clearnet open) and it is still cleartext, so
        it earns no noise. Before secrecy was read from the zone byte this
        case built a zone, because reach was standing in for encryption. */
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, NOISE_ON_ENCRYPTED);
        assert!(
            h.is_null(),
            "outbound-only fluff is not encryption; a cleartext zone earns no \
             noise however its fluff reach is configured"
        );

        // A null handle answers false rather than aborting: a caller that lost
        // its zone has no covert channels by construction.
        assert!(!shekyl_relay_zone_noise_enabled(std::ptr::null()));
    }
}

/// The FFI observation pair round-trips into the zone's `StemWatch`: a
/// recorded stem resolves as *propagated* on arrival, and the deadline drawn
/// at the FFI site is the adopted embargo's (so a poll far past it resolves
/// the unresolved one as *silent*). This is the boundary witness — the
/// per-crate tests already cover the arithmetic; what this asserts is that
/// the packed-byte decoding (32-byte ids, 16-byte uuids, null source =
/// local origin) reaches the right zone calls.
#[test]
fn record_stem_and_arrival_cross_the_boundary_into_the_watch() {
    fn stem_map_id(byte: u8) -> shekyl_relay_privacy::stem_map::ConnectionId {
        shekyl_relay_privacy::stem_map::ConnectionId::from_bytes(id(byte))
    }
    unsafe {
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
        shekyl_relay_zone_on_handshake(h, id(9).as_ptr(), true);

        let mut hashes = [0u8; 64]; // two packed 32-byte canonical tx hashes
        hashes[0] = 0xA1;
        hashes[32] = 0xB2;
        shekyl_relay_zone_record_stem(h, hashes.as_ptr(), 2, id(9).as_ptr(), std::ptr::null(), 0);
        assert_eq!(
            h.as_ref()
                .expect("live zone")
                .driver
                .zone()
                .stem_observations_in_flight(),
            2,
            "both packed ids armed against the successor"
        );

        // First id returns: resolved as propagated.
        shekyl_relay_zone_record_arrival(h, hashes.as_ptr(), 1, id(9).as_ptr());
        assert_eq!(
            shekyl_relay_zone_stem_in_flight(h),
            2,
            "F-10: an echo from the charged successor resolves nothing"
        );
        shekyl_relay_zone_record_arrival(h, hashes.as_ptr(), 1, id(3).as_ptr());
        let t = h
            .as_ref()
            .expect("live zone")
            .driver
            .zone()
            .stem_tally(&stem_map_id(9))
            .expect("arrival resolved against the successor");
        assert_eq!((t.propagated, t.silent), (1, 0));

        // The second never returns. Its deadline was drawn from the adopted
        // embargo at now=0, so a poll at 1h — far past any draw — resolves it
        // as silent through the production poll path, not a test back door.
        shekyl_relay_zone_poll(
            h,
            3_600_000,
            std::ptr::null_mut(),
            rec_gather,
            rec_fluff,
            rec_unbind,
            rec_noise,
        );
        let t = h
            .as_ref()
            .expect("live zone")
            .driver
            .zone()
            .stem_tally(&stem_map_id(9))
            .expect("tally survives");
        assert_eq!(
            (t.propagated, t.silent),
            (1, 1),
            "the unreturned id resolved as silent on the poll clock"
        );

        // Null handle and null hashes: no-ops, not crashes.
        shekyl_relay_zone_record_stem(
            std::ptr::null_mut(),
            hashes.as_ptr(),
            1,
            id(9).as_ptr(),
            std::ptr::null(),
            0,
        );
        shekyl_relay_zone_record_arrival(h, std::ptr::null(), 1, std::ptr::null());
        assert_eq!(
            shekyl_relay_zone_stem_in_flight(h),
            0,
            "both resolved — the in-flight accessor reads the same fact"
        );

        shekyl_relay_zone_free(h);
    }
}

/// An overflowing batch length trips the guard rather than the multiply.
///
/// Without `checked_mul`, `n * 32` wraps to a small number and
/// `from_raw_parts` builds a slice over memory the caller never provided —
/// undefined behaviour reached from a plain integer argument. `read_tx_ids`
/// mirrors `read_ids`: loud in debug, empty in release, never wrapped.
///
/// **Driven at the helper, not through the export, and that is forced rather
/// than chosen.** A panic cannot unwind out of an `extern "C"` function, so
/// reaching this `debug_assert` through `shekyl_relay_zone_record_stem`
/// *aborts the process* instead of unwinding — `#[should_panic]` cannot
/// observe it, and a debug-built daemon would die rather than return. That is
/// acceptable (the guard is a caller-bug tripwire, and `debug_assert`
/// compiles out of release), but it means the guard is only testable where it
/// is defined.
#[test]
#[should_panic(expected = "overflows")]
fn an_overflowing_batch_length_trips_the_guard_not_the_multiply() {
    let hashes = [0u8; 32];
    let ids = unsafe { read_tx_ids(hashes.as_ptr(), usize::MAX) };
    unreachable!("guard did not fire; got {} ids", ids.len());
}

/// A nil successor arms nothing — and the second arm is what makes the first
/// mean something.
///
/// `read_id`'s nil-means-no-id contract is live at this boundary, so an
/// observation charged to "no peer" must not be armed at all. Before these
/// exports went through `read_id`, a nil successor built an all-zeros
/// `ConnectionId` and the observation was charged to a connection that cannot
/// exist — it could never resolve, and would age into a silence against a
/// peer that was never asked to do anything.
#[test]
fn a_nil_successor_arms_no_observation_but_a_real_one_does() {
    unsafe {
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
        let mut hashes = [0u8; 32];
        hashes[0] = 0xA1;

        shekyl_relay_zone_record_stem(
            h,
            hashes.as_ptr(),
            1,
            id(0).as_ptr(), // all-zero uuid == nil
            std::ptr::null(),
            0,
        );
        assert_eq!(
            shekyl_relay_zone_stem_in_flight(h),
            0,
            "a nil successor must arm nothing — an observation it can never \
             resolve would age into a silence against a peer that does not exist"
        );

        shekyl_relay_zone_record_stem(h, hashes.as_ptr(), 1, id(9).as_ptr(), std::ptr::null(), 0);
        assert_eq!(
            shekyl_relay_zone_stem_in_flight(h),
            1,
            "liveness: the identical call with a real successor DOES arm — \
             without this the assertion above passes for any reason at all"
        );
        shekyl_relay_zone_free(h);
    }
}

/// The zone byte selects the transport-bound parameters, and the stem
/// observation window is where that shows.
///
/// §89.2 makes `hop` per-zone, but the handle was still built from
/// `DandelionParams::adopted()` for every zone — so an anonymity zone armed a
/// clearnet 190 s observation against the 499 s embargo its own successor
/// draws. Every honest i2p/tor peer would age into `silent` before it was even
/// allowed to re-relay, and `stem_tallies` would report the whole anonymity
/// peer set as withholding.
///
/// Sampled rather than pinned: the deadline is a geometric draw on `OsRng`.
/// The epoch is set far past both means so `next_wake` reports the observation
/// rather than the epoch roll. The means differ by ~2.6x, so a 1.5x threshold
/// cannot flake.
#[test]
fn the_zone_byte_selects_the_observation_window() {
    const ROUNDS: u32 = 200;
    const EPOCH_BEYOND_BOTH_MEANS_SECS: u32 = 1_000_000;

    let mean_wake = |zone: u8| -> f64 {
        let mut total = 0f64;
        for _ in 0..ROUNDS {
            unsafe {
                let h = shekyl_relay_zone_new(0, zone, 2, EPOCH_BEYOND_BOTH_MEANS_SECS, 0, 0);
                let mut hashes = [0u8; 32];
                hashes[0] = 0xA1;
                shekyl_relay_zone_record_stem(
                    h,
                    hashes.as_ptr(),
                    1,
                    id(9).as_ptr(),
                    std::ptr::null(),
                    0,
                );
                // Lossless rather than an `as` cast with a precision allow:
                // these deadlines are milliseconds well under `u32::MAX`
                // (~49 days), so a value that does not fit is a defect worth
                // failing on rather than rounding.
                let wake = u32::try_from(shekyl_relay_zone_next_wake(h))
                    .expect("an embargo deadline in ms fits u32 at this epoch length");
                total += f64::from(wake);
                shekyl_relay_zone_free(h);
            }
        }
        total / f64::from(ROUNDS)
    };

    let clearnet = mean_wake(PUBLIC);
    let anonymity = mean_wake(RelayZone::Tor.as_u8());
    assert!(
        anonymity > clearnet * 1.5,
        "the anonymity zone must arm a longer observation window than clearnet \
         (§89.2): clearnet {clearnet:.0} ms vs anonymity {anonymity:.0} ms"
    );

    // Negative control: two samples of the SAME zone must not separate, or the
    // assertion above would pass on any source of variance at all.
    let clearnet_again = mean_wake(PUBLIC);
    assert!(
        clearnet_again < clearnet * 1.5 && clearnet < clearnet_again * 1.5,
        "two clearnet samples must not separate: {clearnet:.0} vs {clearnet_again:.0} ms"
    );
}

/// The §55 telemetry readout crosses the boundary as fixed rows, and its
/// two-call sizing contract holds: a short buffer writes nothing and reports
/// the needed row count.
#[test]
fn stem_snapshot_reports_row_count_and_writes_only_when_it_fits() {
    unsafe {
        let h = shekyl_relay_zone_new(0, PUBLIC, 2, 600, 30, 0);
        shekyl_relay_zone_on_handshake(h, id(9).as_ptr(), true);

        // Empty zone: zero rows, not an error.
        let mut rows = [std::mem::zeroed::<ShekylStemTallyRow>(); 4];
        let n = shekyl_relay_zone_stem_snapshot(h, rows.as_mut_ptr(), rows.len());
        assert_eq!(n, 0, "no observations is an empty snapshot");

        let mut hashes = [0u8; 32];
        hashes[0] = 0xA1;
        shekyl_relay_zone_record_stem(h, hashes.as_ptr(), 1, id(9).as_ptr(), std::ptr::null(), 0);
        shekyl_relay_zone_record_arrival(h, hashes.as_ptr(), 1, id(3).as_ptr());

        let need = shekyl_relay_zone_stem_snapshot(h, std::ptr::null_mut(), 0);
        assert_eq!(need, 1, "a resolved observation must produce one row");

        // Short buffer: nothing written, count still reported. Sentinel proves
        // "wrote nothing" rather than a partial fill.
        let mut small = [ShekylStemTallyRow {
            peer: [0xEE; 16],
            propagated: 0xEEEE_EEEE_EEEE_EEEE,
            silent: 0xEEEE_EEEE_EEEE_EEEE,
            distinct_sources: 0xEEEE_EEEE_EEEE_EEEE,
        }];
        assert_eq!(
            shekyl_relay_zone_stem_snapshot(h, small.as_mut_ptr(), 0),
            need
        );
        assert_eq!(small[0].peer, [0xEE; 16], "cap 0 must not touch the buffer");

        let n = shekyl_relay_zone_stem_snapshot(h, rows.as_mut_ptr(), rows.len());
        assert_eq!(n, 1);
        assert_eq!(rows[0].peer, id(9));
        assert_eq!(rows[0].propagated, 1);
        assert_eq!(rows[0].silent, 0);
        assert_eq!(
            rows[0].distinct_sources, 1,
            "local origin (null source) is still one distinct source key"
        );
        shekyl_relay_zone_free(h);
    }
}

/// The zone-route byte policy, exercised through the REAL exports — the C++
/// static_asserts pin known values, so these pin what happens OUTSIDE them.
///
/// The load-bearing arm is the inverted one: for `originated_stays_in_zone`
/// an unknown ZONE byte on a `local` origin must return `true`, because
/// `false` lets the record upgrade to `stem`/`fluff` and the next pool
/// re-relay puts an anonymity-origin transaction on clearnet (§30.5). A
/// future zone added on the C++ side before this crate learns its byte must
/// fail toward liveness loss, never toward the leak.
#[test]
fn zone_route_unknown_bytes_fail_toward_refusal_never_clearnet() {
    const LOCAL: u8 = 1;
    const STEM: u8 = 2;
    const TOR: u8 = 3;
    const UNKNOWN_ZONE: u8 = 4; // first byte a future zone would claim
    const UNKNOWN_METHOD: u8 = 9;
    const FAIL_CLOSED: u8 = 1;

    // The inverted arm: local + undecodable zone keeps `local`.
    assert!(shekyl_relay_zone_originated_stays_in_zone(
        LOCAL,
        UNKNOWN_ZONE
    ));
    // No `local` claim is invented for an undecodable method…
    assert!(!shekyl_relay_zone_originated_stays_in_zone(
        UNKNOWN_METHOD,
        TOR
    ));
    // …and a relayed class on an unknown zone keeps its own record.
    assert!(!shekyl_relay_zone_originated_stays_in_zone(
        STEM,
        UNKNOWN_ZONE
    ));

    // The send-path decision on any undecodable input is fail-closed — send
    // nothing is the one default that cannot leak.
    assert_eq!(
        shekyl_relay_zone_once_at_origin_route(STEM, UNKNOWN_ZONE),
        FAIL_CLOSED
    );
    assert_eq!(
        shekyl_relay_zone_once_at_origin_route(UNKNOWN_METHOD, TOR),
        FAIL_CLOSED
    );

    // No coherence claim is invented for a zone that does not decode; the
    // fail-closed token above is what actually guards the send.
    assert!(!shekyl_relay_zone_r1_coherence_keeps_origin(
        STEM,
        UNKNOWN_ZONE
    ));
    assert!(!shekyl_relay_zone_is_pre_fluff_relay(UNKNOWN_METHOD));
}

/// The composed roll export returns only the two zone bytes the contract
/// names — whichever way the draw lands, the byte is `invalid` (0) or
/// `public_` (1), never a third value and never an anonymity zone directly
/// (the zone map resolves `invalid`; that indirection is the fail-closed
/// design, §30.5).
#[test]
fn roll_originated_zone_returns_only_the_two_contract_bytes() {
    for _ in 0..64 {
        let z = shekyl_relay_zone_roll_originated_zone();
        assert!(z == 0 || z == 1, "roll returned byte {z}");
    }
}
