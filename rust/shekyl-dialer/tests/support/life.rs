// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The judge's clock in a test (`crate::judge`), and each session's last
//! received byte as the test sets it. The clock is the test's manual clock
//! in milliseconds ([`Life::install`]), or its own ([`Life::install_own`]):
//! the judge reads the byte-stamp clock, which need not move with the
//! engine's.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use shekyl_dialer::Dialer;
use shekyl_seam::SocketId;
use shekyl_timing_engine::{Clock, ManualClock};

/// The received bytes a test shows the judge, and the judge's clock.
#[derive(Clone)]
pub struct Life {
    stamps: Arc<Mutex<HashMap<u64, u64>>>,
    alive: Arc<AtomicBool>,
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
    own: Arc<AtomicU64>,
}

/// Milliseconds of `clock`, the judge's unit.
pub fn ms(clock: &ManualClock) -> u64 {
    clock.now().get() / 1_000_000
}

impl Life {
    /// Drive `dialer`'s judge from `clock`. Nothing has received a byte.
    pub fn install(dialer: &Dialer, clock: &ManualClock) -> Self {
        let clock = clock.clone();
        Self::with_clock(dialer, Arc::new(move || ms(&clock)), Arc::default())
    }

    /// Drive `dialer`'s judge from a clock of its own, at `start_ms` until
    /// [`Self::set_ms`] moves it.
    pub fn install_own(dialer: &Dialer, start_ms: u64) -> Self {
        let own = Arc::new(AtomicU64::new(start_ms));
        let read = Arc::clone(&own);
        Self::with_clock(dialer, Arc::new(move || read.load(Ordering::Acquire)), own)
    }

    fn with_clock(
        dialer: &Dialer,
        now: Arc<dyn Fn() -> u64 + Send + Sync>,
        own: Arc<AtomicU64>,
    ) -> Self {
        let life = Self {
            stamps: Arc::default(),
            alive: Arc::default(),
            now,
            own,
        };
        let read = life.clone();
        dialer.set_life_clock(
            Arc::clone(&life.now),
            Arc::new(move |id| {
                if read.alive.load(Ordering::Acquire) {
                    return (read.now)();
                }
                read.stamps
                    .lock()
                    .expect("stamps")
                    .get(&id)
                    .copied()
                    .unwrap_or(0)
            }),
        );
        life
    }

    /// The judge's clock now.
    pub fn now_ms(&self) -> u64 {
        (self.now)()
    }

    /// Move the judge's own clock ([`Self::install_own`]) to `at_ms`.
    pub fn set_ms(&self, at_ms: u64) {
        self.own.store(at_ms, Ordering::Release);
    }

    /// Every session has just received a byte, whenever the judge looks:
    /// the link works.
    pub fn keep_alive(&self) {
        self.alive.store(true, Ordering::Release);
    }

    /// `id`'s last byte arrived at `at_ms`.
    pub fn received(&self, id: SocketId, at_ms: u64) {
        self.stamps.lock().expect("stamps").insert(id.get(), at_ms);
    }

    /// `id`'s last byte arrived now, on the judge's clock.
    pub fn received_now(&self, id: SocketId) {
        self.received(id, self.now_ms());
    }
}
