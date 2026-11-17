// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A connector's path readings as a test sets them
//! (`shekyl_transport_layer::PathSource`). The judge asks the dialing
//! connector for a reading taken after a failure; this source answers from
//! the readings the test has put on its timeline, records each ask, and
//! rings the dialer's bell when a reading is added, as a connector's own
//! source does.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use shekyl_dialer::Dialer;
use shekyl_peerlist::ConnectorId;
use shekyl_timing_engine::{Clock, ManualClock, Stamp};
use shekyl_transport_layer::{PathReading, PathReady, PathSource};

/// The dialer these tests drive: on the manual clock.
type TestDialer = Dialer<ManualClock>;

#[derive(Default)]
struct Timeline {
    /// Readings in the order added, each at its instant.
    readings: Vec<(Stamp, PathReading)>,
    /// Every failure the judge asked about, once per ask.
    asks: Vec<Stamp>,
    /// What the last ask gave to ring.
    ready: Option<PathReady>,
    /// Every reading is this one, whenever asked.
    always: Option<PathReading>,
}

/// A scripted source of path readings.
#[derive(Clone)]
pub struct ScriptedPath {
    timeline: Arc<Mutex<Timeline>>,
    wait_nanos: u64,
}

impl ScriptedPath {
    /// A source with `wait_nanos` as its declared wait, installed as
    /// `connector`'s on `dialer`. It has no reading yet.
    pub fn install(dialer: &TestDialer, connector: ConnectorId, wait_nanos: u64) -> Self {
        let path = Self {
            timeline: Arc::default(),
            wait_nanos,
        };
        dialer.set_path_source(connector, Arc::new(path.clone()));
        path
    }

    /// A source whose path always works, installed as `connector`'s: every
    /// uncertain failure counts.
    pub fn working(dialer: &TestDialer, connector: ConnectorId) -> Self {
        let path = Self::install(dialer, connector, 0);
        path.timeline.lock().expect("timeline").always = Some(PathReading::Working);
        path
    }

    /// The path read `reading` at `clock`'s instant now. The dialer's bell
    /// rings, as a connector's source rings it.
    pub fn read_now(&self, clock: &ManualClock, reading: PathReading) {
        let ready = {
            let mut timeline = self.timeline.lock().expect("timeline");
            timeline.readings.push((clock.stamp(), reading));
            timeline.ready.clone()
        };
        if let Some(ready) = ready {
            ready();
        }
    }

    /// How many times the judge asked.
    pub fn asks(&self) -> usize {
        self.timeline.lock().expect("timeline").asks.len()
    }

    /// The failure instants the judge asked about, in order.
    pub fn asked_after(&self) -> Vec<Stamp> {
        self.timeline.lock().expect("timeline").asks.clone()
    }
}

impl PathSource for ScriptedPath {
    fn reading_after(&self, failed: Stamp, now: Stamp, ready: &PathReady) -> Option<PathReading> {
        let mut timeline = self.timeline.lock().expect("timeline");
        timeline.asks.push(failed);
        timeline.ready = Some(Arc::clone(ready));
        if let Some(always) = timeline.always {
            return Some(always);
        }
        timeline
            .readings
            .iter()
            .find(|(at, _)| *at > failed && *at <= now)
            .map(|(_, reading)| *reading)
    }

    fn wait_nanos(&self) -> u64 {
        self.wait_nanos
    }
}
