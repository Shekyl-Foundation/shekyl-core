// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serving task's disk-headroom *measurement*.
//!
//! Mapping onto the board is [`shekyl_operator_alarm::disk`] — this module
//! owns which path, which threshold, and how often, and publishes
//! [`DiskObservation`]s. A dedicated task rather than a line in the
//! refresh loop: the probe is not a serve-set reading, and a wedged
//! refresh must not also silence the volume check.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use shekyl_operator_alarm::disk::{apply as report_disk, DiskObservation};
use shekyl_operator_alarm::OperatorAlarms;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Free space below which the operator is warned that the archival
/// obligation is running out of room (`COMPLETETREE_ACTIVATION.md` Q-2).
///
/// **An operator-UX default, not a derived constant, and not a consensus
/// parameter** — so no derivation is owed and none is faked. The number
/// answers "how much warning is useful", which is a function of how fast a
/// particular node's corpus grows and how long its operator needs to act;
/// both are local facts the wallet cannot know. 8 GiB is chosen to be
/// comfortably more than a segment's growth across many refresh cadences at
/// the rule-76 device floor, while small enough that a Pi-class node with a
/// modest disk is not warned from the day it starts.
///
/// **Reopen criterion (rule 21):** operational measurement showing the
/// warning fires too late to act on (or so early it is ignored) moves this
/// number; it is not a promise to any other layer, and nothing derives from
/// it.
pub(crate) const DISK_HEADROOM_WARN_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Probe the store volume until cancelled, then return so the serving
/// task can disarm the row as not-serving.
///
/// The first reading is taken immediately — the same reason the serve-set
/// reports before the first refresh tick. A hitchhike on that tick would
/// leave the volume unwatched for a full cadence, and would go silent if
/// `refresh` itself wedged (the moment an operator most needs to know the
/// disk is filling).
pub(crate) fn spawn_disk_probe(
    path: PathBuf,
    threshold_bytes: u64,
    cadence: Duration,
    alarms: Arc<OperatorAlarms>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        report_disk(&alarms, observe_disk(&path, threshold_bytes));
        let mut ticker = tokio::time::interval(cadence);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick completes immediately; the line above already
        // reported that reading.
        ticker.tick().await;
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    report_disk(&alarms, observe_disk(&path, threshold_bytes));
                }
            }
        }
    })
}

/// Read free space on the filesystem holding the store.
///
/// `f_bavail × f_frsize` — blocks available *to an unprivileged writer*
/// times the fragment size. Deliberately not `f_bfree`, which counts the
/// root-reserved blocks the wallet cannot actually use: reporting those as
/// headroom would promise room that the process filling the disk does not
/// have.
///
/// A failed probe is [`DiskObservation::Unreadable`], never a guess and
/// never a panic. The disk check is an observability feature; a serving
/// host that stopped because it could not stat a path would have traded a
/// real obligation for a diagnostic (rule 82's inverse).
pub(crate) fn observe_disk(path: &Path, threshold_bytes: u64) -> DiskObservation {
    match rustix::fs::statvfs(path) {
        Ok(stat) => {
            // rustix normalizes both fields to `u64` across platforms, so
            // the product needs no conversion — only saturation, because a
            // nonsense fragment size must not panic a serving task.
            //
            // A saturated product is still a MEASURED reading: it arms the
            // condition and, being enormous, reads clean. That is *not*
            // the same board state as an unreadable probe, which disarms
            // — "the disk has room" and "I cannot tell" are the two
            // sentences this channel exists to keep apart. Saturation here
            // is the benign direction of a value that cannot occur on a
            // real filesystem, not a stand-in for the failure path below.
            let free_bytes = stat.f_bavail.saturating_mul(stat.f_frsize);
            DiskObservation::Measured {
                free_bytes,
                threshold_bytes,
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "could not read free space for the serving store; disk \
                 headroom is unknown until the next tick"
            );
            DiskObservation::Unreadable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_path_is_unreadable() {
        assert_eq!(
            observe_disk(Path::new("/no/such/shekyl-serving-disk-probe"), 1),
            DiskObservation::Unreadable
        );
    }

    #[test]
    fn an_existing_path_is_measured() {
        let reading = observe_disk(&std::env::temp_dir(), 1);
        assert!(
            matches!(reading, DiskObservation::Measured { .. }),
            "a real directory must resolve, not disarm: {reading:?}"
        );
    }
}
