// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one clock sentence (`TOR_SUPERVISOR.md` §5, "Clock skew"; Rick,
//! 2026-11-10).
//!
//! Three sources can name the clock, and the line is one of them. Tor's
//! figure when Tor reported one. This node's lower bound from the consensus
//! otherwise, which only sees behind. The certificate verdict when neither
//! figure is there: it carries none.

use std::time::Duration;

use super::posture::{spoken_duration, Cause, ReportedSkew, Status};

const CHECK: &str = "Check this computer's date and time.";

/// The clock clause of [`super::posture::render`], if any source names it.
pub(super) fn sentence(status: &Status) -> Option<String> {
    if let Cause::ClockSkew { skew } = status.cause {
        return Some(reported(skew, status.clock_behind.is_some()));
    }
    if let Some(behind) = status.clock_behind {
        return Some(lower_bound(behind));
    }
    if matches!(status.cause, Cause::CertificatesOutOfDate) {
        return Some(format!(
            "Tor reports that this computer's date or time looks wrong, so it cannot connect. {CHECK}"
        ));
    }
    None
}

/// Tor's figure. The reachability clause is the consensus check's, not the
/// sign of the figure: an ahead report beside a lag still says the
/// directories may refuse this node's address.
fn reported(skew: ReportedSkew, consensus_behind: bool) -> String {
    let span = spoken_span(Duration::from_secs(skew.seconds().unsigned_abs()));
    let bound = match skew {
        ReportedSkew::Measured(_) => "",
        ReportedSkew::AtLeast(_) => "at least ",
    };
    let direction = if skew.is_behind() {
        "behind"
    } else {
        "ahead of"
    };
    let reach = if consensus_behind {
        " Others may not be able to reach this node."
    } else {
        ""
    };
    format!("This computer's clock is {bound}{span} {direction} the Tor network's.{reach} {CHECK}")
}

/// The consensus check's lower bound. It only sees a clock behind.
fn lower_bound(behind: Duration) -> String {
    let span = spoken_span(behind);
    format!(
        "This computer's clock is at least {span} behind the Tor network's. Others may not be able to reach this node. {CHECK}"
    )
}

/// A span that can run to days, at the precision the clock line needs:
/// days and hours, hours and minutes, or [`spoken_duration`] below an hour.
fn spoken_span(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 86_400 {
        format!("{} d {} h", seconds / 86_400, seconds % 86_400 / 3_600)
    } else if seconds >= 3_600 {
        format!("{} h {} min", seconds / 3_600, seconds % 3_600 / 60)
    } else {
        spoken_duration(duration)
    }
}
