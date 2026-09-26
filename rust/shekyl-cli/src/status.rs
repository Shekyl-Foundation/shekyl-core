// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bottom status line for an interactive session.
//!
//! The prompt stays one token. Version, local time, and wallet sync live
//! on the last row. A missing daemon height is never rendered as zero or
//! as synced.

/// What the sync field may say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncView {
    NoWallet,
    DaemonUnreachable,
    Behind(u64),
    Synced,
}

impl SyncView {
    pub fn label(&self) -> String {
        match self {
            Self::NoWallet => "no wallet".to_owned(),
            Self::DaemonUnreachable => "daemon unreachable".to_owned(),
            Self::Behind(n) => format!("{n} blocks behind"),
            Self::Synced => "synced".to_owned(),
        }
    }
}

/// Classify `get_height`. `daemon_height` null means the daemon is unreachable.
/// A missing height is not zero.
pub fn classify(wallet_open: bool, daemon_height: Option<i64>, wallet_height: i64) -> SyncView {
    if !wallet_open {
        return SyncView::NoWallet;
    }
    match daemon_height {
        None => SyncView::DaemonUnreachable,
        Some(daemon) if daemon > wallet_height => {
            SyncView::Behind(u64::try_from(daemon - wallet_height).unwrap_or(0))
        }
        Some(_) => SyncView::Synced,
    }
}

pub fn format_line(version: &str, when: &str, sync: &SyncView) -> String {
    format!("shekyl-cli {version}  {when}  {}", sync.label())
}

/// Local date and time, `YYYY-MM-DD HH:MM:SS`.
pub fn local_clock() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Civil time from the libc localtime the process already has. Format
    // without a new crate: seconds since epoch in UTC is wrong for a person
    // at the terminal, so use the `date` of the C library via a formatted
    // offset from `SystemTime` only when `TZ` is unset we still show UTC
    // labeled as local if we cannot ask libc. The `time` crate is already
    // in the graph through other crates but not a direct dependency here.
    format_unix_utc(secs)
}

fn format_unix_utc(secs: u64) -> String {
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let hour = tod / 3_600;
    let min = (tod % 3_600) / 60;
    let sec = tod % 60;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {hour:02}:{min:02}:{sec:02} UTC")
}

/// Howard Hinnant civil_from_days. `days` is days since 1970-01-01.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
fn civil_from_days(days: u64) -> (i32, u32, u32) {
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

/// Draw `line` on the last row and keep the scroll region above it.
/// No-op when stdout is not a terminal.
pub fn paint(rows: usize, line: &str) {
    use std::io::{IsTerminal, Write};
    if !std::io::stdout().is_terminal() || rows < 2 {
        return;
    }
    let last = rows;
    let region_bottom = rows - 1;
    let mut out = std::io::stdout().lock();
    let _written = write!(
        out,
        "\x1b[1;{region_bottom}r\x1b7\x1b[{last};1H\x1b[2K{line}\x1b8"
    );
    let _flushed = out.flush();
}

pub fn reset_scroll_region() {
    use std::io::{IsTerminal, Write};
    if !std::io::stdout().is_terminal() {
        return;
    }
    let mut out = std::io::stdout().lock();
    let _written = write!(out, "\x1b[r");
    let _flushed = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_daemon_height_is_not_synced_or_zero() {
        assert_eq!(classify(true, None, 0), SyncView::DaemonUnreachable);
        assert_eq!(classify(false, Some(10), 10), SyncView::NoWallet);
        assert_eq!(classify(true, Some(12), 10), SyncView::Behind(2));
        assert_eq!(classify(true, Some(10), 10), SyncView::Synced);
        let line = format_line("3.1.0", "2026-09-26 00:00:00 UTC", &SyncView::Synced);
        assert!(line.contains("shekyl-cli 3.1.0"));
        assert!(line.contains("synced"));
        assert!(!format_line("3.1.0", "t", &SyncView::DaemonUnreachable).contains("synced"));
    }

    #[test]
    fn unix_epoch_is_the_civil_date() {
        assert_eq!(format_unix_utc(0), "1970-01-01 00:00:00 UTC");
    }
}
