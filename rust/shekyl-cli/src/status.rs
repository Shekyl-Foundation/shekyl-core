// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The line printed above the prompt.
//!
//! Version, local civil time, and wallet sync. Drawn on the prompt thread,
//! once per prompt, so it cannot race the line editor. A missing daemon
//! height is never rendered as zero or as synced.

use time::OffsetDateTime;

/// What the sync field may say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncView {
    NoWallet,
    /// `get_height` itself failed. The wallet RPC did not answer, so the
    /// line does not name the daemon.
    WalletRpcUnreachable,
    /// A successful `get_height` whose `daemon_height` is null.
    DaemonUnreachable,
    Behind(u64),
    Synced,
}

impl SyncView {
    pub fn label(&self) -> String {
        match self {
            Self::NoWallet => "no wallet".to_owned(),
            Self::WalletRpcUnreachable => "wallet RPC unreachable".to_owned(),
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

/// Local civil time, `YYYY-MM-DD HH:MM:SS`.
///
/// When the offset cannot be read, the same fields are labeled `UTC`
/// rather than presented as local.
pub fn local_clock() -> String {
    match OffsetDateTime::now_local() {
        Ok(now) => format_civil(now),
        Err(_) => format!("{} UTC", format_civil(OffsetDateTime::now_utc())),
    }
}

fn format_civil(when: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        when.year(),
        u8::from(when.month()),
        when.day(),
        when.hour(),
        when.minute(),
        when.second(),
    )
}

/// Print `line` when stdout is a terminal. The next prompt is drawn under it.
pub fn print_above_prompt(line: &str) {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        println!("{line}");
    }
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
        let line = format_line("3.1.0", "2026-09-26 00:00:00", &SyncView::Synced);
        assert!(line.contains("shekyl-cli 3.1.0"));
        assert!(line.contains("synced"));
        assert!(!format_line("3.1.0", "t", &SyncView::DaemonUnreachable).contains("synced"));
        let wallet_rpc = format_line("3.1.0", "t", &SyncView::WalletRpcUnreachable);
        assert!(wallet_rpc.contains("wallet RPC unreachable"));
        assert!(!wallet_rpc.contains("daemon"));
    }

    #[test]
    fn local_clock_still_reads_after_another_thread_exists() {
        // `time` 0.3.47 obtains the offset with `localtime_r` on Unix and
        // `SystemTimeToTzSpecificLocalTime` on Windows. Neither refuses
        // because another thread exists, so the status line stays local
        // after the self-hosted session starts its Tokio runtime. A later
        // crate that brings the old refusal back must not relabel the
        // clock UTC without this test failing.
        std::thread::spawn(|| {}).join().expect("thread");
        let clock = local_clock();
        assert!(
            !clock.ends_with(" UTC"),
            "local clock fell back after a second thread: {clock}"
        );
    }

    #[test]
    fn unix_epoch_is_the_civil_date() {
        let epoch = OffsetDateTime::from_unix_timestamp(0).expect("epoch");
        assert_eq!(format_civil(epoch), "1970-01-01 00:00:00");
    }
}
