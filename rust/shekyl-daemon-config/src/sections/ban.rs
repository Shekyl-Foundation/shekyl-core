// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ban file, read at parse. An entry is an IPv4 subnet, one host, or
//! one IP peer. The ban table is keyed by IP, so an onion line is refused
//! rather than read and never applied.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use shekyl_options::{Code, Diagnostic, PeerEndpoint, Source, Value};

use super::Ban;

/// Reads the ban file: one entry per line, `#` starts a comment, blank
/// lines are skipped.
///
/// # Errors
/// `config.ban-file.unreadable` naming the path and the error, or
/// `config.ban-file.line` naming the path, the line and its text.
pub fn read_ban_file(path: &Path) -> Result<Vec<Ban>, Diagnostic> {
    let shown = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|e| {
        Diagnostic::new(Code::BanFileUnreadable, Source::Machine)
            .option("p2p-ban-file")
            .param("path", shown.clone())
            .param("error", e.to_string())
    })?;
    let mut bans = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let entry = parse_ban(line).ok_or_else(|| {
            Diagnostic::new(Code::BanFileLine, Source::Machine)
                .option("p2p-ban-file")
                .param("path", shown.clone())
                .param("line", (i + 1).to_string())
                .param("text", line)
        })?;
        bans.push(entry);
    }
    Ok(bans)
}

/// A ban names a host, an IPv4 subnet, or one IP peer's host.
fn parse_ban(line: &str) -> Option<Ban> {
    if let Some((ip, prefix)) = line.split_once('/') {
        let ip: Ipv4Addr = ip.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        return (prefix <= 32).then_some(Ban::Subnet(ip, prefix));
    }
    if let Ok(ip) = line.parse::<IpAddr>() {
        return Some(Ban::Host(ip));
    }
    match shekyl_options::Kind::PeerEndpoint(shekyl_options::PeerRule::Any).parse_text(line) {
        Ok(Value::Peer(PeerEndpoint::Ip(endpoint))) => Some(Ban::Peer(endpoint)),
        _ => None,
    }
}
