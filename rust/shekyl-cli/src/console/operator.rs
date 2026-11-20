// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The §13 words that had no renderer in the moved console.
//!
//! Each call names its method by type. A refusal is the error class and the
//! diagnostic code.

use super::call;
use crate::daemon::DaemonClient;
use shekyl_rpc_client::wire;
use shekyl_rpc_types::hash::HashHex;
use shekyl_rpc_types::kinds::{Duration, Height, NoParams, Text};
use shekyl_rpc_types::wire::node::{OptionRow, OptionSource};
use shekyl_rpc_types::wire::shared::{OpenMap, Slot};

/// `chain coinbase sum --from <height> --to <height>`, inclusive.
pub(super) fn chain_coinbase_sum(src: &DaemonClient, from: u64, to: u64) -> Result<String, String> {
    let reply = call::<wire::ChainCoinbaseSum>(
        src,
        &wire::chain::CoinbaseSumRange {
            from: Height(from),
            to: Height(to),
        },
    )?;
    Ok(format!(
        "emission: {} SKL\nfee: {} SKL",
        reply.emission.to_atomic_units().to_skl_string(),
        reply.fee.to_atomic_units().to_skl_string()
    ))
}

fn hash_of(hash: &str) -> Result<HashHex, String> {
    HashHex::from_hex(hash).map_err(|error| error.to_string())
}

/// What one named id's slot in an `Acted` reply says: acted on, or the
/// pool this caller may see holds no such entry (IG-Q89).
fn acted_on(reply: &[Slot<HashHex>], hash: &str, verb: &str) -> Result<String, String> {
    match reply {
        [Slot::Item(_)] => Ok(format!("{verb} {hash}")),
        [_] => Err(format!("the pool holds no transaction {hash}")),
        other => Err(format!(
            "asked about 1 transaction, got {} slots",
            other.len()
        )),
    }
}

/// `tx relay <id>`: offer the node's own pool entry to the relay again.
pub(super) fn tx_relay(src: &DaemonClient, hash: &str) -> Result<String, String> {
    let reply = call::<wire::TxRelay>(
        src,
        &wire::tx::RelayIds {
            id: vec![hash_of(hash)?],
        },
    )?;
    acted_on(&reply, hash, "relayed")
}

/// `txpool list [--short]`.
pub(super) fn txpool_list(src: &DaemonClient, short: bool) -> Result<String, String> {
    let reply = call::<wire::TxpoolList>(src, &NoParams)?;
    if reply.is_empty() {
        return Ok("The pool is empty.".to_owned());
    }
    Ok(reply
        .iter()
        .map(|tx| {
            if short {
                tx.id.to_string()
            } else {
                format!(
                    "{}  {} weight  {} SKL",
                    tx.id,
                    tx.weight.0,
                    tx.fee.to_atomic_units().to_skl_string()
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

/// `txpool flush [<id>]`: one entry, or every entry the caller may see.
pub(super) fn txpool_flush(src: &DaemonClient, id: Option<&str>) -> Result<String, String> {
    let ids = id.map(hash_of).transpose()?.map(|hash| vec![hash]);
    let reply = call::<wire::TxpoolFlush>(src, &wire::tx::FlushIds { id: ids })?;
    match id {
        Some(hash) => acted_on(&reply, hash, "flushed"),
        None => Ok("flushed the pool".to_owned()),
    }
}

/// `ban list`.
pub(super) fn ban_list(src: &DaemonClient) -> Result<String, String> {
    let reply = call::<wire::BanList>(src, &NoParams)?;
    if reply.is_empty() {
        return Ok("No bans.".to_owned());
    }
    Ok(reply
        .iter()
        .map(|ban| match ban.duration.0 {
            Some(left) if !ban.permanent => format!("{}  {} s", ban.host.0, left.0),
            _ => format!("{}  until lifted", ban.host.0),
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

/// `ban add <host> [--duration <seconds>]`.
pub(super) fn ban_add(
    src: &DaemonClient,
    ip: &str,
    duration: Option<u64>,
) -> Result<String, String> {
    call::<wire::BanAdd>(
        src,
        &wire::node::BanAdd {
            host: Text(ip.to_owned()),
            duration: duration.map(Duration),
        },
    )?;
    Ok(match duration {
        Some(seconds) => format!("banned {ip} for {seconds} s"),
        None => format!("banned {ip} until lifted"),
    })
}

/// `ban remove <host>`.
pub(super) fn ban_remove(src: &DaemonClient, ip: &str) -> Result<String, String> {
    call::<wire::BanRemove>(
        src,
        &wire::node::BanHost {
            host: Text(ip.to_owned()),
        },
    )?;
    Ok(format!("lifted the ban on {ip}"))
}

/// `ban show <host>`: the ban, or `null` when the host is not banned.
pub(super) fn ban_show(src: &DaemonClient, ip: &str) -> Result<String, String> {
    let reply = call::<wire::BanShow>(
        src,
        &wire::node::BanHost {
            host: Text(ip.to_owned()),
        },
    )?;
    Ok(match reply.0 {
        None => format!("{ip} is not banned"),
        Some(ban) => match ban.duration.0 {
            Some(left) if !ban.permanent => format!("{ip} is banned for {} s", left.0),
            _ => format!("{ip} is banned until lifted"),
        },
    })
}

/// An option row's name, whether it holds a value or a secret.
pub(super) fn row_name(row: &OptionRow) -> &str {
    match row {
        OptionRow::Value(value) => &value.name.0,
        OptionRow::Secret(secret) => &secret.name.0,
    }
}

const fn source_word(source: OptionSource) -> &'static str {
    match source {
        OptionSource::Default => "default",
        OptionSource::File => "file",
        OptionSource::Cli => "cli",
        OptionSource::Runtime => "runtime",
    }
}

fn render_options(rows: &[OptionRow]) -> String {
    if rows.is_empty() {
        return "No options.".to_owned();
    }
    rows.iter()
        .map(|row| {
            let (source, runtime, value) = match row {
                OptionRow::Value(row) => (
                    row.source,
                    row.runtime,
                    row.value
                        .0
                        .as_ref()
                        .map_or_else(|| "unset".to_owned(), |text| text.0.clone()),
                ),
                // A secret's value is never shown: only whether it has one.
                OptionRow::Secret(row) => (
                    row.source,
                    row.runtime,
                    if row.assigned { "set" } else { "unset" }.to_owned(),
                ),
            };
            format!(
                "{}  {}  {}  {}",
                row_name(row),
                source_word(source),
                if runtime { "runtime" } else { "startup" },
                value
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `option set <name> <value>`.
pub(super) fn option_set(src: &DaemonClient, name: &str, value: &str) -> Result<String, String> {
    let mut values = std::collections::BTreeMap::new();
    values.insert(name.to_owned(), Text(value.to_owned()));
    let reply = call::<wire::OptionSet>(
        src,
        &wire::node::OptionSet {
            value: OpenMap(values),
        },
    )?;
    Ok(render_options(&reply))
}

/// `option show [<name>]`.
pub(super) fn option_show(src: &DaemonClient, name: Option<&str>) -> Result<String, String> {
    let names = name.map(|name| vec![Text(name.to_owned())]);
    let reply = call::<wire::OptionShow>(src, &wire::node::OptionShow { name: names })?;
    Ok(render_options(&reply))
}

/// `daemon stop`.
pub(super) fn daemon_stop(src: &DaemonClient) -> Result<String, String> {
    call::<wire::DaemonStop>(src, &NoParams)?;
    Ok("The daemon is stopping.".to_owned())
}
