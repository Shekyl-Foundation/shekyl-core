// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The §13 words that had no renderer in the moved console.
//!
//! Each post uses the method table's name. A refusal is the error class
//! and the diagnostic code (`json_rpc_result`).

use super::{native_json_rpc, require_ok, rest_post, Source};
use shekyl_rpc_types::bans::{
    BannedRequest, BannedResponse, GetBansResponse, SetBan, SetBansRequest,
};
use shekyl_rpc_types::mining::StatusOnlyResponse;
use shekyl_rpc_types::options::{OptionPair, OptionSetRequest, OptionShowRequest, OptionsResponse};
use shekyl_rpc_types::pool::{
    FlushTxpoolRequest, GetTransactionPoolHashesResponse, GetTransactionPoolResponse,
    RelayTxRequest,
};
use shekyl_rpc_types::{GetCoinbaseTxSumRequest, GetCoinbaseTxSumResponse, HashHex};
use shekyl_units::AtomicUnits;

pub(super) fn chain_coinbase_sum(src: &Source, from: u64, to: u64) -> Result<String, String> {
    let count = to.saturating_sub(from).saturating_add(1);
    let reply: GetCoinbaseTxSumResponse = native_json_rpc(
        src,
        "get_coinbase_tx_sum",
        &GetCoinbaseTxSumRequest {
            height: from,
            count,
        },
    )?;
    require_ok(&reply.status)?;
    Ok(format!(
        "emission: {} SKL\nfee: {} SKL",
        AtomicUnits::from_raw(reply.emission_amount).to_skl_string(),
        AtomicUnits::from_raw(reply.fee_amount).to_skl_string()
    ))
}

pub(super) fn tx_relay(src: &Source, hash: &str) -> Result<String, String> {
    let reply: StatusOnlyResponse = native_json_rpc(
        src,
        "relay_tx",
        &RelayTxRequest {
            txids: vec![HashHex::from_hex(hash).map_err(|error| error.to_string())?],
        },
    )?;
    require_ok(&reply.status)?;
    Ok(format!("relayed {hash}"))
}

pub(super) fn txpool_list(src: &Source, short: bool) -> Result<String, String> {
    if short {
        let body = rest_post(src, "/get_transaction_pool_hashes", b"{}".to_vec())?;
        let reply: GetTransactionPoolHashesResponse =
            serde_json::from_slice(&body).map_err(|error| error.to_string())?;
        require_ok(&reply.status)?;
        if reply.tx_hashes.is_empty() {
            return Ok("The pool is empty.".to_owned());
        }
        return Ok(reply
            .tx_hashes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n"));
    }
    let body = rest_post(src, "/get_transaction_pool", b"{}".to_vec())?;
    let reply: GetTransactionPoolResponse =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    require_ok(&reply.status)?;
    if reply.transactions.is_empty() {
        return Ok("The pool is empty.".to_owned());
    }
    Ok(reply
        .transactions
        .iter()
        .map(|tx| {
            format!(
                "{}  {} bytes  {} SKL",
                tx.id_hash,
                tx.blob_size,
                AtomicUnits::from_raw(tx.fee).to_skl_string()
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

pub(super) fn txpool_flush(src: &Source, id: Option<&str>) -> Result<String, String> {
    let txids = match id {
        Some(hash) => vec![HashHex::from_hex(hash).map_err(|error| error.to_string())?],
        None => Vec::new(),
    };
    let reply: StatusOnlyResponse =
        native_json_rpc(src, "flush_txpool", &FlushTxpoolRequest { txids })?;
    require_ok(&reply.status)?;
    Ok(match id {
        Some(hash) => format!("flushed {hash}"),
        None => "flushed the pool".to_owned(),
    })
}

pub(super) fn ban_list(src: &Source) -> Result<String, String> {
    let reply: GetBansResponse = native_json_rpc(src, "get_bans", &serde_json::json!({}))?;
    require_ok(&reply.status)?;
    if reply.bans.is_empty() {
        return Ok("No bans.".to_owned());
    }
    Ok(reply
        .bans
        .iter()
        .map(|ban| {
            if ban.permanent {
                format!("{}  until lifted", ban.host)
            } else {
                format!("{}  {} s", ban.host, ban.seconds)
            }
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

pub(super) fn ban_add(src: &Source, ip: &str, duration: Option<u64>) -> Result<String, String> {
    let reply: StatusOnlyResponse = native_json_rpc(
        src,
        "set_bans",
        &SetBansRequest {
            bans: vec![SetBan {
                host: ip.to_owned(),
                ban: true,
                seconds: duration,
            }],
        },
    )?;
    require_ok(&reply.status)?;
    Ok(match duration {
        Some(seconds) => format!("banned {ip} for {seconds} s"),
        None => format!("banned {ip} until lifted"),
    })
}

pub(super) fn ban_remove(src: &Source, ip: &str) -> Result<String, String> {
    let reply: StatusOnlyResponse = native_json_rpc(
        src,
        "set_bans",
        &SetBansRequest {
            bans: vec![SetBan {
                host: ip.to_owned(),
                ban: false,
                seconds: None,
            }],
        },
    )?;
    require_ok(&reply.status)?;
    Ok(format!("lifted the ban on {ip}"))
}

pub(super) fn ban_show(src: &Source, ip: &str) -> Result<String, String> {
    let reply: BannedResponse = native_json_rpc(
        src,
        "banned",
        &BannedRequest {
            address: ip.to_owned(),
        },
    )?;
    require_ok(&reply.status)?;
    if !reply.banned {
        return Ok(format!("{ip} is not banned"));
    }
    if reply.permanent {
        Ok(format!("{ip} is banned until lifted"))
    } else {
        Ok(format!("{ip} is banned for {} s", reply.seconds))
    }
}

fn render_options(reply: &OptionsResponse) -> String {
    if reply.options.is_empty() {
        return "No options.".to_owned();
    }
    reply
        .options
        .iter()
        .map(|row| {
            let value = match row.value() {
                Some(Some(text)) => text.to_owned(),
                Some(None) => "unset".to_owned(),
                None => {
                    if row.set() == Some(true) {
                        "set".to_owned()
                    } else {
                        "unset".to_owned()
                    }
                }
            };
            format!(
                "{}  {}  {}  {}",
                row.name(),
                row.source(),
                if row.runtime() { "runtime" } else { "startup" },
                value
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn option_set(src: &Source, name: &str, value: &str) -> Result<String, String> {
    let reply: OptionsResponse = native_json_rpc(
        src,
        "option_set",
        &OptionSetRequest {
            options: vec![OptionPair {
                name: name.to_owned(),
                value: value.to_owned(),
            }],
        },
    )?;
    Ok(render_options(&reply))
}

pub(super) fn option_show(src: &Source, name: Option<&str>) -> Result<String, String> {
    let names = name.map(|name| vec![name.to_owned()]);
    let reply: OptionsResponse = native_json_rpc(src, "option_show", &OptionShowRequest { names })?;
    Ok(render_options(&reply))
}

pub(super) fn daemon_stop(src: &Source) -> Result<String, String> {
    let body = rest_post(src, "/stop_daemon", b"{}".to_vec())?;
    let reply: StatusOnlyResponse =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    require_ok(&reply.status)?;
    Ok("The daemon is stopping.".to_owned())
}
