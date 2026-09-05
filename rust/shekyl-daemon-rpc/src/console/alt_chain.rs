// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `alt_chain_info`.

use super::info::{daa_target_seconds, fetch_get_info};
use super::{
    ffi_json_rpc_result, human_readable_timespan, json_rpc_result, native_json_rpc, require_ok,
    trimmed, wide_difficulty_decimal, Source,
};
use crate::chain_facts::FfiChainFacts;
use crate::ctl_client;

/// One entry of the `get_alternate_chains` reply.
///
/// **A bridged leg, on purpose** (§2.1.1): `get_alternate_chains` is RK-8's
/// and is still served from the C++ table (`core_rpc_ffi.cpp:284`). Required
/// fields for the reason [`GetLimitReplyProvisional`] gives — a defaulted
/// `length` would make every alt chain read as zero blocks long, which is a
/// sentence about the chain rather than about the reply.
#[derive(serde::Deserialize)]
struct AltChainProvisional {
    block_hash: shekyl_rpc_types::HashHex,
    height: u64,
    length: u64,
    wide_difficulty: String,
    block_hashes: Vec<shekyl_rpc_types::HashHex>,
    main_chain_parent_block: shekyl_rpc_types::HashHex,
}

/// The `get_alternate_chains` reply. See [`AltChainProvisional`].
#[derive(serde::Deserialize)]
struct AltChainsReplyProvisional {
    status: shekyl_rpc_types::RpcStatus,
    chains: Vec<AltChainProvisional>,
}

/// Fetch `get_alternate_chains` — bridged on both arms.
fn fetch_alt_chains(src: &Source) -> Result<Vec<AltChainProvisional>, String> {
    let reply: AltChainsReplyProvisional = match src {
        Source::Live(core) => {
            let raw = core
                .json_rpc("get_alternate_chains", "{}")
                .ok_or_else(|| "no reply from get_alternate_chains".to_owned())?;
            ffi_json_rpc_result(&raw, "get_alternate_chains")?
        }
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "get_alternate_chains",
            }))
            .map_err(|e| format!("cannot encode the request: {e}"))?;
            let raw = ctl_client::post_blocking(address, "/json_rpc", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            json_rpc_result::<AltChainsReplyProvisional>(&raw, "get_alternate_chains")?
        }
    };
    if reply.status.is_ok() {
        Ok(reply.chains)
    } else {
        Err(reply.status.0)
    }
}

/// Fetch `get_block_header_by_hash` — native here, over `/json_rpc` remotely.
fn fetch_block_headers_by_hash(
    src: &Source,
    hashes: Vec<shekyl_rpc_types::HashHex>,
) -> Result<Vec<shekyl_rpc_types::BlockHeaderSlot>, String> {
    let request = shekyl_rpc_types::GetBlockHeaderByHashRequest {
        hashes,
        fill_pow_hash: false,
    };
    let reply = native_json_rpc(src, "get_block_header_by_hash", &request, |core| {
        crate::methods::get_block_header_by_hash(&FfiChainFacts::new(core.clone()), &request, false)
    })?;
    require_ok(&reply.status)?;
    Ok(reply.block_headers)
}

/// Read the headers for `requested`, insisting each slot answers the hash it
/// was asked about.
///
/// **This is the check the C++ `bhres.block_headers.size() != chain.length + 1`
/// became**, and it is a different kind of check. A count could only say "the
/// daemon returned the wrong number of headers"; against the per-element
/// reply it can say *which hash* has no header — and it also catches a reply
/// of the right length whose slots are in the wrong order or answer hashes
/// nobody asked about, which the count could not see at all.
///
/// A missing slot is normal rather than exceptional here: `alt_chain_info`
/// asks `get_alternate_chains` for hashes and then asks for their headers, so
/// a reorg between the two calls makes one vanish. That is the case the old
/// batching could not express — it returned zero headers and an error string
/// naming nothing.
pub(super) fn headers_in_correspondence(
    slots: &[shekyl_rpc_types::BlockHeaderSlot],
    requested: &[shekyl_rpc_types::HashHex],
) -> Result<Vec<shekyl_rpc_types::BlockHeader>, String> {
    if slots.len() != requested.len() {
        return Err(format!(
            "the daemon answered {} of {} block hashes",
            slots.len(),
            requested.len()
        ));
    }
    let mut headers = Vec::with_capacity(slots.len());
    for (slot, asked) in slots.iter().zip(requested) {
        if slot.hash != *asked {
            return Err(format!(
                "the daemon answered about {} where {asked} was asked",
                slot.hash
            ));
        }
        let Some(header) = slot.block_header.as_ref() else {
            return Err(format!(
                "no block header for {asked} — the chain may have moved since it was listed"
            ));
        };
        headers.push(header.clone());
    }
    Ok(headers)
}

/// `alt_chain_info [<tip> | >above | -last_blocks]`.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn alt_chain_info(
    src: &Source,
    tip: &str,
    above: u64,
    last_blocks: u64,
    now: u64,
) -> Result<String, String> {
    let info = fetch_get_info(src)?;
    let (target, target_warning) = daa_target_seconds(info.target);
    let mut chains = fetch_alt_chains(src)?;
    // The alt chain's first block. Saturating: an alt chain longer than our
    // own height is not something this console gets to be surprised by.
    let start_of = |c: &AltChainProvisional| c.height.saturating_sub(c.length).saturating_add(1);
    // "deep" as the C++ computed it: how far below our tip the fork point is.
    let depth_of =
        |c: &AltChainProvisional| info.height.saturating_sub(start_of(c)).saturating_sub(1);

    if tip.is_empty() {
        // The listing form derives nothing from T, so a disagreement is not
        // reported there — a warning attached to output it cannot affect
        // would train its reader to ignore the one that matters.
        chains.sort_by_key(|c| c.height);
        let shown: Vec<&AltChainProvisional> = chains
            .iter()
            .filter(|c| c.length > above)
            .filter(|c| last_blocks == 0 || depth_of(c) < last_blocks)
            .collect();
        let mut out = vec![format!("{} alternate chains found:", shown.len())];
        for c in shown {
            out.push(format!(
                "{} blocks long, from height {} ({} deep), diff {}: {}",
                c.length,
                start_of(c),
                depth_of(c),
                wide_difficulty_decimal(&c.wide_difficulty),
                c.block_hash
            ));
        }
        return Ok(out.join("\n"));
    }

    let Some(chain) = chains.iter().find(|c| c.block_hash.to_string() == tip) else {
        return Err(format!(
            "Block hash {tip} is not the tip of any known alternate chain"
        ));
    };
    // **The declared length must match the hashes supplied.** The C++ check
    // this replaced was `bhres.block_headers.size() != chain.length + 1`
    // against a request of `block_hashes` plus the parent — which is
    // `block_hashes.len() == length` said indirectly. The per-hash
    // correspondence below is stronger on *which* hash answered and
    // **weaker here**, because a reply declaring `length = 10` while
    // supplying two hashes has every slot correspond: the console would then
    // print a depth and a hash-rate share computed from ten blocks over two
    // headers' timespan. Checked before the fetch, so a malformed reply costs
    // no header reads.
    if chain.block_hashes.len() as u64 != chain.length {
        return Err(format!(
            "the daemon declared a {}-block alt chain but listed {} of its blocks",
            chain.length,
            chain.block_hashes.len()
        ));
    }
    let start_height = start_of(chain);
    let mut out: Vec<String> = target_warning.into_iter().collect();
    out.extend([
        format!("Found alternate chain with tip {tip}"),
        format!(
            "{} blocks long, from height {start_height} ({} deep), diff {}:",
            chain.length,
            depth_of(chain),
            wide_difficulty_decimal(&chain.wide_difficulty)
        ),
    ]);
    for hash in &chain.block_hashes {
        out.push(format!("  {hash}"));
    }
    out.push(format!(
        "Chain parent on main chain: {}",
        chain.main_chain_parent_block
    ));

    // The chain's own blocks, then its parent on the main chain — the parent
    // last, because the difficulty read below is `.back()`.
    let mut requested = chain.block_hashes.clone();
    requested.push(chain.main_chain_parent_block);
    let slots = fetch_block_headers_by_hash(src, requested.clone())?;
    let headers = headers_in_correspondence(&slots, &requested)?;

    let (earliest, latest) = headers.iter().fold((u64::MAX, 0u64), |(lo, hi), h| {
        (lo.min(h.timestamp), hi.max(h.timestamp))
    });
    let span = latest.saturating_sub(earliest);
    let age = span.max(now.saturating_sub(earliest));
    out.push(format!("Age: {}", human_readable_timespan(age)));
    if chain.length > 1 {
        out.push(format!("Time span: {}", human_readable_timespan(span)));
        // **The guard is on the span, not on the difficulty.** The C++
        // required `block_headers.back().difficulty > 0` and then computed a
        // percentage the difficulty does not appear in — a check standing in
        // front of a formula it is not part of, whose message named
        // `cumulative difficulty` while reading `difficulty`. The hazard the
        // site actually has is `dt == 0`: two or more blocks sharing a
        // timestamp, which is reachable and which made the C++ print `inf%`.
        if span == 0 {
            out.push(
                "Cannot estimate the network hash rate: the chain's blocks share a timestamp"
                    .to_owned(),
            );
        } else {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a percentage for a human, from a block count and a timespan"
            )]
            let share = 100.0 * (target as f64) * (chain.length as f64) / (span as f64);
            out.push(format!(
                "Approximated {}% of network hash rate",
                trimmed(share, 6)
            ));
        }
    }
    Ok(out.join("\n"))
}
