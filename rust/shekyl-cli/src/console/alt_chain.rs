// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `alt_chain_info`.

use super::info::fetch_get_info;
use super::{native_json_rpc, wide_difficulty_decimal};
use crate::daemon::DaemonClient;
use shekyl_rpc_types::{AltChainInfo, GetAlternateChainsResponse};

/// A chain of no blocks is not a chain this list prints.
const SHORTEST_LISTED_CHAIN: u64 = 1;

/// The `get_alternate_chains` reply is the wire type `shekyl-rpc-types`
/// owns ([`GetAlternateChainsResponse`]): one definition for every reader.
/// Each chain's fields are required: a renamed field is an error naming it,
/// where a defaulted `length` would make every alt chain read as zero
/// blocks long. The `chains` list itself defaults to empty, because an
/// empty container may be omitted.
/// Fetch `get_alternate_chains`: one `/json_rpc` post.
fn fetch_alt_chains(daemon: &DaemonClient) -> Result<Vec<AltChainInfo>, String> {
    let reply: GetAlternateChainsResponse =
        native_json_rpc(daemon, "get_alternate_chains", &serde_json::json!({}))?;
    if reply.status.is_ok() {
        Ok(reply.chains)
    } else {
        Err(reply.status.0)
    }
}

/// `chain alt`: every alternate chain long enough to be a chain, sorted by
/// the height of its tip.
///
/// `chain alt` takes no filter (IG-Q44). A chain shorter than
/// [`SHORTEST_LISTED_CHAIN`] is not listed.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn alt_chain_info(daemon: &DaemonClient) -> Result<String, String> {
    let height = fetch_get_info(daemon)?.health.height;
    let mut chains = fetch_alt_chains(daemon)?;
    // The alt chain's first block. Saturating: an alt chain longer than the
    // main chain's height is still a chain this list can describe.
    let start_of =
        |chain: &AltChainInfo| chain.height.saturating_sub(chain.length).saturating_add(1);
    // How far below the main tip the fork point sits.
    let depth_of = |chain: &AltChainInfo| height.saturating_sub(start_of(chain)).saturating_sub(1);

    chains.sort_by_key(|chain| chain.height);
    let shown: Vec<&AltChainInfo> = chains
        .iter()
        .filter(|chain| chain.length >= SHORTEST_LISTED_CHAIN)
        .collect();
    let mut out = vec![format!("{} alternate chains found:", shown.len())];
    for chain in shown {
        out.push(format!(
            "{} blocks long, from height {} ({} deep), diff {}: {}",
            chain.length,
            start_of(chain),
            depth_of(chain),
            wide_difficulty_decimal(&chain.wide_difficulty),
            chain.block_hash
        ));
    }
    Ok(out.join("\n"))
}
