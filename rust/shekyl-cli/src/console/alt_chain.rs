// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `alt_chain_info`.

use super::info::{chain_count, fetch_status};
use crate::daemon::DaemonClient;
use shekyl_rpc_client::wire;
use shekyl_rpc_types::kinds::NoParams;
use shekyl_rpc_types::wire::chain::AltChain;

/// The shortest alternative chain this word lists.
const SHORTEST_LISTED_CHAIN: u64 = 1;

/// `chain alt`: every alternative chain, oldest fork first.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn alt_chain_info(daemon: &DaemonClient) -> Result<String, String> {
    let height = chain_count(&fetch_status(daemon)?);
    let mut chains = super::call::<wire::ChainAlt>(daemon, &NoParams)?;
    let length_of = |chain: &AltChain| u64::try_from(chain.block.len()).unwrap_or(u64::MAX);
    // The alt chain's first block: its tip's height less its length, plus
    // one. Saturating: an alt chain longer than the main chain's height is
    // still a chain this list can describe.
    let start_of = |chain: &AltChain| {
        chain
            .height
            .0
            .saturating_sub(length_of(chain))
            .saturating_add(1)
    };
    // How far below the main tip the fork point sits.
    let depth_of = |chain: &AltChain| height.saturating_sub(start_of(chain)).saturating_sub(1);

    chains.sort_by_key(|chain| chain.height);
    let shown: Vec<&AltChain> = chains
        .iter()
        .filter(|chain| length_of(chain) >= SHORTEST_LISTED_CHAIN)
        .collect();
    let mut out = vec![format!("{} alternate chains found:", shown.len())];
    for chain in shown {
        out.push(format!(
            "{} blocks long, from height {} ({} deep), diff {}: {}",
            length_of(chain),
            start_of(chain),
            depth_of(chain),
            chain.difficulty_cumulative.get(),
            chain.hash
        ));
    }
    Ok(out.join("\n"))
}
