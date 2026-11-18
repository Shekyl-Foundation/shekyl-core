// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The forged shard-fill chain, connected into a scenario (`CHAIN_FORGE.md`
//! `CF-4a`): the chain the long scenarios build on, forged once from
//! `shekyl-chain-forge/plans/shard-fill.toml`, hosted, and pinned by digest
//! (§10.4).
//!
//! [`connect`] is the one entry: a regtest scenario under the caller's
//! schedule, the forged prefix through shard `shards − 1`'s close, and the
//! closes the manifest names. Every block is connected verbatim through the
//! scenario's own door (`next_template`, then the forged block in the
//! template, `connect_template`), so every rule still judges it under the
//! scenario's own schedule. The forged chain is regtest's: block 0 is the
//! table's genesis, every coinbase from 1 pays
//! `MinerWallet::harness_regtest()`, and the fill spends coinbases from
//! [`FILL_FROM_COINBASE`] up, so coinbases 1 to 9 are the scenario's for
//! its own posts.
//!
//! The close heights are the manifest's (`shard-<k>-closed`), never
//! numbers written here: a re-forge moves them, and a reader that took
//! them from the manifest moves with it. The pin is opened once per
//! [`connect`].

use std::fs::File;
use std::io::BufReader;
use std::num::NonZeroU128;

use shekyl_chain_forge::hosted::{self, Fetched};
use shekyl_chain_forge::{close_event, Manifest};
use shekyl_chain_rules::CappedEpoch;
use shekyl_network::Network;
use shekyl_types::{BlockHeight, ShardId};

use crate::corpus::CorpusReader;
use crate::scenario::{FreeHash, Mined, Scenario};
use crate::scenario_shard::{closed_shards, ClosedShard, Filled, FILL_FROM_COINBASE};
use crate::schedule::ChainRules;
use crate::source::{IngestEvent, Source};

/// The hosted chain's name.
pub const CHAIN: &str = "shard-fill";

/// The first coinbase a scenario on the forged chain may spend for its own
/// posts: regtest's block 0 pays the genesis table, so the miner's first
/// coinbase is block 1's.
pub const FIRST_POST_COINBASE: u64 = 1;

const _: () = assert!(
    FIRST_POST_COINBASE < FILL_FROM_COINBASE,
    "the forged fill leaves coinbases below it to the scenario's posts"
);

/// The forged chain under `epoch`, connected from block 0 through the block
/// that closes shard `shards − 1`.
///
/// The scenario is regtest at fixed difficulty one. Block 0 is the table's
/// genesis. The rules are the scenario's, for the admission heights a reader
/// works out. The closes are the manifest's first `shards` `shard-<k>-closed`
/// events.
///
/// # Panics
///
/// If the chain is not fetched or does not match its pin (the message names
/// the fetch command), if its manifest records fewer than `shards` closes,
/// if a block does not connect under the scenario's rules, or if the
/// producer's count of closed shards after the prefix is not `shards`.
pub async fn connect(
    name: &str,
    epoch: CappedEpoch,
    shards: u64,
) -> (Scenario<FreeHash>, Vec<Mined>, ChainRules, Filled) {
    assert!(shards > 0, "a fill closes at least one shard");
    let rules = ChainRules::new(Network::Regtest, Some(NonZeroU128::MIN), epoch)
        .unwrap_or_else(|refused| panic!("regtest's row permits every lever: {refused}"));
    let (mut scenario, genesis) = Scenario::open_regtest_mined(name, FreeHash, epoch).await;
    let mut chain = vec![genesis];
    let fetched = hosted::open(CHAIN).unwrap_or_else(|fault| panic!("{fault}"));
    let manifest = fetched.manifest().unwrap_or_else(|fault| panic!("{fault}"));
    let closed = closes_through(&manifest, shards);
    extend(&mut scenario, &mut chain, &fetched, &closed).await;
    (scenario, chain, rules, Filled { closed })
}

/// The forged chain's close height of each of its first `shards` shards,
/// from a manifest already read.
fn closes_through(manifest: &Manifest, shards: u64) -> Vec<ClosedShard> {
    (0..shards)
        .map(|k| {
            let name = close_event(k);
            let event = manifest
                .events
                .iter()
                .find(|event| event.name == name)
                .unwrap_or_else(|| panic!("the forged chain's manifest records no `{name}`"));
            ClosedShard {
                shard: ShardId::from_raw(k),
                close_height: BlockHeight::from_raw(event.height),
            }
        })
        .collect()
}

/// How many of `closed` name a height strictly below `height`.
fn closes_before(closed: &[ClosedShard], height: u64) -> u64 {
    let count = closed
        .iter()
        .filter(|close| close.close_height.to_raw() < height)
        .count();
    u64::try_from(count).expect("a fill's shard count fits u64")
}

/// How many of `closed` name `height` itself. One block can close more
/// than one shard.
fn closes_at(closed: &[ClosedShard], height: u64) -> u64 {
    let count = closed
        .iter()
        .filter(|close| close.close_height.to_raw() == height)
        .count();
    u64::try_from(count).expect("a fill's shard count fits u64")
}

/// The same closes, opening the pin. The capture-rule test reads them
/// without connecting.
fn close_heights(shards: u64) -> Vec<ClosedShard> {
    let fetched = hosted::open(CHAIN).unwrap_or_else(|fault| panic!("{fault}"));
    let manifest = fetched.manifest().unwrap_or_else(|fault| panic!("{fault}"));
    closes_through(&manifest, shards)
}

/// Connect the forged prefix into `scenario`, from block 1 through the last
/// of `closed`, extending `chain` (block 0, as `open_regtest_mined` left it).
async fn extend(
    scenario: &mut Scenario<FreeHash>,
    chain: &mut Vec<Mined>,
    fetched: &Fetched,
    closed: &[ClosedShard],
) {
    let last = closed.last().expect("shards > 0").close_height;
    let mut corpus = CorpusReader::open(BufReader::new(
        File::open(fetched.corpus()).expect("the fetched corpus opens"),
    ))
    .unwrap_or_else(|fault| panic!("the forged corpus: {fault}"));
    let mut genesis = true;
    while let Some(record) = corpus
        .next()
        .unwrap_or_else(|fault| panic!("the forged corpus: {fault}"))
    {
        let IngestEvent::Extend(candidate) = record.event else {
            panic!("the forged fill lists no rewind");
        };
        if genesis {
            genesis = false;
            assert_eq!(
                candidate.block.hash(),
                chain[0].hash,
                "the forged chain's block 0 is the scenario's"
            );
            continue;
        }
        let height = u64::try_from(chain.len()).expect("a test chain's length fits u64");
        if height > last.to_raw() {
            break;
        }
        // The manifest's close is this block, or it is not a close. The
        // count just before the block, and the count once it is connected,
        // are the producer's own, not a second reading of the manifest.
        let closes_here = closed
            .iter()
            .any(|close| close.close_height.to_raw() == height);
        if closes_here {
            assert_eq!(
                closed_shards(scenario).await,
                closes_before(closed, height),
                "before block {height} the producer has not counted this close"
            );
        }
        let mut next = scenario
            .next_template(candidate.transactions.clone())
            .await
            .unwrap_or_else(|outcome| panic!("the template at {height}: {outcome}"));
        assert_eq!(
            next.height.to_raw(),
            height,
            "the forged chain loads in order"
        );
        next.template.block = candidate.block;
        chain.push(
            scenario
                .connect_template(next)
                .await
                .unwrap_or_else(|outcome| {
                    panic!(
                        "forged block {height} connects (pinned at {}): {outcome}",
                        fetched.pin().commit
                    )
                }),
        );
        if closes_here {
            assert_eq!(
                closed_shards(scenario).await,
                closes_before(closed, height) + closes_at(closed, height),
                "block {height} is where the manifest says these shards closed"
            );
        }
    }
    let shards = u64::try_from(closed.len()).expect("a fill's shard count fits u64");
    assert_eq!(
        chain.last().expect("block 0 at least").height,
        last,
        "the forged chain reaches shard {}'s close",
        shards - 1
    );
    assert_eq!(
        closed_shards(scenario).await,
        shards,
        "the prefix closes {shards} shards"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario_shard::{levered_epoch, settled_epoch, REORG_CAP_BLOCKS};
    use shekyl_chain_rules::SettlementEpochBlocks;
    use shekyl_types::archival::SHARD_LENGTH;
    use shekyl_types::BlockCount;

    #[test]
    fn a_block_closes_every_shard_the_manifest_names_at_its_height() {
        let closed = [close(0, 10), close(1, 10), close(2, 12)];
        assert_eq!(closes_before(&closed, 10), 0);
        assert_eq!(closes_at(&closed, 10), 2);
        assert_eq!(closes_before(&closed, 12), 2);
        assert_eq!(closes_at(&closed, 12), 1);
        assert_eq!(closes_at(&closed, 11), 0);
    }

    fn close(shard: u64, height: u64) -> ClosedShard {
        ClosedShard {
            shard: ShardId::from_raw(shard),
            close_height: BlockHeight::from_raw(height),
        }
    }

    /// Every listed body's archival length, by height, read off the forged
    /// corpus.
    fn archival_lengths() -> Vec<u64> {
        let fetched = hosted::open(CHAIN).unwrap_or_else(|fault| panic!("{fault}"));
        let mut corpus = CorpusReader::open(BufReader::new(
            File::open(fetched.corpus()).expect("the fetched corpus opens"),
        ))
        .unwrap_or_else(|fault| panic!("the forged corpus: {fault}"));
        let mut lengths = Vec::new();
        while let Some(record) = corpus
            .next()
            .unwrap_or_else(|fault| panic!("the forged corpus: {fault}"))
        {
            let IngestEvent::Extend(candidate) = record.event else {
                panic!("the forged fill lists no rewind");
            };
            lengths.push(
                candidate
                    .transactions
                    .iter()
                    .map(|tx| tx.archival_len().to_raw())
                    .sum(),
            );
        }
        lengths
    }

    /// The close heights a reader takes from the manifest are the capture
    /// rule's own: shard `k` closes at the first block whose listed bodies'
    /// archival lengths, summed from block 0, reach `(k + 1) · W`
    /// (`SHARD_LENGTH`). Worked out here from the corpus's bytes, not read
    /// from the forge (Rick's `CF-4a` ruling, 2026-11-18).
    #[test]
    #[ignore = "reads the hosted shard-fill chain; run by nightly.yml's chain-ingest-ignored job"]
    fn the_manifest_closes_each_shard_where_the_capture_rule_does() {
        let w = SHARD_LENGTH.to_raw();
        let mut total = 0u64;
        let mut by_rule = Vec::new();
        for (height, length) in archival_lengths().into_iter().enumerate() {
            total += length;
            while total >= (by_rule.len() as u64 + 1) * w {
                by_rule.push(u64::try_from(height).expect("small"));
            }
        }
        let manifest: Vec<u64> = close_heights(3)
            .iter()
            .map(|closed| closed.close_height.to_raw())
            .collect();
        assert_eq!(
            by_rule[..3],
            manifest[..],
            "the capture rule and the manifest agree on every close"
        );
    }

    /// The forged prefix connects under every schedule a reader opens it
    /// under, and the producer counts each shard closed where the manifest
    /// says.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "connects the hosted shard-fill chain three times; run by nightly.yml's chain-ingest-ignored job"]
    async fn the_forged_fill_connects_under_every_readers_schedule() {
        let producer = CappedEpoch::new(
            SettlementEpochBlocks::new(1_200).expect("non-zero"),
            BlockCount::from_raw(REORG_CAP_BLOCKS),
        )
        .expect("the cap sits inside the epoch");
        let mut agreed = None;
        for (name, epoch) in [
            ("levered", levered_epoch()),
            ("settled", settled_epoch()),
            ("producer", producer),
        ] {
            let (_, _, _, filled) = connect(&format!("forged-fill-{name}"), epoch, 3).await;
            match &agreed {
                None => {
                    assert_eq!(filled.closed, close_heights(3), "{name}");
                    agreed = Some(filled.closed);
                }
                Some(first) => assert_eq!(&filled.closed, first, "{name}"),
            }
        }
    }
}
