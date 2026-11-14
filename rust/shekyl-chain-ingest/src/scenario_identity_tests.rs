// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The identity test: a chain carrying regtest's identity can never
//! validate as another network's (`CHAIN_FORGE.md` §6, `CF-1a`; the lane
//! brief's security constraint 2).
//!
//! The chain is the driver's ([`Scenario::open_regtest`]): regtest's table
//! genesis as block 0, the regtest miner's coinbases, and one listed
//! transaction — a spend of block 1's coinbase carrying a complete-tree
//! JoinMarket by a persona derived under regtest's name. So the network-
//! bound objects it holds are a spend (its FCMP++ proof and its spend
//! slot) and a bond post (its slot, signed by the persona's identity key).
//! An emission claim and an admitted bundle take the chain's id the same
//! way (`emission_assembly`'s `network`, `admitted_draws`), and the forge's
//! own identity test holds them on its plan (`CF-1c`).
//!
//! Four locks, each asserted with a positive control beside it, so a lock
//! that held only because nothing connected would fail here:
//!
//! 1. **The levers.** The chain's fixed difficulty is a lever regtest's row
//!    alone permits (`NI-R6`): [`ChainRules::new`] refuses it for every
//!    other network, and accepts it for regtest.
//! 2. **Genesis.** Offered to a chain under another network's production
//!    rules, regtest's block 0 is refused by CEN-E1 at height 0; that
//!    network's own table genesis connects through the same offer.
//! 3. **Signatures and proofs.** Every listed transaction passes the
//!    production stateless judgement under regtest's id, and that pass
//!    verified the proof (`StatelessPass::proven`). Under every other id
//!    the same body is CEN-I18's, because the judgement names a bad
//!    signature before a bad proof. The proof row is reached through that
//!    same judgement: [`Spender::signed_under`] keeps the regtest proof and
//!    replaces the authorizations with ones that verify under the other
//!    id, so the signatures pass and the proof row refuses. This chain's
//!    one body is a join, so that row is CEN-J27, whose body is CEN-I15's
//!    verifier. A validator that skipped the genesis pin still refuses the
//!    chain transaction by transaction.
//! 4. **The wire.** A node of another network does not complete a
//!    handshake with a regtest node: the transport's prefix is derived from
//!    the network id (`PWD-T5`, `shekyl-network`'s `prefix_for`). That lock
//!    is the network's, and this test cites it rather than re-testing it:
//!    `shekyl-clearnet/src/tests.rs`,
//!    `a_listener_refuses_every_other_networks_prefix_and_takes_its_own` —
//!    a listener of each network closes every other network's prefix after
//!    zero bytes and seals a session opened with its own.

use shekyl_chain_rules::{
    judge_lone_stateless, Candidate, CappedEpoch, CenRow, ReferenceClaim, ReferenceClaims,
    StatelessPass,
};
use shekyl_genesis_tool::builder::pinned_genesis;
use shekyl_harness_spender::{coinbase_maturity, complete_tree, Linked, Persona, Spender};
use shekyl_network::{Lever, Network, NetworkId};
use shekyl_types::{BlockCount, BlockHeight};
use shekyl_wire::{Block, Transaction};

use super::{FreeHash, Scenario, StepOutcome};
use crate::archival_driver::{ENDPOINT, FEE};
use crate::scenario_shard::levered_rules;
use crate::schedule::{ChainRules, LeverRefused};

/// Every network but regtest.
const OTHERS: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Stagenet];

/// The persona slot the chain's join is posted by.
const SLOT: u32 = 1;

/// One connected block and the bodies it listed.
struct Connected {
    height: BlockHeight,
    block: Block,
    listed: Vec<Transaction>,
}

/// The chain's one listed body proved under regtest, with its
/// authorizations signed under `network` ([`Spender::signed_under`]).
struct SignedFor {
    network: Network,
    body: Transaction,
}

/// The regtest chain the locks are asserted on, and its store.
struct Chain {
    scenario: Scenario<FreeHash>,
    genesis: Block,
    blocks: Vec<Connected>,
    /// The join, re-signed for every network but regtest.
    signed_for: Vec<SignedFor>,
}

/// Mine regtest's chain: block 0 the table's, then the regtest miner's
/// coinbases to block 1's maturity, then a block listing a spend of block
/// 1's coinbase that carries a regtest persona's complete-tree join. The
/// spender is fed from height 0 and its tree is held equal to the store's
/// at every height, block 0's coinbase outputs included.
async fn regtest_chain(name: &str) -> Chain {
    // The levered schedule a complete-tree join is admitted under at its
    // first spendable height (`rpc_store_reads_tests`' bonded persona).
    let (mut scenario, genesis) =
        Scenario::open_regtest(name, FreeHash, levered_rules().schedule()).await;
    let regtest = scenario.network_id();
    assert_eq!(
        regtest,
        Network::Regtest.network_id(),
        "the chain is regtest's"
    );
    assert_ne!(regtest, shekyl_network::HARNESS_NETWORK_ID);

    // Block 1's coinbase is the regtest miner's first; block 0's pays the
    // table's recipients, whose keys no test holds.
    let rule_set = scenario.rules.in_force(BlockHeight::ZERO);
    let first_coinbase = BlockHeight::from_raw(1);
    let connecting = first_coinbase
        .checked_add(coinbase_maturity(&rule_set))
        .expect("a small height");
    let mined = scenario
        .mine(
            connecting
                .checked_sub_count(BlockCount::ONE)
                .expect("above genesis")
                .to_raw(),
        )
        .await;

    let mut spender = Spender::on(regtest, &[Linked::new(&genesis, &[])]);
    for block in &mined {
        spender.push(block);
    }
    let persona = Persona::on(Network::Regtest, SLOT);
    let join = persona.join(complete_tree(), ENDPOINT);
    let spend = spender.spend_coinbase_posting(
        scenario.wallet(),
        first_coinbase,
        connecting,
        FEE,
        Some(&join),
    );
    // The proof stays regtest's. Each other id signs the authorizations,
    // so the production judge under that id reaches the proof row.
    let signed_for = OTHERS
        .into_iter()
        .map(|network| SignedFor {
            network,
            body: spender.signed_under(
                &spend,
                scenario.wallet(),
                first_coinbase,
                connecting,
                Some(&join),
                &network.network_id(),
            ),
        })
        .collect();
    let joined = scenario
        .mine_listing(vec![spend])
        .await
        .unwrap_or_else(|outcome| panic!("the regtest join connects: {outcome}"));
    assert_eq!(joined.height, connecting);
    spender.push(&joined);
    assert!(
        scenario
            .bond_record(persona.id())
            .await
            .expect("the connector answers")
            .is_some(),
        "the regtest persona is bonded"
    );

    let mut blocks = vec![Connected {
        height: BlockHeight::ZERO,
        block: genesis.clone(),
        listed: Vec::new(),
    }];
    blocks.extend(mined.iter().chain([&joined]).map(|m| Connected {
        height: m.height,
        block: m.template.block.clone(),
        listed: m.template.transactions.clone(),
    }));
    for connected in &blocks {
        assert_eq!(
            scenario
                .root_at(connected.height)
                .await
                .expect("the connector answers"),
            Some(spender.root_at(connected.height)),
            "the wallet-side tree is the store's at {}",
            connected.height
        );
    }
    Chain {
        scenario,
        genesis,
        blocks,
        signed_for,
    }
}

/// The claims for `connected`'s listed bodies, one per reference a body
/// names that this chain holds, at that block's height with its header's
/// root (CEN-B5). [`ReferenceClaims::gather`] is the constructor for a
/// caller holding its chain by hash.
fn claims_for(chain: &[Connected], connected: &Connected) -> ReferenceClaims {
    let candidate = Candidate::new(connected.block.clone(), connected.listed.clone());
    ReferenceClaims::gather(&candidate, |reference| {
        chain.iter().find_map(|block| {
            (block.block.hash() == *reference).then_some(ReferenceClaim {
                height: block.height,
                root: block.block.header.curve_tree_root,
            })
        })
    })
}

/// The production stateless judgement of `tx` under `network`.
fn judged(
    tx: &Transaction,
    chain: &Chain,
    connected: &Connected,
    network: &NetworkId,
    claims: &ReferenceClaims,
) -> Result<StatelessPass, shekyl_chain_rules::InvalidBlock> {
    judge_lone_stateless(
        tx,
        &chain.scenario.rules.in_force(connected.height),
        network,
        claims,
        None,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_regtest_chain_never_validates_as_another_network() {
    let chain = regtest_chain("identity-locks").await;
    let rules = chain.scenario.rules;
    let regtest = chain.scenario.network_id();

    // Lock 1 — the levers. The chain's own pair is regtest's to pull and no
    // other network's.
    assert_eq!(rules.network(), Network::Regtest);
    let fixed = rules.fixed_difficulty();
    assert!(fixed.is_some(), "the chain is mined at a fixed difficulty");
    assert!(ChainRules::new(Network::Regtest, fixed, rules.schedule()).is_ok());
    for other in OTHERS {
        assert_eq!(
            ChainRules::new(other, fixed, rules.schedule()),
            Err(LeverRefused {
                network: other,
                lever: Lever::Difficulty,
            }),
            "{other}"
        );
    }

    // Lock 2 — genesis. Under another network's production rules regtest's
    // block 0 is CEN-E1's refusal at height 0, and that network's own
    // table genesis connects through the same offer.
    for other in OTHERS {
        let production = ChainRules::new(other, None, CappedEpoch::PRODUCTION)
            .expect("the production schedule pulls no lever");
        let mut elsewhere =
            Scenario::open_under(&format!("identity-genesis-{other}"), FreeHash, production);
        match elsewhere.offer_genesis(&chain.genesis).await {
            Err(StepOutcome::Refused(refused)) => {
                assert_eq!(refused.rule, CenRow::E1, "{other}: {refused:?}");
            }
            outcome => panic!("{other} took regtest's genesis: {outcome:?}"),
        }
        let own = pinned_genesis(other)
            .unwrap_or_else(|error| panic!("{other}'s table genesis assembles: {error}"));
        assert_eq!(
            elsewhere
                .offer_genesis(&own)
                .await
                .unwrap_or_else(|outcome| panic!("{other}'s own genesis connects: {outcome}")),
            own.hash(),
            "{other}"
        );
        elsewhere.close().await;
    }

    // Lock 3 — signatures and proofs, transaction by transaction. The
    // chain's own body is CEN-I18's under every other id. The same
    // judgement, over that body re-signed for the other id, names the
    // proof row.
    let mut judged_bodies = 0;
    for connected in &chain.blocks {
        for tx in &connected.listed {
            let claims = claims_for(&chain.blocks, connected);
            let pass = judged(tx, &chain, connected, &regtest, &claims)
                .unwrap_or_else(|refused| panic!("under regtest's id: {refused:?}"));
            assert!(
                pass.proven().is_some(),
                "the join's proof was verified against its claim"
            );
            for other in OTHERS {
                let id = other.network_id();
                match judged(tx, &chain, connected, &id, &claims) {
                    Err(refused) => assert_eq!(refused.rule, CenRow::I18, "{other}: {refused:?}"),
                    Ok(_) => panic!("{other}'s id passed a regtest body"),
                }
            }
            assert_eq!(
                chain.signed_for.len(),
                OTHERS.len(),
                "one re-signed body per other network"
            );
            for signed in &chain.signed_for {
                let id = signed.network.network_id();
                match judged(&signed.body, &chain, connected, &id, &claims) {
                    Err(refused) => {
                        assert_eq!(refused.rule, CenRow::J27, "{}: {refused:?}", signed.network);
                    }
                    Ok(proven) => {
                        panic!(
                            "{}'s id passed the join's proof: {proven:?}",
                            signed.network
                        );
                    }
                }
            }
            judged_bodies += 1;
        }
    }
    assert_eq!(judged_bodies, 1, "the chain lists its one join");

    // Lock 4 — the wire — is the transport's (module docs).
    chain.scenario.close().await;
}
