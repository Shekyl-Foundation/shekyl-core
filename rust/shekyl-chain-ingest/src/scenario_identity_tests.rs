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
//!    production stateless judgement under regtest's id and is refused by
//!    CEN-I18, the signature sequence, under every other id. The judgement
//!    stops at the first row, so the proof leg is held separately: each
//!    spend's FCMP++ proof verifies over its `tx_signable` framed with
//!    regtest's id and fails over every other's, by I15's own verifier
//!    call. A validator that skipped the genesis pin still refuses the
//!    chain transaction by transaction.
//! 4. **The wire.** A node of another network does not complete a
//!    handshake with a regtest node: the transport's prefix is derived from
//!    the network id (`PWD-T5`, `shekyl-network`'s `prefix_for`). That lock
//!    is the network's, and this test cites it rather than re-testing it.

use std::collections::BTreeMap;

use shekyl_chain_rules::{
    judge_lone_stateless, Candidate, CappedEpoch, CenRow, ReferenceClaims, StatelessPass,
};
use shekyl_fcmp::leaf::PqcKeyScalar;
use shekyl_fcmp::proof::{self, ShekylFcmpProof};
use shekyl_harness_spender::{coinbase_maturity, complete_tree, Linked, Persona, Spender};
use shekyl_network::{Lever, Network, NetworkId};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, CurveTreeRoot, KeyImage};
use shekyl_wire::{Block, Ct, Input, Transaction};

use super::genesis::table_genesis;
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

/// The regtest chain the locks are asserted on, and its store.
struct Chain {
    scenario: Scenario<FreeHash>,
    genesis: Block,
    blocks: Vec<Connected>,
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
    }
}

/// The claims a listed body's references resolve to, off the chain's own
/// headers: each reference at its height with its header's root (CEN-B5),
/// as `ReferenceClaims::from_headers` reads them.
fn claims_for(chain: &[Connected], connected: &Connected) -> ReferenceClaims {
    let anchors: BTreeMap<BlockHash, (BlockHeight, CurveTreeRoot)> = chain
        .iter()
        .map(|c| (c.block.hash(), (c.height, c.block.header.curve_tree_root)))
        .collect();
    let candidate = Candidate::new(connected.block.clone(), connected.listed.clone());
    let mut claims = ReferenceClaims::EMPTY;
    for reference in candidate.proof_references() {
        let (height, root) = anchors[&reference];
        claims.insert(reference, height, root);
    }
    claims
}

/// I15's verifier call over `tx`'s spends, its message framed with
/// `network`: the key images and PQC keys at the `ToKey` slots, the proof
/// and pseudo-outs from the prunable region, against the claimed anchor at
/// the declared depth plus one layer (`rules/tx_against.rs`, `I15::verify`).
fn fcmp_verifies(tx: &Transaction, claims: &ReferenceClaims, network: &NetworkId) -> bool {
    let Ct::Fcmp {
        pqc_auths,
        reference_block,
        prunable: Some(prunable),
        ..
    } = &tx.ct
    else {
        panic!("a listed spend carries its prunable region");
    };
    let slots: Vec<usize> = tx
        .prefix
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(slot, input)| matches!(input, Input::ToKey { .. }).then_some(slot))
        .collect();
    let key_images: Vec<KeyImage> = slots
        .iter()
        .map(|&slot| match &tx.prefix.inputs[slot] {
            Input::ToKey { key_image, .. } => KeyImage::from_canonical_bytes(*key_image),
            _ => unreachable!("a ToKey slot"),
        })
        .collect();
    let pqc_keys: Vec<PqcKeyScalar> = slots
        .iter()
        .map(|&slot| {
            let auth = &pqc_auths[slot];
            PqcKeyScalar::from_pqc_auth(auth.scheme_id, &auth.hybrid_public_key)
                .expect("a spend slot's key is a hybrid key")
        })
        .collect();
    let claim = claims
        .get(reference_block)
        .expect("the spend's reference is claimed");
    let layers = u8::try_from(prunable.tree_depth)
        .ok()
        .and_then(|depth| depth.checked_add(1))
        .expect("a declared depth fits a layer count");
    let fcmp = ShekylFcmpProof {
        data: prunable.fcmp_proof.clone(),
        num_inputs: u32::try_from(slots.len()).expect("under the cap"),
        tree_depth: layers,
    };
    matches!(
        proof::verify(
            &fcmp,
            &key_images,
            &prunable.pseudo_outs,
            &pqc_keys,
            &claim.root,
            layers,
            tx.tx_signable(network),
        ),
        Ok(true)
    )
}

/// The production stateless judgement of `tx` under `network`.
fn judged(
    tx: &Transaction,
    chain: &Chain,
    connected: &Connected,
    network: &NetworkId,
) -> Result<StatelessPass, shekyl_chain_rules::InvalidBlock> {
    judge_lone_stateless(
        tx,
        &chain.scenario.rules.in_force(connected.height),
        network,
        &claims_for(&chain.blocks, connected),
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
        let own = table_genesis(other);
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

    // Lock 3 — signatures and proofs, transaction by transaction.
    let mut judged_bodies = 0;
    for connected in &chain.blocks {
        for tx in &connected.listed {
            judged(tx, &chain, connected, &regtest)
                .unwrap_or_else(|refused| panic!("under regtest's id: {refused:?}"));
            let claims = claims_for(&chain.blocks, connected);
            assert!(
                fcmp_verifies(tx, &claims, &regtest),
                "the proof verifies over regtest's tx_signable"
            );
            for other in OTHERS {
                let id = other.network_id();
                match judged(tx, &chain, connected, &id) {
                    Err(refused) => assert_eq!(refused.rule, CenRow::I18, "{other}: {refused:?}"),
                    Ok(_) => panic!("{other}'s id passed a regtest body"),
                }
                assert!(
                    !fcmp_verifies(tx, &claims, &id),
                    "{other}: the proof fails over another network's tx_signable"
                );
            }
            judged_bodies += 1;
        }
    }
    assert_eq!(judged_bodies, 1, "the chain lists its one join");

    // Lock 4 — the wire — is the transport's (module docs).
    chain.scenario.close().await;
}
