// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The small plan's chain, forged in this process and held open, judged
//! two ways:
//!
//! - **The identity test's four locks** (`CHAIN_FORGE.md` §6), on a forged
//!   chain (`CF-1a` held them on a driver-built one). Lock 1: the chain's
//!   levers are refused under every other network. Lock 2: its block 0,
//!   regtest's table genesis, is CEN-E1's refusal under another network's
//!   production rules, beside that network's own genesis connecting. Lock
//!   3: every body the chain lists is CEN-I18's refusal under every other
//!   network's id, and a body re-signed under that id reaches the proof row
//!   (CEN-I15 for a spend, CEN-J27 for a bond post). Lock 4, the wire, is
//!   the transport's, cited by path and function (`CF-R15`):
//!   `shekyl-clearnet/src/tests.rs`,
//!   `a_listener_refuses_every_other_networks_prefix_and_takes_its_own`.
//! - **The receipt tamper test** (`CF-R16`), at the chain's tip, through
//!   the real connect path: the witness commits a block's draws, the holder
//!   signs each pass, and the next block is offered carrying the bundle with
//!   one field changed, each field in turn. Each case is refused at the row
//!   it reaches first; the same block untampered connects and admits the
//!   bundle.

#[allow(
    dead_code,
    reason = "each test-kind target uses part of the executor; this one forges in process"
)]
#[path = "../executor/mod.rs"]
mod executor;

use std::collections::BTreeSet;
use std::num::NonZeroUsize;

use executor::{BuiltKind, Forge, Options};
use shekyl_archival_retention::{BundleBody, BundleRef, CHALLENGE_READS};
use shekyl_chain_forge::Plan;
use shekyl_chain_ingest::admitted_draws::{bundle_for, every_draw_passes, DrawnBundle};
use shekyl_chain_ingest::archival_driver::ENDPOINT;
use shekyl_chain_ingest::scenario::{FreeHash, Mined, Scenario, StepOutcome};
use shekyl_chain_ingest::scenario_archival::shard_set;
use shekyl_chain_ingest::schedule::{ChainRules, LeverRefused};
use shekyl_chain_rules::{
    judge_lone_stateless, Candidate, CappedEpoch, CenRow, ReferenceClaim, ReferenceClaims,
    StatelessPass,
};
use shekyl_harness_spender::Spender;
use shekyl_network::{Lever, Network, NetworkId};
use shekyl_types::{BlockCount, BlockHeight};
use shekyl_wire::Transaction;

/// A body re-signed under a network's id.
type Resign = Box<dyn Fn(&NetworkId) -> Transaction>;

/// Every network but regtest.
const OTHERS: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Stagenet];

/// Blocks mined at the tip, each committing its draws, before one draws.
const DRAWING_WITHIN: u64 = 64;

fn plan() -> Plan {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("plans/small.toml");
    Plan::parse(&std::fs::read_to_string(path).expect("the plan reads")).expect("parses")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "minutes of proofs; run in release by chain-forge.yml"]
async fn the_small_plan_is_regtests_alone_and_refuses_a_tampered_receipt() {
    let plan = plan();
    let out = tempfile::tempdir().expect("a directory");
    let mut forge = Forge::open(
        &plan,
        out.path(),
        Options {
            swapped: BTreeSet::new(),
            stop_at_difference: None,
            hashers: NonZeroUsize::MIN,
        },
    )
    .await
    .expect("the forging opens");
    assert!(
        forge.run(&plan).await.expect("the plan runs").is_none(),
        "nothing to stop at"
    );
    identity_locks(&mut forge).await;
    receipt_tamper(&mut forge).await;
    forge.abandon().await;
}

/// The claims for `block`'s listed bodies, one per reference a body names
/// that `chain` holds (CEN-B5).
fn claims_for(chain: &[Mined], block: &Mined) -> ReferenceClaims {
    let candidate = Candidate::new(
        block.template.block.clone(),
        block.template.transactions.clone(),
    );
    ReferenceClaims::gather(&candidate, |reference| {
        chain.iter().find_map(|mined| {
            (mined.hash == *reference).then_some(ReferenceClaim {
                height: mined.height,
                root: mined.template.block.header.curve_tree_root,
            })
        })
    })
}

/// The production stateless judgement of `tx`, listed in `block`, under
/// `network`.
fn judged(
    tx: &Transaction,
    rules: ChainRules,
    block: &Mined,
    network: &NetworkId,
    claims: &ReferenceClaims,
) -> Result<StatelessPass, shekyl_chain_rules::InvalidBlock> {
    judge_lone_stateless(tx, &rules.in_force(block.height), network, claims, None)
}

async fn identity_locks(forge: &mut Forge) {
    let rules = forge.rules();
    let regtest = forge.scenario().network_id();
    assert_eq!(
        regtest,
        Network::Regtest.network_id(),
        "the chain is regtest's"
    );

    // Lock 1 — the levers.
    assert_eq!(rules.network(), Network::Regtest);
    let fixed = rules.fixed_difficulty();
    assert!(fixed.is_some(), "the chain is mined at a fixed difficulty");
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

    // Lock 2 — genesis.
    let genesis = forge.chain()[0].template.block.clone();
    for other in OTHERS {
        let production = ChainRules::new(other, None, CappedEpoch::PRODUCTION)
            .expect("the production schedule pulls no lever");
        let mut elsewhere =
            Scenario::open_under(&format!("forged-genesis-{other}"), FreeHash, production);
        match elsewhere.offer_genesis(&genesis).await {
            Err(StepOutcome::Refused(refused)) => {
                assert_eq!(refused.rule, CenRow::E1, "{other}: {refused:?}");
            }
            outcome => panic!("{other} took the forged chain's genesis: {outcome:?}"),
        }
        let own = shekyl_genesis_tool::builder::pinned_genesis(other)
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

    // Lock 3 — every listed body, under every other id.
    let chain: Vec<Mined> = forge.chain().to_vec();
    let mut bodies = 0usize;
    for block in &chain {
        let claims = claims_for(&chain, block);
        for tx in &block.template.transactions {
            judged(tx, rules, block, &regtest, &claims).unwrap_or_else(|refused| {
                panic!("block {} under regtest: {refused:?}", block.height)
            });
            for other in OTHERS {
                match judged(tx, rules, block, &other.network_id(), &claims) {
                    Err(refused) => assert_eq!(
                        refused.rule,
                        CenRow::I18,
                        "block {} under {other}: {refused:?}",
                        block.height
                    ),
                    Ok(_) => panic!("{other}'s id passed a body of block {}", block.height),
                }
            }
            bodies += 1;
        }
    }
    let built = forge.built().to_vec();
    assert!(
        bodies >= built.len(),
        "every body the plan built is on the chain or popped"
    );

    // The proof row: one body of each kind the spender re-signs, its proof
    // left regtest's, its authorizations re-signed under the other id.
    let wallet = forge.scenario().wallet();
    let mut legs = BTreeSet::new();
    for item in &built {
        let Some(block) = chain.get(usize::try_from(item.connecting.to_raw()).expect("fits"))
        else {
            continue;
        };
        if !block.template.transactions.contains(&item.body) {
            continue; // popped by the plan's reorg
        }
        let claims = claims_for(&chain, block);
        let spender = Spender::on(
            regtest,
            &chain[..usize::try_from(item.connecting.to_raw()).expect("fits")],
        );
        let (row, signed): (CenRow, Resign) = match &item.kind {
            BuiltKind::Spend { coinbases } if coinbases.len() == 1 => {
                let coinbase = coinbases[0];
                let body = item.body.clone();
                let connecting = item.connecting;
                (
                    CenRow::I15,
                    Box::new(move |id| {
                        spender.signed_under(&body, wallet, coinbase, connecting, None, id)
                    }),
                )
            }
            BuiltKind::Join {
                coinbase,
                slot,
                shards,
            } => {
                let persona = forge.persona(*slot).expect("the plan joined it");
                let join = persona.join(shard_set(shards.clone()), ENDPOINT);
                let bodies: Vec<(NetworkId, Transaction)> = OTHERS
                    .iter()
                    .map(|other| {
                        let id = other.network_id();
                        let signed = spender.signed_under(
                            &item.body,
                            wallet,
                            *coinbase,
                            item.connecting,
                            Some(&join),
                            &id,
                        );
                        (id, signed)
                    })
                    .collect();
                (
                    CenRow::J27,
                    Box::new(move |id| {
                        bodies
                            .iter()
                            .find(|(signed_for, _)| signed_for == id)
                            .map(|(_, body)| body.clone())
                            .expect("one body per other network")
                    }),
                )
            }
            _ => continue,
        };
        for other in OTHERS {
            let id = other.network_id();
            match judged(&signed(&id), rules, block, &id, &claims) {
                Err(refused) => assert_eq!(refused.rule, row, "{other}: {refused:?}"),
                Ok(pass) => panic!("{other}'s id passed a regtest proof: {pass:?}"),
            }
        }
        legs.insert(row);
    }
    assert_eq!(
        legs,
        BTreeSet::from([CenRow::I15, CenRow::J27]),
        "the proof row is reached for a spend and for a bond post"
    );
}

/// One tamper case: what it changes, whether the witness signs the change,
/// and the row that refuses it.
struct Case {
    name: &'static str,
    resign: bool,
    row: CenRow,
    edit: fn(&mut DrawnBundle, BlockHeight),
}

const CASES: &[Case] = &[
    Case {
        name: "the revealed seed",
        resign: false,
        row: CenRow::J33,
        edit: |drawn, _| drawn.kept.seed[0] ^= 1,
    },
    Case {
        name: "a record's attempt, unsigned",
        resign: false,
        row: CenRow::J34,
        edit: |drawn, _| drawn.records[0].attempt ^= 1,
    },
    Case {
        name: "a record's anchor height, unsigned",
        resign: false,
        row: CenRow::J34,
        edit: |drawn, h| {
            drawn.records[0].anchor_height = h
                .checked_sub_count(BlockCount::from_raw(2))
                .expect("below the tip");
        },
    },
    Case {
        name: "a record's delivery digest, unsigned",
        resign: false,
        row: CenRow::J34,
        edit: |drawn, _| drawn.records[0].delivery_digest[0] ^= 1,
    },
    Case {
        name: "a record's receipt, unsigned",
        resign: false,
        row: CenRow::J34,
        edit: |drawn, _| drawn.records[0].receipt[0] ^= 1,
    },
    Case {
        name: "a record's attempt past the reads, re-signed",
        resign: true,
        row: CenRow::J35,
        edit: |drawn, _| drawn.records[0].attempt = CHALLENGE_READS,
    },
    Case {
        name: "a record's anchor at the block itself, re-signed",
        resign: true,
        row: CenRow::J36,
        edit: |drawn, h| drawn.records[0].anchor_height = h,
    },
    Case {
        name: "a record's attempt, re-signed",
        resign: true,
        row: CenRow::J37,
        edit: |drawn, _| drawn.records[0].attempt ^= 1,
    },
    Case {
        name: "a record's anchor height, re-signed",
        resign: true,
        row: CenRow::J37,
        edit: |drawn, h| {
            drawn.records[0].anchor_height = h
                .checked_sub_count(BlockCount::from_raw(2))
                .expect("below the tip");
        },
    },
    Case {
        name: "a record's delivery digest, re-signed",
        resign: true,
        row: CenRow::J37,
        edit: |drawn, _| drawn.records[0].delivery_digest[0] ^= 1,
    },
    Case {
        name: "a record's receipt, re-signed",
        resign: true,
        row: CenRow::J37,
        edit: |drawn, _| drawn.records[0].receipt[0] ^= 1,
    },
];

async fn receipt_tamper(forge: &mut Forge) {
    let witness = forge.witness();
    let network = forge.scenario().network_id();
    let mut chain: Vec<Mined> = forge.chain().to_vec();

    // Mine at the tip, each block committing its draws, until one draws.
    // The persona the plan joined holds the chain's one drawable pair.
    let (h, drawn) = 'drawing: {
        for _ in 0..DRAWING_WITHIN {
            let height =
                BlockHeight::from_raw(u64::try_from(chain.len()).expect("a chain's length fits"));
            let (scenario, holder) = forge.scenario_with(0);
            let holder = holder.expect("the plan joined persona 0");
            scenario.commit_next(witness.commitment(height));
            let (block, _) = scenario
                .mine_admitting(Vec::new())
                .await
                .unwrap_or_else(|outcome| panic!("block {height} lands: {outcome}"));
            let hash = block.hash;
            chain.push(block);
            if let Some(drawn) = bundle_for(
                scenario,
                &chain,
                &witness,
                &[holder],
                &every_draw_passes,
                height,
                hash,
            )
            .await
            {
                break 'drawing (height, drawn);
            }
        }
        panic!("no block drew within {DRAWING_WITHIN} blocks of the tip");
    };
    assert!(!drawn.records.is_empty(), "the block's draws passed");
    let (reference, body) = witness.assemble(&network, &drawn);

    for case in CASES {
        let mut tampered = DrawnBundle {
            kept: drawn.kept.clone(),
            records: drawn.records.clone(),
        };
        (case.edit)(&mut tampered, h);
        let (tampered_reference, tampered_body) = if case.resign {
            witness.assemble(&network, &tampered)
        } else {
            // The witness's signature over the untampered bundle, carried
            // over the tampered fields.
            let carried = BundleBody::new(
                body.witness_public_key(),
                body.witness_signature(),
                &tampered.records,
            );
            (BundleRef::of(&tampered.kept, &carried), carried)
        };
        let next = forge
            .scenario()
            .next_template(Vec::new())
            .await
            .unwrap_or_else(|outcome| panic!("a template: {outcome}"));
        match forge
            .scenario()
            .connect_next_carrying(next, (vec![tampered_reference], vec![tampered_body]))
            .await
        {
            Err(StepOutcome::Refused(refused)) => {
                assert_eq!(refused.rule, case.row, "{}: {refused:?}", case.name);
            }
            outcome => panic!(
                "{}: the tampered bundle was not refused: {outcome:?}",
                case.name
            ),
        }
    }

    // A tampered witness signature, the witness key's own field.
    let mut signature = *body.witness_signature();
    signature[0] ^= 1;
    let flipped = BundleBody::new(body.witness_public_key(), &signature, &drawn.records);
    let next = forge
        .scenario()
        .next_template(Vec::new())
        .await
        .expect("a template");
    match forge
        .scenario()
        .connect_next_carrying(
            next,
            (vec![BundleRef::of(&drawn.kept, &flipped)], vec![flipped]),
        )
        .await
    {
        Err(StepOutcome::Refused(refused)) => assert_eq!(refused.rule, CenRow::J34, "{refused:?}"),
        outcome => panic!("a flipped witness signature was not refused: {outcome:?}"),
    }

    // The positive control: the same bundle, untampered, connects.
    let next = forge
        .scenario()
        .next_template(Vec::new())
        .await
        .expect("a template");
    let (block, admitted) = forge
        .scenario()
        .connect_next_carrying(next, (vec![reference], vec![body]))
        .await
        .unwrap_or_else(|outcome| panic!("the untampered bundle's block connects: {outcome}"));
    assert_eq!(admitted.len(), 1, "the block admits the bundle");
    assert_eq!(block.height, h + BlockCount::ONE);
}
