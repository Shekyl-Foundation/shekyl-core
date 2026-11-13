// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One block template built (`BENCHMARK_ALIGNMENT.md` BA-T46):
//! `shekyl_block_template::build`, the call the tip follower makes for a
//! miner's template and the scenario driver makes for every block it
//! mines.
//!
//! The listing is the design load's transaction (`DAEMON_REDB_STORE.md`
//! §1.3a, load profiles: 30 a block, each a 2-in/2-out spend), from a
//! committed fixture block (`src/bench_fixture_tests.rs`). The block lists
//! 28 of them, not 30: 30 pass the weight limit at the genesis median, and
//! `build` refuses a listing that does. The context is that block
//! seen from the producer's side: its height, parent, roots and version. `build` sums the listing's fees and
//! weights, prices the reward at the block's weight, builds the coinbase
//! that pays it (one hybrid KEM encapsulation to the miner, the output and
//! its commitment, the extra fields) and re-prices until the block's
//! weight and the priced weight meet. `build` judges nothing against a
//! chain, so the row needs no store.
//!
//! The miner's hybrid KEM keys are generated in setup and differ run to
//! run. The encapsulation does the same work for any key; the manifest
//! records the spread measured over repeated runs.
//!
//! The emission operands are the genesis era's (nothing generated, the
//! median at the full-reward zone), as the fixture chain's are.
//!
//! The bench is this crate's for the listing: real spends come from the
//! committed corpus, which `bench_support.rs` reads. `shekyl-block-template`
//! is a linked dependency of this crate, and the ledger row's path set
//! names it.
//!
//! An instruction count on the CI runner's x86, never a floor figure
//! (rule 76).

use std::hint::black_box;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use gungraun::{library_benchmark, library_benchmark_group, main};
use shekyl_block_template::{build, EmissionOperands, MinerKeys, Template, TemplateContext};
use shekyl_chain_ingest::bench_support::{blocks_of, RULES};
use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};
use shekyl_economics::{ClosedShardCount, EconomicParams, TxVolume, FULL_REWARD_ZONE};
use shekyl_types::{BlockHeight, Timestamp};
use shekyl_units::AtomicUnits;
use shekyl_wire::block::Block;
use shekyl_wire::transaction::Transaction;
use shekyl_wire::tx_extra;
use zeroize::Zeroizing;

const DESIGN_LOAD: &[u8] = include_bytes!("fixtures/block_path_spend_2in_2out_design.corpus");

/// The design load's transactions that fit one block at the genesis
/// median.
const LISTED: usize = 28;

/// What a context borrows, and the block it is the producer's view of.
struct Operands {
    height: BlockHeight,
    subject: Block,
    listed: Vec<Transaction>,
    params: EconomicParams,
    miner: MinerKeys,
}

impl Operands {
    fn context(&self) -> TemplateContext<'_> {
        let rule_set = RULES.in_force(self.height);
        let header = &self.subject.header;
        TemplateContext {
            height: self.height,
            previous: header.previous,
            curve_tree_root: header.curve_tree_root,
            attestation_root: header.attestation_root,
            major_version: rule_set.header_major_version(),
            now: Timestamp::from_raw(header.timestamp),
            median_timestamp: None,
            unlock_window: rule_set.mined_money_unlock_window(),
            emission: EmissionOperands {
                already_generated_coins: AtomicUnits::ZERO,
                total_burned: AtomicUnits::ZERO,
                median_weight: FULL_REWARD_ZONE,
                tx_volume: TxVolume::ZERO,
                closed_shards: ClosedShardCount::ZERO,
            },
            params: &self.params,
            miner: &self.miner,
            tx_key_secret: Zeroizing::new([0x77; 32]),
            extra_nonce: [0; tx_extra::COINBASE_NONCE_BYTES],
            draw_commitment: tx_extra::CONFORMING_DRAW_COMMITMENT,
            listed: &self.listed,
        }
    }
}

/// The fixture's subject block as a producer's operands.
fn operands(corpus: &[u8]) -> Operands {
    let mut blocks = blocks_of(corpus);
    let subject = blocks.pop().expect("a fixture holds its subject block");
    let height = BlockHeight::from_raw(u64::try_from(blocks.len()).expect("a short chain"));
    assert_eq!(
        subject.transactions.len(),
        LISTED,
        "the design load's listing"
    );
    let (pk, _sk) = HybridX25519MlKem
        .keypair_generate()
        .expect("hybrid KEM keypair generation");
    let operands = Operands {
        height,
        subject: subject.block,
        listed: subject.transactions,
        params: EconomicParams::default(),
        miner: MinerKeys {
            spend_public: EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order([0x4d; 32]))
                .compress()
                .to_bytes(),
            x25519_pk: pk.x25519,
            ml_kem_ek: pk.ml_kem,
        },
    };
    // A context `build` refuses would count the refusal.
    let template = build(&operands.context()).expect("the template builds");
    assert_eq!(template.transactions.len(), LISTED);
    operands
}

#[library_benchmark]
#[bench::design_load(args = (DESIGN_LOAD), setup = operands)]
fn crypto_bench_block_template_build(operands: Operands) -> (Operands, Template) {
    let template = {
        let context = operands.context();
        black_box(build(black_box(&context)).expect("the template builds"))
    };
    (operands, template)
}

library_benchmark_group!(
    name = block_template_group;
    benchmarks = crypto_bench_block_template_build
);

main!(library_benchmark_groups = block_template_group);
