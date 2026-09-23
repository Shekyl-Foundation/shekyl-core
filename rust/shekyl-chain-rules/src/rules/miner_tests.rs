// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Negative fixtures for census 4.F (`CHAIN_RULES_SLICE_4.md` §5): one
//! refusal per predicate row, at [`TxSlot::Miner`] (Q6); a value pin per
//! definition row against `shekyl-economics` (the body the C++ marshals
//! to); the falsifiers of the by-construction rows (F2, F8, F21; F19's is
//! the `validate` doctest) (Q4);
//! and the pins on the fixture points the whole file leans on. Each test
//! names its row and asserts **the row**, not merely a refusal — the
//! discipline slice 2 adopted, and the one Q8 found missing from the E2
//! mutation family.

use super::*;
use crate::block::Candidate;
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, Fault, FormAttempt};
use crate::harness::fixture::{
    candidate, candidate_on, coinbase, recorded, recorded_with_work, G, TWO_G,
};
use crate::harness::{
    assert_refused, expected_seed, formed_on, infallible, judged, Faulted, MockChain, MockSubstrate,
};
use crate::rule_set::RuleSet;
use crate::rules::{BlockContext, BlockRule, FormContext, FormRule};
use crate::trust::Trust;
use crate::validate::{form, validate};
use crate::verdict::{ChainValid, Locus, TxSlot, Verdict};
use crate::view::{RecordedBlock, Tip};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_economics::{base_block_reward, effective_emission, TxVolume};
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Ct, Input, Output, Transaction};

const MINER: Locus = Locus::Tx {
    slot: TxSlot::Miner,
};

/// Judge through both stages against `chain`, claiming the seed the chain
/// expects (D3); the mock never faults.
fn judge_on(chain: &MockChain, candidate: Candidate) -> Verdict<()> {
    let formed = match form(
        candidate,
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        expected_seed(chain),
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => return Err(refused),
        Err(Faulted) => unreachable!("the default MockSubstrate never faults"),
    };
    chain.with_view(|view| {
        judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .map(|_valid: ChainValid<_>| ())
    })
}

/// Judge against an empty chain (the candidate is genesis).
fn judge(candidate: Candidate) -> Verdict<()> {
    judge_on(&MockChain::default(), candidate)
}

/// A one-block chain, so the candidate connects at height 1 — where the
/// genesis exemptions do not apply.
fn one_block() -> MockChain {
    MockChain::default().push(recorded(1_000), crate::harness::fixture::root(1))
}

/// A candidate on `chain` with its coinbase replaced by `f(coinbase)`.
fn with_coinbase(chain: &MockChain, f: impl FnOnce(&mut Transaction)) -> Candidate {
    let mut candidate = candidate_on(chain, Vec::new());
    f(&mut candidate.block.miner_transaction);
    candidate
}

fn check_alone<R: FormRule>(candidate: &Candidate) -> Verdict<()> {
    R::check(&FormContext::new(candidate, &RuleSet::GENESIS))
}

fn check_alone_on<R: BlockRule>(chain: &MockChain, candidate: &Candidate) -> Verdict<()> {
    let formed = formed_on(chain, candidate.clone());
    chain.with_view(|view| {
        infallible(R::check(
            &BlockContext::for_tests(&formed, chain.tip(), None),
            &view,
        ))
    })
}

// --- the fixture's own points ------------------------------------------------

/// The two constants every coinbase fixture carries are what their names
/// say, judged by the crate the rows adopt: `G` is an acceptable output
/// key and a trivial mask; `2·G` is an acceptable mask for a zero-amount
/// coinbase output.
#[test]
fn fixture_points_are_what_they_claim() {
    use crate::harness::fixture::{point, POINTS};
    use shekyl_ct_balance::{check_commitment_masks, check_output_keys, MaskSubject};
    assert!(check_output_keys(&G).is_ok());
    assert!(check_output_keys(&TWO_G).is_ok());
    assert!(check_commitment_masks(&G, 1, MaskSubject::Coinbase { amounts: &[0] }).is_err());
    assert!(check_commitment_masks(&TWO_G, 1, MaskSubject::Coinbase { amounts: &[0] }).is_ok());
    // The table (slice 5): every entry a canonical prime-order point, all
    // sixteen pairwise distinct, the first two the named constants, and
    // `point(k)` the k-th from 1. Pointness is what the fixtures need.
    assert_eq!(POINTS[0], G);
    assert_eq!(POINTS[1], TWO_G);
    // Multiplicity — `POINTS[k−1] == k·G` for every k — is what the balance
    // fixtures rely on (the table's contiguity, see its doc). Curve
    // arithmetic makes it a gate rather than quoted provenance: a renumbered
    // or non-contiguous table fails here, not in a store test three crates
    // away. The same loop holds the pinned table equal to its computed form,
    // `point_at`, so the two never disagree about what `k·G` is.
    {
        use crate::harness::fixture::point_at;
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use curve25519_dalek::scalar::Scalar;
        for (i, p) in POINTS.iter().enumerate() {
            let k = u64::try_from(i + 1).expect("small");
            let expected = (ED25519_BASEPOINT_POINT * Scalar::from(k))
                .compress()
                .to_bytes();
            assert_eq!(*p, expected, "POINTS[{i}] is {k}·G");
            assert_eq!(point_at(k), *p, "point_at({k}) is the pinned entry");
        }
        assert!(
            check_output_keys(&point_at(2_113)).is_ok(),
            "a far entry is a canonical prime-order point too"
        );
    }
    assert_eq!(point(1), G);
    assert_eq!(point(16), POINTS[15]);
    let flat: Vec<u8> = POINTS.iter().flatten().copied().collect();
    assert!(
        check_output_keys(&flat).is_ok(),
        "every entry is a canonical prime-order point"
    );
    let distinct: std::collections::BTreeSet<[u8; 32]> = POINTS.iter().copied().collect();
    assert_eq!(distinct.len(), POINTS.len(), "pairwise distinct");
    // Every entry also serves as a non-trivial mask for a zero-amount
    // output except `G` itself (`zeroCommit(0) = G`), which is the one entry
    // a fixture must not use as a coinbase mask.
    for (i, p) in POINTS.iter().enumerate().skip(1) {
        assert!(
            check_commitment_masks(p, 1, MaskSubject::Coinbase { amounts: &[0] }).is_ok(),
            "entry {i} is a usable mask"
        );
    }
}

/// The fixture coinbase passes every 4.F row at genesis and at height 1.
#[test]
fn the_fixture_coinbase_passes_every_landed_row() {
    judge(candidate(Vec::new())).expect("genesis fixture");
    let chain = one_block();
    judge_on(&chain, candidate_on(&chain, Vec::new())).expect("height-1 fixture");
}

// --- CEN-F1 ------------------------------------------------------------------

#[test]
fn cen_f1_exactly_one_gen_input() {
    let chain = one_block();
    let none = with_coinbase(&chain, |tx| tx.prefix.inputs.clear());
    assert_refused(judge_on(&chain, none), CenRow::F1, MINER);
    let two = with_coinbase(&chain, |tx| tx.prefix.inputs.push(Input::Gen(1)));
    assert_refused(judge_on(&chain, two), CenRow::F1, MINER);
    let spend = with_coinbase(&chain, |tx| {
        tx.prefix.inputs = vec![Input::ToKey {
            amount: 0,
            key_offsets: vec![0],
            key_image: [1; 32],
        }];
    });
    assert_refused(judge_on(&chain, spend), CenRow::F1, MINER);
}

// --- CEN-F3 ------------------------------------------------------------------

#[test]
fn cen_f3_coinbase_ct_type_is_null() {
    let chain = one_block();
    let fcmp = with_coinbase(&chain, |tx| {
        let base = match &tx.ct {
            Ct::Null(base) | Ct::Fcmp { base, .. } => base.clone(),
        };
        tx.ct = Ct::Fcmp {
            fee: 0,
            reference_block: BlockHash::NULL,
            base,
            pqc_auths: Vec::new(),
            prunable: None,
        };
    });
    // Alone, so the refusal is F3's and not a later row's reading of the
    // same field.
    assert_refused(check_alone::<F3>(&fcmp), CenRow::F3, MINER);
    assert_refused(judge_on(&chain, fcmp), CenRow::F3, MINER);
}

// --- CEN-F4 ------------------------------------------------------------------

#[test]
fn cen_f4_exactly_one_output_above_genesis() {
    let chain = one_block();
    let two = with_coinbase(&chain, |tx| {
        let extra = tx.prefix.outputs[0].clone();
        tx.prefix.outputs.push(extra);
        // Keep F10's arity satisfied so the refusal is F4's alone.
        if let Ct::Null(base) = &mut tx.ct {
            base.commitments.push(TWO_G);
            base.enc_amounts.push([0x55; 9]);
            base.enc_labels.push([0x66; 9]);
        }
    });
    assert_refused(check_alone_on::<F4>(&chain, &two), CenRow::F4, MINER);
    assert_refused(judge_on(&chain, two), CenRow::F4, MINER);
    let none = with_coinbase(&chain, |tx| {
        tx.prefix.outputs.clear();
        if let Ct::Null(base) = &mut tx.ct {
            base.commitments.clear();
        }
    });
    assert_refused(check_alone_on::<F4>(&chain, &none), CenRow::F4, MINER);
}

/// Genesis is exempt: the height is the connecting height, caller-derived.
#[test]
fn cen_f4_genesis_is_exempt() {
    let empty = MockChain::default();
    let two = with_coinbase(&empty, |tx| {
        let extra = tx.prefix.outputs[0].clone();
        tx.prefix.outputs.push(extra);
        if let Ct::Null(base) = &mut tx.ct {
            base.commitments.push(TWO_G);
        }
    });
    check_alone_on::<F4>(&empty, &two).expect("two outputs at genesis pass F4");
}

// --- CEN-F5 ------------------------------------------------------------------

#[test]
fn cen_f5_gen_height_is_the_chain_position() {
    let chain = one_block();
    // Connecting at 1; the claim says 0 (a replayed genesis coinbase) or 2.
    for claimed in [0u64, 2, u64::MAX] {
        let wrong = with_coinbase(&chain, |tx| tx.prefix.inputs = vec![Input::Gen(claimed)]);
        assert_refused(check_alone_on::<F5>(&chain, &wrong), CenRow::F5, MINER);
        // F6 reads the connecting height, not the claim, so the spoof
        // trips exactly one row through the pipeline.
        assert_refused(judge_on(&chain, wrong), CenRow::F5, MINER);
    }
}

// --- CEN-F6 ------------------------------------------------------------------

#[test]
fn cen_f6_unlock_time_is_height_plus_the_window() {
    let chain = one_block();
    let window = RuleSet::GENESIS.mined_money_unlock_window().to_raw();
    assert_eq!(window, 60);
    for unlock in [0u64, 1, 1 + window - 1, 1 + window + 1, u64::MAX] {
        let wrong = with_coinbase(&chain, |tx| tx.prefix.unlock_time = unlock);
        assert_refused(check_alone_on::<F6>(&chain, &wrong), CenRow::F6, MINER);
    }
    // `60` alone is genesis's unlock (0 + 60), and is refused at height 1.
    let genesis_unlock = with_coinbase(&chain, |tx| tx.prefix.unlock_time = window);
    assert_refused(judge_on(&chain, genesis_unlock), CenRow::F6, MINER);
}

// --- CEN-F7 ------------------------------------------------------------------

#[test]
fn cen_f7_output_amounts_sum_without_overflow() {
    let chain = one_block();
    let overflow = with_coinbase(&chain, |tx| {
        tx.prefix.outputs[0].amount = u64::MAX;
        tx.prefix.outputs.push(Output {
            amount: 1,
            key: G,
            view_tag: 2,
        });
    });
    // Alone: F4 would refuse the second output first in the pipeline.
    assert_refused(check_alone::<F7>(&overflow), CenRow::F7, MINER);
    let exact = with_coinbase(&chain, |tx| {
        tx.prefix.outputs[0].amount = u64::MAX - 1;
        tx.prefix.outputs.push(Output {
            amount: 1,
            key: G,
            view_tag: 2,
        });
    });
    check_alone::<F7>(&exact).expect("u64::MAX exactly is not an overflow");
}

// --- CEN-F9 ------------------------------------------------------------------

#[test]
fn cen_f9_output_keys_are_canonical_prime_order_points() {
    let chain = one_block();
    let identity = with_coinbase(&chain, |tx| {
        let mut key = [0u8; 32];
        key[0] = 1;
        tx.prefix.outputs[0].key = key;
    });
    assert_refused(judge_on(&chain, identity), CenRow::F9, MINER);
    let non_canonical = with_coinbase(&chain, |tx| tx.prefix.outputs[0].key = [0xff; 32]);
    assert_refused(judge_on(&chain, non_canonical), CenRow::F9, MINER);
}

// --- CEN-F10 -----------------------------------------------------------------

#[test]
fn cen_f10_masks_are_non_trivial_and_one_per_output() {
    let chain = one_block();
    // `G` as the mask of a zero-amount output is both trivial forms at
    // once — `mask = 1, amount = 0`, and `zeroCommit(0) = G + 0·H`: the
    // fingerprint the coinbase subject adds. Refused on F10. The non-zero
    // fingerprint vectors (`G + amount·H`) are `shekyl-ct-balance`'s own,
    // the body this row adopts.
    let g_mask = with_coinbase(&chain, |tx| {
        if let Ct::Null(base) = &mut tx.ct {
            base.commitments[0] = G;
        }
    });
    assert_refused(judge_on(&chain, g_mask), CenRow::F10, MINER);
    // The fixture's `2·G` on a non-zero amount is an honest mask: it is
    // not `G + amount·H` for that amount.
    let honest = with_coinbase(&chain, |tx| tx.prefix.outputs[0].amount = 600_000_000_000);
    judge_on(&chain, honest).expect("a non-fingerprint mask passes");
    // Arity: two masks for one output (S25's clause, now a row's).
    let two_masks = with_coinbase(&chain, |tx| {
        if let Ct::Null(base) = &mut tx.ct {
            base.commitments.push(TWO_G);
        }
    });
    assert_refused(judge_on(&chain, two_masks), CenRow::F10, MINER);
    let no_masks = with_coinbase(&chain, |tx| {
        if let Ct::Null(base) = &mut tx.ct {
            base.commitments.clear();
        }
    });
    assert_refused(judge_on(&chain, no_masks), CenRow::F10, MINER);
}

// --- the definitions: F11, F13, F15, F20 ---------------------------------------

/// A recorded block carrying an emission accumulator and a tx prefix sum,
/// with work that grows with the timestamp so a long chain satisfies
/// SI-10 (D4's window reads the work; these fixtures are not about it).
fn recorded_with_emission(
    timestamp: u64,
    coins_generated: u64,
    cumulative_tx_count: u64,
) -> RecordedBlock {
    RecordedBlock {
        coins_generated: AtomicUnits::from_raw(coins_generated),
        cumulative_tx_count,
        ..recorded_with_work(
            timestamp,
            CumulativeDifficulty::from_raw(u128::from(timestamp)),
        )
    }
}

fn emission_on(chain: &MockChain) -> Emission {
    let connecting = Tip::connecting_height(chain.tip().as_ref());
    chain.with_view(|view| {
        let mut coverage = RuleCoverage::EMPTY;
        Emission::derive(&view, connecting, &mut coverage).expect("the fixture view answers")
    })
}

/// F11: at genesis the subsidy is configured, the window is `(0, 0)`, and
/// all four definition rows are recorded (coverage is complete at height 0
/// as at any other).
#[test]
fn cen_f11_genesis_takes_the_configured_emission_and_recomputes_nothing() {
    let emission = emission_on(&MockChain::default());
    assert_eq!(emission.subsidy, Subsidy::Configured);
    assert_eq!(emission.tx_volume, TxVolume::window(0, 0));
    let formed = formed_on(&MockChain::default(), candidate(Vec::new()));
    let coverage = MockChain::default().with_view(|view| {
        *judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("genesis fixture")
        .coverage()
    });
    for row in [CenRow::F11, CenRow::F13, CenRow::F15, CenRow::F20] {
        assert!(coverage.contains(row), "{row} recorded at genesis");
    }
}

/// F13 / F15: above genesis the subsidy is the curve at the PARENT's
/// accumulator, tail-floored, and the release-modulated emission over the
/// window — both equal to `shekyl-economics` called with the same
/// operands, which is the C++'s body too.
#[test]
fn cen_f13_f15_price_the_parents_accumulator() {
    let params = economics();
    let ag = params.emission_curve_asymptote / 3;
    let chain = MockChain::default().push(
        recorded_with_emission(1_000, ag, 40),
        crate::harness::fixture::root(1),
    );
    let emission = emission_on(&chain);
    // Height 1: window is min(1, W) = 1 block, the parent's 40 listed txs.
    assert_eq!(emission.tx_volume, TxVolume::window(40, 1));
    let Subsidy::Derived { base, effective } = emission.subsidy else {
        panic!("height 1 derives, it does not take the configured amount");
    };
    assert_eq!(
        base.to_raw(),
        base_block_reward(ag, params).expect("shipped params price")
    );
    assert_eq!(
        effective.to_raw(),
        effective_emission(ag, TxVolume::window(40, 1), params).expect("shipped params price")
    );
    // Mid-curve the base is above the tail and the effective emission is
    // the curve scaled: at forty per block against the baseline the
    // multiplier is not one, so the two differ.
    assert_ne!(base, effective);
}

/// F13's floor: a past-asymptote accumulator is a legitimate perpetual-tail
/// state (FL-R12′), priced at the tail, never a fault.
#[test]
fn cen_f13_past_the_asymptote_is_the_tail() {
    let params = economics();
    let chain = MockChain::default().push(
        recorded_with_emission(1_000, params.emission_curve_asymptote + 1, 0),
        crate::harness::fixture::root(1),
    );
    let Subsidy::Derived { base, .. } = emission_on(&chain).subsidy else {
        panic!("derived");
    };
    assert_eq!(
        base.to_raw(),
        shekyl_economics::tail_subsidy_per_block(params).expect("tail")
    );
}

/// F20: the window is the difference of two prefix sums over the prior
/// `min(h, W)` blocks — two reads, not `W`; the lower term is `0` while
/// the window reaches genesis.
#[test]
fn cen_f20_window_is_two_prefix_sums() {
    // Blocks 0..=3 with 5, 7, 11, 13 listed txs → prefix sums 5, 12, 23, 36.
    let mut chain = MockChain::default();
    let mut prefix = 0u64;
    for (h, n) in [5u64, 7, 11, 13].into_iter().enumerate() {
        prefix += n;
        chain = chain.push(
            recorded_with_emission(1_000 + h as u64, 1_000_000 * (h as u64 + 1), prefix),
            crate::harness::fixture::root(u8::try_from(h + 1).expect("small")),
        );
    }
    // Connecting at 4: window = min(4, 720) = 4 blocks [0, 3], sum 36.
    assert_eq!(emission_on(&chain).tx_volume, TxVolume::window(36, 4));
}

/// F20 past the window: with `W + 2` blocks recorded the window drops the
/// oldest, and the lower prefix sum is read rather than assumed zero.
#[test]
fn cen_f20_window_slides_past_w() {
    let w = shekyl_economics::params::TX_VOLUME_WINDOW;
    let mut chain = MockChain::default();
    // Every block lists one tx, so prefix(h) = h + 1.
    for h in 0..=(w + 1) {
        chain = chain.push(
            recorded_with_emission(1_000 + h, 1_000_000, h + 1),
            crate::harness::fixture::root(u8::try_from(h % 200).expect("small")),
        );
    }
    // Connecting at W + 2: blocks [2, W + 1], W of them, W listed txs.
    assert_eq!(emission_on(&chain).tx_volume, TxVolume::window(w, w));
}

/// F20's fault: a prefix sum that decreases is a store that does not hold
/// what it claims — a `Corrupt` fault, never a saturated zero window.
#[test]
fn cen_f20_a_decreasing_prefix_sum_is_a_corrupt_view() {
    let w = shekyl_economics::params::TX_VOLUME_WINDOW;
    let mut chain = MockChain::default();
    for h in 0..=(w + 1) {
        // The block just below the window (height 1, for a candidate at
        // W + 2) claims 10 listed in total; every block inside the window
        // claims 5 — the prefix sum went backwards across the window's
        // lower edge.
        let prefix = if h <= 1 { 10 } else { 5 };
        chain = chain.push(
            recorded_with_emission(1_000 + h, 1_000_000, prefix),
            crate::harness::fixture::root(u8::try_from(h % 200).expect("small")),
        );
    }
    let candidate = candidate_on(&chain, Vec::new());
    let formed = formed_on(&chain, candidate);
    chain.with_view(|view| {
        let fault = validate(formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED)
            .expect_err("a decreasing prefix sum faults");
        assert!(
            matches!(fault, Fault::Corrupt(Corrupt::TxCountNotMonotone { .. })),
            "got {fault:?}"
        );
    });
}

/// The shipped parameter set prices the tail. That overflow is the only
/// `Err` the emission functions return, and [`economics`] refuses a
/// parameter set that produces it before a block is priced.
#[test]
fn shipped_parameters_price_the_tail() {
    assert!(shekyl_economics::tail_subsidy_per_block(economics()).is_ok());
}

// --- the rows that hold by construction (Q4) -------------------------------

/// CEN-F2's falsifier: the wire admits exactly one transaction version.
/// A coinbase re-encoded with version `2` — the C++ `version >= 3` rule's
/// boundary — does not decode, so no `Transaction` with another version
/// can reach a rule.
#[test]
fn f2_the_wire_admits_one_transaction_version() {
    let tx = coinbase(1);
    let mut bytes = Vec::new();
    tx.write(&mut bytes).expect("serialize");
    assert_eq!(bytes[0], 3, "the version varint leads, and is 3");
    assert!(Transaction::from_bytes(&bytes).is_ok());
    for other in [0u8, 1, 2, 4] {
        bytes[0] = other;
        assert!(
            Transaction::from_bytes(&bytes).is_err(),
            "version {other} must not decode"
        );
    }
}

/// CEN-F8's falsifier: the wire admits exactly one output tag
/// (`txout_to_tagged_key`). An output re-encoded under the legacy
/// `txout_to_key` tag, or any other, does not decode.
#[test]
fn f8_the_wire_admits_one_output_tag() {
    let output = Output {
        amount: 0,
        key: G,
        view_tag: 1,
    };
    let mut bytes = Vec::new();
    output.write(&mut bytes).expect("serialize");
    // varint(0) ‖ tag ‖ key ‖ view_tag: the tag is byte 1.
    let tag = bytes[1];
    assert!(Output::read(&mut bytes.as_slice()).is_ok());
    for other in [0x02u8, 0x00, 0x01, 0xff] {
        if other == tag {
            continue;
        }
        bytes[1] = other;
        assert!(
            Output::read(&mut bytes.as_slice()).is_err(),
            "output tag {other:#04x} must not decode"
        );
    }
}

/// CEN-F21's epoch is the one-row hardfork table's height: `{ 1, 1, 0, … }`
/// on every public network (`hardforks.cpp`), which
/// `get_earliest_ideal_height_for_version(HF_VERSION_SHEKYL_NG)` returns.
/// Read from the table, not restated beside [`EMISSION_SPLIT_EPOCH`].
#[test]
fn the_emission_split_epoch_is_the_hardfork_tables_first_row() {
    let hardforks_cpp = include_str!("../../../../src/hardforks/hardforks.cpp");
    for table in [
        "mainnet_hard_forks",
        "testnet_hard_forks",
        "stagenet_hard_forks",
    ] {
        let start = hardforks_cpp
            .find(&format!("const hardfork_t {table}[] = {{"))
            .unwrap_or_else(|| panic!("hardforks.cpp defines {table}"));
        let body = &hardforks_cpp[start..];
        let end = body.find("};").expect("the table closes");
        let rows: Vec<&str> = body[..end]
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|l| l.starts_with('{'))
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "{table} has one row (all features from genesis)"
        );
        // `{ version, height, threshold, time }`
        let fields: Vec<&str> = rows[0]
            .trim_matches(|c| c == '{' || c == '}' || c == ',')
            .split(',')
            .map(str::trim)
            .collect();
        let height: u64 = fields[1].parse().expect("the row's height is an integer");
        assert_eq!(
            EMISSION_SPLIT_EPOCH,
            BlockHeight::from_raw(height),
            "{table}"
        );
    }
}
