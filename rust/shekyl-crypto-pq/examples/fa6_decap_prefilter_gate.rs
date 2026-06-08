// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FA-6 §8.5.1 micro gate: universal ML-KEM decap + `view_tag_prefilter` compare.
//!
//! Models the **dominant chain-scan path** (~255/256 outputs): decap, tag
//! compare, reject (with `ml_kem_ss` wipe inside
//! [`shekyl_crypto_pq::output::ml_kem_decap_prefilter_with_parsed_dk`]).
//!
//! Run on the §8.2 reference device (Pi 4 4GB, active cooling) for §8.7:
//!
//! ```text
//! cargo run --release -p shekyl-crypto-pq --bin fa6_decap_prefilter_gate -- --scenario a
//! cargo run --release -p shekyl-crypto-pq --bin fa6_decap_prefilter_gate -- --scenario b
//! ```
//!
//! `smoke` (10_000 iterations) is for dev/CI sanity only.

use std::time::Instant;

use fips203::ml_kem_768;
use fips203::traits::Decaps;
use fips203::traits::{Encaps, KeyGen, SerDes};
use shekyl_crypto_pq::derivation::derive_view_tag_prefilter;
use shekyl_crypto_pq::kem::{MlKemDecapsKey, ML_KEM_768_CT_LEN, ML_KEM_768_DK_LEN};
use shekyl_crypto_pq::output::ml_kem_decap_prefilter_with_parsed_dk;

const M_MARGIN: f64 = 0.20;

const SCENARIO_A_OUTPUTS: u64 = 2_016_000;
const SCENARIO_B_OUTPUTS: u64 = 525_960_000;
const SMOKE_OUTPUTS: u64 = 10_000;

const T_CEIL_A_SECS: f64 = 45.0;
const T_CEIL_B_SECS: f64 = 20.0 * 60.0;

#[derive(Clone, Copy, Debug)]
enum Scenario {
    Smoke,
    A,
    B,
}

impl Scenario {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "smoke" => Some(Self::Smoke),
            "a" | "A" => Some(Self::A),
            "b" | "B" => Some(Self::B),
            _ => None,
        }
    }

    const fn outputs(self) -> u64 {
        match self {
            Self::Smoke => SMOKE_OUTPUTS,
            Self::A => SCENARIO_A_OUTPUTS,
            Self::B => SCENARIO_B_OUTPUTS,
        }
    }

    const fn t_ceil_secs(self) -> f64 {
        match self {
            Self::Smoke => 0.0,
            Self::A => T_CEIL_A_SECS,
            Self::B => T_CEIL_B_SECS,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum GateOutcome {
    Smoke,
    CleanPass,
    MarginalPass,
    Fail,
}

fn classify(scenario: Scenario, t_meas_secs: f64) -> GateOutcome {
    if matches!(scenario, Scenario::Smoke) {
        return GateOutcome::Smoke;
    }
    let t_ceil = scenario.t_ceil_secs();
    if t_meas_secs <= t_ceil * (1.0 - M_MARGIN) {
        GateOutcome::CleanPass
    } else if t_meas_secs <= t_ceil {
        GateOutcome::MarginalPass
    } else {
        GateOutcome::Fail
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: fa6_decap_prefilter_gate --scenario smoke|a|b [--iterations N]\n\
         \n\
         FA-6_VIEW_TAG_ML_KEM.md §8.5.1 — in-memory decap + pre-filter reject path.\n\
         Scenario a: {SCENARIO_A_OUTPUTS} outputs, ceiling {T_CEIL_A_SECS}s\n\
         Scenario b: {SCENARIO_B_OUTPUTS} outputs, ceiling {T_CEIL_B_SECS}s"
    );
    std::process::exit(2);
}

fn main() {
    let mut scenario = None;
    let mut iterations_override = None;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--scenario" => {
                i += 1;
                scenario = args.get(i).and_then(|s| Scenario::parse(s));
                if scenario.is_none() {
                    usage();
                }
            }
            "--iterations" => {
                i += 1;
                iterations_override = args.get(i).and_then(|s| s.parse::<u64>().ok());
                if iterations_override.is_none() {
                    usage();
                }
            }
            "--help" | "-h" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
        i += 1;
    }
    let Some(scenario) = scenario else {
        usage();
    };

    let iterations = iterations_override.unwrap_or_else(|| scenario.outputs());

    let (ek, dk) = ml_kem_768::KG::try_keygen().expect("ML-KEM-768 keygen");
    let (_ss, ct) = ek.try_encaps().expect("ML-KEM-768 encaps");
    let dk_bytes: [u8; ML_KEM_768_DK_LEN] = dk.into_bytes().try_into().expect("dk length");
    let ct_bytes: [u8; ML_KEM_768_CT_LEN] = ct.into_bytes().try_into().expect("ct length");
    let parsed_dk = MlKemDecapsKey::from_bytes(&dk_bytes).expect("parse decap key");

    // Guaranteed mismatch after decap (dominant scan path): derive the tag for
    // index 0 and use a byte that cannot equal any index's tag for this CT.
    let dk_inner = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes).expect("parse dk inner");
    let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes).expect("parse ciphertext");
    let ss0 = dk_inner.try_decaps(&ct).expect("decap fixture");
    let ss0_bytes: [u8; 32] = ss0.into_bytes();
    let expected0 = derive_view_tag_prefilter(&ss0_bytes, 0);
    let wrong_tag = expected0.wrapping_add(1);

    // Fixed `output_index` — tag derivation cost still includes index in HKDF info;
    // decap dominates; index sweep is not load-bearing for the gate.
    const OUTPUT_INDEX: u64 = 0;

    let progress_every = iterations.min(1_000_000).max(10_000);
    let started = Instant::now();
    for n in 0..iterations {
        let _ =
            ml_kem_decap_prefilter_with_parsed_dk(&parsed_dk, &ct_bytes, wrong_tag, OUTPUT_INDEX)
                .expect_err("wrong tag must reject after decap");
        if n > 0 && n % progress_every == 0 {
            eprintln!(
                "[fa6_gate] progress: {n}/{iterations} ({:.1}%)",
                100.0 * n as f64 / iterations as f64
            );
        }
    }
    let elapsed = started.elapsed();
    let t_meas_secs = elapsed.as_secs_f64();
    let ns_per_output = elapsed.as_nanos() as f64 / iterations as f64;

    let outcome = classify(scenario, t_meas_secs);
    let outcome_str = match outcome {
        GateOutcome::Smoke => "smoke",
        GateOutcome::CleanPass => "clean_pass",
        GateOutcome::MarginalPass => "marginal_pass",
        GateOutcome::Fail => "fail",
    };

    println!("fa6_decap_prefilter_gate");
    println!(
        "scenario={}",
        match scenario {
            Scenario::Smoke => "smoke",
            Scenario::A => "a",
            Scenario::B => "b",
        }
    );
    println!("iterations={iterations}");
    println!("elapsed_secs={t_meas_secs:.6}");
    println!("ns_per_output={ns_per_output:.2}");
    println!("m_margin={M_MARGIN}");
    if !matches!(scenario, Scenario::Smoke) {
        println!("t_ceil_secs={}", scenario.t_ceil_secs());
        println!(
            "t_clean_max_secs={:.6}",
            scenario.t_ceil_secs() * (1.0 - M_MARGIN)
        );
    }
    println!("gate_outcome={outcome_str}");
    println!("spec=FA-6_VIEW_TAG_ML_KEM.md §8.5.1 §8.7");
}
