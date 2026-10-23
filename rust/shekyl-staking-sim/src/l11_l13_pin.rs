// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Five-seed pins of the L11 and L13 vector on the abstract purse.
//!
//! The June sections quoted one seed as a point estimate. These rows are
//! that seed and four others, on the population model as of the check.
//! The bits are exact: the sim is a function of its seed.
//!
//! `c_deep_u` is `committed_deep_under`. The June prose called that
//! figure `deep_und`.

use crate::scenarios::{build_scenarios, run_sim};

const SEEDS: [u64; 5] = [
    0x5EED_1234,
    0x1111_1111,
    0x2222_2222,
    0xA5A5_A5A5,
    0x00FF_00FF,
];

/// Row order of [`BITS`]. One column, shared by every seed.
const NAMES: [&str; 11] = [
    "l11_fill",
    "l11_trim",
    "l11_rho_r02",
    "l11_bud_b100",
    "l13_decay_hi",
    "l13_decay_knee",
    "l13_decay_mid",
    "l13_decay_lo",
    "l13_decay_min",
    "l13_spiral",
    "l13_servo",
];

/// Saturated cell. `1.0` as `f64::to_bits`.
const ONE: u64 = 1.0f64.to_bits();

/// `(bondA, cDeepU, oUmx)` as `f64::to_bits`.
///
/// Outer index is [`SEEDS`]. Inner index is [`NAMES`]. One row is one
/// scenario, so the three cells stay on one line.
#[rustfmt::skip]
const BITS: [[[u64; 3]; 11]; 5] = [
    [
        [4635677538067320668, 4588279309964067648, 4604241292512755043],
        [4635514282580828488, 4593515495130823741, ONE],
        [4635677538067320668, 4588279309964067648, 4604241292512755043],
        [4635677538067320668, 4588279309964067648, 4604241292512755043],
        [4635407322089678438, 4587596984469051649, 4603054119141594453],
        [4634481973103742157, 4592934703680519209, 4599461962295953701],
        [4632702816688450219, 4607089620881801507, ONE],
        [4630497929370883413, ONE, ONE],
        [4626552588447322385, ONE, ONE],
        [4625361011045913941, ONE, ONE],
        [4633943652210783027, 4595921651990973028, ONE],
    ],
    [
        [4634429196545608909, 4595647660862099866, 4590315996666139668],
        [4634343346677712159, 4595353887594099087, 0],
        [4634429196545608909, 4595647660862099866, 4590315996666139668],
        [4634429196545608909, 4595647660862099866, 4590315996666139668],
        [4635523430517571584, 4582894689628726517, 4605708513467423427],
        [4634418641233982259, 4595329477015480505, 4600194074550649397],
        [4632475291082275772, 4606957283752887883, ONE],
        [4630211763144560913, ONE, ONE],
        [4626022477241183983, ONE, ONE],
        [4624249184887906850, ONE, ONE],
        [4633908467838694195, 4595633451925725228, 4604636905967155823],
    ],
    [
        [4634082982324254802, 4598864005370638961, 4605946136549366684],
        [4634409493297239163, 4598561999277980001, ONE],
        [4634082982324254802, 4598864005370638961, 4605946136549366684],
        [4634082982324254802, 4598864005370638961, 4605946136549366684],
        [4635151648985832926, 4590746038978003651, ONE],
        [4634164140942539708, 4593469029533764589, ONE],
        [4631938143001719603, 4606559425708530434, ONE],
        [4629937325042268023, ONE, ONE],
        [4626078772236526114, ONE, ONE],
        [4624314862382472670, ONE, ONE],
        [4633467490375180834, 4597902520173332399, ONE],
    ],
    [
        [4633756471351270441, 4595931221242756689, 4594710912139606804],
        [4634265941059116728, 4600414962478069491, ONE],
        [4633756471351270441, 4595931221242756689, 4594710912139606804],
        [4633756471351270441, 4595931221242756689, 4594710912139606804],
        [4635218499292801707, 4585854941007012094, ONE],
        [4634164140942539708, 4595921724591340684, 4604521200838389388],
        [4632268876099354624, 4606852837174753780, ONE],
        [4630146085649995093, ONE, ONE],
        [4626482219703144721, ONE, ONE],
        [4625337554797854720, ONE, ONE],
        [4633333789761243273, 4598264366446029135, ONE],
    ],
    [
        [4635020293996701286, 4596583947676938842, ONE],
        [4635138513486919762, 4594470258251826289, ONE],
        [4635020293996701286, 4596583947676938842, ONE],
        [4635020293996701286, 4596583947676938842, ONE],
        [4635489418957885713, 4579884532649699682, 4602187517395115585],
        [4634460862480488858, 4592323074050699050, 4603157925515984199],
        [4632322825469890833, 4606864117862291132, ONE],
        [4630122629401935872, ONE, ONE],
        [4626266422220999885, ONE, ONE],
        [4624708927349867588, ONE, ONE],
        [4633777112849562556, 4597080788767202305, ONE],
    ],
];

const _: () = assert!(SEEDS.len() == BITS.len() && NAMES.len() == BITS[0].len());

#[test]
fn pin_names_are_unique() {
    let mut names = NAMES.to_vec();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), NAMES.len());
}

#[test]
#[ignore = "population pin, five seeds; cargo test -p shekyl-staking-sim --release --bin shekyl-staking-sim -- l11_l13_five_seed_pins --ignored"]
fn l11_l13_five_seed_pins() {
    let built = build_scenarios();
    for (seed_ix, seed) in SEEDS.iter().enumerate() {
        for (name_ix, name) in NAMES.iter().enumerate() {
            let [bond_a, c_deep_u, o_umx] = BITS[seed_ix][name_ix];
            let mut cfg = built
                .iter()
                .find(|cfg| cfg.name == *name)
                .unwrap_or_else(|| panic!("missing scenario {name}"))
                .clone();
            cfg.seed = *seed;
            let result = run_sim(&cfg);
            assert_eq!(
                result.bonded_active.to_bits(),
                bond_a,
                "{name} seed {seed:#x} bondA"
            );
            assert_eq!(
                result.committed_deep_under.to_bits(),
                c_deep_u,
                "{name} seed {seed:#x} cDeepU"
            );
            assert_eq!(
                result.oldest_under_max.to_bits(),
                o_umx,
                "{name} seed {seed:#x} oUmx"
            );
        }
    }
}
