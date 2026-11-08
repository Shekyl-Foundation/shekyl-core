// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Five-seed pins of the L11 and L13 vector on the abstract purse, on the
//! registered plateau arm (`RewardArm::RegisteredPlateau`).
//!
//! This is the EUP-3 check half's falsifier: the arm reproduces these bits
//! after every incorporation that does not touch the purse
//! (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §6.1).
//!
//! The June sections quoted one seed as a point estimate. These rows are
//! that seed and four others, on the population model as of the check.
//! The bits are exact: the sim is a function of its seed.
//!
//! `c_deep_u` is `committed_deep_under`. The June prose called that
//! figure `deep_und`.

use crate::reward::RewardArm;
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

/// `(bondA, cDeepU, oUmx)` as `f64::to_bits` on [`RewardArm::Production`],
/// the default arm, taken at the EUP-3 check half (2026-11-08). Same layout
/// as [`BITS`].
#[rustfmt::skip]
const BITS_PRODUCTION: [[[u64; 3]; 11]; 5] = [
    [
        [4635279250975275090, 4566758108544739836, 0],
        [4635315842722247475, 4562254508917369340, 0],
        [4635279250975275090, 4566758108544739836, 0],
        [4635279250975275090, 4566758108544739836, 0],
        [4635383865841619217, 4557097432852324608, 0],
        [4634406913109952649, 4587416800807649274, 4589363828969986315],
        [4632916268545789133, 4606909342416356046, ONE],
        [4630753602474728926, ONE, ONE],
        [4626918505917046238, ONE, ONE],
        [4625590882276894310, ONE, ONE],
        [4633985873457289626, 4596238402771233577, ONE],
    ],
    [
        [4634840150011606467, 4592147324659411290, 0],
        [4634781040266497229, 4591803665364768864, 0],
        [4634840150011606467, 4592147324659411290, 0],
        [4634840150011606467, 4592147324659411290, 0],
        [4635302941785814903, 0, 0],
        [4634370555925460855, 4589220552638107079, 4590985262245439308],
        [4632740346685344973, 4606893813203474273, ONE],
        [4630662123107297963, ONE, ONE],
        [4626421233458190746, ONE, ONE],
        [4624812134841328162, ONE, ONE],
        [4634039822827825835, 4594925857001988132, 4600504667628399086],
    ],
    [
        [4634399641673054290, 4593793482025470063, 4600736089921624345],
        [4634448899793978655, 4593237155012677234, 4603120348547879314],
        [4634399641673054290, 4593793482025470063, 4600736089921624345],
        [4634399641673054290, 4593793482025470063, 4600736089921624345],
        [4635335780533097813, 4557605141404812027, 0],
        [4634303705618492075, 4593649018394301840, ONE],
        [4632294677972219767, 4606491692480619966, ONE],
        [4630261021265485278, ONE, ONE],
        [4626496293451980254, ONE, ONE],
        [4624924724832012425, ONE, ONE],
        [4633533167869746654, 4598186963386936502, ONE],
    ],
    [
        [4634344754052595712, 4588263044995334673, 0],
        [4634344754052595712, 4587355232786982824, 0],
        [4634344754052595712, 4588263044995334673, 0],
        [4634344754052595712, 4588263044995334673, 0],
        [4635245473978069811, 4549671586801728227, 0],
        [4634445615919250364, 4586231692640058896, 4590002020221529960],
        [4632472945457469850, 4606862631872387345, ONE],
        [4630561261240643311, ONE, ONE],
        [4626913814667434394, ONE, ONE],
        [4625633103523400909, ONE, ONE],
        [4633549587243388109, 4597011130089663803, ONE],
    ],
    [
        [4635011849747399967, 4578167227600745096, 0],
        [4635045626744605245, 4575861384591531399, 0],
        [4635011849747399967, 4578167227600745096, 0],
        [4635011849747399967, 4578167227600745096, 0],
        [4635404976464872516, 0, 0],
        [4634369383113057894, 4590541312055230405, 4598521650285843377],
        [4632543314201647514, 4606751758735454946, ONE],
        [4630359537507334007, ONE, ONE],
        [4626660487188394803, ONE, ONE],
        [4625253112304841523, ONE, ONE],
        [4633678596607713826, 4597138745815127241, ONE],
    ],
];

const _: () = assert!(SEEDS.len() == BITS.len() && NAMES.len() == BITS[0].len());
const _: () = assert!(SEEDS.len() == BITS_PRODUCTION.len());

#[test]
fn pin_names_are_unique() {
    let mut names = NAMES.to_vec();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), NAMES.len());
}

/// Run every pinned scenario on every seed under `arm` and compare its
/// `(bondA, cDeepU, oUmx)` bits with `bits`. No shock fires on L11 or L13, so
/// no slash burns capital (A18).
fn check_vector(arm: RewardArm, bits: &[[[u64; 3]; 11]; 5]) {
    let built = build_scenarios();
    for (seed_ix, seed) in SEEDS.iter().enumerate() {
        for (name_ix, name) in NAMES.iter().enumerate() {
            let [bond_a, c_deep_u, o_umx] = bits[seed_ix][name_ix];
            let mut cfg = built
                .iter()
                .find(|cfg| cfg.name == *name)
                .unwrap_or_else(|| panic!("missing scenario {name}"))
                .clone();
            cfg.seed = *seed;
            cfg.reward_arm = arm;
            let result = run_sim(&cfg);
            assert_eq!(result.slash_exits, 0, "{name} seed {seed:#x} slash exits");
            assert_eq!(result.slashed_capital, 0.0, "{name} seed {seed:#x} burned");
            assert_eq!(
                result.bonded_active.to_bits(),
                bond_a,
                "{arm:?} {name} seed {seed:#x} bondA"
            );
            assert_eq!(
                result.committed_deep_under.to_bits(),
                c_deep_u,
                "{arm:?} {name} seed {seed:#x} cDeepU"
            );
            assert_eq!(
                result.oldest_under_max.to_bits(),
                o_umx,
                "{arm:?} {name} seed {seed:#x} oUmx"
            );
        }
    }
}

/// The falsifier: the registered arm reproduces the pins.
#[test]
#[ignore = "population pin, five seeds; cargo test -p shekyl-staking-sim --release --bin shekyl-staking-sim -- l11_l13_five_seed --ignored"]
fn l11_l13_five_seed_pins() {
    check_vector(RewardArm::RegisteredPlateau, &BITS);
}

/// The default arm's reading, held so a later change that moves it is seen.
#[test]
#[ignore = "population pin, five seeds; cargo test -p shekyl-staking-sim --release --bin shekyl-staking-sim -- l11_l13_five_seed --ignored"]
fn l11_l13_five_seed_production_pins() {
    check_vector(RewardArm::Production, &BITS_PRODUCTION);
}
