// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Five-seed pins of the L11 and L13 vector on the abstract purse, on the
//! registered arm (`RewardArm::RegisteredPlateau`): the plateau, deep shards
//! only bonded, a flat carry per bonded shard, and an exit refunded at once,
//! the configuration the published figures were taken on
//! (`SimConfig::arm_defaults`).
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
/// the default arm: production's reward, every held shard bonded, the split
/// carry, and the exit's release cooldown (ruled 2026-11-08, P7 and P8 in
/// `STAKER_ARCHIVAL_SIM.md`). Same layout as [`BITS`].
#[rustfmt::skip]
const BITS_PRODUCTION: [[[u64; 3]; 11]; 5] = [
    [
        [4635657834818950922, 4601712046452638045, ONE],
        [4635919606547291832, 4600216851376351040, ONE],
        [4635657834818950922, 4601712046452638045, ONE],
        [4635657834818950922, 4601712046452638045, ONE],
        [4636053541723709986, 4598438960064822281, ONE],
        [4634887766195166686, 4604849233277293034, ONE],
        [4633148485401575424, ONE, ONE],
        [4630760639349146692, ONE, ONE],
        [4626801224676750131, ONE, ONE],
        [4624089682401104145, ONE, ONE],
        [4633303296638766285, ONE, ONE],
    ],
    [
        [4635735240437546353, 4602337931323929020, ONE],
        [4635930865546360259, 4601564697910983566, ONE],
        [4635735240437546353, 4602337931323929020, ONE],
        [4635735240437546353, 4602337931323929020, ONE],
        [4636229463584154146, 4595913121482687468, ONE],
        [4634866655571913387, 4604699445220051923, ONE],
        [4633183669773664256, ONE, ONE],
        [4630751256849923004, ONE, ONE],
        [4626960727163552836, ONE, ONE],
        [4623517349948459145, ONE, ONE],
        [4633408849755032781, 4607179355126801509, ONE],
    ],
    [
        [4635780276433820058, 4602125141336105480, ONE],
        [4635760573185450312, 4602432445781267233, ONE],
        [4635780276433820058, 4602125141336105480, ONE],
        [4635780276433820058, 4602125141336105480, ONE],
        [4635952679857055334, 4599237593129486947, ONE],
        [4634851409010674893, 4604887072320425426, ONE],
        [4632937379169042432, ONE, ONE],
        [4630732491851475627, ONE, ONE],
        [4627002948410059435, ONE, ONE],
        [4624164742394893653, ONE, ONE],
        [4633392430381391326, ONE, ONE],
    ],
    [
        [4636065973535181373, 4600173824860226030, ONE],
        [4635731018312895693, 4601958243232267631, ONE],
        [4636065973535181373, 4600173824860226030, ONE],
        [4636065973535181373, 4600173824860226030, ONE],
        [4635694661128403900, 4601329866647131328, ONE],
        [4634983936812209493, 4604605963777784502, ONE],
        [4633071079782979994, ONE, ONE],
        [4630781749972399991, ONE, ONE],
        [4626838754673644885, ONE, ONE],
        [4623667469936038161, ONE, ONE],
        [4633249347268230076, ONE, ONE],
    ],
    [
        [4635653612694300262, 4601375777680461048, ONE],
        [4635778869058936504, 4600856362523437651, ONE],
        [4635653612694300262, 4601375777680461048, ONE],
        [4635653612694300262, 4601375777680461048, ONE],
        [4636021875788830037, 4598945371914051919, ONE],
        [4634872519633928192, 4605061146899156859, ONE],
        [4633007747913220096, ONE, ONE],
        [4630788786846817758, ONE, ONE],
        [4626956035913940992, ONE, ONE],
        [4623639322438367095, ONE, ONE],
        [4633436997252703846, ONE, ONE],
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
/// A change that moves it writes its prediction in `STAKER_ARCHIVAL_SIM.md`
/// before it re-pins.
#[test]
#[ignore = "population pin, five seeds; cargo test -p shekyl-staking-sim --release --bin shekyl-staking-sim -- l11_l13_five_seed --ignored"]
fn l11_l13_five_seed_production_pins() {
    check_vector(RewardArm::Production, &BITS_PRODUCTION);
}
