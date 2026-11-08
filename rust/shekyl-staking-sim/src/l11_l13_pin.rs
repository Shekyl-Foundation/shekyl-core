// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Five-seed pins of the L11 and L13 vector on the abstract purse, on the
//! registered arm (`RewardArm::RegisteredPlateau`): the plateau, deep shards
//! only bonded, and a flat carry per bonded shard, the configuration the
//! published figures were taken on (`SimConfig::arm_defaults`).
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
/// the default arm: production's reward, every held shard bonded, and the
/// split carry (ruled 2026-11-08, P7 in `STAKER_ARCHIVAL_SIM.md`). Same
/// layout as [`BITS`].
#[rustfmt::skip]
const BITS_PRODUCTION: [[[u64; 3]; 11]; 5] = [
    [
        [4635785905933354271, 4601243672091391514, ONE],
        [4635975901542633964, 4600213848976599461, ONE],
        [4635785905933354271, 4601243672091391514, ONE],
        [4635785905933354271, 4601243672091391514, ONE],
        [4635916322672563541, 4599483481934044724, ONE],
        [4634758756830840969, 4605097785617215553, ONE],
        [4632878738548894379, ONE, ONE],
        [4630784095597205914, ONE, ONE],
        [4627059243405401566, ONE, ONE],
        [4624202272391788407, ONE, ONE],
        [4633500329122463744, ONE, ONE],
    ],
    [
        [4636025159663558328, 4601107409333435176, ONE],
        [4635959013044031324, 4601262610305209171, ONE],
        [4636025159663558328, 4601107409333435176, ONE],
        [4636025159663558328, 4601107409333435176, ONE],
        [4636074652346963285, 4598472855027059678, ONE],
        [4634947579627717700, 4604689745271963802, ONE],
        [4633052314784532617, ONE, ONE],
        [4630798169346041446, ONE, ONE],
        [4627049860906177877, ONE, ONE],
        [4624230419889459473, ONE, ONE],
        [4633404158505420937, 4607144835392311133, ONE],
    ],
    [
        [4635783091183587164, 4602718556816417827, ONE],
        [4635995604791003709, 4600811149915413853, ONE],
        [4635783091183587164, 4602718556816417827, ONE],
        [4635783091183587164, 4602718556816417827, ONE],
        [4636024221413635959, 4599093707817548165, ONE],
        [4634973381500582844, 4604830572987588188, ONE],
        [4633127374778322125, 4607161206193076895, ONE],
        [4630765330598758537, ONE, ONE],
        [4627012330909283123, ONE, ONE],
        [4624202272391788407, ONE, ONE],
        [4633380702257361715, 4607146541924734345, ONE],
    ],
    [
        [4635943531920312238, 4601163907549959764, ONE],
        [4635884422175203000, 4601788028443201660, ONE],
        [4635943531920312238, 4601163907549959764, ONE],
        [4635943531920312238, 4601163907549959764, ONE],
        [4635655958319106185, 4601222245770911839, ONE],
        [4634881902133151881, 4604790643059761683, ONE],
        [4633059351658950383, ONE, ONE],
        [4630784095597205914, ONE, ONE],
        [4627040478406954189, ONE, ONE],
        [4624221037390235785, ONE, ONE],
        [4633331444136437350, ONE, ONE],
    ],
    [
        [4635939309795661578, 4600279901771134228, ONE],
        [4636065973535181373, 4598976860278948365, ONE],
        [4635939309795661578, 4600279901771134228, ONE],
        [4635939309795661578, 4600279901771134228, ONE],
        [4635996073915964894, 4599117309478368898, ONE],
        [4634784558703706112, 4605145632799316505, ONE],
        [4633049969159726694, 4607155397202253185, ONE],
        [4630755948099534848, ONE, ONE],
        [4627002948410059435, ONE, ONE],
        [4624202272391788407, ONE, ONE],
        [4633125029153516203, ONE, ONE],
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
