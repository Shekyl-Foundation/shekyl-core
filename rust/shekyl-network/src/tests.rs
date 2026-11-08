// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::collections::HashSet;

use super::*;

#[test]
fn each_row_is_its_own_network_and_codes_round_trip() {
    for (i, n) in Network::ALL.into_iter().enumerate() {
        assert_eq!(n.row().network, n);
        assert_eq!(usize::from(n.code()), i);
        assert_eq!(Network::from_code(n.code()), Some(n));
        assert_eq!(Network::from_name(n.name()), Some(n));
        assert_eq!(n.name().parse::<Network>(), Ok(n));
        assert_eq!(n.to_string(), n.name());
    }
    assert_eq!(Network::from_code(4), None);
}

#[test]
fn a_network_has_one_spelling() {
    for word in ["fakechain", "Mainnet", "MAINNET", "regtest ", "main"] {
        assert_eq!(Network::from_name(word), None, "{word:?}");
        assert!(word.parse::<Network>().is_err(), "{word:?}");
    }
}

#[test]
fn the_tag_is_shekyl_slash_the_name() {
    for n in Network::ALL {
        assert_eq!(n.tag(), format!("shekyl/{}", n.name()));
    }
}

/// NI-Q3 test (b), the half that needs no genesis: names, tags, ports,
/// subdirectories and every address prefix are pairwise distinct across
/// networks. The genesis hash, id and wire prefix join it with the pins.
#[test]
fn every_identifying_value_is_pairwise_distinct() {
    let mut names = HashSet::new();
    let mut tags = HashSet::new();
    let mut ports = HashSet::new();
    let mut dirs = HashSet::new();
    let mut prefixes = HashSet::new();
    for n in Network::ALL {
        assert!(names.insert(n.name()), "{n}: name");
        assert!(tags.insert(n.tag()), "{n}: tag");
        assert!(ports.insert(n.ports().p2p), "{n}: p2p port");
        assert!(ports.insert(n.ports().rpc), "{n}: rpc port");
        assert!(dirs.insert(n.subdirectory()), "{n}: subdirectory");
        for p in n.prefixes().all() {
            assert!(prefixes.insert(p), "{n}: prefix {p}");
        }
    }
}

/// NI-R6's invariant: `permits` is empty on every row but regtest's.
#[test]
fn only_regtest_permits_levers() {
    for n in Network::ALL {
        let expected = n == Network::Regtest;
        for lever in Lever::ALL {
            assert_eq!(n.permits(lever), expected, "{n}: {lever:?}");
        }
    }
}

/// NI-R9: staging flags are accepted on the test networks only, and each
/// has an owner, an exit and a deadline release the release gate can read.
#[test]
fn staging_is_the_test_networks_and_never_mainnets() {
    for flag in Staging::ALL {
        assert!(!Network::Mainnet.stages(flag), "{flag:?}");
        for n in [Network::Testnet, Network::Stagenet, Network::Regtest] {
            assert!(n.stages(flag), "{n}: {flag:?}");
        }
        assert!(!flag.owner().is_empty() && !flag.exit().is_empty());
        let deadline = flag.deadline();
        let core = deadline
            .strip_prefix('v')
            .and_then(|v| v.split('-').next())
            .unwrap_or_else(|| panic!("{flag:?}: {deadline} is not vMAJOR.MINOR.PATCH[-pre]"));
        let parts: Vec<&str> = core.split('.').collect();
        assert!(
            parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok()),
            "{flag:?}: {deadline} is not vMAJOR.MINOR.PATCH[-pre]"
        );
    }
}

#[cfg(feature = "serde")]
#[test]
fn serde_spells_the_name() {
    for n in Network::ALL {
        let text = serde_json::to_string(&n).unwrap();
        assert_eq!(text, format!("\"{}\"", n.name()));
        assert_eq!(serde_json::from_str::<Network>(&text).unwrap(), n);
    }
    assert!(serde_json::from_str::<Network>("\"fakechain\"").is_err());
}

#[test]
fn the_id_is_a_function_of_the_genesis_hash() {
    let a = [1u8; 32];
    let mut b = a;
    b[31] = 2;
    let id_a = network_id_from_genesis(&a);
    assert_eq!(id_a, network_id_from_genesis(&a));
    assert_ne!(id_a, network_id_from_genesis(&b));
    assert_ne!(prefix_for(&id_a), prefix_for(&network_id_from_genesis(&b)));
}

/// Recorded output of [`Network::network_id`] and [`prefix_for`] over each
/// network's table genesis. Re-recorded with the signing envelope's
/// regenesis (`NETWORK_IDENTITY.md` §2.4.1): the genesis transaction key is
/// derived under the network's `name_id`, so every id and prefix moved. A
/// regenesis that moves a hash fails this until the bytes are re-recorded
/// with it. These are not a second definition of the id; the pin is held
/// where the derivation is.
const RECORDED: [(Network, [u8; 16], [u8; 8]); 4] = [
    (
        Network::Mainnet,
        [
            0x9E, 0x77, 0xDD, 0x8E, 0xF6, 0x4F, 0xAE, 0xF2, 0xC4, 0x3C, 0x42, 0xB1, 0xCF, 0x5B,
            0xC5, 0x54,
        ],
        [0x6A, 0xEE, 0x8B, 0x20, 0x26, 0x94, 0xAA, 0xA4],
    ),
    (
        Network::Testnet,
        [
            0x4E, 0x94, 0x8C, 0xF2, 0x48, 0x14, 0x73, 0xD8, 0x94, 0x9D, 0xA6, 0x45, 0x69, 0x24,
            0x64, 0xDE,
        ],
        [0xA3, 0x2D, 0x47, 0x0A, 0x0E, 0xF9, 0x45, 0x7E],
    ),
    (
        Network::Stagenet,
        [
            0x3A, 0x6B, 0x9B, 0x9F, 0xF5, 0xB7, 0x32, 0x7C, 0xB4, 0x4B, 0x19, 0x2C, 0xC1, 0xD9,
            0x8E, 0xC8,
        ],
        [0x5E, 0xAF, 0x7F, 0x64, 0xCE, 0xFF, 0x6F, 0x5B],
    ),
    (
        Network::Regtest,
        [
            0x39, 0x90, 0x64, 0x29, 0x84, 0x36, 0xB7, 0x6E, 0x73, 0x49, 0xDF, 0x0A, 0x18, 0xCF,
            0xBA, 0xDF,
        ],
        [0xCB, 0x51, 0xD2, 0xBD, 0x58, 0xBB, 0x9A, 0x64],
    ),
];

/// Every network, regtest included, derives its own recorded id from its
/// own genesis (NI-Q8: regtest's id is not mainnet's).
#[test]
fn each_genesis_derives_its_recorded_id_and_prefix() {
    assert_eq!(RECORDED.len(), Network::ALL.len());
    for (net, id_kat, prefix_kat) in RECORDED {
        let id = net.network_id();
        assert_eq!(id, network_id_from_genesis(&net.genesis().hash()), "{net}");
        assert_eq!(id, id_kat, "{net}");
        assert_eq!(prefix_for(&id), prefix_kat, "{net}");
    }
}

/// A permit exists exactly where the row permits the lever, and names it.
#[test]
fn a_permit_is_the_rows_permission() {
    for net in Network::ALL {
        for lever in Lever::ALL {
            assert_eq!(
                net.permit(lever).map(Permit::lever),
                net.permits(lever).then_some(lever),
                "{net} {lever:?}"
            );
        }
    }
}

/// The seeds are the row's: mainnet and testnet share six hosts, testnet
/// pairs each with its onion, and stagenet and regtest have none.
#[test]
fn the_seed_lists_are_the_rows() {
    let main = Network::Mainnet.seeds();
    let test = Network::Testnet.seeds();
    assert_eq!(main.len(), 6);
    assert_eq!(test.len(), 6);
    for (m, t) in main.iter().zip(test) {
        assert_eq!((m.ipv4, m.place), (t.ipv4, t.place));
        assert_eq!(m.onion, None);
        let onion = t.onion.expect("testnet pairs each host with its onion");
        assert!(onion.ends_with(".onion") && onion.len() == 62, "{onion}");
    }
    let mut places: Vec<_> = main.iter().map(|s| s.place).collect();
    places.sort_unstable();
    places.dedup();
    assert_eq!(places.len(), 6, "six distinct hosts");
    assert!(Network::Stagenet.seeds().is_empty());
    assert!(Network::Regtest.seeds().is_empty());
}

/// No network's row has the harness id, so a harness signature never
/// verifies on a real network.
#[test]
fn no_row_has_the_harness_id() {
    for net in Network::ALL {
        assert_ne!(net.network_id(), HARNESS_NETWORK_ID, "{net}");
    }
}

/// `name_id` is the tag's cSHAKE256 under `shekyl/network-name-v1`, first
/// 16 bytes, on every network (the signing envelope §2.6); the four
/// constants are distinct. The values are the stdlib oracle's
/// (`scripts/kat/stdlib_cshake.py`, anchored on NIST SP 800-185's samples).
#[test]
fn the_name_id_is_the_tags_cshake() {
    let pinned = [
        (Network::Mainnet, "5e6f51beafca4a33dbc98267574fc1c8"),
        (Network::Testnet, "866a986774ba359c8950f938e8deb30a"),
        (Network::Stagenet, "fd3a11446a2937826860949474456312"),
        (Network::Regtest, "4b22be743ef0c275c6f9b05bb44ff33f"),
    ];
    for (net, hex) in pinned {
        let derived = shekyl_crypto_hash::cshake256_32(NETWORK_NAME_DST, net.tag().as_bytes());
        assert_eq!(
            net.name_id().as_bytes()[..],
            derived[..16],
            "{net}: the constant is the derivation"
        );
        let shown: String = net
            .name_id()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(shown, hex, "{net}: the oracle's value");
    }
    for (i, a) in Network::ALL.iter().enumerate() {
        for b in &Network::ALL[i + 1..] {
            assert_ne!(a.name_id(), b.name_id(), "{a} and {b}");
        }
    }
}
