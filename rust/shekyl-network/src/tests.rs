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
