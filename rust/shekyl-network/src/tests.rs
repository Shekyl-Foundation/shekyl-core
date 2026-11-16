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
/// network's table genesis, computed by the stdlib oracle
/// (`scripts/kat/stdlib_cshake.py`). A regenesis that moves a hash fails
/// this until the bytes are re-recorded with it. These are not a second definition of the id; the pin is held
/// where the derivation is.
const RECORDED: [(Network, [u8; 16], [u8; 8]); 4] = [
    (
        Network::Mainnet,
        [
            0xD7, 0xBA, 0xEB, 0x42, 0xD8, 0x38, 0xBA, 0x20, 0xA6, 0xAB, 0xC1, 0xAE, 0x08, 0xE7,
            0x19, 0x33,
        ],
        [0x9F, 0x24, 0x6A, 0x6D, 0xD7, 0xEA, 0xA5, 0x00],
    ),
    (
        Network::Testnet,
        [
            0x73, 0xEB, 0xDF, 0x3C, 0xAD, 0x08, 0x5C, 0x19, 0x78, 0x01, 0x31, 0x82, 0x68, 0x7A,
            0xDE, 0x42,
        ],
        [0x3B, 0x82, 0xEF, 0xC6, 0xC5, 0xF3, 0x28, 0x28],
    ),
    (
        Network::Stagenet,
        [
            0x0A, 0xBD, 0xDF, 0x62, 0xB1, 0x63, 0x65, 0xC0, 0xB9, 0xA0, 0x6A, 0x3A, 0x94, 0xDF,
            0x38, 0xBD,
        ],
        [0xED, 0x59, 0xBB, 0x24, 0x97, 0xE5, 0x51, 0x24],
    ),
    (
        Network::Regtest,
        [
            0xDD, 0x00, 0x7E, 0x2D, 0x53, 0xA3, 0x91, 0x03, 0x2A, 0xF8, 0x5B, 0x8F, 0x09, 0x6D,
            0x5C, 0xAE,
        ],
        [0xC7, 0x5F, 0x32, 0x05, 0x13, 0x62, 0x1B, 0x0C],
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

/// A mint time's pin is decimal seconds and one newline, and every row's
/// compiled time is that pin (`GenesisTimestamp::to_pin` / `from_pin`).
#[test]
fn a_timestamp_pin_round_trips() {
    let stamp = crate::GenesisTimestamp::new(1_794_760_828).expect("a mint time");
    assert_eq!(stamp.to_pin(), "1794760828\n");
    assert_eq!(
        crate::GenesisTimestamp::from_pin("1794760828\n"),
        Some(stamp)
    );
    assert_eq!(crate::GenesisTimestamp::from_pin("1794760828"), Some(stamp));
    assert_eq!(crate::GenesisTimestamp::new(0), None);
    let max = crate::GenesisTimestamp::new(u64::MAX).expect("u64::MAX is not zero");
    assert_eq!(crate::GenesisTimestamp::from_pin(&max.to_pin()), Some(max));
    for net in Network::ALL {
        let row = net.genesis().timestamp();
        assert_eq!(
            crate::GenesisTimestamp::from_pin(&row.to_pin()),
            Some(row),
            "{net}"
        );
    }
}

/// One reading refuses a pin that is zero, padded, empty, signed, not
/// decimal, or too wide for a `u64`.
#[test]
fn a_malformed_timestamp_pin_is_refused() {
    for text in [
        "0\n",
        "0",
        "01794760828\n",
        "",
        "\n",
        "-1\n",
        "+1\n",
        "17947608a8\n",
        "1794760828\n\n",
        "1794760828\r\n",
        "99999999999999999999\n",
    ] {
        assert!(
            crate::GenesisTimestamp::from_pin(text).is_none(),
            "{text:?} was accepted"
        );
    }
}
