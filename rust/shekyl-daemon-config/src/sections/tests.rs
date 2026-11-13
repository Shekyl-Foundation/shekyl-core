// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use shekyl_options::{Code, Diagnostic, Source, Value};

use super::{
    build, link_limits, log_location_writable, read_ban_file, Ban, Clearnet, DaemonConfig, Onion,
    Socks, SocksCredential, Tor,
};
use crate::network::Network;
use crate::platform::{Platform, RunMode};
use crate::resolve::{choosers, resolve};
use crate::table::TABLE;

/// A fixture path that is absolute on the host running the test: `unix`
/// as written on Unix, `C:` and backslashes on Windows, where `/srv/op` is
/// not absolute and the path kinds refuse it (DC-F40). A TOML fixture
/// quotes the result with `'…'`, the literal string, so the backslashes
/// are not escapes.
fn abs(unix: &str) -> String {
    if cfg!(windows) {
        format!("C:{}", unix.replace('/', "\\"))
    } else {
        unix.to_owned()
    }
}

/// The per-account root under the fixture home: `Shekyl` on Windows,
/// `.shekyl` elsewhere (IG-13).
fn home_root() -> PathBuf {
    PathBuf::from(abs("/srv/op")).join(if cfg!(windows) { "Shekyl" } else { ".shekyl" })
}

fn platform() -> Platform {
    Platform {
        home: Some(PathBuf::from(abs("/srv/op"))),
        program_data: None,
        session_dir: None,
    }
}

fn build_from(cli: &[&str], file: &str) -> Result<DaemonConfig, Vec<Diagnostic>> {
    let args: Vec<OsString> = cli.iter().map(OsString::from).collect();
    let cli = shekyl_options::read_cli(&TABLE, args)?;
    let (network, mode) = choosers(&cli);
    let given = shekyl_options::read_file(&TABLE, Path::new("/etc/shekyl/x.toml"), file)?;
    let mut resolved = resolve(&TABLE, network, cli, given)?;
    build(&mut resolved, network, mode, &platform(), None)
}

fn codes(r: Result<DaemonConfig, Vec<Diagnostic>>) -> Vec<(Code, String)> {
    r.expect_err("expected refusals")
        .into_iter()
        .map(|d| (d.code, d.option.unwrap_or_default()))
        .collect()
}

#[test]
fn the_defaults_build_a_managed_tor_clearnet_node_on_mainnet() {
    let c = build_from(&[], "").unwrap();
    assert_eq!(c.network, Network::Mainnet);
    assert_eq!(c.data_dir, home_root());
    assert_eq!(
        c.logging.file,
        home_root().join("logs").join("shekyld-mainnet.log")
    );
    assert_eq!(c.logging.directive().as_str(), "warn");
    assert_eq!(c.tor, Tor::Managed { binary: None });
    assert!(
        matches!(&c.clearnet, Clearnet::On { listen, socks: None, advertise } if listen.len() == 1 && listen[0].port() == 11021 && advertise.is_empty())
    );
    assert_eq!(c.rpc.admin_listen, vec!["127.0.0.1:11029".parse().unwrap()]);
    assert!(c.rpc.view_listen.is_empty());
    assert_eq!(c.rpc.connections_max.get(), 25);
    assert_eq!(c.p2p.upload_max, None);
    assert!(c.dev.sync);
    assert!(!c.offline());
}

#[test]
fn explicit_paths_are_taken_as_given_and_defaults_follow_the_network() {
    let c = build_from(
        &["--network", "testnet", "--data-dir", &abs("/srv/chain")],
        &format!("log-file = '{}'\n", abs("/var/log/s.log")),
    )
    .unwrap();
    assert_eq!(c.data_dir, PathBuf::from(abs("/srv/chain")));
    assert_eq!(c.logging.file, PathBuf::from(abs("/var/log/s.log")));
    assert!(matches!(&c.clearnet, Clearnet::On { listen, .. } if listen[0].port() == 12021));
    assert_eq!(c.rpc.admin_listen[0].port(), 12029);
}

#[test]
fn no_home_refuses_each_path_that_needs_it_and_not_an_explicit_one() {
    let args: Vec<OsString> = ["--data-dir", &abs("/srv/chain")]
        .iter()
        .map(OsString::from)
        .collect();
    let cli = shekyl_options::read_cli(&TABLE, args).unwrap();
    let mut resolved = resolve(&TABLE, Network::Mainnet, cli, Vec::new()).unwrap();
    let d = build(
        &mut resolved,
        Network::Mainnet,
        RunMode::User,
        &Platform::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(d.len(), 1);
    assert_eq!(
        (d[0].code, d[0].option.as_deref()),
        (Code::PathNoHome, Some("log-file"))
    );
}

#[test]
fn an_operator_tor_needs_its_socks_and_an_onion_needs_its_listener() {
    assert_eq!(
        codes(build_from(&["--tor", "operator"], "")),
        vec![(Code::ValueRequires, "tor".into())]
    );
    let c = build_from(&["--tor", "operator", "--tor-socks", "127.0.0.1:9050"], "").unwrap();
    assert!(matches!(c.tor, Tor::Operator { onion: None, .. }));
    let host = shekyl_onion_v3_hostname();
    let d = codes(build_from(
        &[
            "--tor",
            "operator",
            "--tor-socks",
            "127.0.0.1:9050",
            "--tor-onion",
            &format!("{host}:11021"),
        ],
        "",
    ));
    assert_eq!(d, vec![(Code::ValueRequires, "tor-onion".into())]);
    let c = build_from(
        &[
            "--tor",
            "operator",
            "--tor-socks",
            "127.0.0.1:9050",
            "--tor-onion",
            &format!("{host}:11021"),
            "--tor-onion-listen",
            "127.0.0.1:41021",
        ],
        "",
    )
    .unwrap();
    assert!(matches!(
        c.tor,
        Tor::Operator {
            onion: Some(Onion {
                virtual_port: 11021,
                ..
            }),
            ..
        }
    ));
}

/// A valid v3 onion: the Ed25519 base point's hostname.
fn shekyl_onion_v3_hostname() -> String {
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    shekyl_onion_v3::v3_onion_hostname(&b)
}

#[test]
fn a_connector_that_is_off_cannot_carry_its_endpoints_or_its_peers() {
    let d = codes(build_from(
        &["--tor", "off", "--tor-socks", "127.0.0.1:9050"],
        "",
    ));
    assert_eq!(d, vec![(Code::ValueConflict, "tor-socks".into())]);
    let d = codes(build_from(
        &["--clearnet", "off", "--clearnet-listen", "0.0.0.0:11021"],
        "",
    ));
    assert_eq!(d, vec![(Code::ValueConflict, "clearnet-listen".into())]);
    let d = codes(build_from(
        &["--clearnet", "off", "--p2p-peer", "8.8.8.8:11021"],
        "",
    ));
    assert_eq!(d, vec![(Code::ValueConflict, "p2p-peer".into())]);
    let d = codes(build_from(
        &["--tor-file", &abs("/opt/tor"), "--tor", "off"],
        "",
    ));
    assert_eq!(d, vec![(Code::ValueConflict, "tor-file".into())]);
    let c = build_from(&["--clearnet", "off", "--tor", "off"], "").unwrap();
    assert!(c.offline());
}

#[test]
fn socks_credentials_need_each_other_and_their_endpoint() {
    let d = codes(build_from(
        &["--clearnet-socks", "127.0.0.1:1080"],
        "clearnet-socks-username = \"u\"\n",
    ));
    assert_eq!(
        d,
        vec![(Code::ValueRequires, "clearnet-socks-username".into())],
        "a username names the password it needs"
    );
    let d = codes(build_from(
        &["--clearnet-socks", "127.0.0.1:1080"],
        "clearnet-socks-password = \"p\"\n",
    ));
    assert_eq!(
        d,
        vec![(Code::ValueRequires, "clearnet-socks-password".into())]
    );
    let d = codes(build_from(
        &[],
        "clearnet-socks-username = \"u\"\nclearnet-socks-password = \"p\"\n",
    ));
    assert_eq!(
        d,
        vec![
            (Code::ValueRequires, "clearnet-socks-username".into()),
            (Code::ValueRequires, "clearnet-socks-password".into())
        ],
        "a pair without its proxy names the proxy"
    );
    let c = build_from(&["--clearnet-socks", "127.0.0.1:1080"], "").unwrap();
    assert!(matches!(
        c.clearnet,
        Clearnet::On {
            socks: Some(Socks { endpoint, credential: None }),
            ..
        } if endpoint.port() == 1080
    ));
}

#[test]
fn a_socks_pair_is_carried_to_its_proxy_and_never_shown() {
    let c = build_from(
        &["--clearnet-socks", "127.0.0.1:1080"],
        "clearnet-socks-username = \"u\"\nclearnet-socks-password = \"hunter2\"\n",
    )
    .unwrap();
    let Clearnet::On {
        socks: Some(Socks {
            credential: Some(credential),
            ..
        }),
        ..
    } = &c.clearnet
    else {
        panic!("the clearnet proxy carries its pair: {:?}", c.clearnet);
    };
    assert_eq!(credential.username(), b"u");
    assert_eq!(credential.password(), b"hunter2");
    assert!(
        !format!("{c:?}").contains("hunter2"),
        "the configuration's Debug shows no secret"
    );
    let c = build_from(
        &["--tor", "operator", "--tor-socks", "127.0.0.1:9050"],
        "tor-socks-username = \"op\"\ntor-socks-password = \"pw\"\n",
    )
    .unwrap();
    assert!(matches!(
        &c.tor,
        Tor::Operator {
            socks: Socks { credential: Some(credential), .. },
            ..
        } if credential.username() == b"op" && credential.password() == b"pw"
    ));
}

#[test]
fn a_socks_pair_is_one_to_255_bytes_each_as_rfc_1929_carries_it() {
    // Empty: the grammar refuses an empty secret before the sections read it.
    let d = codes(build_from(
        &["--clearnet-socks", "127.0.0.1:1080"],
        "clearnet-socks-username = \"\"\nclearnet-socks-password = \"p\"\n",
    ));
    assert_eq!(
        d,
        vec![(Code::ValueSyntax, "clearnet-socks-username".into())]
    );
    // Longer than RFC 1929's one-byte length can carry.
    let long = "x".repeat(SocksCredential::MAX_BYTES + 1);
    let d = build_from(
        &["--clearnet-socks", "127.0.0.1:1080"],
        &format!("clearnet-socks-username = \"{long}\"\nclearnet-socks-password = \"{long}\"\n"),
    )
    .unwrap_err();
    let found: Vec<(Code, String)> = d
        .iter()
        .map(|d| (d.code, d.option.clone().unwrap_or_default()))
        .collect();
    assert_eq!(
        found,
        vec![
            (Code::ValueRange, "clearnet-socks-username".into()),
            (Code::ValueRange, "clearnet-socks-password".into())
        ]
    );
    assert!(
        !format!("{d:?}").contains(&long),
        "a refusal never prints the secret"
    );
    let most = "x".repeat(SocksCredential::MAX_BYTES);
    assert!(build_from(
        &["--clearnet-socks", "127.0.0.1:1080"],
        &format!("clearnet-socks-username = \"{most}\"\nclearnet-socks-password = \"{most}\"\n"),
    )
    .is_ok());
}

#[test]
fn advertise_takes_one_endpoint_per_family() {
    let d = codes(build_from(
        &[
            "--clearnet-advertise",
            "8.8.8.8:1",
            "--clearnet-advertise",
            "9.9.9.9:1",
        ],
        "",
    ));
    assert_eq!(d, vec![(Code::ValueRange, "clearnet-advertise".into())]);
    assert!(build_from(
        &[
            "--clearnet-advertise",
            "8.8.8.8:1",
            "--clearnet-advertise",
            "[2a01:4f8::1]:1"
        ],
        ""
    )
    .is_ok());
}

#[test]
fn a_mining_address_is_checked_against_the_network() {
    let d = codes(build_from(&["--mine-address", "shekyl1notanaddress"], ""));
    assert_eq!(d, vec![(Code::ValueSyntax, "mine-address".into())]);
}

#[test]
fn log_categories_become_the_owners_directive() {
    let c = build_from(
        &[
            "--log-level",
            "info",
            "--log-category",
            "p2p=debug",
            "--log-category",
            "rpc=trace",
        ],
        "",
    )
    .unwrap();
    let d = c.logging.directive();
    assert!(d.as_str().starts_with("info,"), "{d}");
    assert!(
        d.as_str().contains("shekyl_dialer=debug")
            && d.as_str().contains("shekyl_daemon_rpc=trace"),
        "{d}"
    );
    let sink = c.logging.file_sink();
    assert_eq!(sink.filename_prefix, "shekyld-mainnet.log");
}

/// A C++ log category is not a subsystem: the key is refused where it is
/// read, on the command line and in the file, so a configuration written
/// for the C++ daemon fails at start instead of filtering nothing.
#[test]
fn a_cxx_log_category_is_refused_as_a_key() {
    let cli = build_from(&["--log-category", "net=debug"], "").unwrap_err();
    assert_eq!(cli[0].option.as_deref(), Some("log-category"), "{cli:?}");
    let file = build_from(&[], "log-category = { blockchain = \"debug\" }\n").unwrap_err();
    assert_eq!(file[0].option.as_deref(), Some("log-category"), "{file:?}");
    // The same form with a subsystem key is the user guide's example, and
    // builds: the refusal is the key's.
    let ok = build_from(&[], "log-category = { p2p = \"debug\", tor = \"trace\" }\n").unwrap();
    assert!(ok
        .logging
        .directive()
        .as_str()
        .contains("shekyl_dialer=debug"));
}

#[test]
fn an_ipv6_admin_listener_is_accepted() {
    let c = build_from(&["--rpc-admin-listen", "[::1]:11029"], "").unwrap();
    assert_eq!(c.rpc.admin_listen, vec!["[::1]:11029".parse().unwrap()]);
}

#[test]
fn the_ban_file_is_read_at_parse_and_a_bad_line_is_named() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("bans");
    std::fs::write(
        &p,
        "# comment\n10.0.0.0/8 # a subnet\n8.8.8.8\n9.9.9.9:11021\n\n",
    )
    .unwrap();
    let c = build_from(&["--p2p-ban-file", p.to_str().unwrap()], "").unwrap();
    assert_eq!(c.p2p.bans.len(), 3);
    assert_eq!(c.p2p.bans[0], Ban::Subnet(Ipv4Addr::new(10, 0, 0, 0), 8));
    assert!(matches!(c.p2p.bans[2], Ban::Peer(endpoint) if endpoint.port() == 11021));
    std::fs::write(&p, "8.8.8.8\nnot an address\n").unwrap();
    let e = read_ban_file(&p).unwrap_err();
    assert_eq!(e.code, Code::BanFileLine);
    assert_eq!(e.get("line"), Some("2"));
    // The ban table is keyed by IP: an onion line is refused, not read
    // and silently never applied.
    std::fs::write(
        &p,
        format!("8.8.8.8\n{}:11021\n", shekyl_onion_v3_hostname()),
    )
    .unwrap();
    let e = read_ban_file(&p).unwrap_err();
    assert_eq!((e.code, e.get("line")), (Code::BanFileLine, Some("2")));
    let e = read_ban_file(&d.path().join("missing")).unwrap_err();
    assert_eq!(e.code, Code::BanFileUnreadable);
}

#[test]
fn the_log_location_is_created_or_refused() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("logs").join("shekyld-mainnet.log");
    log_location_writable(&f).unwrap();
    assert!(f.is_file());
    let blocked = d.path().join("file");
    std::fs::write(&blocked, "").unwrap();
    let e = log_location_writable(&blocked.join("x.log")).unwrap_err();
    assert_eq!(e.code, Code::LogUnwritable);
}

#[test]
fn notify_commands_and_levers_are_carried() {
    let c = build_from(
        &[
            "--network",
            "regtest",
            "--dev-difficulty",
            "1",
            "--dev-sync",
            "off",
        ],
        &format!(
            "notify-block = ['{}', '{{height}}']\n",
            abs("/usr/bin/logger")
        ),
    )
    .unwrap();
    assert_eq!(
        c.notify.block.as_deref(),
        Some(&[abs("/usr/bin/logger"), "{height}".to_owned()][..])
    );
    assert_eq!(c.dev.difficulty, Some(1));
    assert!(!c.dev.sync);
    assert_eq!(c.mine.threads, None, "auto");
}

/// `mine` defaults off; `on` needs `mine-address`, refused at parse naming
/// that row (IG-11; Rick, 2026-11-02); an address alone starts nothing.
/// Red edit: let `mine = on` build without an address.
#[test]
fn mine_on_needs_an_address_and_an_address_alone_starts_nothing() {
    let c = build_from(&[], "").unwrap();
    assert!(!c.mine.start);
    assert_eq!(
        codes(build_from(&["--mine", "on"], "")),
        vec![(Code::ValueRequires, "mine".into())]
    );
    let refused = build_from(&["--mine", "on"], "").unwrap_err();
    assert_eq!(
        refused[0].params,
        vec![("requires", "mine-address".to_owned())]
    );
    assert_eq!(
        codes(build_from(&["--mine", "maybe"], "")),
        vec![(Code::ValueWord, "mine".into())]
    );
    let text = shekyl_address::ShekylAddress::new(
        shekyl_address::Network::Mainnet,
        [0xaa; 32],
        [0xbb; 32],
        [0xee; shekyl_address::MSG_SIGN_PK_LEN],
        vec![0xcc; shekyl_address::PQC_PAYLOAD_LEN],
    )
    .encode()
    .unwrap();
    let c = build_from(&["--mine-address", &text], "").unwrap();
    assert!(!c.mine.start, "an address alone starts nothing");
    let c = build_from(&["--mine", "on", "--mine-address", &text], "").unwrap();
    assert!(c.mine.start);
    let c = build_from(&["--mine", "off", "--mine-address", &text], "").unwrap();
    assert!(!c.mine.start);
}

/// The decode's keys stay with the address. The miner assembles from them
/// and does not parse the text a second time.
#[test]
fn a_mining_address_keeps_the_decoded_keys() {
    let addr = shekyl_address::ShekylAddress::new(
        shekyl_address::Network::Mainnet,
        [0xaa; 32],
        [0xbb; 32],
        [0xee; shekyl_address::MSG_SIGN_PK_LEN],
        vec![0xcc; shekyl_address::PQC_PAYLOAD_LEN],
    );
    let text = addr.encode().unwrap();
    let c = build_from(&["--mine-address", &text], "").unwrap();
    let mined = c.mine.address.expect("the address decoded");
    assert_eq!(mined.text, text);
    assert_eq!(mined.spend, [0xaa; 32]);
    assert_eq!(mined.view, [0xbb; 32]);
    assert_eq!(mined.ml_kem, vec![0xcc; shekyl_address::PQC_PAYLOAD_LEN]);
    assert_eq!(
        mined.x25519,
        shekyl_crypto_pq::montgomery::ed25519_pk_to_x25519_pk(&[0xbb; 32]).unwrap(),
        "the coinbase's X25519 half is the view key's image"
    );
}

/// An address whose keys no coinbase can pay is refused at the row, once:
/// the C++ decode's checks (`coinbase_recipient`), and the full address.
#[test]
fn a_mining_address_a_coinbase_cannot_pay_is_refused() {
    let off_curve = (2u8..=255)
        .map(|y| {
            let mut bytes = [0u8; 32];
            bytes[0] = y;
            bytes
        })
        .find(|bytes| {
            shekyl_crypto_pq::account::coinbase_recipient(
                bytes,
                &[0xbb; 32],
                &[0xcc; shekyl_address::PQC_PAYLOAD_LEN],
            ) == Err(shekyl_crypto_pq::account::RecipientRefused::SpendKeyNotAPoint)
        })
        .expect("about half of all encodings are not points");
    let address = |spend: [u8; 32], ml_kem: Vec<u8>| {
        shekyl_address::ShekylAddress::new(
            shekyl_address::Network::Mainnet,
            spend,
            [0xbb; 32],
            [0xee; shekyl_address::MSG_SIGN_PK_LEN],
            ml_kem,
        )
    };
    let full = address(off_curve, vec![0xcc; shekyl_address::PQC_PAYLOAD_LEN])
        .encode()
        .unwrap();
    let malformed = address([0xaa; 32], vec![0xff; shekyl_address::PQC_PAYLOAD_LEN])
        .encode()
        .unwrap();
    let display = address([0xaa; 32], vec![0xcc; shekyl_address::PQC_PAYLOAD_LEN])
        .encode_classical_display()
        .unwrap();
    for (text, reason) in [
        (full, "spend key is not a valid curve point"),
        (malformed, "ML-KEM-768 key is not a well-formed"),
        (display, "mine to the full address"),
    ] {
        let refused = build_from(&["--mine-address", &text], "").expect_err("refused");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0].code, Code::ValueSyntax);
        assert_eq!(refused[0].option.as_deref(), Some("mine-address"));
        let expected = refused[0]
            .params
            .iter()
            .find(|(key, _)| *key == "expected")
            .map(|(_, value)| value.as_str());
        assert!(
            expected.is_some_and(|said| said.contains(reason)),
            "{reason}: {expected:?}"
        );
    }
}

/// A row the table fills is not replaced with a quieter default when it is
/// missing. `rpc-connections-max` in particular must not become 1.
#[test]
fn a_missing_defaulted_row_is_a_fault() {
    let cli = shekyl_options::read_cli(&TABLE, std::iter::empty::<OsString>()).unwrap();
    let (network, mode) = choosers(&cli);
    let mut resolved = resolve(&TABLE, network, cli, Vec::new()).unwrap();
    resolved.values.remove("rpc-connections-max");
    resolved.values.remove("log-level");
    let err = build(&mut resolved, network, mode, &platform(), None).unwrap_err();
    assert!(err.iter().any(|d| {
        d.code == Code::ValueSyntax && d.option.as_deref() == Some("rpc-connections-max")
    }));
    assert!(err
        .iter()
        .any(|d| d.code == Code::ValueSyntax && d.option.as_deref() == Some("log-level")));
}

/// A rate the constructor did not admit is a fault, not an unlimited link.
#[test]
fn a_rate_of_the_wrong_arm_is_not_unlimited() {
    let cli = shekyl_options::read_cli(&TABLE, std::iter::empty::<OsString>()).unwrap();
    let (network, _) = choosers(&cli);
    let mut resolved = resolve(&TABLE, network, cli, Vec::new()).unwrap();
    resolved
        .values
        .insert("p2p-upload-max", (Value::Integer(1), Source::Cli));
    let err = link_limits(&resolved).unwrap_err();
    assert!(err
        .iter()
        .any(|d| d.code == Code::ValueSyntax && d.option.as_deref() == Some("p2p-upload-max")));
    let (upload, download) = link_limits(
        &resolve(
            &TABLE,
            Network::Mainnet,
            shekyl_options::read_cli(&TABLE, std::iter::empty::<OsString>()).unwrap(),
            Vec::new(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!((upload, download), (None, None));
}

/// An integer past `u32::MAX` is the row's range, not a count of 1.
#[test]
fn a_count_past_u32_is_a_range_fault() {
    let cli = shekyl_options::read_cli(&TABLE, std::iter::empty::<OsString>()).unwrap();
    let (network, mode) = choosers(&cli);
    let mut resolved = resolve(&TABLE, network, cli, Vec::new()).unwrap();
    resolved.values.insert(
        "rpc-connections-max",
        (Value::Integer(u64::from(u32::MAX) + 1), Source::Cli),
    );
    let err = build(&mut resolved, network, mode, &platform(), None).unwrap_err();
    assert!(err.iter().any(|d| {
        d.code == Code::ValueRange && d.option.as_deref() == Some("rpc-connections-max")
    }));
}

/// The values a default start uses are in the map, with source `default`.
/// `tor-file` stays absent: it is a search, not a path this build invents.
/// Clearnet off does not name a listen the process does not open.
#[test]
fn derived_defaults_are_in_the_map_and_clearnet_off_names_no_listen() {
    let mut resolved = resolve(
        &TABLE,
        Network::Mainnet,
        shekyl_options::read_cli(&TABLE, std::iter::empty::<OsString>()).unwrap(),
        Vec::new(),
    )
    .unwrap();
    let config = build(
        &mut resolved,
        Network::Mainnet,
        RunMode::User,
        &platform(),
        None,
    )
    .unwrap();
    for name in [
        "data-dir",
        "log-file",
        "clearnet-listen",
        "rpc-admin-listen",
    ] {
        assert_eq!(resolved.source(name), Some(&Source::Default), "{name}");
    }
    assert!(resolved.get("tor-file").is_none());
    assert_eq!(
        resolved.get("data-dir").map(Value::render).as_deref(),
        Some(config.data_dir.display().to_string()).as_deref()
    );
    assert_eq!(
        resolved
            .get("rpc-admin-listen")
            .map(Value::render)
            .as_deref(),
        Some("127.0.0.1:11029")
    );

    let mut off = resolve(
        &TABLE,
        Network::Mainnet,
        shekyl_options::read_cli(
            &TABLE,
            ["--clearnet", "off", "--tor", "off"]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap(),
        Vec::new(),
    )
    .unwrap();
    build(&mut off, Network::Mainnet, RunMode::User, &platform(), None).unwrap();
    assert!(off.get("clearnet-listen").is_none());
    assert_eq!(off.source("data-dir"), Some(&Source::Default));
    assert_eq!(
        off.get("rpc-admin-listen").map(Value::render).as_deref(),
        Some("127.0.0.1:11029")
    );
}

/// A `shekyld.toml` saved by a Windows editor ends its lines with CRLF.
/// `file::open` reads the bytes as they are (`read_to_string`, no
/// conversion) and `read_file` parses them as TOML, which treats CRLF as
/// a newline, so the CRLF text builds the same configuration as its LF
/// twin, and a refusal in it names the same line (review 3 §3 of the
/// Rust-binary PR; DC-F42). Red edit: make the parser refuse `\r`.
#[test]
fn a_crlf_file_builds_what_its_lf_twin_builds() {
    let lf = format!(
        "log-level = 'debug'\nmine-threads = 2\nnotify-block = ['{}', '{{height}}']\n",
        abs("/usr/bin/logger")
    );
    let crlf = lf.replace('\n', "\r\n");
    assert!(crlf.contains("\r\n") && !lf.contains('\r'));
    let from_lf = build_from(&[], &lf).unwrap();
    let from_crlf = build_from(&[], &crlf).unwrap();
    assert_eq!(from_crlf, from_lf);
    assert_eq!(from_crlf.mine.threads.map(std::num::NonZero::get), Some(2));

    let bad = "log-level = 'debug'\r\nmine-threads = 'two'\r\n";
    let refused = build_from(&[], bad).unwrap_err();
    assert_eq!(
        refused[0].option.as_deref(),
        Some("mine-threads"),
        "{refused:?}"
    );
    assert!(
        matches!(&refused[0].source, Source::File { line: 2, .. }),
        "{:?}",
        refused[0].source
    );
}

/// A named instance is a second node and keeps its own state, so it names
/// its own data directory (`RPC_CHANNEL.md` §7.1). Red edit: drop the
/// `given("data-dir")` check and the first assertion fails.
#[test]
fn a_named_instance_needs_its_own_data_directory() {
    assert_eq!(
        codes(build_from(&["--instance", "bench"], "")),
        vec![(Code::ValueRequires, "instance".into())]
    );
    let c = build_from(
        &["--instance", "bench", "--data-dir", &abs("/srv/bench")],
        "",
    )
    .unwrap();
    assert_eq!(
        c.rpc.instance,
        shekyl_rpc_channel::Instance::Named(
            shekyl_rpc_channel::InstanceName::parse("bench").unwrap()
        )
    );
    assert_eq!(
        build_from(&[], "").unwrap().rpc.instance,
        shekyl_rpc_channel::Instance::Default
    );
}

/// The instance name's rule is the channel crate's, and `default` names
/// the default instance (`RPC_CHANNEL.md` §7.1).
#[test]
fn an_instance_name_outside_the_rule_is_refused_at_parse() {
    for bad in ["default", "Bench", "-bench", "a_b", "seventeen-chars-x"] {
        let refused =
            build_from(&["--instance", bad, "--data-dir", &abs("/srv/bench")], "").expect_err(bad);
        assert_eq!(refused.len(), 1, "{bad}");
        assert_eq!(refused[0].code, Code::ValueRange, "{bad}");
        assert_eq!(refused[0].option.as_deref(), Some("instance"), "{bad}");
    }
}

/// A service serves no owner socket, so a socket directory with `service`
/// is refused rather than ignored (IG-Q105). Red edit: drop the conflict and
/// the service start builds.
#[cfg(not(windows))]
#[test]
fn a_service_is_given_no_socket_directory() {
    let paths = [
        "--data-dir",
        "/var/lib/shekyl",
        "--log-file",
        "/var/log/shekyl/shekyld.log",
    ];
    let mut with_dir = vec!["--service", "--rpc-socket-dir", "/run/shekyl"];
    with_dir.extend(paths);
    assert_eq!(
        codes(build_from(&with_dir, "")),
        vec![(Code::ValueConflict, "rpc-socket-dir".into())]
    );
    let mut service = vec!["--service"];
    service.extend(paths);
    let c = build_from(&service, "").unwrap();
    assert_eq!(c.run_mode, RunMode::Service);
    assert_eq!(c.rpc.socket_dir, None);
    let c = build_from(&["--rpc-socket-dir", "/run/shekyl"], "").unwrap();
    assert_eq!(c.rpc.socket_dir, Some(PathBuf::from("/run/shekyl")));
}

/// On Windows `service` also answers the service manager, whose dispatcher
/// is RT-W14's, so the switch is refused there as the reserved row was.
#[cfg(windows)]
#[test]
fn a_windows_start_refuses_service_until_rt_w14() {
    let d = codes(build_from(
        &["--service", "--data-dir", &abs("/srv/chain")],
        &format!("log-file = '{}'\n", abs("/var/log/s.log")),
    ));
    assert!(d.contains(&(Code::NameReserved, "service".into())), "{d:?}");
}
