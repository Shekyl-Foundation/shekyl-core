// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddrV4};
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

fn platform() -> Platform {
    Platform {
        home: Some(PathBuf::from("/srv/op")),
        program_data: None,
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
    assert_eq!(c.data_dir, PathBuf::from("/srv/op/.shekyl"));
    assert_eq!(
        c.logging.file,
        PathBuf::from("/srv/op/.shekyl/logs/shekyld-mainnet.log")
    );
    assert_eq!(c.logging.directive(), "warn");
    assert_eq!(c.tor, Tor::Managed { binary: None });
    assert!(
        matches!(&c.clearnet, Clearnet::On { listen, socks: None, advertise } if listen.len() == 1 && listen[0].port() == 11021 && advertise.is_empty())
    );
    assert_eq!(c.rpc.admin_listen, vec!["127.0.0.1:11029".parse().unwrap()]);
    assert!(c.rpc.view_listen.is_empty());
    assert_eq!(c.rpc.connections_max.get(), 25);
    assert_eq!(c.txpool_weight_max, 648_000_000);
    assert_eq!(c.p2p.upload_max, None);
    assert!(c.dev.sync);
    assert!(!c.offline());
    assert!(!c.is_client());
}

#[test]
fn explicit_paths_are_taken_as_given_and_defaults_follow_the_network() {
    let c = build_from(
        &["--network", "testnet", "--data-dir", "/srv/chain"],
        "log-file = \"/var/log/s.log\"\n",
    )
    .unwrap();
    assert_eq!(c.data_dir, PathBuf::from("/srv/chain"));
    assert_eq!(c.logging.file, PathBuf::from("/var/log/s.log"));
    assert!(matches!(&c.clearnet, Clearnet::On { listen, .. } if listen[0].port() == 12021));
    assert_eq!(c.rpc.admin_listen[0].port(), 12029);
}

#[test]
fn no_home_refuses_each_path_that_needs_it_and_not_an_explicit_one() {
    let args: Vec<OsString> = ["--data-dir", "/srv/chain"]
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
    let d = codes(build_from(&["--tor-file", "/opt/tor", "--tor", "off"], ""));
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
    assert!(d.starts_with("info,"), "{d}");
    assert!(
        d.contains("shekyl_dialer=debug") && d.contains("shekyl_daemon_rpc=trace"),
        "{d}"
    );
    let sink = c.logging.file_sink();
    assert_eq!(sink.filename_prefix, "shekyld-mainnet.log");
}

#[test]
fn positional_words_make_a_client_that_needs_an_admin_endpoint() {
    let c = build_from(&["status"], "").unwrap();
    assert!(c.is_client());
    assert_eq!(
        c.session.client_endpoint,
        Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 11029))
    );
    let d = codes(build_from(&["--rpc-admin-listen", "none", "status"], ""));
    assert_eq!(d, vec![(Code::ClientNoEndpoint, "rpc-admin-listen".into())]);
}

/// The console dials IPv4. A daemon may bind an IPv6 admin listener; a
/// client command to one is refused at parse, with the grammar's range code.
#[test]
fn a_client_refuses_an_admin_endpoint_the_console_cannot_dial() {
    let d = codes(build_from(
        &["--rpc-admin-listen", "[::1]:11029", "status"],
        "",
    ));
    assert_eq!(d, vec![(Code::ValueRange, "rpc-admin-listen".into())]);
    let c = build_from(&["--rpc-admin-listen", "[::1]:11029"], "").unwrap();
    assert_eq!(c.rpc.admin_listen, vec!["[::1]:11029".parse().unwrap()]);
    assert!(c.session.client_endpoint.is_none());
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
        "notify-block = [\"/usr/bin/logger\", \"{height}\"]\n",
    )
    .unwrap();
    assert_eq!(
        c.notify.block.as_deref(),
        Some(&["/usr/bin/logger".to_owned(), "{height}".to_owned()][..])
    );
    assert_eq!(c.dev.difficulty, Some(1));
    assert!(!c.dev.sync);
    assert_eq!(c.mine.threads, None, "auto");
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
