// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests of the binary: the endpoints a run opens, the default wallet
//! directory, and a self-hosted session's start. They sit beside `main.rs`
//! so that file stays the session and the command loop. The option rows
//! themselves are `shekyl_cli::config`'s tests.

use super::*;

use shekyl_os_account::private_file::write_private;
use shekyl_os_account::test_fixture;

/// A run's options, with a named empty configuration file so a file in the
/// account's real root never reaches the test.
fn options(args: &[&str]) -> Options {
    let dir = test_fixture::tempdir().expect("a fixture directory");
    let file = dir.path().join("config.toml");
    write_private(&file, b"").expect("the configuration file");
    let mut full = vec![
        std::ffi::OsString::from("--config-file"),
        file.into_os_string(),
    ];
    full.extend(args.iter().map(std::ffi::OsString::from));
    match config::load(full, &shekyl_process::platform::current(), false) {
        Ok(Action::Run { options, .. }) => *options,
        Ok(_) => panic!("{args:?}: not a run"),
        Err(faults) => panic!("{args:?}: {faults:?}"),
    }
}

/// With no `daemon-endpoint` the daemon is "this computer" on the network
/// (RT-W10 step 5), the session is self-hosted, and beside an external
/// wallet server the proxy is that server's. The edit that turns this red
/// is defaulting to the plaintext port again.
#[test]
fn the_default_daemon_is_this_computer_on_the_network() {
    let this_computer = |args: &[&str]| match Endpoints::of(&options(args)).daemon().target {
        DaemonTarget::ThisComputer { network, .. } => network,
        ref other => panic!("{other:?}"),
    };
    assert_eq!(this_computer(&[]), Network::Mainnet);
    assert_eq!(this_computer(&["--network", "testnet"]), Network::Testnet);
    assert_eq!(
        this_computer(&[
            "--wallet-rpc-endpoint",
            "127.0.0.1:29500",
            "--daemon-socks",
            "127.0.0.1:9050"
        ]),
        Network::Mainnet
    );
    let named = options(&[
        "--network",
        "testnet",
        "--daemon-endpoint",
        "192.0.2.7:11029",
        "--daemon-bundle-file",
        if cfg!(windows) {
            r"C:\test\bundle"
        } else {
            "/test/bundle"
        },
    ]);
    assert!(matches!(
        &Endpoints::of(&named).daemon().target,
        DaemonTarget::Channel { node, .. } if node.leg.to_string() == "192.0.2.7:11029"
    ));
}

/// An external server is an external session, and its daemon is still the
/// one the options name. Red edit: return `SelfHosted` whenever a daemon is
/// named.
#[test]
fn an_external_server_is_not_self_hosted() {
    let external = options(&[
        "--wallet-rpc-endpoint",
        "127.0.0.1:29500",
        "--daemon-endpoint",
        "127.0.0.1:11029",
        "--daemon-bundle-file",
        if cfg!(windows) {
            r"C:\test\bundle"
        } else {
            "/test/bundle"
        },
    ]);
    let endpoints = Endpoints::of(&external);
    assert!(
        matches!(&endpoints, Endpoints::External { url, .. } if url == "http://127.0.0.1:29500")
    );
    assert!(matches!(
        &endpoints.daemon().target,
        DaemonTarget::Channel { node, .. } if node.leg.to_string() == "127.0.0.1:11029"
    ));
}

/// The default wallet dir is per-network (`wallets/<network>/`, CU-1)
/// in the per-account root (rule 83 IG-13), pinned as the rule states
/// it, so wallets on different networks never share a directory; an
/// explicit `wallet-dir` is taken as given. Red edit: the old
/// `dirs::home_dir()` plus `.shekyl` fails on Windows, and under a moved
/// `HOME`.
#[test]
fn the_default_wallet_dir_is_per_network() {
    let dir_of = |args: &[&str]| {
        let options = options(args);
        resolved_wallet_dir(&options, options.network).unwrap()
    };
    let home = shekyl_os_account::account_home().expect("the test account has a home");
    let wallets = home
        .join(if cfg!(windows) { "Shekyl" } else { ".shekyl" })
        .join("wallets");
    assert_eq!(dir_of(&["--network", "testnet"]), wallets.join("testnet"));
    assert_eq!(dir_of(&[]), wallets.join("mainnet"));
    assert_eq!(dir_of(&["--network", "stagenet"]), wallets.join("stagenet"));
    let named = if cfg!(windows) {
        r"C:\w\wallets"
    } else {
        "/w/wallets"
    };
    assert_eq!(
        dir_of(&["--wallet-dir", named]),
        std::path::PathBuf::from(named)
    );
}

/// A self-hosted session's start makes the per-account root and not the
/// wallet directory: an `rpc` enrollment word, which makes no wallet,
/// left an empty `wallets/<network>` (finding on #1482's Windows run).
/// This is `build_session`'s own start past the options, with a root in a
/// scratch directory, so the test makes nothing in the home of the
/// account it runs under. Red edit: `create_dir_all(&wallet_dir)` back in
/// `host_session` (where `build_session` had it) fails here.
#[test]
fn a_session_start_makes_the_root_and_not_the_wallet_dir() {
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let root = scratch.path().join("root");
    let wallets = root.join("wallets").join("regtest");
    let rpc = host_session(
        wallets.clone(),
        Network::Regtest,
        DaemonTarget::fixture_address("http://127.0.0.1:1"),
        shekyl_wallet_rpc::server::TorFile::discover(),
        false,
        Some(&root),
    )
    .expect("the session starts");
    assert!(root.is_dir(), "the root is made at the start");
    assert!(
        !wallets.exists(),
        "a session that makes no wallet makes no wallet folder"
    );
    assert_eq!(rpc.shutdown(), rpc_client::WalletClose::NotOpen);
}

/// The daemon-down hint (F1) fires for this machine only, this computer
/// or a loopback address, and names the network-matched `shekyld`
/// invocation, plus the port for an address; a remote daemon gets no
/// "start it" copy.
#[test]
fn the_daemon_down_hint_is_loopback_only_and_names_the_network() {
    let testnet = Network::Testnet;
    let hint = daemon_down_hint(testnet, &DaemonTarget::fixture_address("127.0.0.1:12029"))
        .expect("loopback gets a hint");
    assert!(hint.contains("shekyld --network testnet"), "got {hint}");
    assert!(hint.contains("12029"), "got {hint}");
    assert!(daemon_down_hint(
        testnet,
        &DaemonTarget::fixture_address("node.example.com:12029")
    )
    .is_none());
    assert!(
        daemon_down_hint(
            testnet,
            &DaemonTarget::fixture_address("http://127.0.0.1.evil.com:12029")
        )
        .is_none(),
        "a spoofed 127.0.0.1 prefix is not loopback"
    );
    assert!(daemon_down_hint(testnet, &DaemonTarget::fixture_address("[::1]:12029")).is_some());
    assert!(
        daemon_down_hint(testnet, &DaemonTarget::fixture_address("127.0.0.2:12029")).is_some(),
        "127.0.0.0/8 is loopback"
    );

    let here = daemon_down_hint(
        testnet,
        &DaemonTarget::ThisComputer {
            network: testnet,
            account: Default::default(),
        },
    )
    .expect("this computer gets a hint");
    assert!(here.contains("shekyld --network testnet"), "got {here}");

    let mainnet_hint = daemon_down_hint(
        Network::Mainnet,
        &DaemonTarget::fixture_address("127.0.0.1:11029"),
    )
    .expect("hint");
    assert!(mainnet_hint.contains("shekyld"), "got {mainnet_hint}");
    assert!(
        !mainnet_hint.contains("--"),
        "mainnet is flagless: {mainnet_hint}"
    );
}
