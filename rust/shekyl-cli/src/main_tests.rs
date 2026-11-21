// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests of the binary: flag resolution, the default wallet directory,
//! and a self-hosted session's start. They sit beside `main.rs` so that
//! file stays the session and the command loop.

use super::*;

/// With no `--daemon-address` the daemon is "this computer" on the
/// selected network (RT-W10 step 5); a given address is taken as given,
/// as a URL; an unknown network fails before anything is dialed; and a
/// proxy with no address is refused in a self-hosted run, where it could
/// only be the daemon's, but not beside `--rpc-url`, whose server it
/// reaches. The edit that turns this red is defaulting to the plaintext
/// port again.
#[test]
fn the_default_daemon_is_this_computer_on_the_network() {
    let args = |argv: &[&str]| ReplArgs::try_parse_from(argv).expect("parses");
    let this_computer = |argv: &[&str]| match args(argv).daemon_target().unwrap() {
        DaemonTarget::ThisComputer { network, .. } => network,
        other => panic!("{other:?}"),
    };
    assert_eq!(this_computer(&["shekyl-cli"]), Network::Mainnet);
    assert_eq!(
        this_computer(&["shekyl-cli", "--network", "testnet"]),
        Network::Testnet
    );
    assert_eq!(
        this_computer(&[
            "shekyl-cli",
            "--rpc-url",
            "http://127.0.0.1:29500",
            "--proxy",
            "socks5h://127.0.0.1:9050"
        ]),
        Network::Mainnet
    );
    assert!(matches!(
        args(&[
            "shekyl-cli",
            "--network",
            "testnet",
            "--daemon-address",
            "node.example.com:11029"
        ])
        .daemon_target()
        .unwrap(),
        DaemonTarget::Address { url, proxy: None } if url == "http://node.example.com:11029"
    ));
    assert!(args(&["shekyl-cli", "--network", "bogus"])
        .daemon_target()
        .is_err());
    let proxied = args(&["shekyl-cli", "--proxy", "socks5h://127.0.0.1:9050"])
        .daemon_target()
        .expect_err("a self-hosted proxy needs an address");
    assert!(proxied.contains("--daemon-address"), "{proxied}");
}

/// A scripted run against an external wallet-RPC server opens no daemon
/// of its own, so it never consults `--network` — the flag's own help
/// says the server it configures is not started. The edit that turns
/// this red is resolving the daemon unconditionally (which is what
/// `--network` parsing hangs off): `Endpoints::resolve` then fails on a
/// network this run had no use for.
#[test]
fn a_scripted_external_run_resolves_no_daemon_and_no_network() {
    let args = |argv: &[&str]| ReplArgs::try_parse_from(argv).expect("parses");
    let external = args(&[
        "shekyl-cli",
        "--rpc-url",
        "http://127.0.0.1:29500",
        "--network",
        "bogus",
    ]);

    let scripted = Endpoints::resolve(&external, false)
        .expect("no daemon is opened, so the network is never parsed");
    assert!(scripted.daemon().is_none(), "no daemon endpoint is dialed");

    // The REPL *does* open a daemon client, and with no --daemon-address
    // it is this computer's node on the network — so there the bad value
    // is fatal, at the point it is actually needed.
    assert!(Endpoints::resolve(&external, true).is_err());

    // ...and naming the daemon removes even that need.
    let named = args(&[
        "shekyl-cli",
        "--rpc-url",
        "http://127.0.0.1:29500",
        "--network",
        "bogus",
        "--daemon-address",
        "127.0.0.1:11029",
    ]);
    let repl = Endpoints::resolve(&named, true).expect("the daemon is named");
    assert!(matches!(
        &repl.daemon().expect("a daemon").target,
        DaemonTarget::Address { url, .. } if url == "http://127.0.0.1:11029"
    ));
}

/// The enrollment flags are checked before a session opens, and the
/// check reads only what was typed: no bundle file, no remote; a bundle
/// file without the channel's address is refused; with one, the remote
/// is the bundle and that address. The key's path is not resolved here
/// (`EnrollOptions::key_file` is the flag as given), so a session whose
/// account has no home is not refused for a key it never reads. The
/// edit that turns this red is dropping the address check: the bundle
/// alone would then reach the plaintext port's default.
#[test]
fn the_enrollment_flags_are_checked_as_typed() {
    let args = |argv: &[&str]| ReplArgs::try_parse_from(argv).expect("parses");
    assert!(args(&["shekyl-cli"])
        .enroll_remote()
        .expect("no bundle")
        .is_none());
    assert_eq!(
        args(&["shekyl-cli", "--daemon-bundle-file", "node.bundle"])
            .enroll_remote()
            .expect_err("a bundle without the channel's address"),
        shekyl_cli::enroll::CHANNEL_ADDRESS_REQUIRED
    );
    let remote = args(&[
        "shekyl-cli",
        "--daemon-bundle-file",
        "node.bundle",
        "--daemon-address",
        "192.0.2.7:11031",
    ])
    .enroll_remote()
    .expect("a bundle and the channel's address")
    .expect("a remote");
    assert_eq!(remote.bundle_file, std::path::PathBuf::from("node.bundle"));
}

/// `--testnet` / `--stagenet` are shorthand for `--network testnet` /
/// `--network stagenet`, the spelling `shekyld` takes. Combining spellings is a
/// parse error, not a precedence rule — a run that says two networks
/// must not silently pick one (CU-1).
#[test]
fn testnet_and_stagenet_flags_select_the_network() {
    let args = |argv: &[&str]| ReplArgs::try_parse_from(argv).expect("parses");
    let network = |argv: &[&str]| match args(argv).daemon_target().unwrap() {
        DaemonTarget::ThisComputer { network, .. } => network,
        other => panic!("{other:?}"),
    };
    assert_eq!(network(&["shekyl-cli", "--testnet"]), Network::Testnet);
    assert_eq!(network(&["shekyl-cli", "--stagenet"]), Network::Stagenet);
    assert!(ReplArgs::try_parse_from(["shekyl-cli", "--testnet", "--network", "testnet"]).is_err());
    assert!(
        ReplArgs::try_parse_from(["shekyl-cli", "--stagenet", "--network", "stagenet"]).is_err()
    );
    assert!(ReplArgs::try_parse_from(["shekyl-cli", "--testnet", "--stagenet"]).is_err());
}

/// `--tor-file` is the self-hosted server's: with `--rpc-url` no server is
/// started, so the pair is refused at parse rather than the path ignored.
#[test]
fn the_tor_file_is_the_self_hosted_servers_and_refused_with_rpc_url() {
    let parsed = ReplArgs::try_parse_from(["shekyl-cli", "--tor-file", "/opt/tor/tor"])
        .expect("parses alone");
    assert_eq!(
        parsed.tor_file.as_deref(),
        Some(std::path::Path::new("/opt/tor/tor"))
    );
    let refused = ReplArgs::try_parse_from([
        "shekyl-cli",
        "--tor-file",
        "/opt/tor/tor",
        "--rpc-url",
        "http://127.0.0.1:29500",
    ]);
    assert!(
        refused.is_err(),
        "--tor-file with --rpc-url must be refused"
    );
}

/// Connection flags are global (CU-1): they parse after a subcommand
/// name, so `shekyl-cli create w --seed-out s --testnet` works instead
/// of demanding the flags come first.
#[test]
fn connection_flags_parse_after_a_subcommand() {
    let cli = Cli::try_parse_from([
        "shekyl-cli",
        "create",
        "w",
        "--seed-out",
        "/tmp/seed.txt",
        "--testnet",
    ])
    .expect("global connection flags parse after the subcommand");
    assert!(cli.repl.testnet);
    assert!(matches!(cli.command, Some(Commands::Create(_))));
}

/// The default wallet dir is per-network (`wallets/<network>/`, CU-1)
/// in the per-account root (rule 83 IG-13), pinned as the rule states
/// it, so wallets on different networks never share a directory; an
/// explicit `--wallet-dir` is taken as given. The directory follows the
/// network the flags parse to. Red edit: the old `dirs::home_dir()` plus
/// `.shekyl` fails on Windows, and under a moved `HOME`.
#[test]
fn the_default_wallet_dir_is_per_network() {
    let args = |argv: &[&str]| ReplArgs::try_parse_from(argv).expect("parses");
    let dir_of = |argv: &[&str]| {
        let cli = args(argv);
        let network = parse_network(cli.network_name()).expect("a network");
        cli.resolved_wallet_dir(network).unwrap()
    };
    let home = shekyl_os_account::account_home().expect("the test account has a home");
    let wallets = home
        .join(if cfg!(windows) { "Shekyl" } else { ".shekyl" })
        .join("wallets");
    assert_eq!(
        dir_of(&["shekyl-cli", "--testnet"]),
        wallets.join("testnet")
    );
    assert_eq!(dir_of(&["shekyl-cli"]), wallets.join("mainnet"));
    assert_eq!(
        dir_of(&["shekyl-cli", "--network", "stagenet"]),
        wallets.join("stagenet")
    );
    assert_eq!(
        dir_of(&["shekyl-cli", "--engine-dir", "/tmp/wallets"]),
        std::path::PathBuf::from("/tmp/wallets")
    );
}

/// A self-hosted session's start makes the per-account root and not the
/// wallet directory: an `rpc` enrollment word, which makes no wallet,
/// left an empty `wallets/<network>` (finding on #1482's Windows run).
/// This is `build_session`'s own start past the flags, with a root in a
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
        DaemonTarget::address("http://127.0.0.1:1"),
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
    rpc.shutdown();
}

/// The daemon-down hint (F1) fires for this machine only, this computer
/// or a loopback address, and names the network-matched `shekyld`
/// invocation, plus the port for an address; a remote daemon gets no
/// "start it" copy.
#[test]
fn the_daemon_down_hint_is_loopback_only_and_names_the_network() {
    let args = |argv: &[&str]| ReplArgs::try_parse_from(argv).expect("parses");
    let testnet = args(&["shekyl-cli", "--testnet"]);
    let hint = daemon_down_hint(&testnet, &DaemonTarget::address("127.0.0.1:12029"))
        .expect("loopback gets a hint");
    assert!(hint.contains("shekyld --network testnet"), "got {hint}");
    assert!(hint.contains("12029"), "got {hint}");
    assert!(daemon_down_hint(&testnet, &DaemonTarget::address("node.example.com:12029")).is_none());
    assert!(
        daemon_down_hint(
            &testnet,
            &DaemonTarget::address("http://127.0.0.1.evil.com:12029")
        )
        .is_none(),
        "a spoofed 127.0.0.1 prefix is not loopback"
    );
    assert!(daemon_down_hint(&testnet, &DaemonTarget::address("[::1]:12029")).is_some());
    assert!(
        daemon_down_hint(&testnet, &DaemonTarget::address("127.0.0.2:12029")).is_some(),
        "127.0.0.0/8 is loopback"
    );

    let here = daemon_down_hint(&testnet, &testnet.daemon_target().unwrap())
        .expect("this computer gets a hint");
    assert!(here.contains("shekyld --network testnet"), "got {here}");

    let mainnet_hint = daemon_down_hint(
        &args(&["shekyl-cli"]),
        &DaemonTarget::address("127.0.0.1:11029"),
    )
    .expect("hint");
    assert!(mainnet_hint.contains("shekyld"), "got {mainnet_hint}");
    assert!(
        !mainnet_hint.contains("--"),
        "mainnet is flagless: {mainnet_hint}"
    );
}
