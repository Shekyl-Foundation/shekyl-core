// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! WI-RPC-2a integration tests: the CLI's `RpcSession` against a real
//! self-hosted `shekyl-wallet-rpc` server over the private UDS socket.
//!
//! The daemon address is a never-connecting endpoint (`http://127.0.0.1:1`),
//! matching the wallet-rpc crate's own test posture: everything up to the
//! first daemon-touching step runs for real, and daemon-touching steps fail
//! with typed wallet-RPC errors (never transport errors or hangs).

use std::os::unix::fs::PermissionsExt;

use serde_json::json;
use shekyl_cli::rpc_client::{RpcError, RpcSession};
use shekyl_wallet_rpc::Network;

/// Never-connecting daemon: port 1 refuses immediately.
const NO_DAEMON: &str = "http://127.0.0.1:1";

fn host(dir: &std::path::Path) -> RpcSession {
    RpcSession::host_in_process(
        dir.to_path_buf(),
        Network::Stagenet,
        NO_DAEMON.into(),
        false,
    )
    .expect("host in-process wallet RPC")
}

/// The self-hosted session serves over a private UDS socket (0600 in a 0700
/// dir), answers `get_version`, and removes the socket dir on shutdown.
#[test]
fn session_serves_over_private_uds_and_cleans_up() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpc = host(dir.path());

    let socket = rpc
        .socket_path()
        .expect("self-hosted session exposes a UDS socket");
    let socket_dir = socket
        .parent()
        .expect("socket has a parent dir")
        .to_path_buf();

    let mode =
        |p: &std::path::Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode(socket), 0o600, "socket must be owner-only");
    assert_eq!(mode(&socket_dir), 0o700, "socket dir must be owner-only");

    let version = rpc.call("get_version", json!({})).expect("get_version");
    assert_eq!(
        version.get("api_version").and_then(|v| v.as_i64()),
        Some(i64::from(shekyl_wallet_rpc::API_VERSION)),
    );
    assert!(version.get("version").and_then(|v| v.as_str()).is_some());

    rpc.shutdown();
    assert!(
        !socket_dir.exists(),
        "shutdown must remove the private socket dir"
    );
}

/// Create → mnemonic → restore round-trip through the CLI transport: the
/// restored wallet reproduces the original primary address, and the restore
/// response never echoes backup material.
#[test]
fn create_restore_round_trip_reproduces_the_primary_address() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpc = host(dir.path());

    let created = rpc
        .call("create_wallet", json!({ "name": "orig", "password": "pw" }))
        .expect("create_wallet");
    let mnemonic = created["mnemonic"]
        .as_str()
        .expect("stagenet create returns a BIP-39 mnemonic")
        .to_owned();

    let orig_addr = rpc.call("get_primary_address", json!({})).expect("address")["address"]
        .as_str()
        .expect("address string")
        .to_owned();
    rpc.call("close_wallet", json!({})).expect("close");

    let restored = rpc
        .call(
            "restore_wallet",
            json!({
                "name": "rest",
                "password": "other-pw",
                "mnemonic": mnemonic,
                "restore_height": 0,
            }),
        )
        .expect("restore_wallet");
    assert!(
        restored.get("mnemonic").is_none() && restored.get("raw_seed_hex").is_none(),
        "restore must not echo backup material"
    );

    let rest_addr = rpc.call("get_primary_address", json!({})).expect("address")["address"]
        .as_str()
        .expect("address string")
        .to_owned();
    assert_eq!(orig_addr, rest_addr, "restore must reproduce the account");

    rpc.call("close_wallet", json!({})).expect("close");
    rpc.shutdown();
}

/// The send lifecycle the CLI confirmation flow rides on: build refusals and
/// discard refusals surface as typed wallet-RPC errors (allocated codes and
/// stable messages), never as transport failures — so `cmd_transfer` can show
/// them to the user as-is and nothing is ever submitted without a build.
#[test]
fn send_lifecycle_errors_are_typed_end_to_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpc = host(dir.path());

    // No wallet open: -29001 WalletNotOpen.
    let err = rpc
        .call(
            "build_pending_tx",
            json!({
                "recipients": [{ "address": "skl1abc", "amount": "1" }],
                "priority": "STANDARD",
            }),
        )
        .expect_err("no wallet open");
    assert_eq!(err.code(), Some(-29001), "typed WalletNotOpen, got {err}");

    rpc.call("create_wallet", json!({ "name": "w", "password": "pw" }))
        .expect("create_wallet");

    // Invalid recipient: a typed refusal (allocated code), not a transport
    // error — the CLI flow discards/reports and never reaches submit.
    let err = rpc
        .call(
            "build_pending_tx",
            json!({
                "recipients": [{ "address": "not-an-address", "amount": "1" }],
                "priority": "STANDARD",
            }),
        )
        .expect_err("invalid recipient must refuse");
    assert!(
        matches!(err, RpcError::Rpc { .. }),
        "typed RPC error, got {err}"
    );

    // Discarding an unknown reservation succeeds (idempotent by contract) —
    // that is what makes the CLI's discard-on-decline path safe to repeat.
    rpc.call("discard_pending_tx", json!({ "pending_tx_id": "12345" }))
        .expect("discard is idempotent for unknown ids");

    // A malformed reservation id, by contrast, is a typed InvalidParams
    // refusal, not a transport failure.
    let err = rpc
        .call(
            "discard_pending_tx",
            json!({ "pending_tx_id": "not-a-number" }),
        )
        .expect_err("malformed pending_tx_id must refuse");
    assert!(
        matches!(err, RpcError::Rpc { .. }),
        "typed RPC error, got {err}"
    );

    rpc.call("close_wallet", json!({})).expect("close");
    rpc.shutdown();
}

/// The non-interactive `create`/`restore` subcommands (the scriptable path
/// that closes the interactive seed-leak finding): `create` writes the
/// one-time seed to a 0600 file and refuses to overwrite it, and `restore`
/// reads it back to reproduce the same account — the seed never touches a
/// terminal or a pipe.
#[test]
fn scripted_create_writes_seed_file_and_restore_round_trips() {
    use shekyl_cli::commands::scripted::{run_create, run_restore, CreateArgs, RestoreArgs};

    let dir = tempfile::tempdir().expect("tempdir");
    let rpc = host(dir.path());

    let seed_out = dir.path().join("seed.txt");
    let pw_file = dir.path().join("pw");
    std::fs::write(&pw_file, "s3cret\n").expect("write password file");

    let create = CreateArgs {
        name: "orig".into(),
        seed_out: seed_out.clone(),
        password_file: Some(pw_file.clone()),
        password_stdin: false,
    };
    run_create(&rpc, &create).expect("scripted create");

    // Seed written owner-only and non-empty; the seed never reached stdout.
    let mode = std::fs::metadata(&seed_out)
        .expect("seed metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "seed file must be owner-only");
    assert!(
        !std::fs::read_to_string(&seed_out)
            .expect("read seed")
            .trim()
            .is_empty(),
        "seed file must hold the backup"
    );

    // O_EXCL: refuse to overwrite an existing seed-out path (the check runs
    // before create_wallet, so nothing is created on this refusal).
    let clobber = CreateArgs {
        name: "orig2".into(),
        seed_out: seed_out.clone(),
        password_file: Some(pw_file.clone()),
        password_stdin: false,
    };
    run_create(&rpc, &clobber).expect_err("must refuse to overwrite an existing seed file");

    let orig_addr = rpc.call("get_primary_address", json!({})).expect("address")["address"]
        .as_str()
        .expect("address string")
        .to_owned();
    rpc.call("close_wallet", json!({})).expect("close");

    let restore = RestoreArgs {
        name: "rest".into(),
        seed_file: seed_out.clone(),
        restore_height: None,
        password_file: Some(pw_file.clone()),
        password_stdin: false,
    };
    run_restore(&rpc, &restore).expect("scripted restore");

    let rest_addr = rpc.call("get_primary_address", json!({})).expect("address")["address"]
        .as_str()
        .expect("address string")
        .to_owned();
    assert_eq!(
        orig_addr, rest_addr,
        "scripted restore must reproduce the account"
    );

    rpc.call("close_wallet", json!({})).expect("close");
    rpc.shutdown();
}

/// WI-RPC-2a grep gate: the CLI has no wallet2 / EngineContext /
/// shekyl-engine-rpc code reference left. Prose may say "wallet2" only to
/// state the absence or name the era; identifiers may not.
#[test]
fn no_wallet2_references_remain() {
    const FORBIDDEN: &[&str] = &[
        "shekyl_engine_rpc",
        "shekyl-engine-rpc",
        "EngineContext",
        "Wallet2",
    ];

    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources: Vec<std::path::PathBuf> = vec![crate_root.join("Cargo.toml")];
    let mut stack = vec![crate_root.join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                sources.push(path);
            }
        }
    }

    for path in sources {
        let contents = std::fs::read_to_string(&path).expect("read source");
        for token in FORBIDDEN {
            assert!(
                !contents.contains(token),
                "{} still references {token}",
                path.display()
            );
        }
    }
}
