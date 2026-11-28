// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a test that starts `shekyl-cli` needs so the run is its own: a
//! named, empty configuration file, so a file in the account's real root
//! never reaches the run, and secret files only this account can read.

use std::path::{Path, PathBuf};

use shekyl_os_account::private_file::write_private;
use shekyl_os_account::test_fixture::{self, FixtureDir};

/// An empty configuration file, removed when this drops. It sits under the
/// account's home because the load refuses a file below a directory another
/// account can write, the system's temporary directory included.
pub struct EmptyConfig {
    _dir: FixtureDir,
    path: PathBuf,
}

impl EmptyConfig {
    /// The value for `--config-file`.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A new empty configuration file.
pub fn empty_config() -> EmptyConfig {
    let dir = test_fixture::tempdir().expect("a fixture directory");
    let path = dir.path().join("config.toml");
    write_private(&path, b"").expect("the configuration file");
    EmptyConfig { _dir: dir, path }
}

/// A file only this account can read, as the CLI requires of a password or
/// recovery-words file.
#[allow(dead_code, reason = "not every test binary writes a secret file")]
pub fn write_secret_file(path: &Path, text: &str) {
    write_private(path, text.as_bytes()).expect("the secret file");
}

/// An isolated key and bundle for a test that deliberately names an offline
/// daemon. No test borrows an enrolled identity from the account running it.
#[allow(
    dead_code,
    reason = "only subprocess tests naming a daemon use this fixture"
)]
pub fn offline_channel_config() -> EmptyConfig {
    use shekyl_rpc_transport::channel::{bundle_text, create_client_key};
    let config = empty_config();
    let dir = config.path().parent().unwrap();
    let key_file = dir.join("client.key");
    create_client_key(&key_file).expect("create fixture client identity");
    let public = shekyl_rpc_channel::handshake::StaticKeypair::generate().unwrap();
    let mut bytes = public.public().x25519().to_vec();
    bytes.extend_from_slice(public.public().mlkem_ek());
    let bundle = dir.join("bundle");
    std::fs::write(&bundle, bundle_text(&bytes)).unwrap();
    // JSON strings are valid TOML basic strings, including Windows paths.
    let text = format!(
        "daemon-bundle-file = {}\nrpc-key-file = {}\n",
        serde_json::json!(bundle),
        serde_json::json!(key_file)
    );
    std::fs::write(config.path(), text).unwrap();
    config
}
