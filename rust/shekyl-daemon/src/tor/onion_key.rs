// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! This node's persistent onion (`tor-onion-key-file`; Rick, 2026-11-21).
//!
//! A managed Tor publishes a new onion at every boot unless the operator
//! names Tor's own `hs_ed25519_secret_key`: then the onion is that key's, at
//! every boot, as a seed node's must be. The walk loads it once
//! ([`load`]), so the key the check judged is the key the start hands Tor.
//! A key that is named and cannot be used refuses the start: a node never
//! falls back to a new onion, which would put a seed at a random address.
//!
//! The file is read through `shekyl-os-account`'s key-file reader (only this
//! account and the superuser may reach it; a systemd credential qualifies)
//! and parsed in `shekyl-onion-key` (rule 36). This module holds no byte of
//! the secret itself: the read buffer is wiped on drop, and the keypair is
//! heap-held.

use std::path::Path;

use shekyl_onion_key::{OnionKeypair, TOR_SECRET_KEY_FILE_BYTES};
use shekyl_options::{Code, Diagnostic, Source};
use shekyl_os_account::key_file::{read_key_file, KeyFileError};
use shekyl_tor_control_client::onion_identity::OnionIdentity;

/// The option the key is named by.
const OPTION: &str = "tor-onion-key-file";

/// The onion identity in the key file at `path`, named from `source`.
///
/// # Errors
///
/// `config.onion-key.missing` when there is no file,
/// `config.onion-key.unreadable` when it cannot be read,
/// `config.onion-key.exposed` when another account can reach it, and
/// `config.onion-key.not-a-key` when it is not Tor's key file.
pub(crate) fn load(path: &Path, source: &Source) -> Result<OnionIdentity, Diagnostic> {
    let refused = |code| {
        Diagnostic::new(code, source.clone())
            .option(OPTION)
            .param("path", path.display().to_string())
    };
    let bytes = match read_key_file(path, TOR_SECRET_KEY_FILE_BYTES) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err(refused(Code::OnionKeyMissing)),
        Err(KeyFileError::Exposed(_, why)) => {
            return Err(refused(Code::OnionKeyExposed).param("why", why))
        }
        Err(error) => {
            return Err(refused(Code::OnionKeyUnreadable).param("error", error.to_string()))
        }
    };
    let keypair = OnionKeypair::from_tor_secret_key_file(&bytes)
        .map_err(|why| refused(Code::OnionKeyNotAKey).param("why", why.to_string()))?;
    Ok(OnionIdentity::from_keypair(keypair))
}
