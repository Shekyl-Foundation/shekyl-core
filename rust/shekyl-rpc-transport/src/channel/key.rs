// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! This client's key file, and a daemon's public bundle as text.

use shekyl_rpc_channel::handshake::{StaticKeypair, StaticPublic};

/// This client's key at `path`, checked to be this account's alone
/// (`shekyl_os_account::private_file`); `None` when there is none.
///
/// # Errors
///
/// The file is unreadable, readable by another account, or not a key.
pub fn read_client_key(path: &std::path::Path) -> Result<Option<StaticKeypair>, String> {
    let Some(bytes) =
        shekyl_os_account::private_file::read_private(path).map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    StaticKeypair::from_key_file(&bytes)
        .map(Some)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// A new key at `path`, this account's alone in the creating call (IG-Q109);
/// refused if anything is there.
///
/// # Errors
///
/// Something is at `path`, or the key could not be made or written.
pub fn create_client_key(path: &std::path::Path) -> Result<StaticKeypair, String> {
    publish_client_key(path)?.ok_or_else(|| {
        format!(
            "{} already holds a key; showing it prints its fingerprint",
            path.display()
        )
    })
}

/// Publish complete owner-only bytes without replacing a concurrent creator.
/// The private staging directory is on the same filesystem as the final key.
pub(super) fn publish_client_key(path: &std::path::Path) -> Result<Option<StaticKeypair>, String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let at = |e: std::io::Error| format!("{}: {e}", path.display());
    shekyl_os_account::create_account_dir_all(parent).map_err(at)?;
    let stage = tempfile::tempdir_in(parent).map_err(at)?;
    let source = stage.path().join("key");
    let key = StaticKeypair::generate().map_err(|e| e.to_string())?;
    shekyl_os_account::private_file::write_private(&source, &key.to_key_file())
        .map_err(|e| e.to_string())?;
    match std::fs::hard_link(&source, path) {
        Ok(()) => {
            shekyl_os_account::private_file::sync_dir(parent).map_err(at)?;
            Ok(Some(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(e) => Err(at(e)),
    }
}

/// A fingerprint as `rpc client list` prints one, so the operator pastes it
/// into `rpc client add` unchanged.
#[must_use]
pub fn fingerprint_hex(key: &StaticPublic) -> String {
    hex::encode(key.fingerprint().as_bytes())
}

/// A daemon's public bundle from its bytes: the X25519 key, then the
/// ML-KEM-768 encapsulation key. Each half takes its exact length; any
/// other total is not a bundle.
#[must_use]
pub fn bundle_from_bytes(bytes: &[u8]) -> Option<StaticPublic> {
    let (x25519, mlkem) = bytes.split_at_checked(shekyl_rpc_channel::X25519_PUBLIC_LEN)?;
    StaticPublic::from_parts(x25519.try_into().ok()?, mlkem.try_into().ok()?).ok()
}

/// A daemon's bundle as `rpc bundle show` prints it and a
/// `daemon-bundle-file` holds it: the `bytes` kind's base64 (IG-6).
#[must_use]
pub fn bundle_text(bundle: &[u8]) -> String {
    serde_json::to_value(shekyl_rpc_types::kinds::Bytes(bundle.to_vec()))
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The bundle [`bundle_text`] printed, read back.
#[must_use]
pub fn bundle_from_text(text: &str) -> Option<StaticPublic> {
    let bytes: shekyl_rpc_types::kinds::Bytes =
        serde_json::from_value(serde_json::Value::String(text.trim().to_owned())).ok()?;
    bundle_from_bytes(&bytes.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simultaneous_creators_publish_one_complete_identity() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("identity").join("rpc-client.key");
        let start = std::sync::Barrier::new(8);
        let keys = std::thread::scope(|scope| {
            let attempts: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        publish_client_key(&file).unwrap()
                    })
                })
                .collect();
            attempts
                .into_iter()
                .filter_map(|attempt| attempt.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(keys.len(), 1);
        let stored = read_client_key(&file).unwrap().unwrap();
        assert_eq!(
            stored.public().fingerprint(),
            keys[0].public().fingerprint()
        );
    }

    /// A bundle printed as `rpc bundle show` prints it reads back as the
    /// same keys, and a short or mangled one does not. Red edit: print it as
    /// hex in `bundle_text`, and it does not read back.
    #[test]
    fn a_printed_bundle_reads_back() {
        let key = StaticKeypair::generate().unwrap();
        let public = key.public();
        let mut bytes = public.x25519().to_vec();
        bytes.extend_from_slice(public.mlkem_ek());
        let text = bundle_text(&bytes);
        let read = bundle_from_text(&text).expect("the bundle");
        assert_eq!(read.fingerprint(), public.fingerprint());
        assert!(bundle_from_text(&bundle_text(&bytes[..bytes.len() - 1])).is_none());
        assert!(bundle_from_text("not base64!").is_none());
    }
}
