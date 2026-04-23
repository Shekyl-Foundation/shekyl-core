// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `WalletFileHandle`: high-level lifecycle for a Shekyl v1 wallet pair.
//!
//! This module assembles the primitives from [`crate::atomic`],
//! [`crate::lock`], [`crate::payload`], [`crate::paths`], and the
//! envelope layer in [`shekyl_crypto_pq::wallet_envelope`] into a
//! single opinionated API:
//!
//! ```text
//! WalletFileHandle::create(base, password, …, initial_ledger) → Handle
//! WalletFileHandle::open  (base, password)                    → (Handle, WalletLedger)
//! handle.save_state     (&ledger)                             → ()
//! handle.rotate_password(old, new, new_kdf_opt)               → ()
//! ```
//!
//! The handle owns:
//!
//! - The decrypted [`OpenedKeysFile`], kept alive so that every
//!   auto-save can re-bind `.wallet` to the same `seed_block_tag`
//!   without re-running Argon2.
//! - Wait — we *do* re-run Argon2 per auto-save (this is a design
//!   tradeoff documented in §4.3 of `docs/WALLET_FILE_FORMAT_V1.md`:
//!   "each auto-save re-runs the Argon2id wrap derivation"). So the
//!   handle holds the keys-file *bytes* (for region-2 AAD binding) and
//!   the user's password is passed in fresh on each save. The
//!   [`OpenedKeysFile`] is kept for read-only metadata access
//!   (creation_timestamp, restore_height_hint, network, …) and is
//!   never used as the file_kek source — that derivation always goes
//!   back through the envelope.
//!
//! Actually, re-reading §4.3 carefully: the envelope's
//! `seal_state_file` takes `(password, keys_file_bytes,
//! state_plaintext)`, so the password is required per-save. The
//! handle's job is to hold the keys-file bytes and the advisory lock,
//! not the password. Callers (the FFI, the GUI) supply the password
//! on each save.
//!
//! # Thread safety
//!
//! A handle is **not** `Sync` for `save_state` — auto-save is serialized
//! by the caller. Concurrent reads of the cached `OpenedKeysFile`
//! metadata are safe (all fields are immutable bytes). Two handles
//! against the same wallet pair cannot coexist in the same process by
//! construction: the advisory lock will refuse the second `acquire`.
//!
//! # This commit's scope
//!
//! Per the plan split ("2h happy-path"): `create`, `save_state`,
//! `rotate_password`, and the **happy path** of `open`. Error-branch
//! opens (lost-`.wallet` rescan recovery, pre-v1 refusal, network
//! mismatch, capability dispatch) live in 2i.

use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use shekyl_crypto_pq::wallet_envelope::{
    open_keys_file, open_state_file, rewrap_keys_file_password, seal_keys_file, seal_state_file,
    CapabilityContent, KdfParams, OpenedKeysFile, EXPECTED_CLASSICAL_ADDRESS_BYTES,
};
use shekyl_wallet_state::WalletLedger;

use crate::atomic::atomic_write_file;
use crate::error::WalletFileError;
use crate::lock::KeysFileLock;
use crate::paths::{keys_path_from, state_path_from};
use crate::payload::{decode_payload, encode_payload, PayloadKind};

/// Parameters for creating a fresh wallet. Grouped into a struct so the
/// constructor signature stays readable and so fields can be extended
/// later without cascading changes through call sites.
///
/// Borrows everything it can so no secrets are duplicated on the stack.
pub struct CreateParams<'a> {
    /// Base path. `.keys` is appended for the seed file; the base
    /// itself is used for the state file. See [`crate::paths`].
    pub base_path: &'a Path,
    /// User-supplied password. Stretched to `wrap_key` via Argon2id.
    pub password: &'a [u8],
    /// `0x00 = Mainnet`, `0x01 = Testnet`, `0x02 = Stagenet`,
    /// `0x03 = Fakechain`. Enum-equivalent; the envelope does not
    /// interpret values beyond the registered set.
    pub network: u8,
    /// `0x00 = BIP-39 mnemonic`, `0x01 = raw 32-byte hex`. Stored for
    /// UX ("offer the same restore UI we used at creation").
    pub seed_format: u8,
    /// FULL / VIEW_ONLY / HARDWARE_OFFLOAD. Envelope discriminates
    /// `cap_content` layout from this value.
    pub capability: &'a CapabilityContent<'a>,
    /// Seconds since Unix epoch at wallet creation.
    pub creation_timestamp: u64,
    /// Block height at wallet creation; used as the rescan floor on
    /// the lost-`.wallet` recovery path.
    pub restore_height_hint: u32,
    /// Canonical 65-byte classical address — `version(1) || spend_pk(32)
    /// || view_pk(32)`. The envelope cross-checks this at open time
    /// against the address it would derive from `cap_content` under
    /// the declared `(network, seed_format)`.
    pub expected_classical_address: &'a [u8; EXPECTED_CLASSICAL_ADDRESS_BYTES],
    /// Argon2id cost parameters. `KdfParams::default()` gives the
    /// V3.0 OWASP-memory-constrained profile.
    pub kdf: KdfParams,
    /// Initial ledger state. A fresh wallet's ledger is usually
    /// [`WalletLedger::empty`], but the API accepts an arbitrary
    /// starting state so tests and restore flows can seed specific
    /// ledger shapes without a subsequent `save_state`.
    pub initial_ledger: &'a WalletLedger,
}

/// Opaque handle representing one opened wallet pair. Drop releases
/// the advisory lock.
///
/// `Debug` is hand-rolled to redact the cached keys-file bytes so the
/// sealed-but-AAD-visible fields never land in a panic message.
pub struct WalletFileHandle {
    keys_path: PathBuf,
    state_path: PathBuf,
    keys_file_bytes: Vec<u8>,
    opened_keys: Zeroizing<OpenedKeysFileOwned>,
    /// Held for Drop semantics; not read after construction.
    _lock: KeysFileLock,
}

impl std::fmt::Debug for WalletFileHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletFileHandle")
            .field("keys_path", &self.keys_path)
            .field("state_path", &self.state_path)
            .field("keys_file_bytes", &"<redacted>")
            .field("opened_keys", &"<redacted>")
            .field("_lock", &self._lock)
            .finish()
    }
}

/// `OpenedKeysFile` itself holds `Zeroizing` fields; we wrap the whole
/// thing in `Zeroizing` so on drop we overwrite the struct's bytes too.
/// Needed because `OpenedKeysFile` does not implement `ZeroizeOnDrop`
/// at the struct level (only its secret-bearing fields are wiped).
struct OpenedKeysFileOwned(OpenedKeysFile);

impl zeroize::Zeroize for OpenedKeysFileOwned {
    fn zeroize(&mut self) {
        // cap_content is Zeroizing<Vec<u8>> and wipes on drop already;
        // here we belt-and-braces zero the whole struct footprint for
        // any future secrets that land in it without a dedicated
        // Zeroize impl (e.g. if we added a [u8; 32] derived key).
        self.0.cap_content.zeroize();
        // Public-ish fields; zeroizing them avoids leaving any
        // fingerprint in memory snapshots.
        self.0.creation_timestamp = 0;
        self.0.restore_height_hint = 0;
        self.0.expected_classical_address.zeroize();
        self.0.seed_block_tag.zeroize();
    }
}

impl WalletFileHandle {
    /// Create a fresh wallet pair on disk.
    ///
    /// 1. Refuse if the keys file already exists.
    /// 2. Seal the keys file in memory and write it atomically.
    /// 3. Acquire the advisory lock on the newly-written keys file.
    /// 4. Seal the initial state file (keys bytes + SWSP-framed
    ///    postcard payload) and write it atomically.
    ///
    /// A crash between (2) and (4) leaves a `.wallet.keys` alone on
    /// disk; the next open will hit the lost-`.wallet` rescan path
    /// (2i).
    pub fn create(params: &CreateParams<'_>) -> Result<Self, WalletFileError> {
        let keys_path = keys_path_from(params.base_path);
        let state_path = state_path_from(params.base_path);

        if keys_path.exists() {
            return Err(WalletFileError::KeysFileAlreadyExists {
                path: keys_path.clone(),
            });
        }

        let keys_bytes = seal_keys_file(
            params.password,
            params.network,
            params.seed_format,
            params.capability,
            params.creation_timestamp,
            params.restore_height_hint,
            params.expected_classical_address,
            params.kdf,
        )?;

        atomic_write_file(&keys_path, &keys_bytes)?;

        let lock = KeysFileLock::acquire(&keys_path)?;

        let opened = open_keys_file(params.password, &keys_bytes)?;

        let body = params.initial_ledger.to_postcard_bytes()?;
        let framed = encode_payload(PayloadKind::WalletLedgerPostcard, &body)?;
        let state_bytes = seal_state_file(params.password, &keys_bytes, &framed)?;
        atomic_write_file(&state_path, &state_bytes)?;

        Ok(Self {
            keys_path,
            state_path,
            keys_file_bytes: keys_bytes,
            opened_keys: Zeroizing::new(OpenedKeysFileOwned(opened)),
            _lock: lock,
        })
    }

    /// Open an existing wallet pair. Returns the handle plus the
    /// current ledger snapshot.
    ///
    /// This commit implements the **happy path** only: both files
    /// present, envelope opens cleanly, SWSP frame valid, ledger
    /// decodes. Error branches (lost-`.wallet`, pre-v1 refusal,
    /// network mismatch, capability dispatch) are 2i's scope.
    pub fn open(
        base_path: &Path,
        password: &[u8],
    ) -> Result<(Self, WalletLedger), WalletFileError> {
        let keys_path = keys_path_from(base_path);
        let state_path = state_path_from(base_path);

        let lock = KeysFileLock::acquire(&keys_path)?;

        let keys_bytes = std::fs::read(&keys_path)?;
        let opened = open_keys_file(password, &keys_bytes)?;

        let state_bytes = std::fs::read(&state_path)?;
        let plaintext: Zeroizing<Vec<u8>> = open_state_file(password, &keys_bytes, &state_bytes)?;

        let framed = decode_payload(&plaintext)?;
        // Currently only one kind; `from_byte` has already rejected
        // anything else, so a `match` here would be a single arm. When
        // V3.1 introduces a second kind the dispatch will live here.
        let ledger = WalletLedger::from_postcard_bytes(framed.body)?;

        let handle = Self {
            keys_path,
            state_path,
            keys_file_bytes: keys_bytes,
            opened_keys: Zeroizing::new(OpenedKeysFileOwned(opened)),
            _lock: lock,
        };
        Ok((handle, ledger))
    }

    /// Rewrite `.wallet` with the given ledger state. Does **not**
    /// touch `.wallet.keys`; write-once is enforced by construction
    /// (the function physically never names that path as a write
    /// target) and belt-and-braces by the atomic-write helper.
    ///
    /// Requires the password on every call because the envelope's
    /// `seal_state_file` runs Argon2id to recover `file_kek` (no
    /// caching — see §4.3 of the spec).
    pub fn save_state(
        &self,
        password: &[u8],
        ledger: &WalletLedger,
    ) -> Result<(), WalletFileError> {
        let body = ledger.to_postcard_bytes()?;
        let framed = encode_payload(PayloadKind::WalletLedgerPostcard, &body)?;
        let state_bytes = seal_state_file(password, &self.keys_file_bytes, &framed)?;
        atomic_write_file(&self.state_path, &state_bytes)?;
        Ok(())
    }

    /// Rotate the wallet password. Rewrites `.wallet.keys` with a
    /// fresh wrap salt/nonce and re-encrypts `file_kek` under the new
    /// password; region 1 of `.wallet.keys` and every byte of
    /// `.wallet` remain byte-identical (see §4.2 of the spec).
    ///
    /// The handle's cached `keys_file_bytes` is updated so subsequent
    /// `save_state` calls use the rotated bytes (their tag of region 1
    /// is the same, so the anti-swap AAD binding to `.wallet` is
    /// unchanged).
    pub fn rotate_password(
        &mut self,
        old_password: &[u8],
        new_password: &[u8],
        new_kdf: Option<KdfParams>,
    ) -> Result<(), WalletFileError> {
        let new_keys_bytes =
            rewrap_keys_file_password(old_password, new_password, &self.keys_file_bytes, new_kdf)?;
        atomic_write_file(&self.keys_path, &new_keys_bytes)?;
        self.keys_file_bytes = new_keys_bytes;
        Ok(())
    }

    /// Path to the `.wallet.keys` file backing this handle.
    pub fn keys_path(&self) -> &Path {
        &self.keys_path
    }

    /// Path to the `.wallet` file backing this handle.
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// Read-only view of the decrypted keys-file metadata.
    pub fn opened_keys(&self) -> &OpenedKeysFile {
        &self.opened_keys.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN;
    use shekyl_wallet_state::WalletLedger;

    /// Build a reasonable `CreateParams`-input bundle. `view_sk`,
    /// `ml_kem_dk`, `spend_pk` are arbitrary bytes: the envelope layer
    /// does not interpret the capability content for VIEW_ONLY, so
    /// this is sufficient for orchestrator-level tests. End-to-end
    /// cryptographic correctness is covered by the envelope's own
    /// tests.
    struct Fixture {
        view_sk: [u8; 32],
        ml_kem_dk: [u8; ML_KEM_768_DK_LEN],
        spend_pk: [u8; 32],
        address: [u8; EXPECTED_CLASSICAL_ADDRESS_BYTES],
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                view_sk: [0x11; 32],
                ml_kem_dk: [0x22; ML_KEM_768_DK_LEN],
                spend_pk: [0x33; 32],
                address: {
                    let mut a = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
                    a[0] = 0x01; // version byte
                    a
                },
            }
        }

        fn capability(&self) -> CapabilityContent<'_> {
            CapabilityContent::ViewOnly {
                view_sk: &self.view_sk,
                ml_kem_dk: &self.ml_kem_dk,
                spend_pk: &self.spend_pk,
            }
        }

        fn fast_kdf() -> KdfParams {
            // KAT-profile Argon2id: 256 KiB, t=1, p=1. Production
            // wallets use the defaults; this shaves ~1s/test.
            KdfParams {
                m_log2: 0x08,
                t: 1,
                p: 1,
            }
        }
    }

    fn make_params<'a>(
        fx: &'a Fixture,
        base: &'a Path,
        password: &'a [u8],
        ledger: &'a WalletLedger,
        cap: &'a CapabilityContent<'a>,
    ) -> CreateParams<'a> {
        CreateParams {
            base_path: base,
            password,
            network: 0x01, // Testnet
            seed_format: 0x00,
            capability: cap,
            creation_timestamp: 0x6000_0000,
            restore_height_hint: 0,
            expected_classical_address: &fx.address,
            kdf: Fixture::fast_kdf(),
            initial_ledger: ledger,
        }
    }

    #[test]
    fn create_open_roundtrip_empty_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();

        let handle = {
            let params = make_params(&fx, &base, b"correct horse battery staple", &ledger, &cap);
            WalletFileHandle::create(&params).expect("create")
        };
        // Drop the handle so the advisory lock is released for open.
        drop(handle);

        let (handle2, ledger2) =
            WalletFileHandle::open(&base, b"correct horse battery staple").expect("open");
        assert_eq!(handle2.keys_path(), keys_path_from(&base));
        assert_eq!(handle2.state_path(), state_path_from(&base));
        assert_eq!(ledger2.format_version, ledger.format_version);
        assert_eq!(ledger2.ledger.block_version, ledger.ledger.block_version);
    }

    #[test]
    fn save_state_is_idempotent_across_handles() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();

        let handle = {
            let params = make_params(&fx, &base, b"pw", &ledger, &cap);
            WalletFileHandle::create(&params).expect("create")
        };
        handle.save_state(b"pw", &ledger).expect("save1");
        handle.save_state(b"pw", &ledger).expect("save2");
        drop(handle);

        let (_, ledger_back) = WalletFileHandle::open(&base, b"pw").expect("open");
        assert_eq!(ledger_back.format_version, ledger.format_version);
    }

    #[test]
    fn save_state_never_rewrites_keys_file() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();

        let handle = {
            let params = make_params(&fx, &base, b"pw", &ledger, &cap);
            WalletFileHandle::create(&params).expect("create")
        };

        let keys_before = std::fs::read(handle.keys_path()).unwrap();
        for _ in 0..8 {
            handle.save_state(b"pw", &ledger).expect("save");
        }
        let keys_after = std::fs::read(handle.keys_path()).unwrap();
        assert_eq!(
            keys_before, keys_after,
            "`.wallet.keys` bytes MUST be byte-identical across auto-saves"
        );
    }

    #[test]
    fn rotate_password_preserves_region1_and_state() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();

        let mut handle = {
            let params = make_params(&fx, &base, b"old", &ledger, &cap);
            WalletFileHandle::create(&params).expect("create")
        };

        let state_before = std::fs::read(handle.state_path()).unwrap();
        let keys_before = std::fs::read(handle.keys_path()).unwrap();

        handle
            .rotate_password(b"old", b"new", None)
            .expect("rotate");

        let keys_after = std::fs::read(handle.keys_path()).unwrap();
        let state_after = std::fs::read(handle.state_path()).unwrap();

        // Wrap layer changes; region 1 (nonce + ct + tag) stays.
        assert_ne!(
            &keys_before[30..54],
            &keys_after[30..54],
            "wrap_nonce/wrap_ct must change on rotation"
        );
        assert_eq!(
            &keys_before[102..],
            &keys_after[102..],
            "region 1 (nonce + ct + tag) must be byte-identical after rotation"
        );
        assert_eq!(
            state_before, state_after,
            "`.wallet` must be untouched by rotation"
        );

        // Drop the write-holding handle before re-opening.
        drop(handle);
        // Old password now rejected.
        assert!(WalletFileHandle::open(&base, b"old").is_err());
        // New password works.
        let (_, _) = WalletFileHandle::open(&base, b"new").expect("open-with-new-pw");
    }

    #[test]
    fn create_refuses_existing_keys_file() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();

        {
            let params = make_params(&fx, &base, b"pw", &ledger, &cap);
            WalletFileHandle::create(&params).expect("create1");
        }
        let params = make_params(&fx, &base, b"pw", &ledger, &cap);
        let err = WalletFileHandle::create(&params).expect_err("create2 must refuse");
        match err {
            WalletFileError::KeysFileAlreadyExists { path } => {
                assert_eq!(path, keys_path_from(&base));
            }
            other => panic!("expected KeysFileAlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn lock_is_released_on_handle_drop() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();

        {
            let params = make_params(&fx, &base, b"pw", &ledger, &cap);
            let _h = WalletFileHandle::create(&params).expect("create");
        }
        // Handle dropped; lock released. Re-open must succeed.
        let (_, _) = WalletFileHandle::open(&base, b"pw").expect("reopen");
    }

    #[test]
    fn second_open_while_first_holds_lock_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();

        let _first = {
            let params = make_params(&fx, &base, b"pw", &ledger, &cap);
            WalletFileHandle::create(&params).expect("create")
        };
        let err = WalletFileHandle::open(&base, b"pw").expect_err("second open must fail");
        match err {
            WalletFileError::AlreadyLocked { path } => {
                assert_eq!(path, keys_path_from(&base));
            }
            other => panic!("expected AlreadyLocked, got {other:?}"),
        }
    }
}
