// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `WalletFile`: high-level lifecycle for a Shekyl v1 wallet pair.
//!
//! This module assembles the primitives from [`crate::atomic`],
//! [`crate::lock`], [`crate::payload`], [`crate::paths`], and the
//! envelope layer in [`shekyl_crypto_pq::wallet_envelope`] into a
//! single opinionated API:
//!
//! ```text
//! WalletFile::create(base, password, …, initial_ledger) → Handle
//! WalletFile::open  (base, password)                    → (Handle, OpenOutcome)
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

use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use shekyl_address::Network;
use shekyl_crypto_pq::wallet_envelope::{
    open_keys_file, open_state_file, rewrap_keys_file_password, seal_keys_file, seal_state_file,
    CapabilityContent, KdfParams, OpenedKeysFile, EXPECTED_CLASSICAL_ADDRESS_BYTES,
};
use shekyl_engine_prefs::{
    load_prefs as prefs_load_prefs, save_prefs as prefs_save_prefs,
    LoadOutcome as PrefsLoadOutcome, PrefsHmacKey, WalletPrefs,
};
use shekyl_engine_state::{
    BookkeepingBlock, LedgerBlock, SyncStateBlock, TxMetaBlock, WalletLedger,
};

use crate::atomic::atomic_write_file;
use crate::capability::Capability;
use crate::error::WalletFileError;
use crate::lock::KeysFileLock;
use crate::overrides::SafetyOverrides;
use crate::paths::{keys_path_from, state_path_from};
use crate::payload::{decode_payload, encode_payload, PayloadKind};

/// Outcome of a successful [`WalletFile::open`]. The happy path
/// returns [`Self::StateLoaded`] with the ledger decoded from `.wallet`.
/// The lost-state recovery path ([`Self::StateLost`]) is returned when
/// `.wallet` is missing (`io::ErrorKind::NotFound`) but `.wallet.keys`
/// is intact; the caller receives a fresh empty ledger pre-seeded with
/// the rescan floor from the keys file, and is expected to drive a
/// full-history refresh and then `save_state` the rebuilt ledger.
///
/// # Recovery policy (2i-happy)
///
/// We trigger the rescan path **only** on `NotFound`. Other failure
/// modes (truncation, bad magic, AEAD-auth failure, seed-block
/// mismatch) refuse loudly — they indicate either tampering, a
/// corrupt disk, or a paired-with-wrong-keys scenario, and silently
/// discarding the state would mask the signal. 2i-errors will refine
/// this policy if we decide mid-write-crash truncation should also be
/// recoverable (see spec §4.4).
///
/// # Why not merge into `WalletLedger`?
///
/// We could overload by returning just `WalletLedger` and letting the
/// caller check `sync_state.scan_completed == false`. We don't,
/// because "scan_completed == false on a fresh empty ledger" is
/// indistinguishable from "scan_completed == false because this wallet
/// is still doing its initial sync". The discriminator here is
/// structural (did we load state from disk, or seed it?), not
/// state-derived.
#[derive(Debug)]
pub enum OpenOutcome {
    /// `.wallet` was present and decoded successfully. The ledger is
    /// the caller's persisted state.
    StateLoaded(WalletLedger),

    /// `.wallet` was missing. A fresh ledger has been constructed with
    /// `sync_state.restore_from_height` set from the keys file's
    /// `restore_height_hint`. The caller should:
    ///
    /// 1. Treat in-memory state as empty (no transfers, no
    ///    bookkeeping).
    /// 2. Start a rescan from `restore_from_height`.
    /// 3. Persist the rebuilt ledger via [`WalletFile::save_state`].
    StateLost {
        ledger: WalletLedger,
        restore_from_height: u64,
    },
}

impl OpenOutcome {
    /// Borrow the ledger regardless of which branch fired. Convenient
    /// for call sites that only want the state and will separately
    /// check [`Self::is_lost`] to decide whether to kick off a rescan.
    pub fn ledger(&self) -> &WalletLedger {
        match self {
            Self::StateLoaded(l) | Self::StateLost { ledger: l, .. } => l,
        }
    }

    /// Consume the outcome and return the ledger, discarding the
    /// recovery-path signal. Use only if you really don't need to
    /// distinguish the two cases.
    pub fn into_ledger(self) -> WalletLedger {
        match self {
            Self::StateLoaded(l) | Self::StateLost { ledger: l, .. } => l,
        }
    }

    /// True when the state file was missing and a rescan is required.
    pub fn is_lost(&self) -> bool {
        matches!(self, Self::StateLost { .. })
    }
}

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
    /// Network binding for the wallet. Persisted in the envelope's
    /// AAD and cross-checked by [`WalletFile::open`] against the
    /// caller-supplied `expected_network`, so a wallet bound to one
    /// chain can never be silently opened as another.
    pub network: Network,
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
pub struct WalletFile {
    keys_path: PathBuf,
    state_path: PathBuf,
    keys_file_bytes: Vec<u8>,
    opened_keys: Zeroizing<OpenedKeysFileOwned>,
    /// Decoded once at open/create time so the public `network()` and
    /// `capability()` accessors can be infallible.
    network: Network,
    capability: Capability,
    /// CLI-ephemeral overrides applied at this `open`. Die with the
    /// handle; never persisted. `create` seeds this with
    /// [`SafetyOverrides::none`] because `create` is a provisioning
    /// operation, not a user-facing session start.
    overrides: SafetyOverrides,
    /// HMAC key for the per-wallet `prefs.toml.hmac` companion file,
    /// derived once at open/create time from `file_kek` and
    /// `expected_classical_address` under HKDF-Expand per
    /// `docs/WALLET_PREFS.md §2.2`. Cached for the session so each
    /// `load_prefs` / `save_prefs` avoids a second Argon2id run.
    /// Zeroized on drop via [`PrefsHmacKey`]'s `Zeroizing<[u8; 32]>`
    /// interior; callers never see the raw bytes.
    prefs_hmac_key: PrefsHmacKey,
    /// Held for Drop semantics; not read after construction.
    _lock: KeysFileLock,
}

impl std::fmt::Debug for WalletFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletFile")
            .field("keys_path", &self.keys_path)
            .field("state_path", &self.state_path)
            .field("keys_file_bytes", &"<redacted>")
            .field("opened_keys", &"<redacted>")
            .field("network", &self.network)
            .field("capability", &self.capability)
            .field("overrides", &self.overrides)
            .field("prefs_hmac_key", &self.prefs_hmac_key)
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
        // `file_kek` is the 32-byte key that decrypts region 1 and
        // every `.wallet`. Its `Zeroizing<[u8; 32]>` container already
        // wipes on drop; this extra call zeroes the bytes eagerly so
        // they do not linger between the "we're done with the handle"
        // signal and the actual struct drop. Belt-and-braces, matches
        // `cap_content` above.
        self.0.file_kek.zeroize();
    }
}

impl WalletFile {
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
            params.network.as_u8(),
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
        // Re-decode from `opened` rather than trusting `params.network`
        // so the handle reflects exactly what the AAD says — if the
        // envelope ever silently drops the byte, we find out here
        // instead of when a cross-chain bug lands in production.
        let network = decode_network(opened.network)?;
        let capability = Capability::from_envelope_byte(opened.capability_mode)?;
        debug_assert_eq!(
            network, params.network,
            "envelope round-trip must preserve the network byte"
        );

        let body = params.initial_ledger.to_postcard_bytes()?;
        let framed = encode_payload(PayloadKind::WalletLedgerPostcard, &body)?;
        let state_bytes = seal_state_file(params.password, &keys_bytes, &framed)?;
        atomic_write_file(&state_path, &state_bytes)?;

        // Derive the prefs HMAC key once so every subsequent
        // `load_prefs`/`save_prefs` on this handle avoids re-running
        // the envelope's Argon2id wrap. See `docs/WALLET_PREFS.md §2.2`
        // for the derivation formula and security argument.
        let prefs_hmac_key =
            PrefsHmacKey::derive(&opened.file_kek, &opened.expected_classical_address);

        Ok(Self {
            keys_path,
            state_path,
            keys_file_bytes: keys_bytes,
            opened_keys: Zeroizing::new(OpenedKeysFileOwned(opened)),
            network,
            capability,
            // Provisioning path: no user session → no overrides.
            overrides: SafetyOverrides::none(),
            prefs_hmac_key,
            _lock: lock,
        })
    }

    /// Open an existing wallet pair. Returns the handle plus an
    /// [`OpenOutcome`] that tells the caller whether the state file
    /// was loaded from disk or synthesized because `.wallet` was
    /// missing.
    ///
    /// # Network binding
    ///
    /// `expected_network` is enforced against the AAD-committed network
    /// byte in the keys file. A mismatch returns
    /// [`WalletFileError::NetworkMismatch`] **before** `.wallet` is
    /// read, so a misfiled testnet wallet can never be accidentally
    /// served as mainnet (or vice versa).
    ///
    /// # Recovery scope (2i-happy)
    ///
    /// The only recovery trigger in this commit is `.wallet` returning
    /// `io::ErrorKind::NotFound`. That one case is handled by
    /// constructing a fresh [`WalletLedger`] whose sync-state block
    /// has `restore_from_height` populated from the keys-file's
    /// `restore_height_hint` (widened from `u32` to `u64` because the
    /// sync-state block uses the wider type for long-term chain-height
    /// headroom).
    ///
    /// Other failure modes — truncated `.wallet`, bad magic,
    /// AEAD-auth failure, seed-block mismatch — refuse loudly. A
    /// silent rescan on AEAD-auth-failed bytes would mask tampering;
    /// a silent rescan on bad magic would mask a misfiled companion
    /// file.
    ///
    /// # Safety overrides
    ///
    /// `overrides` supplies the CLI-ephemeral layer of the three-layer
    /// preference model (see `docs/WALLET_PREFS.md` §2.3). The struct
    /// is `Copy` and stored on the handle for the session. GUI callers
    /// pass [`SafetyOverrides::none`]. CLI callers may pass a
    /// non-empty struct; on open, every active field produces a
    /// `tracing::warn!` line naming the field, the override value,
    /// and the network default, so operators running under any
    /// subscriber see the deviation loudly.
    pub fn open(
        base_path: &Path,
        password: &[u8],
        expected_network: Network,
        overrides: SafetyOverrides,
    ) -> Result<(Self, OpenOutcome), WalletFileError> {
        let keys_path = keys_path_from(base_path);
        let state_path = state_path_from(base_path);

        let lock = KeysFileLock::acquire(&keys_path)?;

        let keys_bytes = std::fs::read(&keys_path)?;
        let opened = open_keys_file(password, &keys_bytes)?;

        // Network-mismatch refusal happens BEFORE `.wallet` is touched
        // so we don't spend an Argon2id derivation on a wallet we
        // already know we will refuse. Also avoids any possibility of
        // a cross-chain `.wallet` being even speculatively considered.
        let network = decode_network(opened.network)?;
        if network != expected_network {
            return Err(WalletFileError::NetworkMismatch {
                expected: expected_network,
                found: network,
            });
        }
        let capability = Capability::from_envelope_byte(opened.capability_mode)?;

        let outcome = match std::fs::read(&state_path) {
            Ok(state_bytes) => {
                let plaintext: Zeroizing<Vec<u8>> =
                    open_state_file(password, &keys_bytes, &state_bytes)?;
                let framed = decode_payload(&plaintext)?;
                // Currently only one kind; `from_byte` has already rejected
                // anything else, so a `match` here would be a single arm.
                // When V3.1 introduces a second kind the dispatch will
                // live here.
                let ledger = WalletLedger::from_postcard_bytes(framed.body)?;
                OpenOutcome::StateLoaded(ledger)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let restore_from_height = u64::from(opened.restore_height_hint);
                tracing::warn!(
                    target: "shekyl_engine_file",
                    state_path = %state_path.display(),
                    restore_from_height,
                    "state cache missing; rebuilding ledger from chain from restore_height_hint"
                );
                let ledger = WalletLedger::new(
                    LedgerBlock::empty(),
                    BookkeepingBlock::empty(),
                    TxMetaBlock::empty(),
                    SyncStateBlock::new(restore_from_height, None),
                );
                OpenOutcome::StateLost {
                    ledger,
                    restore_from_height,
                }
            }
            Err(e) => return Err(WalletFileError::Io(e)),
        };

        // Emit WARN lines for any active override before returning
        // so the session log unambiguously records the deviation
        // regardless of what the caller does next.
        overrides.log_warn_if_active(network);

        // Derive the prefs HMAC key once from the envelope's
        // `file_kek` and `expected_classical_address`; cache for the
        // session so prefs I/O does not pay Argon2id per call.
        let prefs_hmac_key =
            PrefsHmacKey::derive(&opened.file_kek, &opened.expected_classical_address);

        let handle = Self {
            keys_path,
            state_path,
            keys_file_bytes: keys_bytes,
            opened_keys: Zeroizing::new(OpenedKeysFileOwned(opened)),
            network,
            capability,
            overrides,
            prefs_hmac_key,
            _lock: lock,
        };
        Ok((handle, outcome))
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
        // Aggregator-level invariants fire BEFORE we spend an
        // Argon2id derivation on the write path. Debug builds route
        // through `debug_assert!` so test runs abort loudly with the
        // full panic message; release builds return the typed error
        // so a live-user save cannot panic.
        ledger.preflight_save()?;
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

    /// Relocate the wallet pair to a new base path, atomically within
    /// a single filesystem.
    ///
    /// # Operation
    ///
    /// 1. Refuse if either target path (`<new_base>.keys` or
    ///    `<new_base>`) already exists. Mirrors the write-once posture
    ///    of [`Self::create`]; the caller (CLI / GUI) is expected to
    ///    confirm overwrite-intent before reaching this layer.
    /// 2. Pre-flight cross-filesystem check (POSIX `st_dev`
    ///    comparison): if the target's parent directory lives on a
    ///    different filesystem from the current keys file, return
    ///    [`WalletFileError::SaveAsCrossFilesystem`] **before** any
    ///    on-disk mutation. `rename(2)` is atomic only within a single
    ///    filesystem, and a fallback copy + fsync + unlink dance would
    ///    have an observable window where the file exists at both
    ///    locations or neither — we refuse that silently.
    /// 3. Pre-encode the state file (preflight invariants + postcard +
    ///    SWSP frame + AEAD seal) so a failure here leaves the original
    ///    pair untouched.
    /// 4. `rename(self.keys_path, new_keys_path)`. Atomic. The advisory
    ///    lock follows the open file description through the rename
    ///    (POSIX `flock(2)` is per-OFD, Windows `LockFileEx` is per-
    ///    handle), so we do **not** need to release-and-reacquire.
    ///    `EXDEV` is converted to
    ///    [`WalletFileError::SaveAsCrossFilesystem`] defensively; a
    ///    well-behaved pre-flight should have caught it already, but
    ///    layered filesystems (overlayfs, bind mounts) can fool the
    ///    `st_dev` comparison.
    /// 5. Atomically write the new state file at `new_state_path`.
    /// 6. Best-effort delete the original state file. A failure here is
    ///    surfaced as a `tracing::warn!` (the wallet is correctly
    ///    relocated; the old file is just stranded clutter).
    /// 7. Update `self.keys_path` and `self.state_path` to the new
    ///    locations.
    ///
    /// On any failure between steps 4 and 5 the wallet is partially
    /// relocated: keys at new path, state at old path. The next open
    /// from the new base path triggers the lost-`.wallet` recovery
    /// flow (2i-happy), which rebuilds state from a rescan; the next
    /// open from the old base path fails with "keys file missing"
    /// because the file was in fact renamed. Both outcomes are safe.
    ///
    /// # Password
    ///
    /// `password` is the wallet's *current* password. It is required
    /// because `seal_state_file` runs Argon2id on every save and the
    /// handle does not cache the password (see §4.3 of the spec). Use
    /// [`Self::rotate_password`] separately if you also want to change
    /// the password — `save_as` does not couple the two.
    ///
    /// # Companion files
    ///
    /// `<base>.address.txt` and `<base>.prefs.toml` are **not**
    /// relocated by this method. The address file is a UX cosmetic
    /// regenerated on demand by the caller; the prefs file is the
    /// caller's responsibility to copy or rewrite. We deliberately
    /// keep `save_as` tightly scoped to the canonical wallet pair so
    /// the atomicity guarantee is precise.
    pub fn save_as(
        &mut self,
        new_base_path: &Path,
        password: &[u8],
        ledger: &WalletLedger,
    ) -> Result<(), WalletFileError> {
        let new_keys_path = keys_path_from(new_base_path);
        let new_state_path = state_path_from(new_base_path);

        if new_keys_path.exists() {
            return Err(WalletFileError::SaveAsTargetExists {
                path: new_keys_path,
            });
        }
        if new_state_path.exists() {
            return Err(WalletFileError::SaveAsTargetExists {
                path: new_state_path,
            });
        }

        // Pre-flight cross-fs detection. Returns `Ok(())` on POSIX when
        // the source and target's parent live on the same `st_dev`;
        // returns `Ok(())` on Windows after a best-effort drive-letter
        // comparison (the `EXDEV` translation in step 4 is the safety
        // net for cases the pre-flight cannot catch).
        cross_fs_preflight(&self.keys_path, &new_keys_path)?;

        // Pre-encode so a failure during postcard/seal does NOT leave
        // the pair half-relocated.
        ledger.preflight_save()?;
        let body = ledger.to_postcard_bytes()?;
        let framed = encode_payload(PayloadKind::WalletLedgerPostcard, &body)?;
        let state_bytes = seal_state_file(password, &self.keys_file_bytes, &framed)?;

        // Step 4: rename keys file. Atomic within a filesystem; the
        // advisory lock survives the rename (per-OFD on POSIX, per-
        // handle on Windows). `EXDEV` translation is the belt-and-
        // suspenders for layered filesystems whose `st_dev` lies.
        match std::fs::rename(&self.keys_path, &new_keys_path) {
            Ok(()) => {}
            Err(e) if is_cross_device_error(&e) => {
                return Err(WalletFileError::SaveAsCrossFilesystem {
                    from_path: self.keys_path.clone(),
                    target: new_keys_path,
                });
            }
            Err(e) => {
                return Err(WalletFileError::AtomicWriteRename {
                    target: new_keys_path,
                    source: e,
                });
            }
        }

        // Step 5: write new state file atomically.
        atomic_write_file(&new_state_path, &state_bytes)?;

        // Step 6: best-effort cleanup of stranded old state file.
        match std::fs::remove_file(&self.state_path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    target: "shekyl_engine_file",
                    old_state_path = %self.state_path.display(),
                    error = %e,
                    "save_as: failed to remove stranded old state file; safe to delete manually",
                );
            }
        }

        // Step 7: update internal bookkeeping. The lock's stored path
        // still references the old location for diagnostics — that is
        // intentional clutter; the OFD itself is the authoritative
        // lock holder.
        self.keys_path = new_keys_path;
        self.state_path = new_state_path;

        Ok(())
    }

    /// Load the wallet's user preferences from the co-located
    /// `<base>.prefs.toml` / `<base>.prefs.toml.hmac` pair, verifying
    /// the HMAC with the session-cached [`PrefsHmacKey`]. The
    /// advisory failure policy in `docs/WALLET_PREFS.md §5` applies:
    ///
    /// * Files absent → [`PrefsLoadOutcome::Missing`] + defaults.
    /// * Files present & verified → [`PrefsLoadOutcome::Loaded`] with
    ///   the parsed [`WalletPrefs`].
    /// * HMAC mismatch, oversize body, parse failure, Bucket-3
    ///   collision → offenders are quarantined to
    ///   `<orig>.tampered-<unix_secs>[.N]`, a `WARN` line is logged,
    ///   and [`PrefsLoadOutcome::Tampered`] is returned carrying
    ///   defaults. Callers can surface the tamper event in the UI
    ///   without treating it as a refuse-to-open.
    ///
    /// Only hard errors (I/O failure, internal HMAC-length bug) are
    /// surfaced as [`WalletFileError`]; every advisory tamper
    /// signal folds into the `LoadOutcome::Tampered` arm so the
    /// wallet still opens.
    pub fn load_prefs(&self) -> Result<PrefsLoadOutcome, WalletFileError> {
        let outcome = prefs_load_prefs(&self.state_path, &self.prefs_hmac_key)?;
        Ok(outcome)
    }

    /// Persist `prefs` to `<base>.prefs.toml` + `<base>.prefs.toml.hmac`.
    /// Both files are written atomically (tmp → fsync → rename →
    /// fsync(parent)); the TOML body is HMACed with the
    /// session-cached key. A crash between the two renames leaves a
    /// body-without-matching-HMAC which the next `load_prefs` treats
    /// as a tamper event and quarantines — the same code path as an
    /// attacker-tampered file.
    ///
    /// # Errors
    ///
    /// * [`WalletFileError::Prefs`] — serialization failure (shouldn't
    ///   happen for `WalletPrefs`'s built-in schema), HMAC-length bug,
    ///   or Bucket-3 field slipped through an earlier parser.
    /// * [`WalletFileError::Io`] / [`WalletFileError::AtomicWriteRename`]
    ///   — filesystem failures are currently surfaced via the
    ///   prefs crate's own `PrefsError::Io`; callers should treat
    ///   both variants as "try again later / check disk".
    pub fn save_prefs(&self, prefs: &WalletPrefs) -> Result<(), WalletFileError> {
        prefs_save_prefs(&self.state_path, &self.prefs_hmac_key, prefs)?;
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

    /// Network this wallet is bound to. Decoded once at open/create
    /// time; never fails. Callers should branch on this value (rather
    /// than re-decoding `opened_keys().network`) so the dependency on
    /// the envelope's byte layout stays contained in one place.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Capability profile of this wallet (`Full` / `ViewOnly` /
    /// `HardwareOffload`). Decoded once at open/create time. Callers
    /// driving UX should use [`Capability::can_spend_locally`] instead
    /// of matching against `Capability::Full` directly, so future
    /// capability variants do not silently disable the spend path.
    pub fn capability(&self) -> Capability {
        self.capability
    }

    /// Canonical 65-byte classical address committed in the keys
    /// file's AAD (`version(1) || spend_pk(32) || view_pk(32)`).
    /// Stable for the wallet's lifetime.
    pub fn expected_classical_address(&self) -> &[u8; EXPECTED_CLASSICAL_ADDRESS_BYTES] {
        &self.opened_keys.0.expected_classical_address
    }

    /// Unix-epoch seconds at wallet creation. Persisted in the AAD so
    /// the UX can display "Engine created on …" without trusting the
    /// state file.
    pub fn creation_timestamp(&self) -> u64 {
        self.opened_keys.0.creation_timestamp
    }

    /// Block-height floor for full-history rescans. Also the value
    /// seeded into [`crate::OpenOutcome::StateLost::restore_from_height`]
    /// on the lost-`.wallet` recovery path.
    pub fn restore_height_hint(&self) -> u32 {
        self.opened_keys.0.restore_height_hint
    }

    /// Raw CLI-ephemeral overrides captured at `open` time. Callers
    /// typically do not need this — prefer the `effective_*`
    /// accessors below, which already overlay the overrides on the
    /// per-network defaults. Exposed for diagnostics, dry-run tools,
    /// and for the FFI layer to surface "any override active?" to C++.
    pub fn overrides(&self) -> SafetyOverrides {
        self.overrides
    }

    /// Minimum confirmations before a transfer is treated as final.
    /// Equals [`NetworkSafetyConstants::max_reorg_depth`] for the
    /// handle's network unless a CLI override replaced it for this
    /// session.
    ///
    /// [`NetworkSafetyConstants::max_reorg_depth`]: shekyl_engine_state::NetworkSafetyConstants::max_reorg_depth
    pub fn effective_max_reorg_depth(&self) -> u64 {
        self.overrides.effective_max_reorg_depth(self.network)
    }

    /// Starting height for a from-scratch scan. Applies only on paths
    /// that do not have a persisted `SyncStateBlock` to anchor them
    /// (fresh wallet, lost-`.wallet` recovery, explicit rescan).
    /// See `docs/WALLET_PREFS.md` §3.3.
    pub fn effective_skip_to_height(&self) -> u64 {
        self.overrides.effective_skip_to_height(self.network)
    }

    /// Refresh cursor used when the wallet opens without a
    /// `SyncStateBlock`. Mirrors `effective_skip_to_height` but
    /// scoped to the recovery path per the audit doc §3.3.
    pub fn effective_refresh_from_block_height(&self) -> u64 {
        self.overrides
            .effective_refresh_from_block_height(self.network)
    }
}

/// Decode the envelope's raw network byte into a typed [`Network`].
///
/// Extracted as a free function so both `create` (which re-validates
/// the byte that just went through `seal_keys_file`) and `open` (which
/// vets a byte read from disk) share one implementation, keeping the
/// defensive-decode path auditable in a single place.
fn decode_network(v: u8) -> Result<Network, WalletFileError> {
    Network::from_u8(v).ok_or(WalletFileError::UnknownNetwork(v))
}

/// Best-effort pre-flight detection of a cross-filesystem `save_as`
/// before any on-disk mutation. POSIX uses `st_dev` comparison via the
/// safe [`std::os::unix::fs::MetadataExt`] trait. Windows compares the
/// path roots (drive letter / UNC prefix) as a coarse approximation —
/// the rename's `EXDEV` translation in `save_as` is the safety net for
/// cases this approximation cannot detect.
///
/// Returns `Ok(())` when the source and target are believed to live on
/// the same filesystem. Returns
/// [`WalletFileError::SaveAsCrossFilesystem`] when they are known to
/// differ. I/O failures (e.g. parent directory missing) are surfaced as
/// [`WalletFileError::Io`].
fn cross_fs_preflight(source: &Path, target: &Path) -> Result<(), WalletFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let target_parent = target.parent().ok_or_else(|| {
            WalletFileError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "save_as target has no parent directory: {}",
                    target.display()
                ),
            ))
        })?;
        let src_dev = std::fs::metadata(source)?.dev();
        let dst_dev = std::fs::metadata(target_parent)?.dev();
        if src_dev != dst_dev {
            return Err(WalletFileError::SaveAsCrossFilesystem {
                from_path: source.to_path_buf(),
                target: target.to_path_buf(),
            });
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        // Windows: compare the first path component (drive letter or
        // UNC server share). This is a deliberately coarse check; the
        // safety net is the rename's `ERROR_NOT_SAME_DEVICE` (17)
        // translation in `is_cross_device_error`.
        let src_root = source.components().next();
        let dst_root = target.components().next();
        if src_root != dst_root {
            return Err(WalletFileError::SaveAsCrossFilesystem {
                from_path: source.to_path_buf(),
                target: target.to_path_buf(),
            });
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    {
        // Unknown platform: skip pre-flight; rely on the `EXDEV`
        // translation in `is_cross_device_error` after the rename
        // attempt.
        let _ = (source, target);
        Ok(())
    }
}

/// Translate a `rename(2)` `io::Error` into the cross-filesystem
/// signal. POSIX `EXDEV` is `18` on Linux/macOS/FreeBSD; Windows
/// `ERROR_NOT_SAME_DEVICE` is `17`. The standard library does not yet
/// stabilize a portable `io::ErrorKind::CrossesDevices`, so we match
/// `raw_os_error()` directly.
fn is_cross_device_error(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        // `EXDEV = 18` on every Unix we support (Linux, macOS, FreeBSD).
        e.raw_os_error() == Some(18)
    }
    #[cfg(windows)]
    {
        // `ERROR_NOT_SAME_DEVICE = 17`.
        e.raw_os_error() == Some(17)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = e;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN;
    use shekyl_engine_state::WalletLedger;

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

    /// Default network used by every test that does not exercise the
    /// network-binding logic directly. Kept as a module-level `const`
    /// so a sweep over all tests reveals exactly which ones care about
    /// the value (grep for `TEST_NETWORK`).
    const TEST_NETWORK: Network = Network::Testnet;

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
            network: TEST_NETWORK,
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
            WalletFile::create(&params).expect("create")
        };
        // Drop the handle so the advisory lock is released for open.
        drop(handle);

        let (handle2, outcome) = WalletFile::open(
            &base,
            b"correct horse battery staple",
            TEST_NETWORK,
            SafetyOverrides::none(),
        )
        .expect("open");
        assert_eq!(handle2.keys_path(), keys_path_from(&base));
        assert_eq!(handle2.state_path(), state_path_from(&base));
        assert!(
            !outcome.is_lost(),
            "fresh create→open must go through StateLoaded"
        );
        let ledger2 = outcome.into_ledger();
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
            WalletFile::create(&params).expect("create")
        };
        handle.save_state(b"pw", &ledger).expect("save1");
        handle.save_state(b"pw", &ledger).expect("save2");
        drop(handle);

        let (_, outcome) =
            WalletFile::open(&base, b"pw", TEST_NETWORK, SafetyOverrides::none()).expect("open");
        let ledger_back = outcome.into_ledger();
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
            WalletFile::create(&params).expect("create")
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
            WalletFile::create(&params).expect("create")
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
        assert!(WalletFile::open(&base, b"old", TEST_NETWORK, SafetyOverrides::none()).is_err());
        // New password works.
        let (_, _) = WalletFile::open(&base, b"new", TEST_NETWORK, SafetyOverrides::none())
            .expect("open-with-new-pw");
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
            WalletFile::create(&params).expect("create1");
        }
        let params = make_params(&fx, &base, b"pw", &ledger, &cap);
        let err = WalletFile::create(&params).expect_err("create2 must refuse");
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
            let _h = WalletFile::create(&params).expect("create");
        }
        // Handle dropped; lock released. Re-open must succeed.
        let (_, _) =
            WalletFile::open(&base, b"pw", TEST_NETWORK, SafetyOverrides::none()).expect("reopen");
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
            WalletFile::create(&params).expect("create")
        };
        let err = WalletFile::open(&base, b"pw", TEST_NETWORK, SafetyOverrides::none())
            .expect_err("second open must fail");
        match err {
            WalletFileError::AlreadyLocked { path } => {
                assert_eq!(path, keys_path_from(&base));
            }
            other => panic!("expected AlreadyLocked, got {other:?}"),
        }
    }

    /// Recovery path per spec §4.5: `.wallet.keys` is intact but
    /// `.wallet` is missing. We should return `StateLost` with a
    /// fresh empty ledger whose `restore_from_height` matches the
    /// keys-file's `restore_height_hint` (widened u32→u64).
    #[test]
    fn open_with_missing_state_returns_lost() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();

        const RESTORE_HINT: u32 = 1_234_567;
        {
            let mut params = make_params(&fx, &base, b"pw", &ledger, &cap);
            params.restore_height_hint = RESTORE_HINT;
            let _h = WalletFile::create(&params).expect("create");
        }
        // Kill the state file; keys file remains.
        let state_path = state_path_from(&base);
        std::fs::remove_file(&state_path).expect("remove .wallet");
        assert!(keys_path_from(&base).exists(), "keys file must still exist");
        assert!(!state_path.exists(), ".wallet must be gone");

        let (_handle, outcome) =
            WalletFile::open(&base, b"pw", TEST_NETWORK, SafetyOverrides::none()).expect("open");
        match outcome {
            OpenOutcome::StateLost {
                ledger,
                restore_from_height,
            } => {
                assert_eq!(restore_from_height, u64::from(RESTORE_HINT));
                assert_eq!(
                    ledger.sync_state.restore_from_height,
                    u64::from(RESTORE_HINT),
                    "fresh ledger must inherit restore_height_hint from keys file"
                );
                // Fresh ledger: no transfers, no tx_meta, no bookkeeping.
                assert!(ledger.ledger.transfers.is_empty());
                assert!(ledger.tx_meta.tx_keys.is_empty());
                assert!(ledger.bookkeeping.subaddress_labels.per_index.is_empty());
                assert!(!ledger.sync_state.scan_completed);
            }
            OpenOutcome::StateLoaded(_) => panic!("expected StateLost for missing .wallet"),
        }
    }

    /// After a rescan-recovery open, calling `save_state` must
    /// successfully write a fresh `.wallet`, which is then readable on
    /// the next open as a normal `StateLoaded`.
    #[test]
    fn save_after_state_lost_persists_and_reopens_as_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();

        {
            let params = make_params(&fx, &base, b"pw", &ledger, &cap);
            let _h = WalletFile::create(&params).expect("create");
        }
        std::fs::remove_file(state_path_from(&base)).expect("remove .wallet");

        let rebuilt = {
            let (handle, outcome) =
                WalletFile::open(&base, b"pw", TEST_NETWORK, SafetyOverrides::none())
                    .expect("open-lost");
            assert!(outcome.is_lost());
            let ledger = outcome.into_ledger();
            handle.save_state(b"pw", &ledger).expect("save");
            ledger
        };

        let (_handle, outcome) =
            WalletFile::open(&base, b"pw", TEST_NETWORK, SafetyOverrides::none())
                .expect("open-loaded");
        assert!(!outcome.is_lost(), "after save, open must see StateLoaded");
        let reloaded = outcome.into_ledger();
        assert_eq!(reloaded.format_version, rebuilt.format_version);
        assert_eq!(
            reloaded.sync_state.restore_from_height,
            rebuilt.sync_state.restore_from_height,
        );
    }

    /// A truncated `.wallet` (exists but too short for the envelope
    /// header) is **not** treated as a recovery trigger in 2i-happy.
    /// The envelope's `TooShort` error is surfaced loudly so the user
    /// can decide whether this is a mid-write crash (spec §4.4, which
    /// 2i-errors may decide to auto-recover) or disk corruption. This
    /// test pins the current conservative policy.
    #[test]
    fn truncated_state_file_refuses_not_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();

        {
            let params = make_params(&fx, &base, b"pw", &ledger, &cap);
            let _h = WalletFile::create(&params).expect("create");
        }
        std::fs::write(state_path_from(&base), b"\x00\x00\x00").expect("truncate .wallet");

        let err = WalletFile::open(&base, b"pw", TEST_NETWORK, SafetyOverrides::none())
            .expect_err("must refuse");
        match err {
            WalletFileError::Envelope(_) => { /* expected: TooShort / BadMagic surfaced */ }
            other => panic!(
                "expected Envelope refusal on truncated .wallet, got {other:?} \
                 (recovery policy must not silently swallow tampered/corrupt bytes)"
            ),
        }
    }

    /// 2i-errors / pre-v1 refusal: a file at the keys path whose bytes
    /// don't start with `SHEKYLWT` must surface the envelope's
    /// `BadMagic` unchanged. Callers below the handle (FFI, C++ glue)
    /// rely on this one-to-one mapping to render a "this is not a
    /// Shekyl v1 wallet" message rather than masking it as a generic
    /// I/O error.
    #[test]
    fn open_refuses_non_shekyl_magic() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("garbage.wallet");
        // Write a wrong-magic file at the keys path long enough to
        // clear the envelope's `expect_at_least(OFF_REGION1_CT)`
        // length-floor check, so the failure path we exercise here is
        // specifically the magic check ("this file is well-sized but
        // is not a Shekyl v1 wallet") and not a generic TooShort on
        // an obviously-truncated input. 512 bytes is well past
        // `OFF_REGION1_CT`.
        let mut garbage = vec![0u8; 512];
        garbage[..8].copy_from_slice(b"NOTSHEKY");
        std::fs::write(keys_path_from(&base), &garbage).expect("write garbage keys file");

        let err = WalletFile::open(&base, b"pw", TEST_NETWORK, SafetyOverrides::none())
            .expect_err("non-Shekyl magic must be refused");
        match err {
            WalletFileError::Envelope(e) => {
                // Envelope crate's error taxonomy: `BadMagic` is the
                // canonical "this is not a Shekyl v1 wallet" signal.
                // We match on the Display string rather than the enum
                // to avoid coupling this crate's tests to every
                // future variant of `WalletEnvelopeError`.
                let msg = e.to_string();
                assert!(
                    msg.contains("magic"),
                    "expected envelope error to mention magic mismatch, got: {msg}"
                );
            }
            other => panic!("expected Envelope(BadMagic), got {other:?}"),
        }
    }

    /// 2i-errors / network-mismatch: a keys file created on one
    /// network must be refused when `open` is called with any other
    /// network, **before** `.wallet` is touched (so a cross-chain
    /// `.wallet` cannot be even speculatively considered).
    #[test]
    fn open_refuses_network_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();

        // Create bound to Testnet (via `make_params`), then try to
        // open it as Mainnet.
        {
            let params = make_params(&fx, &base, b"pw", &ledger, &cap);
            assert_eq!(params.network, Network::Testnet, "fixture precondition");
            let _h = WalletFile::create(&params).expect("create");
        }
        let err = WalletFile::open(&base, b"pw", Network::Mainnet, SafetyOverrides::none())
            .expect_err("mainnet open of testnet wallet must refuse");
        match err {
            WalletFileError::NetworkMismatch { expected, found } => {
                assert_eq!(expected, Network::Mainnet);
                assert_eq!(found, Network::Testnet);
            }
            other => panic!("expected NetworkMismatch, got {other:?}"),
        }
    }

    /// 2i-errors / capability dispatch: a `ViewOnly` wallet (the
    /// default fixture) must expose `Capability::ViewOnly` via the
    /// accessor, and `can_spend_locally()` must return `false`. This
    /// pins the contract that the FFI "should I show a send button?"
    /// predicate relies on.
    #[test]
    fn handle_exposes_view_only_capability_and_network() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();

        let handle = {
            let params = make_params(&fx, &base, b"pw", &ledger, &cap);
            WalletFile::create(&params).expect("create")
        };
        assert_eq!(handle.capability(), Capability::ViewOnly);
        assert!(!handle.capability().can_spend_locally());
        assert_eq!(handle.network(), TEST_NETWORK);
        assert_eq!(handle.creation_timestamp(), 0x6000_0000);
        assert_eq!(handle.restore_height_hint(), 0);
        assert_eq!(handle.expected_classical_address()[0], 0x01);
    }

    /// Capability dispatch entry point: `can_spend_locally` must be
    /// the single source of truth for "is this wallet allowed to
    /// produce a signature on-device?" Future capability variants
    /// (multisig quorum, offload devices, hardware signers) must
    /// extend this predicate instead of forcing every call site to
    /// pattern-match raw variants.
    #[test]
    fn can_spend_locally_is_the_dispatch_predicate() {
        assert!(Capability::Full.can_spend_locally());
        assert!(!Capability::ViewOnly.can_spend_locally());
        assert!(!Capability::HardwareOffload.can_spend_locally());
    }

    /// 2k.2 contract: when `open` receives `SafetyOverrides::none()`
    /// the handle's `effective_*` accessors must return the network's
    /// hardcoded defaults — i.e. the no-override path is transparent.
    #[test]
    fn open_without_overrides_exposes_network_defaults() {
        use shekyl_engine_state::NetworkSafetyConstants;
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();
        {
            let params = make_params(&fx, &base, b"pw", &ledger, &cap);
            let _h = WalletFile::create(&params).expect("create");
        }
        let (handle, _outcome) =
            WalletFile::open(&base, b"pw", TEST_NETWORK, SafetyOverrides::none()).expect("open");

        assert_eq!(handle.overrides(), SafetyOverrides::none());
        let k = NetworkSafetyConstants::for_network(TEST_NETWORK);
        assert_eq!(handle.effective_max_reorg_depth(), k.max_reorg_depth);
        assert_eq!(handle.effective_skip_to_height(), k.default_skip_to_height);
        assert_eq!(
            handle.effective_refresh_from_block_height(),
            k.default_refresh_from_block_height,
        );
    }

    /// 2k.2 contract: an active override must flow through to the
    /// `effective_*` accessors without affecting any other field, and
    /// must survive beyond the `open` call on the handle. This pins
    /// the "request-scoped but handle-lifetimed" policy documented in
    /// `docs/WALLET_PREFS.md` §3.3 and in the `overrides` module
    /// header.
    #[test]
    fn open_with_overrides_propagates_to_effective_accessors() {
        use shekyl_engine_state::NetworkSafetyConstants;
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("x.wallet");
        let fx = Fixture::new();
        let cap = fx.capability();
        let ledger = WalletLedger::empty();
        {
            let params = make_params(&fx, &base, b"pw", &ledger, &cap);
            let _h = WalletFile::create(&params).expect("create");
        }

        let overrides = SafetyOverrides {
            max_reorg_depth: Some(2),
            skip_to_height: Some(12_345),
            refresh_from_block_height: None,
        };
        let (handle, _outcome) =
            WalletFile::open(&base, b"pw", TEST_NETWORK, overrides).expect("open");

        // Overrides survive on the handle.
        assert_eq!(handle.overrides(), overrides);
        // Overridden fields take the override's value.
        assert_eq!(handle.effective_max_reorg_depth(), 2);
        assert_eq!(handle.effective_skip_to_height(), 12_345);
        // Non-overridden field still reads the network default.
        let k = NetworkSafetyConstants::for_network(TEST_NETWORK);
        assert_eq!(
            handle.effective_refresh_from_block_height(),
            k.default_refresh_from_block_height,
        );
    }
}
