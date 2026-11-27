// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A group wallet's files (R-30; `docs/WALLET_FILE_FORMAT_V1.md` §2.3).
//!
//! A group wallet is its own set of wallet files and its own handle. Its
//! `.wallet.keys` holds capability `0x04`: one member's member file, sealed
//! by the password as a seed is and written once. Its region-2 key binds to
//! the group's address ([`group_wallet_binding`]) where a solo wallet's binds
//! to its classical address. `.wallet` holds a [`GroupWalletLedger`] under
//! its own payload kind, and `.wallet.multisig` the member's ceremony
//! records; both seal under that key.
//!
//! [`WalletFile`](super::WalletFile) refuses this capability, and this
//! handle refuses every other, so neither reads the other's content. This
//! handle deliberately has no seed accessor, no `.wallet.pscan` or
//! `.wallet.pending` (a group wallet does not stake, R-32), and no
//! `save_as`, which would leave `.wallet.multisig` and its input
//! reservations behind at the old path.
//!
//! The member file is opaque here: this crate does not depend on
//! `shekyl-multisig`. The layer that parses it recomputes the binding from
//! the parsed address and compares it with [`GroupWalletFile::binding`].

use std::io;
use std::path::{Path, PathBuf};

use shekyl_address::multisig_address::MultisigAddressPayload;
use shekyl_crypto_pq::wallet_envelope::{
    derive_wrap_key_region_2, group_wallet_binding, open_keys_file,
    open_state_file_with_wrap_key_region_2, seal_keys_file, seal_state_file_with_wrap_key_region_2,
    CapabilityContent, KdfParams, CAPABILITY_GROUP_MEMBER, EXPECTED_CLASSICAL_ADDRESS_BYTES,
    FILE_KEK_BYTES,
};
use shekyl_engine_state::{GroupWalletLedger, SyncStateBlock};
use shekyl_types::BlockHeight;
use zeroize::{Zeroize, Zeroizing};

use super::{decode_network, prepare_new_wallet_path, OpenedKeysFileOwned};
use crate::atomic::{atomic_write_file, Durability};
use crate::error::WalletFileError;
use crate::lock::KeysFileLock;
use crate::paths::{keys_path_from, multisig_state_path_from, state_path_from};
use crate::payload::{decode_payload, encode_payload, PayloadKind};
use crate::Network;

/// Inputs to [`GroupWalletFile::create`]. The network is the group
/// address's.
pub struct GroupCreateParams<'a> {
    /// The wallet's base path, as for a solo wallet.
    pub base_path: &'a Path,
    /// The password that seals the keys file.
    pub password: &'a [u8],
    /// The group's address: the region-2 key binds to it.
    pub group_address: &'a MultisigAddressPayload,
    /// This member's member file, whose address is `group_address`.
    pub member_file: &'a [u8],
    /// Seconds since the Unix epoch at wallet creation.
    pub creation_timestamp: u64,
    /// The rescan floor when `.wallet` is lost.
    pub restore_height_hint: u32,
    /// Argon2id cost parameters.
    pub kdf: KdfParams,
    /// The first ledger written to `.wallet`.
    pub initial_ledger: &'a GroupWalletLedger,
}

/// How [`GroupWalletFile::open`] came by its ledger.
#[derive(Debug)]
pub enum GroupOpenOutcome {
    /// `.wallet` was present and decoded.
    StateLoaded(GroupWalletLedger),
    /// `.wallet` was missing: an empty ledger whose scan starts at
    /// `restore_from_height`. The chain rebuilds it.
    StateLost {
        /// The fresh ledger.
        ledger: GroupWalletLedger,
        /// The keys file's restore height.
        restore_from_height: u64,
    },
}

/// An open group wallet's files. Holds the keys file's lock for its life.
pub struct GroupWalletFile {
    keys_path: PathBuf,
    state_path: PathBuf,
    multisig_path: PathBuf,
    keys_file_bytes: Zeroizing<Vec<u8>>,
    _lock: KeysFileLock,
    opened_keys: Zeroizing<OpenedKeysFileOwned>,
    network: Network,
    wrap_key_region_2: Zeroizing<[u8; FILE_KEK_BYTES]>,
}

impl std::fmt::Debug for GroupWalletFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupWalletFile")
            .field("keys_path", &self.keys_path)
            .field("state_path", &self.state_path)
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl GroupWalletFile {
    /// Create a group wallet's files from a member file.
    ///
    /// Refuses a path that already has a keys file, and clears the orphaned
    /// siblings of a wallet deleted from it, as a solo create does. The
    /// keys file is written once.
    ///
    /// # Errors
    ///
    /// A [`WalletFileError`]; a member file of a length no group has is the
    /// envelope's `CapContentLenMismatch`.
    pub fn create(params: &GroupCreateParams<'_>) -> Result<Self, WalletFileError> {
        prepare_new_wallet_path(params.base_path)?;
        let keys_path = keys_path_from(params.base_path);
        let state_path = state_path_from(params.base_path);

        let keys_bytes = seal_keys_file(
            params.password,
            params.group_address.network().code(),
            &CapabilityContent::GroupMember {
                member_file: params.member_file,
            },
            params.creation_timestamp,
            params.restore_height_hint,
            &group_wallet_binding(params.group_address),
            params.kdf,
        )?;
        atomic_write_file(&keys_path, &keys_bytes)?;
        let lock = KeysFileLock::acquire(&keys_path)?;

        let mut opened = open_keys_file(params.password, &keys_bytes)?;
        let network = decode_network(opened.network)?;
        let wrap_key_region_2 =
            derive_wrap_key_region_2(&opened.file_kek, &opened.expected_classical_address);
        // The session needs only the region-2 key (format §2.6).
        opened.file_kek.zeroize();
        let file = Self {
            multisig_path: multisig_state_path_from(&state_path),
            keys_path,
            state_path,
            keys_file_bytes: Zeroizing::new(keys_bytes),
            _lock: lock,
            opened_keys: Zeroizing::new(OpenedKeysFileOwned(opened)),
            network,
            wrap_key_region_2,
        };
        file.save_state(params.initial_ledger)?;
        Ok(file)
    }

    /// Open a group wallet's files.
    ///
    /// The network is checked before `.wallet` is read. A missing `.wallet`
    /// is [`GroupOpenOutcome::StateLost`]; any other defect refuses.
    ///
    /// # Errors
    ///
    /// [`WalletFileError::NotAGroupWalletKeysFile`] for a solo wallet's keys
    /// file, [`WalletFileError::NetworkMismatch`], and the envelope's and
    /// ledger's own refusals. A state file sealed beside another group's
    /// keys file does not open.
    pub fn open(
        base_path: &Path,
        password: &[u8],
        expected_network: Network,
    ) -> Result<(Self, GroupOpenOutcome), WalletFileError> {
        let keys_path = keys_path_from(base_path);
        let state_path = state_path_from(base_path);
        let (lock, keys_file_bytes) = KeysFileLock::acquire_and_read(&keys_path)?;
        let mut opened = open_keys_file(password, &keys_file_bytes)?;
        let network = decode_network(opened.network)?;
        if network != expected_network {
            return Err(WalletFileError::NetworkMismatch {
                expected: expected_network,
                found: network,
            });
        }
        if opened.capability_mode != CAPABILITY_GROUP_MEMBER {
            return Err(WalletFileError::NotAGroupWalletKeysFile);
        }
        let wrap_key_region_2 =
            derive_wrap_key_region_2(&opened.file_kek, &opened.expected_classical_address);
        // The session needs only the region-2 key (format §2.6).
        opened.file_kek.zeroize();

        let outcome = match std::fs::read(&state_path) {
            Ok(state_bytes) => {
                let plaintext = open_state_file_with_wrap_key_region_2(
                    &wrap_key_region_2,
                    &keys_file_bytes,
                    &state_bytes,
                )?;
                let framed = decode_payload(&plaintext)?;
                if framed.payload_kind != PayloadKind::GroupWalletLedgerPostcard {
                    return Err(WalletFileError::UnexpectedPayloadKind {
                        expected: PayloadKind::GroupWalletLedgerPostcard as u8,
                        got: framed.payload_kind as u8,
                    });
                }
                GroupOpenOutcome::StateLoaded(GroupWalletLedger::from_postcard_bytes(framed.body)?)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let restore_from_height = u64::from(opened.restore_height_hint);
                tracing::warn!(
                    target: "shekyl_engine_file",
                    state_path = %state_path.display(),
                    restore_from_height,
                    "group state missing; rebuilding ledger from chain from restore_height_hint"
                );
                let mut ledger = GroupWalletLedger::empty();
                ledger.sync_state =
                    SyncStateBlock::new(BlockHeight::from_raw(restore_from_height), None);
                GroupOpenOutcome::StateLost {
                    ledger,
                    restore_from_height,
                }
            }
            Err(e) => return Err(WalletFileError::Io(e)),
        };

        let file = Self {
            multisig_path: multisig_state_path_from(&state_path),
            keys_path,
            state_path,
            keys_file_bytes,
            _lock: lock,
            opened_keys: Zeroizing::new(OpenedKeysFileOwned(opened)),
            network,
            wrap_key_region_2,
        };
        Ok((file, outcome))
    }

    /// Seal `ledger` to `.wallet`, crash-atomically.
    ///
    /// # Errors
    ///
    /// The ledger's version gate, or the seal's or write's refusal.
    pub fn save_state(&self, ledger: &GroupWalletLedger) -> Result<Durability, WalletFileError> {
        ledger.check_all_block_versions()?;
        ledger.check_invariants()?;
        let body = Zeroizing::new(ledger.to_postcard_bytes()?);
        let framed = encode_payload(PayloadKind::GroupWalletLedgerPostcard, &body)?;
        self.write_sealed(&self.state_path, &framed)
    }

    /// Persist the ceremony records to `.wallet.multisig`. `body` is the
    /// postcard-encoded `MultisigState`. Crash-atomic: a reservation is
    /// durable before the nonce it guards exists.
    ///
    /// # Errors
    ///
    /// The seal's or write's refusal.
    pub fn save_multisig_state(&self, body: &[u8]) -> Result<Durability, WalletFileError> {
        let framed = encode_payload(PayloadKind::MultisigStatePostcard, body)?;
        self.write_sealed(&self.multisig_path, &framed)
    }

    /// Load the ceremony records from `.wallet.multisig`.
    ///
    /// `Ok(None)` when the file does not exist yet: a group wallet before
    /// its first ceremony, whose caller starts from `MultisigState::empty()`.
    ///
    /// # Errors
    ///
    /// [`WalletFileError::UnexpectedPayloadKind`] for a swapped sibling, and
    /// the envelope's own refusals.
    pub fn open_multisig_state(&self) -> Result<Option<Vec<u8>>, WalletFileError> {
        let file_bytes = match std::fs::read(&self.multisig_path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(WalletFileError::Io(e)),
        };
        let framed = open_state_file_with_wrap_key_region_2(
            &self.wrap_key_region_2,
            &self.keys_file_bytes,
            &file_bytes,
        )?;
        let decoded = decode_payload(&framed)?;
        if decoded.payload_kind != PayloadKind::MultisigStatePostcard {
            return Err(WalletFileError::UnexpectedPayloadKind {
                expected: PayloadKind::MultisigStatePostcard as u8,
                got: decoded.payload_kind as u8,
            });
        }
        Ok(Some(decoded.body.to_vec()))
    }

    fn write_sealed(&self, path: &Path, framed: &[u8]) -> Result<Durability, WalletFileError> {
        let sealed = seal_state_file_with_wrap_key_region_2(
            &self.wrap_key_region_2,
            &self.keys_file_bytes,
            framed,
        )?;
        atomic_write_file(path, &sealed)
    }

    /// The member file the keys file holds. Secret-bearing: parse it and
    /// let it go; it is not to be logged or copied out of a wiped buffer.
    #[must_use]
    pub fn member_file(&self) -> &[u8] {
        self.opened_keys.0.cap_content.as_slice()
    }

    /// The 65-byte value the region-2 key is bound to, as the keys file
    /// holds it.
    #[must_use]
    pub fn binding(&self) -> &[u8; EXPECTED_CLASSICAL_ADDRESS_BYTES] {
        &self.opened_keys.0.expected_classical_address
    }

    /// The network the keys file is bound to.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// The `.wallet.keys` path.
    #[must_use]
    pub fn keys_path(&self) -> &Path {
        &self.keys_path
    }

    /// The `.wallet` path.
    #[must_use]
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// The `.wallet.multisig` path.
    #[must_use]
    pub fn multisig_path(&self) -> &Path {
        &self.multisig_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_address::multisig_address::HYBRID_KEM_PUBKEY_LEN;
    use shekyl_crypto_pq::wallet_envelope::group_member_content_len;

    /// Neither constructor keeps the key that opens region 1 and every
    /// sealed file: an open handle holds the region-2 key alone.
    #[test]
    fn an_open_handle_does_not_hold_the_file_key() {
        const N: u8 = 3;
        let address = MultisigAddressPayload::new(
            Network::Testnet,
            N,
            2,
            [0x31; 32],
            [0x32; 32],
            vec![0x31; HYBRID_KEM_PUBKEY_LEN],
            (1..=N)
                .map(|k| vec![0x31 + k; HYBRID_KEM_PUBKEY_LEN])
                .collect(),
        )
        .expect("a valid group address");
        let member_file = vec![0x31; group_member_content_len(N)];
        let ledger = GroupWalletLedger::empty();
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("group.wallet");
        let created = GroupWalletFile::create(&GroupCreateParams {
            base_path: &base,
            password: b"pw",
            group_address: &address,
            member_file: &member_file,
            creation_timestamp: 0,
            restore_height_hint: 0,
            kdf: KdfParams {
                m_log2: 0x08,
                t: 1,
                p: 1,
            },
            initial_ledger: &ledger,
        })
        .unwrap();
        assert_eq!(*created.opened_keys.0.file_kek, [0u8; FILE_KEK_BYTES]);
        assert_ne!(*created.wrap_key_region_2, [0u8; FILE_KEK_BYTES]);
        drop(created);

        let (opened, _) = GroupWalletFile::open(&base, b"pw", Network::Testnet).unwrap();
        assert_eq!(*opened.opened_keys.0.file_kek, [0u8; FILE_KEK_BYTES]);
        assert_ne!(*opened.wrap_key_region_2, [0u8; FILE_KEK_BYTES]);
    }
}
