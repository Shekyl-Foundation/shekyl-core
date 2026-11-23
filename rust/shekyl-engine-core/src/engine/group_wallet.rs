// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A group wallet on disk (R-30), created from a member file and reopened.
//!
//! This is the one place the opaque member file in the keys file meets its
//! parser: [`shekyl_engine_file::GroupWalletFile`] does not depend on
//! `shekyl-multisig`. Opening parses the file and recomputes the region-2
//! binding from the parsed address, so a keys file whose member file is for
//! another group than the one it is bound to refuses.
//!
//! There are no recovery words: a group wallet's backup is its member file,
//! and nothing here has a seed or a mnemonic to return. No command line, RPC
//! or GUI surface reaches this module.

use std::path::Path;

use shekyl_crypto_pq::wallet_envelope::{group_wallet_binding, KdfParams};
use shekyl_engine_file::{
    Durability, GroupCreateParams, GroupOpenOutcome, GroupWalletFile, Network, WalletFileError,
};
use shekyl_engine_state::GroupWalletLedger;
use shekyl_multisig::{MemberFile, MemberFileError};
use shekyl_types::BlockHeight;

use super::Credentials;

/// Why a group wallet could not be created, opened or saved.
#[derive(Debug, thiserror::Error)]
pub enum GroupWalletError {
    /// The wallet files' own refusal.
    #[error("wallet file: {0}")]
    File(#[from] WalletFileError),
    /// The keys file's content is not a valid member file.
    #[error("member file: {0}")]
    MemberFile(#[from] MemberFileError),
    /// The keys file and its member file's address name different networks.
    #[error("the keys file is for {keys_file}, its member file's group is for {address}")]
    NetworkMismatch {
        /// The network the keys file is bound to.
        keys_file: Network,
        /// The network of the member file's group address.
        address: Network,
    },
    /// The keys file is bound to another group than its member file's.
    #[error("the keys file is bound to another group than its member file")]
    BindingMismatch,
}

/// Inputs to [`GroupWallet::create`].
pub struct GroupWalletCreate<'a> {
    /// The wallet's base path.
    pub base_path: &'a Path,
    /// The password that seals the keys file.
    pub credentials: &'a Credentials<'a>,
    /// The member file the dealer handed this member.
    pub member: &'a MemberFile,
    /// Seconds since the Unix epoch at wallet creation.
    pub creation_timestamp: u64,
    /// The height the group's first scan starts from.
    pub restore_height_hint: u32,
    /// Argon2id cost parameters.
    pub kdf: KdfParams,
}

/// An open group wallet: its files, its member file and its ledger.
#[derive(Debug)]
pub struct GroupWallet {
    file: GroupWalletFile,
    member: MemberFile,
    ledger: GroupWalletLedger,
}

impl GroupWallet {
    /// Create a group wallet's files from a member file. Once imported, the
    /// member file lives only in the keys file.
    ///
    /// # Errors
    ///
    /// [`GroupWalletError::File`] for the file layer's refusals, a path
    /// that already holds a wallet among them.
    pub fn create(params: &GroupWalletCreate<'_>) -> Result<Self, GroupWalletError> {
        let mut ledger = GroupWalletLedger::empty();
        if params.restore_height_hint > 0 {
            ledger.sync_state.restore_from_height =
                BlockHeight::from_raw(u64::from(params.restore_height_hint));
        }
        let member_file = params.member.to_bytes();
        let file = GroupWalletFile::create(&GroupCreateParams {
            base_path: params.base_path,
            password: params.credentials.password(),
            group_address: params.member.address(),
            member_file: &member_file,
            creation_timestamp: params.creation_timestamp,
            restore_height_hint: params.restore_height_hint,
            kdf: params.kdf,
            initial_ledger: &ledger,
        })?;
        // The member is read back from what was sealed, as every later open
        // reads it.
        let member = checked_member(&file)?;
        Ok(Self {
            file,
            member,
            ledger,
        })
    }

    /// Open a group wallet. A lost `.wallet` opens with an empty ledger
    /// that scans from the keys file's restore height.
    ///
    /// # Errors
    ///
    /// The file layer's refusals (a solo wallet's keys file, the wrong
    /// password or network, another group's state file), a member file
    /// that does not parse, and a binding that is not its address's.
    pub fn open(
        base_path: &Path,
        credentials: &Credentials<'_>,
        network: Network,
    ) -> Result<Self, GroupWalletError> {
        let (file, outcome) = GroupWalletFile::open(base_path, credentials.password(), network)?;
        let member = checked_member(&file)?;
        let ledger = match outcome {
            GroupOpenOutcome::StateLoaded(ledger) | GroupOpenOutcome::StateLost { ledger, .. } => {
                ledger
            }
        };
        Ok(Self {
            file,
            member,
            ledger,
        })
    }

    /// Seal the ledger to `.wallet`.
    ///
    /// # Errors
    ///
    /// The file layer's refusal.
    pub fn save(&self) -> Result<Durability, GroupWalletError> {
        Ok(self.file.save_state(&self.ledger)?)
    }

    /// The wallet's files.
    #[must_use]
    pub fn file(&self) -> &GroupWalletFile {
        &self.file
    }

    /// This member's member file.
    #[must_use]
    pub fn member(&self) -> &MemberFile {
        &self.member
    }

    /// The group ledger.
    #[must_use]
    pub fn ledger(&self) -> &GroupWalletLedger {
        &self.ledger
    }

    /// The group ledger, to update.
    pub fn ledger_mut(&mut self) -> &mut GroupWalletLedger {
        &mut self.ledger
    }
}

/// The keys file's member file, parsed and held to the keys file's network
/// and binding.
fn checked_member(file: &GroupWalletFile) -> Result<MemberFile, GroupWalletError> {
    let member = MemberFile::from_bytes(file.member_file())?;
    let address = member.address();
    if address.network() != file.network() {
        return Err(GroupWalletError::NetworkMismatch {
            keys_file: file.network(),
            address: address.network(),
        });
    }
    if &group_wallet_binding(address) != file.binding() {
        return Err(GroupWalletError::BindingMismatch);
    }
    Ok(member)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use shekyl_address::multisig_address::{MultisigAddressPayload, HYBRID_KEM_PUBKEY_LEN};
    use shekyl_crypto_pq::kem::{HybridKemSecretKey, HYBRID_KEM_SECRET_LEN};
    use shekyl_crypto_pq::multisig_envelope::mint_multisig_envelope_keypair;
    use shekyl_multisig::MemberSecrets;
    use zeroize::Zeroizing;

    const PASSWORD: &[u8] = b"group-password";
    const N: u8 = 3;

    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        }
    }

    fn address(network: Network, fill: u8) -> MultisigAddressPayload {
        MultisigAddressPayload::new(
            network,
            N,
            2,
            [fill; 32],
            [fill.wrapping_add(1); 32],
            vec![fill; HYBRID_KEM_PUBKEY_LEN],
            (1..=N)
                .map(|k| vec![fill + k; HYBRID_KEM_PUBKEY_LEN])
                .collect(),
        )
        .expect("a valid group address")
    }

    fn member(network: Network, fill: u8, index: u8) -> MemberFile {
        let mut keys: Vec<_> = (0..N)
            .map(|_| mint_multisig_envelope_keypair(&mut OsRng).expect("an envelope key pair"))
            .collect();
        let publics = keys.iter().map(|(pk, _)| pk.clone()).collect();
        let (_, envelope_secret) = keys.swap_remove(usize::from(index));
        let kem = |byte: u8| {
            HybridKemSecretKey::from_canonical_bytes(&[byte; HYBRID_KEM_SECRET_LEN])
                .expect("a canonical KEM secret")
        };
        MemberFile::new(
            address(network, fill),
            index,
            vec![[0x7A; 32]; usize::from(N)],
            publics,
            MemberSecrets {
                b: Zeroizing::new([0x0B; 32]),
                y_share: Zeroizing::new([0x0F; 32]),
                group_kem_secret: kem(0x6A),
                member_kem_secret: kem(0x6B),
                transport_secret: Zeroizing::new([0x5E; 32]),
                envelope_secret,
            },
        )
        .expect("a valid member file")
    }

    fn create(base: &Path, member: &MemberFile) -> GroupWallet {
        let credentials = Credentials::password_only(PASSWORD);
        GroupWallet::create(&GroupWalletCreate {
            base_path: base,
            credentials: &credentials,
            member,
            creation_timestamp: 0x6000_0000,
            restore_height_hint: 120,
            kdf: fast_kdf(),
        })
        .expect("create")
    }

    /// The brief's gate: a group wallet created from a member file, closed
    /// and reopened, has that member file and its ledger.
    #[test]
    fn a_group_wallet_created_from_a_member_file_closes_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("group.wallet");
        let original = member(Network::Testnet, 0x21, 1);

        let mut wallet = create(&base, &original);
        assert_eq!(*wallet.member().to_bytes(), *original.to_bytes());
        assert_eq!(
            wallet.ledger().sync_state.restore_from_height,
            BlockHeight::from_raw(120)
        );
        wallet.ledger_mut().sync_state.restore_from_height = BlockHeight::from_raw(130);
        wallet.save().unwrap();
        drop(wallet);

        let credentials = Credentials::password_only(PASSWORD);
        let reopened = GroupWallet::open(&base, &credentials, Network::Testnet).unwrap();
        assert_eq!(*reopened.member().to_bytes(), *original.to_bytes());
        assert_eq!(reopened.member().member_index(), 1);
        assert_eq!(
            reopened.ledger().sync_state.restore_from_height,
            BlockHeight::from_raw(130)
        );
    }

    /// A keys file bound to one group and holding another's member file
    /// refuses at open, whichever way it came to exist.
    #[test]
    fn a_member_file_for_another_group_than_the_binding_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("group.wallet");
        let held = member(Network::Testnet, 0x21, 0);
        let bound_to = address(Network::Testnet, 0x31);
        let empty = GroupWalletLedger::empty();
        drop(
            GroupWalletFile::create(&GroupCreateParams {
                base_path: &base,
                password: PASSWORD,
                group_address: &bound_to,
                member_file: &held.to_bytes(),
                creation_timestamp: 0,
                restore_height_hint: 0,
                kdf: fast_kdf(),
                initial_ledger: &empty,
            })
            .unwrap(),
        );
        let credentials = Credentials::password_only(PASSWORD);
        assert!(matches!(
            GroupWallet::open(&base, &credentials, Network::Testnet),
            Err(GroupWalletError::BindingMismatch)
        ));
    }

    /// A keys file on one network holding a group on another refuses by
    /// network, before the binding is compared.
    #[test]
    fn a_member_file_on_another_network_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("group.wallet");
        let held = member(Network::Stagenet, 0x21, 0);
        let bound_to = address(Network::Testnet, 0x21);
        let empty = GroupWalletLedger::empty();
        drop(
            GroupWalletFile::create(&GroupCreateParams {
                base_path: &base,
                password: PASSWORD,
                group_address: &bound_to,
                member_file: &held.to_bytes(),
                creation_timestamp: 0,
                restore_height_hint: 0,
                kdf: fast_kdf(),
                initial_ledger: &empty,
            })
            .unwrap(),
        );
        let credentials = Credentials::password_only(PASSWORD);
        assert!(matches!(
            GroupWallet::open(&base, &credentials, Network::Testnet),
            Err(GroupWalletError::NetworkMismatch {
                keys_file: Network::Testnet,
                address: Network::Stagenet,
            })
        ));
    }

    /// The wrong password is the envelope's one refusal.
    #[test]
    fn the_wrong_password_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("group.wallet");
        drop(create(&base, &member(Network::Testnet, 0x21, 0)));
        let credentials = Credentials::password_only(b"not-the-password");
        assert!(matches!(
            GroupWallet::open(&base, &credentials, Network::Testnet),
            Err(GroupWalletError::File(WalletFileError::Envelope(
                shekyl_engine_file::WalletEnvelopeError::InvalidPasswordOrCorrupt
            )))
        ));
    }
}
