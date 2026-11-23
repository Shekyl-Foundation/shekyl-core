// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `.wallet.multisig` (R-30): a group wallet's ceremony records seal under
//! the wallet's region-2 key beside `.wallet`, read back as written, are
//! absent before the first ceremony, and refuse a swapped sibling by its
//! payload kind.

use shekyl_address::multisig_address::{MultisigAddressPayload, HYBRID_KEM_PUBKEY_LEN};
use shekyl_address::Network;
use shekyl_crypto_pq::multisig_intent::IntentSeed;
use shekyl_crypto_pq::wallet_envelope::{group_member_content_len, KdfParams};
use shekyl_engine_file::paths::multisig_state_path_from;
use shekyl_engine_file::payload::PayloadKind;
use shekyl_engine_file::{
    CreateParams, GroupCreateParams, GroupOpenOutcome, GroupWalletFile, WalletFile, WalletFileError,
};
use shekyl_engine_state::{GroupWalletLedger, MultisigState, WalletLedger};
use shekyl_types::{BlockHeight, GlobalOutputIndex};

const PASSWORD: &[u8] = b"pw";
const N: u8 = 3;

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_log2: 0x08,
        t: 1,
        p: 1,
    }
}

fn group_address(fill: u8) -> MultisigAddressPayload {
    MultisigAddressPayload::new(
        Network::Testnet,
        N,
        2,
        [fill; 32],
        [fill.wrapping_add(1); 32],
        vec![fill; HYBRID_KEM_PUBKEY_LEN],
        (0..N)
            .map(|k| vec![fill.wrapping_add(k); HYBRID_KEM_PUBKEY_LEN])
            .collect(),
    )
    .expect("a valid group address")
}

/// A group wallet at `base`. The member file is opaque at this layer, so
/// any bytes of a member file's length serve.
fn group_wallet_at(base: &std::path::Path, fill: u8) -> GroupWalletFile {
    let address = group_address(fill);
    let member_file = vec![fill; group_member_content_len(N)];
    let empty = GroupWalletLedger::empty();
    GroupWalletFile::create(&GroupCreateParams {
        base_path: base,
        password: PASSWORD,
        group_address: &address,
        member_file: &member_file,
        creation_timestamp: 0x6000_0000,
        restore_height_hint: 77,
        kdf: fast_kdf(),
        initial_ledger: &empty,
    })
    .expect("create")
}

fn wallet(dir: &std::path::Path) -> GroupWalletFile {
    group_wallet_at(&dir.join("group.wallet"), 0x31)
}

/// The records read back as written, from a sibling of `.wallet`; before
/// the first ceremony there is no file and no records.
#[test]
fn the_records_seal_and_open() {
    let dir = tempfile::tempdir().unwrap();
    let file = wallet(dir.path());
    assert!(file.open_multisig_state().unwrap().is_none());

    let mut state = MultisigState::empty();
    state
        .reserve(
            &[0xA1; 32],
            &[GlobalOutputIndex::from_raw(7)],
            BlockHeight::from_raw(90),
        )
        .unwrap();
    state.record_responder_approval(&[0xB2; 32]);
    state.record_seen_seed(&IntentSeed::new(&[3; 32]).fingerprint());
    file.save_multisig_state(&state.to_postcard_bytes().unwrap())
        .unwrap();

    let body = file.open_multisig_state().unwrap().expect("present");
    assert_eq!(MultisigState::from_postcard_bytes(&body).unwrap(), state);
    assert_eq!(
        file.multisig_path(),
        multisig_state_path_from(file.state_path())
    );
    assert!(file.multisig_path().exists());
}

/// Another sibling dropped into `.wallet.multisig` decrypts under the same
/// key and is refused by its kind byte.
#[test]
fn a_swapped_sibling_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let file = wallet(dir.path());
    std::fs::copy(file.state_path(), file.multisig_path()).unwrap();
    let err = file
        .open_multisig_state()
        .expect_err("a swapped sibling must be refused");
    assert!(
        matches!(
            err,
            WalletFileError::UnexpectedPayloadKind { expected, got }
                if expected == PayloadKind::MultisigStatePostcard as u8
                    && got == PayloadKind::GroupWalletLedgerPostcard as u8
        ),
        "got {err:?}"
    );
}

/// Closed and reopened, a group wallet has its member file, its binding,
/// its ledger and its ceremony records.
#[test]
fn a_group_wallet_closes_and_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("group.wallet");
    let file = group_wallet_at(&base, 0x31);
    let mut ledger = GroupWalletLedger::empty();
    ledger.sync_state.restore_from_height = BlockHeight::from_raw(55);
    file.save_state(&ledger).unwrap();
    let mut state = MultisigState::empty();
    state.record_responder_approval(&[0xB2; 32]);
    file.save_multisig_state(&state.to_postcard_bytes().unwrap())
        .unwrap();
    drop(file);

    let (file, outcome) = GroupWalletFile::open(&base, PASSWORD, Network::Testnet).unwrap();
    let GroupOpenOutcome::StateLoaded(loaded) = outcome else {
        panic!("the state file is there");
    };
    assert_eq!(
        loaded.to_postcard_bytes().unwrap(),
        ledger.to_postcard_bytes().unwrap()
    );
    assert_eq!(file.member_file(), vec![0x31; group_member_content_len(N)]);
    assert_eq!(
        file.binding(),
        &shekyl_crypto_pq::wallet_envelope::group_wallet_binding(&group_address(0x31))
    );
    let body = file.open_multisig_state().unwrap().expect("present");
    assert_eq!(MultisigState::from_postcard_bytes(&body).unwrap(), state);
}

/// A lost `.wallet` is an empty group ledger from the keys file's height.
#[test]
fn a_lost_state_file_rebuilds_from_the_restore_height() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("group.wallet");
    let file = group_wallet_at(&base, 0x31);
    let state_path = file.state_path().to_path_buf();
    drop(file);
    std::fs::remove_file(state_path).unwrap();

    let (_file, outcome) = GroupWalletFile::open(&base, PASSWORD, Network::Testnet).unwrap();
    let GroupOpenOutcome::StateLost {
        ledger,
        restore_from_height,
    } = outcome
    else {
        panic!("the state file is gone");
    };
    assert_eq!(restore_from_height, 77);
    assert_eq!(
        ledger.sync_state.restore_from_height,
        BlockHeight::from_raw(77)
    );
    assert_eq!(ledger.ledger.coins().count(), 0);
}

/// The brief's wargame row: a keys file from one group beside state files
/// from another does not open them.
#[test]
fn another_groups_state_files_do_not_open() {
    let dir = tempfile::tempdir().unwrap();
    let ours = dir.path().join("ours.wallet");
    let theirs = dir.path().join("theirs.wallet");
    let our_file = group_wallet_at(&ours, 0x31);
    let their_file = group_wallet_at(&theirs, 0x41);
    their_file
        .save_multisig_state(&MultisigState::empty().to_postcard_bytes().unwrap())
        .unwrap();

    std::fs::copy(their_file.multisig_path(), our_file.multisig_path()).unwrap();
    assert!(matches!(
        our_file.open_multisig_state(),
        Err(WalletFileError::Envelope(
            shekyl_engine_file::WalletEnvelopeError::StateSeedBlockMismatch
        ))
    ));

    let our_state = our_file.state_path().to_path_buf();
    std::fs::copy(their_file.state_path(), &our_state).unwrap();
    drop(our_file);
    assert!(matches!(
        GroupWalletFile::open(&ours, PASSWORD, Network::Testnet),
        Err(WalletFileError::Envelope(
            shekyl_engine_file::WalletEnvelopeError::StateSeedBlockMismatch
        ))
    ));
}

/// Neither handle opens the other's keys file: a member file is never read
/// as a seed, nor a seed as a member file.
#[test]
fn solo_and_group_handles_refuse_each_others_keys() {
    use shekyl_crypto_pq::wallet_envelope::{CapabilityContent, EXPECTED_CLASSICAL_ADDRESS_BYTES};
    let dir = tempfile::tempdir().unwrap();

    let group = dir.path().join("group.wallet");
    drop(group_wallet_at(&group, 0x31));
    assert!(matches!(
        WalletFile::open(
            &group,
            PASSWORD,
            Network::Testnet,
            shekyl_engine_file::SafetyOverrides::none()
        ),
        Err(WalletFileError::GroupWalletKeysFile)
    ));

    let solo = dir.path().join("solo.wallet");
    let seed = [0x51u8; 32];
    let mut address = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
    address[0] = 0x01;
    let ledger = WalletLedger::empty();
    drop(
        WalletFile::create(&CreateParams {
            base_path: &solo,
            password: PASSWORD,
            network: Network::Testnet,
            capability: &CapabilityContent::Full { seed: &seed },
            creation_timestamp: 0,
            restore_height_hint: 0,
            expected_classical_address: &address,
            kdf: fast_kdf(),
            initial_ledger: &ledger,
        })
        .unwrap(),
    );
    assert!(matches!(
        GroupWalletFile::open(&solo, PASSWORD, Network::Testnet),
        Err(WalletFileError::NotAGroupWalletKeysFile)
    ));

    // The solo create path takes no group content, and writes nothing.
    let refused = dir.path().join("refused.wallet");
    let content = vec![0u8; group_member_content_len(N)];
    assert!(matches!(
        WalletFile::create(&CreateParams {
            base_path: &refused,
            password: PASSWORD,
            network: Network::Testnet,
            capability: &CapabilityContent::GroupMember {
                member_file: &content
            },
            creation_timestamp: 0,
            restore_height_hint: 0,
            expected_classical_address: &address,
            kdf: fast_kdf(),
            initial_ledger: &ledger,
        }),
        Err(WalletFileError::GroupWalletKeysFile)
    ));
    assert!(!shekyl_engine_file::paths::keys_path_from(&refused).exists());
}

/// A wallet created at a path clears a deleted group wallet's records.
#[test]
fn create_clears_an_orphaned_records_file() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("group.wallet");
    let file = group_wallet_at(&base, 0x31);
    file.save_multisig_state(&MultisigState::empty().to_postcard_bytes().unwrap())
        .unwrap();
    let (keys, state, records) = (
        file.keys_path().to_path_buf(),
        file.state_path().to_path_buf(),
        file.multisig_path().to_path_buf(),
    );
    drop(file);
    std::fs::remove_file(keys).unwrap();
    std::fs::remove_file(state).unwrap();
    assert!(records.exists());

    let file = group_wallet_at(&base, 0x41);
    assert!(!records.exists());
    assert!(file.open_multisig_state().unwrap().is_none());
}
