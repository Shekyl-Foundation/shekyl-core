// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `.wallet.multisig` (R-30): a group wallet's ceremony records seal under
//! the wallet's region-2 key beside `.wallet`, read back as written, are
//! absent before the first ceremony, and refuse a swapped sibling by its
//! payload kind.

use shekyl_address::Network;
use shekyl_crypto_pq::multisig_intent::IntentSeed;
use shekyl_crypto_pq::wallet_envelope::{
    CapabilityContent, KdfParams, EXPECTED_CLASSICAL_ADDRESS_BYTES,
};
use shekyl_engine_file::paths::multisig_state_path_from;
use shekyl_engine_file::payload::PayloadKind;
use shekyl_engine_file::{CreateParams, WalletFile, WalletFileError};
use shekyl_engine_state::{MultisigState, WalletLedger};
use shekyl_types::{BlockHeight, GlobalOutputIndex};

/// A wallet file to seal the records beside. The records' file is the same
/// for every capability; the group wallet's keys file lands with the
/// keys-file capability (R-30).
fn wallet(dir: &std::path::Path) -> WalletFile {
    let seed = [0x31u8; 32];
    let capability = CapabilityContent::Full { seed: &seed };
    let mut address = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
    address[0] = 0x01;
    let empty = WalletLedger::empty();
    WalletFile::create(&CreateParams {
        base_path: &dir.join("group.wallet"),
        password: b"pw",
        network: Network::Testnet,
        capability: &capability,
        creation_timestamp: 0x6000_0000,
        restore_height_hint: 0,
        expected_classical_address: &address,
        kdf: KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        initial_ledger: &empty,
    })
    .expect("create")
}

/// The records read back as written, from a sibling of `.wallet`; before
/// the first ceremony there is no file and no records.
#[test]
fn the_records_seal_and_open() {
    let dir = tempfile::tempdir().unwrap();
    let file = wallet(dir.path());
    let key = *file.session_wrap_key_region_2();
    assert!(file.open_multisig_state(&key).unwrap().is_none());

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
    file.save_multisig_state(&key, &state.to_postcard_bytes().unwrap())
        .unwrap();

    let body = file.open_multisig_state(&key).unwrap().expect("present");
    assert_eq!(MultisigState::from_postcard_bytes(&body).unwrap(), state);
    assert_eq!(
        file.multisig_path(),
        multisig_state_path_from(file.state_path())
    );
    assert_ne!(file.multisig_path(), file.pscan_path());
    assert_ne!(file.multisig_path(), file.pending_path());
    assert!(file.multisig_path().exists());
}

/// Another sibling dropped into `.wallet.multisig` decrypts under the same
/// key and is refused by its kind byte.
#[test]
fn a_swapped_sibling_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let file = wallet(dir.path());
    let key = *file.session_wrap_key_region_2();
    file.save_pending_posts(&key, b"pending-body").unwrap();
    std::fs::copy(file.pending_path(), file.multisig_path()).unwrap();
    let err = file
        .open_multisig_state(&key)
        .expect_err("a swapped sibling must be refused");
    assert!(
        matches!(
            err,
            WalletFileError::UnexpectedPayloadKind { expected, got }
                if expected == PayloadKind::MultisigStatePostcard as u8
                    && got == PayloadKind::PendingPostBlockPostcard as u8
        ),
        "got {err:?}"
    );
}
