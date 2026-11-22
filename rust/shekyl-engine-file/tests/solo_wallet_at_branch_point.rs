// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! R-36: the group ledger changes nothing in the solo ledger. A solo wallet
//! written by `dev` at this branch's branch point (`25745115a4`, ledger
//! format 26) opens here and saves again to the same bytes.
//!
//! The schema snapshots record struct names, not bytes, so they cannot show
//! this; the fixture can. It is `fixtures/solo_wallet_at_branch_point/`,
//! written by `dev`'s own code from [`populated_solo_ledger`] (its README
//! has the steps). Every block of the ledger is filled, the send journal
//! with both destinations a send records.
//!
//! A save seals under a nonce drawn fresh each time, so the sealed `.wallet`
//! differs on every save by its nonce and what that nonce encrypts. What is
//! compared is everything else: the ledger the file decrypts to, and the
//! keys file, which a save never writes.

use std::path::{Path, PathBuf};

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
use shekyl_address::Network;
use shekyl_crypto_pq::handle::derive_output_handle;
use shekyl_crypto_pq::kem::HybridCiphertext;
use shekyl_crypto_pq::key_image::KeyImage;
use shekyl_crypto_pq::tx_key::TxKey;
use shekyl_crypto_pq::wallet_envelope::open_state_file;
use shekyl_curve_primitives::Commitment;
use shekyl_engine_file::{OpenOutcome, SafetyOverrides, WalletFile};
use shekyl_engine_state::{
    AddressBookEntry, BlockchainTip, BookkeepingBlock, LedgerBlock, PaymentId, PaymentRequestId,
    ReceiveAttribution, ReorgBlocks, SendDestination, SendInputRef, SendRecipient, StakingBlock,
    SyncStateBlock, TransferDetails, TxSecretKey, UnspendableReason, WalletLedger, SPENDABLE_AGE,
};
use shekyl_types::{BlockHash, BlockHeight, GlobalOutputIndex, OutputIndexInTx, TxHash};

/// The password the fixture was sealed under.
const PASSWORD: &[u8] = b"r36-branch-point";
/// The send the fixture's wallet dispatched and the chain confirmed.
const SENT_TXID: [u8; 32] = [0x5E; 32];
/// The send it dispatched that is still in flight.
const HELD_TXID: [u8; 32] = [0x6F; 32];

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/solo_wallet_at_branch_point")
}

fn transfer(seed: u8, height: u64) -> TransferDetails {
    let tx_hash = TxHash::from_bytes([seed; 32]);
    TransferDetails {
        tx_hash,
        internal_output_index: OutputIndexInTx::from_raw(u64::from(seed % 4)),
        global_output_index: GlobalOutputIndex::from_raw(1_000 + u64::from(seed)),
        block_height: BlockHeight::from_raw(height),
        key: ED25519_BASEPOINT_POINT,
        key_offset: Scalar::from(u64::from(seed) + 1),
        commitment: Commitment::new(
            Scalar::from(u64::from(seed) + 2),
            1_000_000 + u64::from(seed),
        ),
        payment_id: Some(PaymentId([seed; 8])),
        spent: false,
        spent_height: None,
        key_image: Some(KeyImage::from_canonical_bytes([seed ^ 0xFF; 32])),
        spending_tx_hash: None,
        source_ciphertext: Some(HybridCiphertext {
            x25519: [seed.wrapping_add(1); 32],
            ml_kem: vec![seed.wrapping_add(2); 1088],
        }),
        output_handle: Some(derive_output_handle(
            &[seed.wrapping_add(3); 32],
            &tx_hash,
            u64::from(seed % 4),
        )),
        eligible_height: BlockHeight::from_raw(height) + SPENDABLE_AGE,
        unspendable: None,
        fcmp_precomputed_path: None,
        receive_attribution: ReceiveAttribution::default(),
    }
}

fn tx_secret(a: u8) -> TxSecretKey {
    let mut bytes = [0u8; 32];
    bytes[0] = a;
    bytes[31] = a ^ 0xAA;
    TxSecretKey::new(TxKey::seeded(bytes).store())
}

/// The fixture's ledger: every block filled, and the send journal holding
/// a confirmed send to an address and a held send funding the wallet's own
/// persona.
#[must_use]
pub fn populated_solo_ledger() -> WalletLedger {
    let mut spent = transfer(2, 140);
    spent.spent = true;
    spent.spent_height = Some(BlockHeight::from_raw(190));
    spent.spending_tx_hash = Some(TxHash::from_bytes(SENT_TXID));
    let mut refused = transfer(3, 150);
    refused.unspendable = Some(UnspendableReason::PqcLeafMismatch);
    refused.key_image = None;
    let mut matched = transfer(4, 160);
    matched.receive_attribution = ReceiveAttribution::Matched(PaymentRequestId(7));
    matched.payment_id = None;

    let tip = BlockHash::from_bytes([0xAA; 32]);
    let mut wallet = WalletLedger::new(
        LedgerBlock::new(
            vec![transfer(1, 120), spent, refused, matched],
            BlockchainTip::new(BlockHeight::from_raw(200), tip),
            ReorgBlocks {
                blocks: (196u8..200)
                    .map(|h| {
                        (
                            BlockHeight::from_raw(u64::from(h)),
                            BlockHash::from_bytes([h; 32]),
                        )
                    })
                    .chain(std::iter::once((BlockHeight::from_raw(200), tip)))
                    .collect(),
            },
        ),
        BookkeepingBlock::new(
            Some("Main".into()),
            vec![
                AddressBookEntry {
                    address: "shekyl1alice".into(),
                    description: "alice".into(),
                    payment_id: Some(PaymentId([9; 8])),
                },
                AddressBookEntry {
                    address: "shekyl1bob".into(),
                    description: "bob".into(),
                    payment_id: None,
                },
            ],
        ),
        shekyl_engine_state::TxMetaBlock::empty(),
        SyncStateBlock::new(BlockHeight::from_raw(100), Some([0xC1; 32])),
        StakingBlock::new(true, 3, vec![5, 8]),
    );
    wallet
        .staking
        .record_first_sighting(5, BlockHeight::from_raw(170));

    wallet.record_retained_tx_key(SENT_TXID, tx_secret(0x51));
    wallet.record_dispatched_send(
        SENT_TXID,
        30_000,
        vec![SendRecipient {
            destination: SendDestination::Address("shekyl1alice".into()),
            amount: 600_000,
            rid: Some(PaymentRequestId(11)),
        }],
        vec![SendInputRef {
            gindex: 1_002,
            amount: 1_000_002,
        }],
        vec![0xB7; 512],
    );
    wallet.stamp_send_lock_baseline(&SENT_TXID, 190);
    wallet
        .set_note(SENT_TXID, "rent".into())
        .expect("a note on a send the wallet made");

    wallet.record_retained_tx_key(HELD_TXID, tx_secret(0x62));
    wallet.record_dispatched_send(
        HELD_TXID,
        20_000,
        vec![SendRecipient {
            destination: SendDestination::OwnPersonaFunding,
            amount: 400_000,
            rid: None,
        }],
        vec![SendInputRef {
            gindex: 1_001,
            amount: 1_000_001,
        }],
        vec![0xC8; 384],
    );
    wallet
}

/// The fixture's two files, copied where the test can open and save them.
fn copied_fixture(dir: &Path) -> PathBuf {
    let base = dir.join("solo.wallet");
    for name in ["solo.wallet.keys", "solo.wallet"] {
        std::fs::copy(fixture_dir().join(name), dir.join(name)).expect("copy fixture");
    }
    base
}

/// The ledger `dev` wrote opens unchanged, and a save writes it back to the
/// same bytes.
#[test]
fn a_solo_wallet_from_the_branch_point_opens_and_saves_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let base = copied_fixture(dir.path());
    let keys_before = std::fs::read(dir.path().join("solo.wallet.keys")).unwrap();
    let state_before = std::fs::read(&base).unwrap();
    let plaintext_before = open_state_file(PASSWORD, &keys_before, &state_before).unwrap();

    let (file, outcome) =
        WalletFile::open(&base, PASSWORD, Network::Testnet, SafetyOverrides::none())
            .expect("the branch opens dev's solo wallet");
    let OpenOutcome::StateLoaded(ledger) = outcome else {
        panic!("the fixture's state file did not load");
    };
    // The framed plaintext is the payload header and the ledger's postcard
    // body. The branch encodes the ledger it opened, and the ledger the
    // fixture was made from, to the body `dev` wrote.
    let body = ledger.to_postcard_bytes().unwrap();
    assert!(
        plaintext_before.ends_with(&body),
        "the opened ledger re-encodes differently"
    );
    assert_eq!(body, populated_solo_ledger().to_postcard_bytes().unwrap());

    file.save_state(file.session_wrap_key_region_2(), &ledger)
        .expect("save");
    drop(file);

    let keys_after = std::fs::read(dir.path().join("solo.wallet.keys")).unwrap();
    let state_after = std::fs::read(&base).unwrap();
    assert_eq!(keys_after, keys_before, "a save never writes the keys file");
    assert_eq!(state_after.len(), state_before.len());
    let plaintext_after = open_state_file(PASSWORD, &keys_after, &state_after).unwrap();
    assert_eq!(
        *plaintext_after, *plaintext_before,
        "the saved ledger's bytes moved"
    );
}
