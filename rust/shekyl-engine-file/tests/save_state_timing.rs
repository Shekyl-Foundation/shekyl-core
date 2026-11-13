// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What one `save_state` costs on a large wallet (A19).
//!
//! Since A19 every send saves the whole ledger twice: once before its bytes
//! leave, and once with the daemon's verdict. This measures that save on a
//! ledger of `TRANSFERS` synthetic transfers (each with its source
//! ciphertext, so the row is as large as a received output's) and a send
//! journal of `HELD_SENDS` rows holding their signed bytes, on the machine
//! it runs on. Ignored: it is a measurement, run by hand on the floor device
//! and reported in the PR, not a pass/fail gate.
//!
//! ```text
//! cargo test --release -p shekyl-engine-file --test save_state_timing -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
use shekyl_address::Network;
use shekyl_crypto_pq::handle::derive_output_handle;
use shekyl_crypto_pq::kem::HybridCiphertext;
use shekyl_crypto_pq::wallet_envelope::{
    CapabilityContent, KdfParams, EXPECTED_CLASSICAL_ADDRESS_BYTES,
};
use shekyl_curve_primitives::Commitment;
use shekyl_engine_file::{CreateParams, WalletFile};
use shekyl_engine_state::{
    BlockchainTip, LedgerBlock, ReorgBlocks, SendInputRef, SendRecipient, TransferDetails,
    WalletLedger, SPENDABLE_AGE,
};
use shekyl_types::{BlockHash, BlockHeight, TxHash};

const TRANSFERS: usize = 10_000;
const HELD_SENDS: usize = 50;
/// A two-input, two-output FCMP++ transaction is a few kilobytes; the
/// journal's bytes are sized at the top of that range.
const SEND_BYTES: usize = 4_096;
const SAVES: usize = 30;

fn transfer(seed: u64) -> TransferDetails {
    let lo = (seed & 0xff) as u8;
    let mut tx_hash = [lo; 32];
    tx_hash[..8].copy_from_slice(&seed.to_le_bytes());
    TransferDetails {
        tx_hash: TxHash::from_bytes(tx_hash),
        internal_output_index: shekyl_types::OutputIndexInTx::from_raw(0),
        global_output_index: shekyl_types::GlobalOutputIndex::from_raw(1_000 + seed),
        block_height: BlockHeight::from_raw(100),
        key: ED25519_BASEPOINT_POINT,
        key_offset: Scalar::ONE,
        commitment: Commitment::new(Scalar::ONE, 1_000_000 + seed),
        payment_id: None,
        spent: false,
        spent_height: None,
        key_image: Some(shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
            {
                let mut ki = [lo ^ 0xFF; 32];
                ki[..8].copy_from_slice(&seed.to_le_bytes());
                ki
            },
        )),
        spending_tx_hash: None,
        source_ciphertext: Some(HybridCiphertext {
            x25519: [lo.wrapping_add(1); 32],
            ml_kem: vec![lo.wrapping_add(2); 1088],
        }),
        output_handle: Some(derive_output_handle(
            &[lo.wrapping_add(3); 32],
            &TxHash::from_bytes(tx_hash),
            0,
        )),
        eligible_height: BlockHeight::from_raw(100) + SPENDABLE_AGE,
        frozen: false,
        unspendable: None,
        fcmp_precomputed_path: None,
        receive_attribution: shekyl_engine_state::ReceiveAttribution::default(),
    }
}

fn large_ledger() -> WalletLedger {
    let mut wallet = WalletLedger::empty();
    let tip = BlockchainTip::new(
        BlockHeight::from_raw(200),
        BlockHash::from_bytes([0xAA; 32]),
    );
    let reorg = ReorgBlocks {
        blocks: (190..=200)
            .map(|h| {
                (
                    BlockHeight::from_raw(h),
                    BlockHash::from_bytes([h as u8; 32]),
                )
            })
            .collect(),
    };
    wallet.ledger = LedgerBlock::new((0..TRANSFERS as u64).map(transfer).collect(), tip, reorg);
    for n in 0..HELD_SENDS as u64 {
        let mut txid = [0x5Eu8; 32];
        txid[..8].copy_from_slice(&n.to_le_bytes());
        wallet.record_dispatched_send(
            txid,
            1_000,
            vec![SendRecipient {
                destination: shekyl_engine_state::SendDestination::Address("shekyl1x".into()),
                amount: 1,
                rid: None,
            }],
            vec![SendInputRef {
                gindex: 1_000 + n,
                amount: 1_000_000 + n,
            }],
            vec![0xB7; SEND_BYTES],
        );
    }
    wallet
}

#[test]
#[ignore = "a measurement; run by hand on the floor device"]
fn save_state_on_a_large_wallet() {
    let dir = tempfile::tempdir().expect("tempdir");
    let base = dir.path().join("timing.wallet");
    let seed = [0x11u8; 32];
    let capability = CapabilityContent::Full { seed: &seed };
    let mut address = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
    address[0] = 0x01;
    let empty = WalletLedger::empty();
    let file = WalletFile::create(&CreateParams {
        base_path: &base,
        password: b"timing",
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
    .expect("create");
    let key = file.session_wrap_key_region_2();

    let ledger = large_ledger();
    let body = ledger.to_postcard_bytes().expect("serializes").len();

    let mut times: Vec<Duration> = Vec::with_capacity(SAVES);
    for _ in 0..SAVES {
        let started = Instant::now();
        file.save_state(&key, &ledger).expect("save");
        times.push(started.elapsed());
    }
    times.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1_000.0;
    let file_size = std::fs::metadata(&base).expect("state file").len();
    eprintln!(
        "save_state: {TRANSFERS} transfers, {HELD_SENDS} held sends of {SEND_BYTES} bytes; \
         ledger {body} bytes, file {file_size} bytes; {SAVES} saves: \
         min {:.1} ms, median {:.1} ms, p90 {:.1} ms, max {:.1} ms",
        ms(times[0]),
        ms(times[SAVES / 2]),
        ms(times[SAVES * 9 / 10]),
        ms(times[SAVES - 1]),
    );
}
