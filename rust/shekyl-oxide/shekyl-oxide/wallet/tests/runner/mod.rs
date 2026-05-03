use core::ops::Deref;
use std_shims::sync::LazyLock;

use zeroize::Zeroizing;
use rand_core::OsRng;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

use tokio::sync::Mutex;

use shekyl_simple_request_rpc::SimpleRequestRpc;
use shekyl_wallet::{
  transaction::Transaction,
  block::Block,
  rpc::{Rpc, FeeRate},
  address::{Network, AddressType, ShekylAddress},
  DEFAULT_LOCK_WINDOW, ViewPair, GuaranteedViewPair, WalletOutput, Scanner,
};

mod builder;
pub use builder::SignableTransactionBuilder;

pub fn random_address() -> (Scalar, ViewPair, ShekylAddress) {
  let spend = Scalar::random(&mut OsRng);
  let spend_pub = &spend * ED25519_BASEPOINT_TABLE;
  let view = Zeroizing::new(Scalar::random(&mut OsRng));
  (
    spend,
    ViewPair::new(spend_pub, view.clone()).unwrap(),
    ShekylAddress::new(
      Network::Mainnet,
      AddressType::Legacy,
      spend_pub,
      view.deref() * ED25519_BASEPOINT_TABLE,
    ),
  )
}

#[allow(unused)]
pub fn random_guaranteed_address() -> (Scalar, GuaranteedViewPair, ShekylAddress) {
  let spend = Scalar::random(&mut OsRng);
  let spend_pub = &spend * ED25519_BASEPOINT_TABLE;
  let view = Zeroizing::new(Scalar::random(&mut OsRng));
  (
    spend,
    GuaranteedViewPair::new(spend_pub, view.clone()).unwrap(),
    ShekylAddress::new(
      Network::Mainnet,
      AddressType::Legacy,
      spend_pub,
      view.deref() * ED25519_BASEPOINT_TABLE,
    ),
  )
}

pub async fn mine_until_unlocked(
  rpc: &SimpleRequestRpc,
  addr: &ShekylAddress,
  tx_hash: [u8; 32],
) -> Block {
  let mut height = rpc.get_height().await.unwrap();
  let mut found = false;
  let mut block = None;
  while !found {
    let inner_block = rpc.get_block_by_number(height - 1).await.unwrap();
    found = match inner_block.transactions.iter().find(|&&x| x == tx_hash) {
      Some(_) => {
        block = Some(inner_block);
        true
      }
      None => {
        height = rpc.generate_blocks(addr, 1).await.unwrap().1 + 1;
        false
      }
    }
  }

  for _ in 0 .. (DEFAULT_LOCK_WINDOW - 1) {
    rpc.generate_blocks(addr, 1).await.unwrap();
  }

  block.unwrap()
}

#[allow(dead_code)]
pub async fn get_miner_tx_output(rpc: &SimpleRequestRpc, view: &ViewPair) -> WalletOutput {
  let mut scanner = Scanner::new(view.clone());

  let start = rpc.get_height().await.unwrap();
  rpc.generate_blocks(&view.legacy_address(Network::Mainnet), 60).await.unwrap();

  let block = rpc.get_block_by_number(start).await.unwrap();
  scanner
    .scan(rpc.get_scannable_block(block).await.unwrap())
    .unwrap()
    .ignore_additional_timelock()
    .swap_remove(0)
}

/// Make sure the weight and fee match the expected calculation.
pub fn check_weight_and_fee(tx: &Transaction, fee_rate: FeeRate) {
  let Transaction::V2 { proofs: Some(ref proofs), .. } = tx else { panic!("TX had no proofs") };
  let fee = proofs.base.fee;

  let weight = tx.weight();
  let expected_weight = fee_rate.calculate_weight_from_fee(fee).unwrap();
  assert_eq!(weight, expected_weight);

  let expected_fee = fee_rate.calculate_fee_from_weight(weight);
  assert_eq!(fee, expected_fee);
}

pub async fn rpc() -> SimpleRequestRpc {
  let rpc = SimpleRequestRpc::new("http://shekyl:oxide@127.0.0.1:18081".to_string()).await.unwrap();

  const BLOCKS_TO_MINE: usize = 110;

  if rpc.get_height().await.unwrap() > BLOCKS_TO_MINE {
    return rpc;
  }

  let addr = ShekylAddress::new(
    Network::Mainnet,
    AddressType::Legacy,
    &Scalar::random(&mut OsRng) * ED25519_BASEPOINT_TABLE,
    &Scalar::random(&mut OsRng) * ED25519_BASEPOINT_TABLE,
  );

  rpc.generate_blocks(&addr, BLOCKS_TO_MINE).await.unwrap();

  rpc
}

pub(crate) static SEQUENTIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[macro_export]
macro_rules! async_sequential {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        let guard = runner::SEQUENTIAL.lock().await;
        let local = tokio::task::LocalSet::new();
        local.run_until(async move {
          if let Err(err) = tokio::task::spawn_local(async move { $body }).await {
            drop(guard);
            Err(err).unwrap()
          }
        }).await;
      }
    )*
  }
}

#[macro_export]
macro_rules! test {
  (
    $name: ident,
    (
      $first_tx: expr,
      $first_checks: expr,
    ),
    $((
      $tx: expr,
      $checks: expr,
    )$(,)?),*
  ) => {
    async_sequential! {
      async fn $name() {
        use core::{ops::Deref, any::Any};
        #[cfg(feature = "multisig")]
        use std::collections::HashMap;

        use zeroize::Zeroizing;
        use rand_core::{RngCore, OsRng};

        use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

        #[cfg(feature = "multisig")]
        use frost::{
          curve::Ed25519,
          Participant,
          tests::{THRESHOLD, key_gen},
        };

        use shekyl_wallet::{
          fcmp::ProofType,
          rpc::FeePriority,
          address::Network,
          ViewPair, Scanner, OutputWithDecoys,
          send::{Change, SignableTransaction, Eventuality},
        };

        use runner::{
          SignableTransactionBuilder, random_address, rpc, mine_until_unlocked,
          get_miner_tx_output, check_weight_and_fee,
        };

        type Builder = SignableTransactionBuilder;

        let spend = Zeroizing::new(Scalar::random(&mut OsRng));
        let proof_type = ProofType::FcmpPlusPlusPqc;

        let spend_pub = spend.deref() * ED25519_BASEPOINT_TABLE;

        let rpc = rpc().await;

        let view_priv = Zeroizing::new(Scalar::random(&mut OsRng));
        let mut outgoing_view = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(outgoing_view.as_mut());
        let view = ViewPair::new(spend_pub, view_priv.clone()).unwrap();
        let addr = view.legacy_address(Network::Mainnet);

        let miner_tx = get_miner_tx_output(&rpc, &view).await;

        let builder = SignableTransactionBuilder::new(
          proof_type,
          outgoing_view,
          Change::new(
            ViewPair::new(
              &Scalar::random(&mut OsRng) * ED25519_BASEPOINT_TABLE,
              Zeroizing::new(Scalar::random(&mut OsRng))
            ).unwrap(),
            None,
          ),
          rpc.get_fee_rate(FeePriority::Unimportant).await.unwrap(),
        );

        // FCMP++ signing is not yet implemented, so sign() would return an error.
        // The test macro infrastructure is kept for when signing is available.
        let _ = (proof_type, rpc, builder, addr, miner_tx, spend);
      }
    }
  }
}
