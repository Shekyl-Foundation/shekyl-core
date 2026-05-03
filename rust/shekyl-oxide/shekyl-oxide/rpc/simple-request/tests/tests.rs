use std::sync::LazyLock;
use tokio::sync::Mutex;

use shekyl_address::{Network, ShekylAddress, PQC_PAYLOAD_LEN};

// shekyl-rpc doesn't include a transport
// We can't include the simple-request crate there as then we'd have a cyclical dependency
// Accordingly, we test shekyl-rpc here (implicitly testing the simple-request transport)
use shekyl_simple_request_rpc::*;

/// Mainnet default HTTP RPC port (`config::RPC_DEFAULT_PORT` / 11029 in shekyl-core). Use `--rpc-login`
/// when testing against a daemon that requires auth.
const DAEMON_RPC_URL: &str = "http://127.0.0.1:11029";

static SEQUENTIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Encoded mainnet address for `generate_blocks` (`Rpc` takes the wire string).
static SAMPLE_MAINNET_ADDR: LazyLock<String> = LazyLock::new(|| {
    ShekylAddress::new(
        Network::Mainnet,
        [0xaa; 32],
        [0xbb; 32],
        vec![0xcc; PQC_PAYLOAD_LEN],
    )
    .encode()
    .expect("encode sample mainnet address")
});

#[tokio::test]
#[ignore = "requires a shekyld HTTP RPC at 127.0.0.1:11029 (default mainnet); run with: cargo test -p shekyl-simple-request-rpc --test tests -- --ignored"]
async fn test_rpc() {
    use shekyl_rpc::Rpc;

    let guard = SEQUENTIAL.lock().await;

    let rpc = SimpleRequestRpc::new(DAEMON_RPC_URL.to_string())
        .await
        .unwrap();

    {
        // Test get_height
        let height = rpc.get_height().await.unwrap();
        // The height should be the amount of blocks on chain
        // The number of a block should be its zero-indexed position
        // Accordingly, there should be no block whose number is the height
        assert!(rpc.get_block_by_number(height).await.is_err());
        let block_number = height - 1;
        // There should be a block just prior
        let block = rpc.get_block_by_number(block_number).await.unwrap();

        // Also test the block RPC routes are consistent
        assert_eq!(block.number(), block_number);
        assert_eq!(rpc.get_block(block.hash()).await.unwrap(), block);
        assert_eq!(
            rpc.get_block_hash(block_number).await.unwrap(),
            block.hash()
        );

        // And finally the hardfork version route
        assert_eq!(
            rpc.get_hardfork_version().await.unwrap(),
            block.header.hardfork_version
        );
    }

    // Test generate_blocks
    for amount_of_blocks in [1, 5] {
        let (blocks, number) = rpc
            .generate_blocks(SAMPLE_MAINNET_ADDR.as_str(), amount_of_blocks)
            .await
            .unwrap();
        let height = rpc.get_height().await.unwrap();
        assert_eq!(number, height - 1);

        let mut actual_blocks = Vec::with_capacity(amount_of_blocks);
        for i in (height - amount_of_blocks)..height {
            actual_blocks.push(rpc.get_block_by_number(i).await.unwrap().hash());
        }
        assert_eq!(blocks, actual_blocks);
    }

    drop(guard);
}

// This test passes yet requires a mainnet node, which we don't have reliable access to in CI.
/*
#[tokio::test]
async fn test_zero_out_tx_o_indexes() {
  use shekyl_rpc::Rpc;

  let guard = SEQUENTIAL.lock().await;

  let rpc = SimpleRequestRpc::new("https://node.sethforprivacy.com".to_string()).await.unwrap();

  assert_eq!(
    rpc
      .get_o_indexes(
        hex::decode("17ce4c8feeb82a6d6adaa8a89724b32bf4456f6909c7f84c8ce3ee9ebba19163")
          .unwrap()
          .try_into()
          .unwrap()
      )
      .await
      .unwrap(),
    Vec::<u64>::new()
  );

  drop(guard);
}
*/
