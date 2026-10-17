// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The decorator's one override: a key image spent on the chain or by a
//! pool entry reads as spent; every other read is the chain's.

use shekyl_chain_rules::harness::MockChain;
use shekyl_chain_rules::{ChainView, HeaderView};
use shekyl_types::{BlockHash, BlockHeight, KeyImage, TxHash};

use super::{KeyImages, PoolView};

fn image(n: u8) -> KeyImage {
    KeyImage::from_bytes([n; 32])
}

fn txid(n: u8) -> TxHash {
    TxHash::from_bytes([n; 32])
}

#[test]
fn a_key_image_is_spent_on_the_chain_or_in_the_pool_and_nowhere_else() {
    let chain = MockChain::default().with_key_image(image(1));
    let mut pool = KeyImages::default();
    pool.insert(txid(9), [image(2)]);
    chain.with_view(|view| {
        let decorated = PoolView::new(&view, &pool);
        assert!(
            decorated.has_key_image(&image(1)).unwrap(),
            "M6: the chain's"
        );
        assert!(
            decorated.has_key_image(&image(2)).unwrap(),
            "M7: the pool's"
        );
        assert!(!decorated.has_key_image(&image(3)).unwrap(), "neither's");
        // The negative control on the fixture: the chain alone does not
        // hold the pool's image, so the override is what answered.
        assert!(!view.has_key_image(&image(2)).unwrap());
    });
}

#[test]
fn every_other_read_is_the_chains() {
    let chain = MockChain::default().with_transaction(txid(4));
    let pool = KeyImages::default();
    chain.with_view(|view| {
        let decorated = PoolView::new(&view, &pool);
        assert_eq!(decorated.tip().unwrap(), view.tip().unwrap());
        assert_eq!(
            decorated.has_transaction(&txid(4)).unwrap(),
            view.has_transaction(&txid(4)).unwrap()
        );
        let unknown = BlockHash::from_bytes([0x77; 32]);
        assert_eq!(
            decorated.height_of(&unknown).unwrap(),
            view.height_of(&unknown).unwrap()
        );
        assert_eq!(
            decorated.root_at(BlockHeight::from_raw(0)).unwrap(),
            view.root_at(BlockHeight::from_raw(0)).unwrap()
        );
        assert_eq!(
            decorated.total_burned().unwrap(),
            view.total_burned().unwrap()
        );
    });
}

#[test]
fn the_map_holds_one_spender_and_forgets_only_its_own() {
    let mut pool = KeyImages::default();
    pool.insert(txid(1), [image(1), image(2)]);
    assert_eq!(pool.spender(&image(1)), Some(txid(1)));
    assert_eq!(pool.len(), 2);
    // Another entry's removal leaves these images held.
    pool.remove(&txid(2), [image(1)]);
    assert!(pool.contains(&image(1)));
    pool.remove(&txid(1), [image(1), image(2)]);
    assert!(pool.is_empty());
}
