//! Genesis-block facility (Core, daemon-reusable).
//!
//! Exposes the per-network genesis block to Rust so the wallet's curve-tree
//! client can seed `BlockHeight(0)` from the same consensus bytes the daemon
//! uses, rather than skipping height 0 (the wallet refresh producer starts at
//! height 1; see `docs/design/CT5_ENGINE_WIRING.md` §3.2).
//!
//! ## Source of truth
//!
//! Every value here mirrors the C++ genesis construction so the two cannot
//! produce different genesis blocks:
//!
//! - The per-network coinbase blob (`GENESIS_TX_*`) and `nonce`
//!   (`GENESIS_NONCE`) are verbatim from `src/cryptonote_config.h`
//!   (`config::`, `config::testnet::`, `config::stagenet::`).
//! - The header fields reproduce `generate_genesis_block`
//!   (`src/cryptonote_core/cryptonote_tx_utils.cpp`): `major_version =
//!   CURRENT_BLOCK_MAJOR_VERSION` (1), `minor_version =
//!   CURRENT_BLOCK_MINOR_VERSION` (0), `timestamp = 0`, `prev_id = null`,
//!   `nonce = <per-network>`, and `curve_tree_root =
//!   shekyl_curve_tree_selene_hash_init(...)`.
//!
//! ## The injected curve-tree root
//!
//! The genesis `curve_tree_root` is the empty-tree root `selene_hash_init()`
//! (genesis coinbase outputs are locked for `COINBASE_LOCK_WINDOW` blocks and
//! are not yet drained at height 0). That value is a Helios/Selene curve
//! constant owned by `shekyl-fcmp`, which layers *above* this crate, so the
//! builders take the root as a parameter rather than pinning it as a literal.
//! `shekyl-fcmp`'s `selene_hash_init()` is never hardcoded anywhere in the
//! tree (`curve_tree_freeze.rs` forbids modeling the empty tree as a baked
//! node "absent a CT-2 KAT"); injecting it live preserves that discipline.
//! `shekyl-curve-tree::genesis::genesis_block` is the wallet-side wrapper that
//! supplies it; the daemon does the same via `shekyl_curve_tree_selene_hash_init`.
//!
//! Because both sides feed the identical `selene_hash_init()` and the same
//! `GENESIS_TX`, `genesis_block(network, selene_hash_init()).hash()` is the
//! real Shekyl genesis block hash — not merely a regression value.
//!
//! ## Followups
//!
//! Consolidating these production values into a shared cross-language source
//! (and retiring the C++ `config::GENESIS_TX` / `generate_genesis_block` in
//! favor of this constructor via FFI) is tracked in `docs/FOLLOWUPS.md`; it
//! touches how the C++ daemon sources genesis and needs its own design round.

use std_shims::vec::Vec;

use crate::{
    block::{Block, BlockHeader},
    transaction::Transaction,
};

/// `block_header.major_version` for genesis (`CURRENT_BLOCK_MAJOR_VERSION`).
pub const GENESIS_MAJOR_VERSION: u8 = 1;
/// `block_header.minor_version` for genesis (`CURRENT_BLOCK_MINOR_VERSION`).
pub const GENESIS_MINOR_VERSION: u8 = 0;
/// `block_header.timestamp` for genesis (`generate_genesis_block` pins this to 0).
pub const GENESIS_TIMESTAMP: u64 = 0;
/// `block_header.prev_id` for genesis (defaults to the null hash in C++).
pub const GENESIS_PREVIOUS: [u8; 32] = [0u8; 32];

// Per-network genesis coinbase blobs, verbatim from `src/cryptonote_config.h`.
// Decoded at compile time so a malformed edit fails the build rather than at
// first use.
const GENESIS_TX_MAINNET: &[u8] = &hex_literal::hex!(
    "033c01ff00018080e983b1de16038415337912b33627bb97b87bc18249c02b4efbb22b6b9c439f0556ae654c08eb7fa60901c67f3f1eeef178e8be72d109cb3cbcb65b2e81aa10483b9f43c82d49224198ac06e00854032e50e1f3ff94a95c3b7a10555eb7389344dc3be473f58b7c1c74b3366d209f4cb55f915921559ed75ce92cde8bf5e71cddd44bc108e5b965d503725a28c2c9080be84d579500adba8aaece5678893645ecaa3c7cae1122115099e4b9883eabeca5546556e9b817f30a79e5690e85b6438c995abecb77742524b2052c326de1364fffa35cefe19a21c42c7e93b47dae4b512ee8f98950d26197fd0086d40be7945ff69984f19b4bb37026d0f12eddaa8535e15fe45502f1fe33460c2776447588f451b7642262bdf4c1bc253f068b3edfe390ab8daf73863ffe1490394bd3779acffe6a82af734335ab5d39bf4fe47f7de78d20093a916c53d74a073a67709ee419523d32d3ed35ffc455841288ffc996b308afe964cb95f1dad390ed47d9262e49c9d99587764778c8e98f07979b746f2e6117314c5bbfef6c075286838f2c2426a91174adc71d67c3dc0f9a36f03ba379fffab715c13162d00d62a8e73d5fd31541c7d98ea07d1522bffa30a080b21e51441812b8332e48de789b1358d93f5807e50e362ea95afb81f3b3c4e41f8b94b1e0bc0815fc3d35732339df278c33dcf8d0e8d3a0fd544c067115e80696c0e0abe61055c749a394cce15af7d879d85ee2dad28581a3d16d81066b343fb6e5308579f9bb4a7d334e9a5071c82513d637b52f4fe5584874f4d57afd86dc96797e7367ca03dcb7f163eb5c8e48a3a4207a20d4356cc156d910322e101c1fb2681760058256fdc99fcbbde75bae900730a29baf95ca889a7ef86576cc807b7755aa8ef1dd2214d5f1885e5dabe3956d2226509a8a29e2d83f8530137d5f25c5ce0dda2bbf2c59a45bda2f97f54cc04f591b1d12a7ce04e576ca4a3ae324f29150abcfd277210d7ccf041844e17111869f64f206fc86934b47856333e52ec1a1fe7e77b45f3326821e93fdfdf08e5db63a6554aec5a5d89e0b91c9b6be9170c1ea91e683665fc5daddaeec02e2b4c8b151d25c9336dae53b33e80876b7778adc6da7b260d3186e6732d8d00c2c3af1f8274b48813dae49bcbc320b7d15f0555c730db21f4839b477e599f1e261eeb9fdb0adba811a2f8a76348405f2d8b3096d1885fdde66b114fde250a7072837cb1159b307a4a59eab68db56cf8119eb37d57ff4e0534cf10cb071455f5f89ad845fb4093293de940e18717fe9b02e6aa874ecc3656775d3d2345296c814a9bfe121eb57f1313816939971d13b08a02de03c30908ff5321075a90c7c80241b7a404d6c40c011db802b1b7e18f61101bddfa9e07bc2795c42294bcb442bb091d96040fead457d16bddae8045ddf68e2a93f7d49b7f11662b89e7a5ca3b231032900223c2e3404c6a3bae8232fe9e618a5160533f0617792ea09779cca00a00b8616cf671c35536df504a31448341561b3788d52196ca16129d8c0c0226c347ec000e3785c566e933c6389f541bda3690f51f2d5afbb7592b5320961c654df13bbe767b1ea23f1f621ab547d68bc524797f1464d1095037441658e13a3336d8665e134dac7e9a18ef6b3efde29e777010c49028b49f6ad4c21ab3a8095bcd81c5965cf07204da4b6632245d15e4fb21babc487b140f50ab476318f1bb92030c29d10e8772b00c8cd11891c0a6a96f1f33727617c5c73398bc549ad254db71e6a64955f99b9abaf056d5cb039c0c41df18375a9f1ae4b14dd"
);
const GENESIS_TX_TESTNET: &[u8] = &hex_literal::hex!(
    "033c01ff0005808095e789c6040378c52591151c8159001690dcfa368f7ede243348ad8d6d8752dc963e09c6ca2d5a808095e789c604038888a80b8804689c5b66b1b863aa9484bf9de8c901a314dbc2a2a9629188ff5db4808095e789c6040377f6a8c9728bf7e1275d28aab5327ccb5c943243aa0cb0b4788cdc35d05b480c62808095e789c604030c053efc76d296587d97dbee68c71f1158d96f2216d27b45352db816657e636fcd808095e789c6040300fb3a862b2b1d5a06a2b427a4d418534161348493f1b400f94f4630ae46222a57a72d01f70c4225ea26b8927054ee878182222297af6ae9086eec07a8dff448a33b59bc06e02b2940b5c83d414c5232bdfbb8d04060547ced996099e0d2895727eede7b13740955b9e973f11fa7a2545f0d38d0fca9eec696b3d2565f594f486a41cd4fab9f4cdbbf29aca3699d0d8636fafc8374e1d843cf92a9090421cc7fdc0d5af72739be1691fae98c73393eb20e679bbdfe425bd6a32e78428f576884353d3aa076d4544165317380c05ebb0022daebc17705f2e8f7295c32224efecc011323a1742ffde80cd2dbd866e3c0ed70acdfb0c1874561a968194c410df7a5ee2af5a93f6e6e747a53d4a1a2eb24a509f1671491180969aab529cd5e207cd9264c7b0c78944ce37b37751b539d20"
);
const GENESIS_TX_STAGENET: &[u8] = &hex_literal::hex!(
    "033c01ff00018080e983b1de160352f562a672bcf8d7a75ab618fc321fe7d7c2fe8bad038dbf5d565015bf334d8a2ba60901e61a551ca4daa7411d9c91da75df8330b1f582cc4d55aeb7bee5367d890ec07906e0084b6abc62355d85a111358a61aaf1ffe7dda8732479685479aa58c1647c3c03345ac2db41ea26eb05fd0e9df5affd9db7aaf8428a15f75bbc2aecad63635c013d9630e5d556939480229b18dc1819db3788be8fb21ad302d402b237de3075e9e986961f1696d4c50e793ff133ef979d579099f0dd4785789c4c83c072c81130f3986d43e0f0edd16848771d8e9f3f50b755419323131e8aad41317814902af8a0eeaec14326f964a8dde1999beca0efc8038f0adb278b3e96fee2a65e7c9d8a1274e6e2bd2555c316412ad3cb643f8b43d5bc3d878d3b9fefaeace9135526edbe7f0e9beed35fe19f4228f9d0365946250057fc65bf1cbc077caa6ec713bfb2901b7f3486619a2682d75b558f5f4c92f8bda3e004a43be5990dc4dae5d6c037b7b4ab77eee874f1e99e5ae554474a1a16920c9bdc79e8913af1b462b7fb57fb08a62e0d2f8c478cdacbf513c39f1aafd4ea6726c04e01528c45fff4c94b327cec3df05ff1619e01b8702303e555d29da20f599c5a6961365d0acfdb0c98a2fdd47df5452c551c02797d7ae20eb6"
);

/// The Shekyl network whose genesis block is being constructed.
///
/// Mirrors the `config::`, `config::testnet::`, `config::stagenet::` split in
/// `src/cryptonote_config.h`. This is a self-contained selector for the
/// low-level protocol crate; consumers holding `shekyl_address::Network` map
/// at the call site.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
    /// Mainnet (`config::`).
    Mainnet,
    /// Testnet (`config::testnet::`).
    Testnet,
    /// Stagenet (`config::stagenet::`).
    Stagenet,
}

impl Network {
    /// `block_header.nonce` for this network's genesis block
    /// (`config::GENESIS_NONCE`).
    pub const fn genesis_nonce(self) -> u32 {
        match self {
            Network::Mainnet => 10000,
            Network::Testnet => 10101,
            Network::Stagenet => 10002,
        }
    }

    /// The raw genesis coinbase blob (`config::GENESIS_TX`) for this network.
    pub const fn genesis_tx_bytes(self) -> &'static [u8] {
        match self {
            Network::Mainnet => GENESIS_TX_MAINNET,
            Network::Testnet => GENESIS_TX_TESTNET,
            Network::Stagenet => GENESIS_TX_STAGENET,
        }
    }
}

/// Parse the genesis coinbase transaction for `network`.
///
/// The bytes are a compile-time constant from `cryptonote_config.h`; a parse
/// failure here would mean the embedded blob no longer round-trips through the
/// v3 transaction reader, which is a build-breaking invariant violation.
pub fn genesis_transaction(network: Network) -> Transaction {
    Transaction::read(&mut network.genesis_tx_bytes())
        .expect("embedded GENESIS_TX is a valid v3 coinbase")
}

/// Build the genesis block header for `network`.
///
/// `curve_tree_root` must be `shekyl_fcmp::tree::selene_hash_init()` (the
/// empty-tree root); it is injected rather than pinned (see module docs).
pub fn genesis_header(network: Network, curve_tree_root: [u8; 32]) -> BlockHeader {
    BlockHeader {
        hardfork_version: GENESIS_MAJOR_VERSION,
        hardfork_signal: GENESIS_MINOR_VERSION,
        timestamp: GENESIS_TIMESTAMP,
        previous: GENESIS_PREVIOUS,
        nonce: network.genesis_nonce(),
        curve_tree_root,
    }
}

/// Build the full genesis block for `network`.
///
/// `curve_tree_root` must be `shekyl_fcmp::tree::selene_hash_init()`; with the
/// correct root this reproduces the daemon's genesis block byte-for-byte, so
/// `genesis_block(network, selene_hash_init()).hash()` is the canonical Shekyl
/// genesis block hash.
pub fn genesis_block(network: Network, curve_tree_root: [u8; 32]) -> Block {
    Block::new(
        genesis_header(network, curve_tree_root),
        genesis_transaction(network),
        Vec::new(),
    )
    .expect("genesis block passes Block::new coinbase sanity checks")
}
