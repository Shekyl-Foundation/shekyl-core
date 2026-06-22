use crate::transaction::{Input, NotPruned, Timelock, Transaction};

// Legacy Monero transaction vectors (V1, CLSAG) are no longer parseable since
// Shekyl only supports version-3 FCMP++ transactions. These tests verify that
// legacy bytes are correctly rejected.

#[test]
fn legacy_transaction_vectors_rejected() {
    const TRANSACTIONS: &str = include_str!("./vectors/transactions.json");

    #[derive(serde::Deserialize)]
    struct Vector {
        hex: String,
        #[serde(flatten)]
        _rest: serde_json::Value,
    }

    let vectors: Vec<Vector> = serde_json::from_str(TRANSACTIONS).unwrap();
    for v in vectors {
        let bytes = hex::decode(&v.hex).unwrap();
        let result = Transaction::<NotPruned>::read(&mut bytes.as_slice());
        // All legacy test vectors should fail to parse since Shekyl only accepts
        // version-3 FCMP++ transactions. If any succeed, it can only be because
        // they happen to be a valid v3 coinbase.
        if let Ok(tx) = result {
            assert_eq!(tx.version(), 3, "only v3 transactions should parse");
        }
    }
}

#[test]
fn v3_coinbase_round_trip() {
    use crate::io::CompressedPoint;
    use crate::transaction::{Output, TransactionPrefix};

    let tx = Transaction::V3 {
        prefix: TransactionPrefix {
            additional_timelock: Timelock::Block(100),
            inputs: vec![Input::Gen(500)],
            outputs: vec![Output {
                amount: Some(1_000_000_000),
                key: CompressedPoint([1; 32]),
                view_tag: None,
                staking: None,
            }],
            extra: vec![1, 2, 3],
        },
        proofs: None,
    };

    let serialized = tx.serialize();
    let deserialized = Transaction::read(&mut serialized.as_slice()).unwrap();
    assert_eq!(tx, deserialized);
    assert_eq!(tx.hash(), deserialized.hash());
    assert!(deserialized.signature_hash().is_none());
}

/// Cross-language KAT: the **real** mainnet `GENESIS_TX` (a genuine consensus
/// v3 coinbase, `src/cryptonote_config.h` `GENESIS_TX`) must parse through
/// `Transaction::read`, report `version() == 3`, and decode to the expected
/// coinbase shape (one `txin_gen` at height 0, one `txout_to_tagged_key`
/// output). This is the byte-level proof that the v3 wire-version handling
/// accepts real Shekyl consensus bytes — the pre-fix `version != 2` gate
/// rejected it outright. End-to-end genesis-block-hash and leaf-eligibility
/// parity is validated in CT-5a pre-1 (the genesis facility).
#[test]
fn real_mainnet_genesis_tx_parses_as_v3() {
    use crate::transaction::Input;

    // Verbatim from `src/cryptonote_config.h` mainnet `config_t::GENESIS_TX`.
    const GENESIS_TX_HEX: &str = "033c01ff00018080e983b1de16038415337912b33627bb97b87bc18249c02b4efbb22b6b9c439f0556ae654c08eb7fa60901c67f3f1eeef178e8be72d109cb3cbcb65b2e81aa10483b9f43c82d49224198ac06e00854032e50e1f3ff94a95c3b7a10555eb7389344dc3be473f58b7c1c74b3366d209f4cb55f915921559ed75ce92cde8bf5e71cddd44bc108e5b965d503725a28c2c9080be84d579500adba8aaece5678893645ecaa3c7cae1122115099e4b9883eabeca5546556e9b817f30a79e5690e85b6438c995abecb77742524b2052c326de1364fffa35cefe19a21c42c7e93b47dae4b512ee8f98950d26197fd0086d40be7945ff69984f19b4bb37026d0f12eddaa8535e15fe45502f1fe33460c2776447588f451b7642262bdf4c1bc253f068b3edfe390ab8daf73863ffe1490394bd3779acffe6a82af734335ab5d39bf4fe47f7de78d20093a916c53d74a073a67709ee419523d32d3ed35ffc455841288ffc996b308afe964cb95f1dad390ed47d9262e49c9d99587764778c8e98f07979b746f2e6117314c5bbfef6c075286838f2c2426a91174adc71d67c3dc0f9a36f03ba379fffab715c13162d00d62a8e73d5fd31541c7d98ea07d1522bffa30a080b21e51441812b8332e48de789b1358d93f5807e50e362ea95afb81f3b3c4e41f8b94b1e0bc0815fc3d35732339df278c33dcf8d0e8d3a0fd544c067115e80696c0e0abe61055c749a394cce15af7d879d85ee2dad28581a3d16d81066b343fb6e5308579f9bb4a7d334e9a5071c82513d637b52f4fe5584874f4d57afd86dc96797e7367ca03dcb7f163eb5c8e48a3a4207a20d4356cc156d910322e101c1fb2681760058256fdc99fcbbde75bae900730a29baf95ca889a7ef86576cc807b7755aa8ef1dd2214d5f1885e5dabe3956d2226509a8a29e2d83f8530137d5f25c5ce0dda2bbf2c59a45bda2f97f54cc04f591b1d12a7ce04e576ca4a3ae324f29150abcfd277210d7ccf041844e17111869f64f206fc86934b47856333e52ec1a1fe7e77b45f3326821e93fdfdf08e5db63a6554aec5a5d89e0b91c9b6be9170c1ea91e683665fc5daddaeec02e2b4c8b151d25c9336dae53b33e80876b7778adc6da7b260d3186e6732d8d00c2c3af1f8274b48813dae49bcbc320b7d15f0555c730db21f4839b477e599f1e261eeb9fdb0adba811a2f8a76348405f2d8b3096d1885fdde66b114fde250a7072837cb1159b307a4a59eab68db56cf8119eb37d57ff4e0534cf10cb071455f5f89ad845fb4093293de940e18717fe9b02e6aa874ecc3656775d3d2345296c814a9bfe121eb57f1313816939971d13b08a02de03c30908ff5321075a90c7c80241b7a404d6c40c011db802b1b7e18f61101bddfa9e07bc2795c42294bcb442bb091d96040fead457d16bddae8045ddf68e2a93f7d49b7f11662b89e7a5ca3b231032900223c2e3404c6a3bae8232fe9e618a5160533f0617792ea09779cca00a00b8616cf671c35536df504a31448341561b3788d52196ca16129d8c0c0226c347ec000e3785c566e933c6389f541bda3690f51f2d5afbb7592b5320961c654df13bbe767b1ea23f1f621ab547d68bc524797f1464d1095037441658e13a3336d8665e134dac7e9a18ef6b3efde29e777010c49028b49f6ad4c21ab3a8095bcd81c5965cf07204da4b6632245d15e4fb21babc487b140f50ab476318f1bb92030c29d10e8772b00c8cd11891c0a6a96f1f33727617c5c73398bc549ad254db71e6a64955f99b9abaf056d5cb039c0c41df18375a9f1ae4b14dd";

    let bytes = hex::decode(GENESIS_TX_HEX).expect("genesis tx hex decodes");

    // The first byte is the version varint: `0x03`. The pre-fix `version != 2`
    // gate rejected this; the fix must accept it.
    assert_eq!(bytes[0], 0x03, "genesis tx wire version byte is 3");

    let tx = Transaction::<NotPruned>::read(&mut bytes.as_slice())
        .expect("real mainnet GENESIS_TX parses as a v3 transaction");

    assert_eq!(tx.version(), 3, "genesis coinbase reports version 3");

    let prefix = tx.prefix();
    assert!(
        matches!(prefix.inputs.as_slice(), [Input::Gen(0)]),
        "genesis coinbase has a single txin_gen at height 0",
    );
    assert_eq!(
        prefix.outputs.len(),
        1,
        "mainnet genesis has one founder treasury output",
    );
    assert!(
        prefix.outputs[0].view_tag.is_some(),
        "genesis output is a txout_to_tagged_key (dense tag 0x00)",
    );
}
