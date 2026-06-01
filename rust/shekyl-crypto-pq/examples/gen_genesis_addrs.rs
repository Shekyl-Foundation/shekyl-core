//! Emit deterministic genesis recipient addresses for `genesis_builder` JSON.
//!
//! Treasury placeholders (mainnet/stagenet): BIP-39 from domain-separated entropy.
//! Testnet developers: raw-32 seeds from domain-separated labels (testnet format).

use sha2::{Digest, Sha256};
use shekyl_address::{Network, ShekylAddress};
use shekyl_crypto_pq::account::{
    generate_account_from_bip39, generate_account_from_raw_seed, DerivationNetwork,
};

fn domain_entropy(label: &str) -> [u8; 32] {
    let digest = Sha256::digest(label.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn encode_bip39(network: Network, label: &str) -> String {
    let entropy = domain_entropy(label);
    let mnemonic =
        shekyl_crypto_pq::bip39::mnemonic_from_entropy(&entropy).expect("mnemonic_from_entropy");
    let net = match network {
        Network::Mainnet => DerivationNetwork::Mainnet,
        Network::Stagenet => DerivationNetwork::Stagenet,
        Network::Testnet => panic!("BIP-39 treasury path is mainnet/stagenet only"),
    };
    let (_, blob) =
        generate_account_from_bip39(&mnemonic, "", net).expect("generate_account_from_bip39");
    ShekylAddress::new(
        network,
        *blob.spend_pk.as_canonical_bytes(),
        *blob.view_pk.as_canonical_bytes(),
        blob.ml_kem_ek.to_vec(),
    )
    .encode()
    .expect("encode address")
}

fn encode_raw32(network: Network, label: &str) -> String {
    let seed = domain_entropy(label);
    let (_, blob) = generate_account_from_raw_seed(&seed, DerivationNetwork::Testnet)
        .expect("generate_account_from_raw_seed");
    ShekylAddress::new(
        network,
        *blob.spend_pk.as_canonical_bytes(),
        *blob.view_pk.as_canonical_bytes(),
        blob.ml_kem_ek.to_vec(),
    )
    .encode()
    .expect("encode address")
}

fn main() {
    println!(
        "mainnet_treasury={}",
        encode_bip39(
            Network::Mainnet,
            "shekyl-v3-genesis-treasury-mainnet-placeholder-v1"
        )
    );
    println!(
        "stagenet_treasury={}",
        encode_bip39(
            Network::Stagenet,
            "shekyl-v3-genesis-treasury-stagenet-placeholder-v1"
        )
    );
    for i in 1..=5 {
        println!(
            "testnet_developer_{i}={}",
            encode_raw32(
                Network::Testnet,
                &format!("shekyl-v3-genesis-testnet-developer-{i}-v1")
            )
        );
    }
}
