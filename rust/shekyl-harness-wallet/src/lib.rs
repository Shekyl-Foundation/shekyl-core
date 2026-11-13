// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The harness's wallet side: the deterministic miner every fixture
//! coinbase pays, the recipients a scenario pays and the owners who
//! recover what they were paid, and a coinbase composed as that wallet
//! will scan it. The spending half — the tree walk, the prover, the
//! signer — is `shekyl-harness-spender`, which depends on this crate.
//!
//! # Why a crate, and why this one is wallet-side only
//!
//! The rules crate's `harness` feature builds the coinbase every fixture
//! block carries, and the store's and the ingest's tests spend those
//! coinbases through a real prover. One wallet therefore has to be
//! reachable from both sides — the composer that pays it and the spender
//! that scans and spends what it was paid — and the rules crate's no-store
//! belt (`check_chain_rules_no_store.sh`, over normal **and** dev edges)
//! forbids the rules crate from reaching `shekyl-curve-tree`, which the
//! spender needs for the tree walk and `redb`-backs. So the identities and
//! the composition live here, with nothing of the tree in the closure, and
//! the spending half lives in a sibling crate that depends on this one.
//!
//! # The second-oracle property
//!
//! [`coinbase::paying`] composes a coinbase from the same two owners
//! `shekyl-block-template` composes its own from —
//! [`shekyl_crypto_pq::output::construct_output`] for the output and
//! [`shekyl_wire::tx_extra::build_coinbase_extra`] for the `extra` — and
//! shares no code with the template above those owners. It is written from
//! the census, not copied from the template: a test that validates both a
//! template's coinbase and a fixture's is judging two independent
//! producers against one validator, and a composition defect in either is
//! a disagreement the validator reports rather than a shared blind spot.
//! The template is production; this crate is not, and it must never become
//! what the template reads.
//!
//! # Determinism
//!
//! Every value here is a function of a seed and a height. The miner is
//! derived from [`HARNESS_SEED`] through this crate's own fixed fixture
//! derivation ([`fixture_expand`]) and the stack's ML-KEM keygen
//! (`ml_kem_keypair_from_d_z`), so the same coinbase bytes come out of every
//! test run and every crate — a fixture pinned in one place is the fixture
//! every other place builds. The fixture derivation is not a wallet's: a
//! wallet derives through `shekyl_crypto_pq::account` (`NETWORK_IDENTITY.md`
//! NI-R7), and nothing here may stand in for it.
//!
//! A chain that carries a network's identity pays a wallet of that network
//! instead ([`MinerWallet::from_account`], [`MinerWallet::harness_regtest`]):
//! the keys come out of `account_from_seed` under the network's name, as
//! a wallet restored from the same seed on that network derives them, and
//! this crate only copies them (`CHAIN_FORGE.md` §6, `CF-1a`). The fixture
//! derivation stays the miner of the chains that mine their own genesis.

#![forbid(unsafe_code)]

pub mod coinbase;

use std::sync::LazyLock;

use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha512;
use shekyl_crypto_pq::account::{account_from_seed, ml_kem_keypair_from_d_z, Network, SEED_BYTES};
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_crypto_pq::kem::{HybridKemSecretKey, ML_KEM_768_DK_LEN};
use zeroize::Zeroizing;

/// The seed the harness miner is derived from. **Public, and regtest-only**
/// (`CHAIN_FORGE.md` §6, `CF-R15`): this wallet exists so tests can spend
/// what fixtures pay, and a secret that every test binary carries is not a
/// secret. Anyone who restores it can spend every coinbase a regtest chain
/// paid [`MinerWallet::harness_regtest`], and that is intended: a test
/// chain's coins are worth nothing off regtest. Its regtest addresses carry
/// regtest's prefixes, which a mainnet, testnet or stagenet wallet refuses
/// as another network's (`tests::the_regtest_miners_address_is_refused_off_regtest`).
/// Never pay a seed derived from it on any other network.
pub const HARNESS_SEED: [u8; 32] = *b"shekyl-harness-wallet-miner-v1\0\0";

/// The fixture derivation's HKDF salt. Fixed, and not a wallet's: wallets
/// salt by the network's name (`account::salt_for`). Registered test-only in
/// `CRYPTO_DOMAIN_REGISTRY.tsv`.
const FIXTURE_DERIVE_SALT: &[u8] = b"shekyl-master-derive-v1";

/// `N` bytes of HKDF-SHA-512 over `seed` under [`FIXTURE_DERIVE_SALT`] and
/// `info`: the fixture wallet's one derivation.
fn fixture_expand<const N: usize>(seed: &[u8; 32], info: &[u8]) -> [u8; N] {
    let hk = Hkdf::<Sha512>::new(Some(FIXTURE_DERIVE_SALT), seed);
    let mut okm = [0u8; N];
    hk.expand(info, &mut okm)
        .expect("a fixture expand is far below HKDF-SHA-512's maximum");
    okm
}

/// What a payer needs of a wallet: the three public keys an output is
/// addressed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    /// The Edwards spend public key (`B`).
    pub spend_public: [u8; 32],
    /// X25519 half of the hybrid KEM target.
    pub x25519_pk: [u8; 32],
    /// ML-KEM-768 encapsulation key.
    pub ml_kem_ek: Vec<u8>,
}

impl Recipient {
    /// A persona's base address — where its backing and fee outputs live
    /// (`ARCHIVAL_BOND_CONSTRUCTION.md`: funded by a plain payment to `P`).
    #[must_use]
    pub fn persona(keys: &ArchivalPKeys) -> Self {
        Self {
            spend_public: *keys.spend_pk.as_canonical_bytes(),
            x25519_pk: keys.x25519_pk,
            ml_kem_ek: keys.ml_kem_ek.to_vec(),
        }
    }
}

/// What a wallet needs to recognise and spend an output paid to it: the
/// scanner's two decapsulation secrets, and the spend pair. Borrowed, so
/// the secrets stay where their owner wipes them.
pub struct Owner<'a> {
    /// The X25519 decapsulation scalar (the view secret).
    pub x25519_sk: &'a [u8; 32],
    /// The ML-KEM-768 decapsulation key.
    pub ml_kem_dk: &'a [u8],
    /// The Edwards spend public key the output was addressed to.
    pub spend_public: &'a [u8; 32],
    /// The Edwards spend secret `b`; `x = ho + b` is the one-time secret.
    pub spend_secret: &'a [u8; 32],
}

impl Owner<'_> {
    /// A miner's wallet.
    #[must_use]
    pub fn miner(wallet: &MinerWallet) -> Owner<'_> {
        Owner {
            x25519_sk: &wallet.kem_secret.x25519,
            ml_kem_dk: &wallet.kem_secret.ml_kem,
            spend_public: &wallet.recipient.spend_public,
            spend_secret: &wallet.spend_secret,
        }
    }

    /// A persona, over the same secrets the engine's
    /// `derive_p_source_secrets_bundle` reads.
    #[must_use]
    pub fn persona(keys: &ArchivalPKeys) -> Owner<'_> {
        Owner {
            x25519_sk: keys.view_sk.as_canonical_bytes(),
            ml_kem_dk: keys.ml_kem_dk.as_canonical_bytes(),
            spend_public: keys.spend_pk.as_canonical_bytes(),
            spend_secret: keys.spend_sk.as_canonical_bytes(),
        }
    }
}

/// A miner's wallet, secrets included: the Edwards spend pair and the
/// hybrid KEM decapsulation keys the coinbase's `0x06` field is
/// encapsulated to. Kept whole rather than reduced to its
/// [`Recipient`] because the point of the harness paying a wallet is that
/// a test can later spend what it was paid.
pub struct MinerWallet {
    /// The Edwards spend secret `b`; `spend_public = b·G`.
    spend_secret: Zeroizing<[u8; 32]>,
    /// The hybrid KEM decapsulation keys.
    kem_secret: HybridKemSecretKey,
    /// The public half, as a payer sees it.
    recipient: Recipient,
}

impl MinerWallet {
    /// The fixture wallet `seed` derives: the spend secret is the
    /// [`fixture_expand`] of `shekyl-ed25519-spend`, the X25519 scalar that
    /// of `shekyl-ed25519-view` (its public key the raw scalar times the
    /// basepoint, as `HybridX25519MlKem::keypair_generate` forms it), and
    /// the ML-KEM-768 pair is `ml_kem_keypair_from_d_z` over the 64-byte
    /// expand of `shekyl-ml-kem-768`.
    ///
    /// # Panics
    ///
    /// ML-KEM-768 key generation is total over a 64-byte seed; a failure
    /// is a broken primitive, not a seed to handle.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let spend = Zeroizing::new(Scalar::from_bytes_mod_order(fixture_expand::<32>(
            seed,
            b"shekyl-ed25519-spend",
        )));
        let view = Zeroizing::new(Scalar::from_bytes_mod_order(fixture_expand::<32>(
            seed,
            b"shekyl-ed25519-view",
        )));
        let d_z = Zeroizing::new(fixture_expand::<64>(seed, b"shekyl-ml-kem-768"));
        let (ml_kem_ek, ml_kem_dk) =
            ml_kem_keypair_from_d_z(&d_z).expect("ML-KEM-768 keygen is total over a 64-byte seed");
        Self {
            spend_secret: Zeroizing::new(spend.to_bytes()),
            kem_secret: HybridKemSecretKey {
                x25519: view.to_bytes(),
                ml_kem: ml_kem_dk.as_canonical_bytes().to_vec(),
            },
            recipient: Recipient {
                spend_public: EdwardsPoint::mul_base(&spend).compress().to_bytes(),
                x25519_pk: (*view * X25519_BASEPOINT).to_bytes(),
                ml_kem_ek: ml_kem_ek.to_vec(),
            },
        }
    }

    /// The harness miner — [`from_seed`](Self::from_seed) over
    /// [`HARNESS_SEED`], derived once per process. Every
    /// [`coinbase::paying`] call the rules harness makes pays this wallet.
    #[must_use]
    pub fn harness() -> &'static MinerWallet {
        static HARNESS: LazyLock<MinerWallet> =
            LazyLock::new(|| MinerWallet::from_seed(&HARNESS_SEED));
        &HARNESS
    }

    /// The wallet `seed` derives on `network`, through the wallet's own
    /// derivation (`account_from_seed`, NI-R7): the account's spend pair,
    /// its view scalar as the X25519 decapsulation secret (the scanner's,
    /// as [`Owner::persona`] reads a persona's), and its ML-KEM-768 pair.
    /// The same wallet a user restoring `seed` on `network` holds, so a
    /// chain paying it is spendable by the production wallet stack.
    ///
    /// # Panics
    ///
    /// If the account derivation fails, which it does only for a view
    /// scalar on a low-order point: negligible, and a broken primitive
    /// rather than a seed to handle.
    #[must_use]
    pub fn from_account(seed: &[u8; SEED_BYTES], network: Network) -> Self {
        let (_master, keys) =
            account_from_seed(seed, network).expect("the account derivation is total");
        // Into the fields. A deref of `as_canonical_bytes` would leave an
        // unwiped copy of the secret (rule 35).
        let mut spend_secret = Zeroizing::new([0u8; 32]);
        spend_secret.copy_from_slice(keys.spend_sk.as_canonical_bytes());
        let mut kem_secret = HybridKemSecretKey {
            x25519: [0u8; 32],
            ml_kem: vec![0u8; ML_KEM_768_DK_LEN],
        };
        kem_secret
            .x25519
            .copy_from_slice(keys.view_sk.as_canonical_bytes());
        kem_secret
            .ml_kem
            .copy_from_slice(keys.ml_kem_dk.as_canonical_bytes());
        Self {
            spend_secret,
            kem_secret,
            recipient: Recipient {
                spend_public: *keys.spend_pk.as_canonical_bytes(),
                x25519_pk: keys.x25519_pk,
                ml_kem_ek: keys.ml_kem_ek.to_vec(),
            },
        }
    }

    /// The miner of a chain that carries regtest's identity —
    /// [`from_account`](Self::from_account) over [`HARNESS_SEED`] on
    /// [`Network::Regtest`], derived once per process (`CHAIN_FORGE.md` §6).
    #[must_use]
    pub fn harness_regtest() -> &'static MinerWallet {
        static REGTEST: LazyLock<MinerWallet> =
            LazyLock::new(|| MinerWallet::from_account(&HARNESS_SEED, Network::Regtest));
        &REGTEST
    }

    /// The public half, as a payer addresses it.
    #[must_use]
    pub fn recipient(&self) -> &Recipient {
        &self.recipient
    }

    /// The Edwards spend secret `b`.
    #[must_use]
    pub fn spend_secret(&self) -> &[u8; 32] {
        &self.spend_secret
    }

    /// The hybrid KEM decapsulation keys.
    #[must_use]
    pub fn kem_secret(&self) -> &HybridKemSecretKey {
        &self.kem_secret
    }
}

impl core::fmt::Debug for MinerWallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MinerWallet")
            .field("spend_secret", &"[REDACTED]")
            .field("kem_secret", &self.kem_secret)
            .field("recipient", &self.recipient)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_harness_miner_is_a_function_of_its_seed() {
        let again = MinerWallet::from_seed(&HARNESS_SEED);
        assert_eq!(MinerWallet::harness().recipient(), again.recipient());
        assert_eq!(MinerWallet::harness().spend_secret(), again.spend_secret());
        assert_eq!(
            MinerWallet::harness().kem_secret().ml_kem,
            again.kem_secret().ml_kem
        );
    }

    #[test]
    fn two_seeds_are_two_wallets() {
        let other = MinerWallet::from_seed(&[0x11; 32]);
        assert_ne!(MinerWallet::harness().recipient(), other.recipient());
    }

    /// The regtest miner is the account the wallet derives from the seed
    /// on regtest, key for key, and no other network's.
    #[test]
    fn the_regtest_miner_is_the_seeds_regtest_account() {
        let (_master, account) =
            account_from_seed(&HARNESS_SEED, Network::Regtest).expect("derives");
        let miner = MinerWallet::harness_regtest();
        assert_eq!(
            miner.recipient().spend_public,
            *account.spend_pk.as_canonical_bytes()
        );
        assert_eq!(miner.recipient().x25519_pk, account.x25519_pk);
        assert_eq!(miner.recipient().ml_kem_ek, account.ml_kem_ek.to_vec());
        assert_eq!(miner.spend_secret(), account.spend_sk.as_canonical_bytes());
        assert_eq!(
            &miner.kem_secret().x25519,
            account.view_sk.as_canonical_bytes()
        );
        for other in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            assert_ne!(
                MinerWallet::from_account(&HARNESS_SEED, other).recipient(),
                miner.recipient(),
                "{other}"
            );
        }
        assert_ne!(MinerWallet::harness().recipient(), miner.recipient());
    }

    /// The public seed's regtest address is regtest's alone: the wallet's
    /// payment decoder takes it on regtest and refuses it on every other
    /// network as another network's, because its prefix is regtest's
    /// (`HARNESS_SEED`'s docs; `CHAIN_FORGE.md` §6).
    #[test]
    fn the_regtest_miners_address_is_refused_off_regtest() {
        use shekyl_address::{AddressError, PaymentAddress};

        let (_master, account) =
            account_from_seed(&HARNESS_SEED, Network::Regtest).expect("derives");
        let encoded = account
            .to_address(Network::Regtest)
            .encode()
            .expect("the address encodes");
        assert!(
            encoded.starts_with(Network::Regtest.prefixes().classical),
            "{encoded}"
        );
        let accepted = PaymentAddress::decode(&encoded, Network::Regtest)
            .expect("regtest takes its own address");
        assert_eq!(
            accepted.as_address().spend_key,
            MinerWallet::harness_regtest().recipient().spend_public
        );
        for other in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            assert!(
                !encoded.starts_with(other.prefixes().classical),
                "{other}'s prefix is not regtest's"
            );
            match PaymentAddress::decode(&encoded, other) {
                Err(AddressError::NetworkMismatch {
                    addr_net,
                    expected_net,
                }) => {
                    assert_eq!(addr_net, Network::Regtest, "{other}");
                    assert_eq!(expected_net, other);
                }
                refused => panic!("{other} did not refuse regtest's address: {refused:?}"),
            }
        }
    }
}
