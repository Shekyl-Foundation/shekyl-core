// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Deterministic genesis transaction key.
//!
//! The retired C++ builder drew a fresh `keypair::generate` tx key on every
//! run, so the pinned `GENESIS_TX` was never reproducible and the old
//! `verify_genesis.py` byte-compare could never pass. Here the key is derived
//! from the published recipients file itself, so anyone can rebuild the exact
//! pinned bytes from `config/genesis_recipients.<net>.json`.
//!
//! # Derivation (publish verbatim; `docs/GENESIS_ALLOCATIONS.md`)
//!
//! ```text
//! R = varint(n_recipients)
//!     ‖ for each recipient, in file order:
//!         spend_pk(32) ‖ view_pk(32)
//!         ‖ varint(len(ek)) ‖ ek              ML-KEM-768 encap key
//!         ‖ amount_atomic as u64 LE (8 bytes)
//!
//! seed      = frame("shekyl/genesis-txkey-v3", name_id, [R])   32 bytes
//! tx_secret = seed reduced mod ℓ  (Scalar::from_bytes_mod_order, ≡ C++ sc_reduce32)
//! tx_pub    = tx_secret · G       (compressed Ed25519; the tx_extra 0x01 field)
//! ```
//!
//! The frame and the reduction are `shekyl-crypto-pq`'s
//! (`TxKey::from_genesis_seed`, its `GENESIS_TXKEY` domain): the one place
//! a transaction key is made. This module writes `R`.
//!
//! `frame` is the signing envelope's (`shekyl_network::envelope`): cSHAKE256
//! under the customization, over the 16-byte binding then each field behind
//! its u64-LE length. The binding is the network's `name_id`, the value its
//! name derives (`shekyl/network-name-v1`) and the one every key derivation
//! is salted with, so genesis commits to the network's name through it
//! (NI-R12). varint is the shekyl-wire varint. A KAT in
//! `tests/golden_kat.rs` pins the derivation.
//!
//! # Why a public tx key is sound here
//!
//! Genesis is transparent by design: the ct type is Null, output amounts are
//! cleartext varints, and the recipient addresses are published
//! (`docs/GENESIS_TRANSPARENCY.md`). The tx key's only jobs — amount privacy
//! and recipient unlinkability — are deliberately absent at height 0, and the
//! key cannot spend: spending needs the recipients' secret spend keys and
//! FCMP++ membership proofs, and later spends of these outputs are protected
//! by the same membership-proof privacy as any other output. Publishing the
//! derivation therefore reveals nothing beyond what is already published, and
//! buys full reproducibility of the pinned genesis bytes.

use shekyl_address::Network;
use shekyl_crypto_pq::TxKey;
use shekyl_wire::varint::write_varint;

use crate::recipients::Recipient;

/// The genesis transaction's key for `net` over the validated recipients,
/// per the module-doc spec: [`TxKey::from_genesis_seed`] over the network's
/// `name_id` and the recipients field `R`, under
/// [`shekyl_crypto_pq::tx_key::GENESIS_TXKEY`].
///
/// The key is **not secret** — it is recomputable by anyone holding the
/// published recipients file; see the module docs for why that is sound.
#[must_use]
pub fn genesis_tx_key(net: Network, recipients: &[Recipient]) -> TxKey {
    // The table row's `name_id` (`shekyl_network`), never a literal here:
    // genesis commits to the network's name through this key (NI-R12).
    TxKey::from_genesis_seed(&net.name_id(), &recipients_field(recipients))
}

/// The derivation's one field `R`: the recipients' payment identities and
/// amounts, in file order. Payment identity (spend/view/ek + amount), never
/// an address's spelling, so a change of address format cannot rotate the
/// founding transaction.
fn recipients_field(recipients: &[Recipient]) -> Vec<u8> {
    let mut m: Vec<u8> = Vec::new();
    write_varint(recipients.len(), &mut m).expect("writing to a Vec is infallible");
    for r in recipients {
        m.extend_from_slice(&r.address.spend_key);
        m.extend_from_slice(&r.address.view_key);
        let ek = &r.address.ml_kem_encap_key;
        write_varint(ek.len(), &mut m).expect("writing to a Vec is infallible");
        m.extend_from_slice(ek);
        m.extend_from_slice(&r.amount.to_le_bytes());
    }
    m
}
