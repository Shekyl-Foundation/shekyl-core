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
//! M = varint(len(net)) ‖ net_ascii            net ∈ {"mainnet","testnet","stagenet"}
//!     ‖ varint(n_recipients)
//!     ‖ for each recipient, in file order:
//!         spend_pk(32) ‖ view_pk(32)
//!         ‖ varint(len(ek)) ‖ ek              ML-KEM-768 encap key
//!         ‖ amount_atomic as u64 LE (8 bytes)
//!
//! seed      = cSHAKE256-32(customization = "shekyl/genesis-txkey-v2", input = M)
//! tx_secret = seed reduced mod ℓ  (Scalar::from_bytes_mod_order, ≡ C++ sc_reduce32)
//! tx_pub    = tx_secret · G       (compressed Ed25519; the tx_extra 0x01 field)
//! ```
//!
//! varint is the shekyl-wire wire varint. The customization string follows the
//! house `b"shekyl/<domain>-v1"` convention (rule 30); a KAT in
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

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use shekyl_address::Network;
use shekyl_wire::varint::write_varint;

use crate::recipients::{network_str, Recipient};

/// cSHAKE256 customization string for the genesis tx-key derivation.
///
/// v2 remints the preimage onto **payment identity** (spend/view/ek +
/// amount), not the Bech32m spelling. v1 hashed the canonical address
/// string, so a layout correction rotated the founding tx; that coupling
/// is deleted pre-genesis. The `v1` literal is retired unused.
pub const GENESIS_TXKEY_CUSTOMIZATION: &[u8] = b"shekyl/genesis-txkey-v2";

/// Derive the deterministic genesis tx secret scalar (canonical 32-byte form)
/// for `net` over the validated recipients, per the module-doc spec.
///
/// The output is **not secret** — it is recomputable by anyone holding the
/// published recipients file; see the module docs for why that is sound.
#[must_use]
pub fn derive_genesis_tx_secret(net: Network, recipients: &[Recipient]) -> [u8; 32] {
    let mut m: Vec<u8> = Vec::new();
    let net_str = network_str(net).as_bytes();
    write_varint(net_str.len(), &mut m).expect("writing to a Vec is infallible");
    m.extend_from_slice(net_str);
    write_varint(recipients.len(), &mut m).expect("writing to a Vec is infallible");
    for r in recipients {
        m.extend_from_slice(&r.address.spend_key);
        m.extend_from_slice(&r.address.view_key);
        let ek = &r.address.ml_kem_encap_key;
        write_varint(ek.len(), &mut m).expect("writing to a Vec is infallible");
        m.extend_from_slice(ek);
        m.extend_from_slice(&r.amount.to_le_bytes());
    }

    let seed = shekyl_crypto_hash::cshake256_32(GENESIS_TXKEY_CUSTOMIZATION, &m);
    Scalar::from_bytes_mod_order(seed).to_bytes()
}

/// The tx public key `R = r·G` for a canonical secret scalar, compressed —
/// the payload of the genesis `tx_extra` `0x01` field.
#[must_use]
pub fn tx_pubkey(tx_secret: &[u8; 32]) -> [u8; 32] {
    let r = Scalar::from_bytes_mod_order(*tx_secret);
    EdwardsPoint::mul_base(&r).compress().to_bytes()
}
