// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A multisig group for tests: its address, the keys behind it, and each
//! member's scanner (TEST_ONLY, `test-utils`).
//!
//! The keys are fixed scalars and freshly drawn KEM key pairs; the group is
//! one a ceremony could have made, not one it did. A test pays it through
//! a production path and scans the result as each member.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use shekyl_address::multisig_address::MultisigAddressPayload;
use shekyl_address::Network;
use shekyl_crypto_pq::kem::{
    HybridKemPublicKey, HybridKemSecretKey, HybridX25519MlKem, KeyEncapsulation,
};
use shekyl_curve_generators::T;
use zeroize::Zeroizing;

use crate::multisig_scan::MultisigMemberScan;
use crate::{GroupScanner, ViewPair};

/// A test group: its address and the keys its members hold.
pub struct TestGroup {
    /// The group's address.
    pub address: MultisigAddressPayload,
    /// The group's plaintext view/link scalar `b` (every member holds it).
    pub b: Scalar,
    /// The group's spend point `B + Y`.
    pub spend: EdwardsPoint,
    /// The group's hybrid KEM secret (every member holds it).
    pub group_sk: HybridKemSecretKey,
    /// Each member's own hybrid KEM secret, member order.
    pub member_sks: Vec<HybridKemSecretKey>,
}

fn kem_bytes(pk: &HybridKemPublicKey) -> Vec<u8> {
    let mut out = pk.x25519.to_vec();
    out.extend_from_slice(&pk.ml_kem);
    out
}

/// An `m`-of-`n` group on `network`.
///
/// # Panics
///
/// When no group has that size (a test bug).
#[must_use]
pub fn test_group(network: Network, n: u8, m: u8) -> TestGroup {
    let kem = HybridX25519MlKem;
    let b = Scalar::from_bytes_mod_order([0x21; 32]);
    let y = Scalar::from_bytes_mod_order([0x23; 32]);
    let b_point = ED25519_BASEPOINT_POINT * b;
    let y_point = *T * y;
    let (group_pk, group_sk) = kem.keypair_generate().expect("a KEM key pair");
    let (member_pks, member_sks): (Vec<_>, Vec<_>) = (0..n)
        .map(|_| kem.keypair_generate().expect("a KEM key pair"))
        .unzip();
    let address = MultisigAddressPayload::new(
        network,
        n,
        m,
        b_point.compress().to_bytes(),
        y_point.compress().to_bytes(),
        kem_bytes(&group_pk),
        member_pks.iter().map(kem_bytes).collect(),
    )
    .expect("a valid group address");
    TestGroup {
        address,
        b,
        spend: b_point + y_point,
        group_sk,
        member_sks,
    }
}

impl TestGroup {
    /// The network id the group's outputs bind: its address's network's.
    #[must_use]
    pub fn network_id(&self) -> [u8; 16] {
        self.address.network().network_id()
    }

    /// Member `i`'s scanner.
    ///
    /// # Panics
    ///
    /// When the group has no member `i` (a test bug).
    #[must_use]
    pub fn member_scanner(&self, i: u8) -> GroupScanner {
        let pair = ViewPair::new(
            self.spend,
            Zeroizing::new(Scalar::from_bytes_mod_order([0x07; 32])),
            Zeroizing::new(self.group_sk.x25519),
            Zeroizing::new(self.group_sk.ml_kem.clone()),
        )
        .expect("a valid view pair");
        GroupScanner::new(
            pair,
            Zeroizing::new(self.b.to_bytes()),
            MultisigMemberScan::new(
                i,
                self.address.n_total(),
                self.address.m_required(),
                self.member_sks[usize::from(i)].clone(),
                self.network_id(),
            ),
        )
    }
}
