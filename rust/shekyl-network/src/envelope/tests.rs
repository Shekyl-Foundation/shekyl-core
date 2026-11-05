// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use crate::Network;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const ID_2: IdDomain<2> = IdDomain::new(b"shekyl/tx-signable-v1");
const ID_2_WIDE: IdDomain<2, W64> = IdDomain::new(b"shekyl/tx-signable-v1");
const NAME_2: NameDomain<2> = NameDomain::new(b"shekyl/multisig-address-v3");

/// The input is the binding, raw, then each field behind its u64-LE length
/// (§2.6), hashed under the domain: the construction, byte for byte.
#[test]
fn the_input_is_the_binding_then_each_field_behind_its_length() {
    let id = Network::Testnet.network_id();
    let (a, b): (&[u8], &[u8]) = (b"field one", b"");
    let mut x = id.to_vec();
    x.extend_from_slice(&9u64.to_le_bytes());
    x.extend_from_slice(a);
    x.extend_from_slice(&0u64.to_le_bytes());
    assert_eq!(
        ID_2.frame(&id, [a, b]),
        cshake256_32(b"shekyl/tx-signable-v1", &x)
    );
    // Moving a byte across a field boundary changes the digest: the
    // lengths are what keeps the fields apart.
    assert_ne!(
        ID_2.frame(&id, [b"ab", b"c"]),
        ID_2.frame(&id, [b"a", b"bc"])
    );
}

/// The stdlib oracle's values (`scripts/kat/stdlib_cshake.py`, `frame()`,
/// anchored on NIST SP 800-185's cSHAKE256 samples #3 and #4): one per
/// width and one per binding. The 64-byte output extends the 32-byte one,
/// as an XOF's does.
#[test]
fn the_frames_are_the_oracles() {
    let id = Network::Testnet.network_id();
    let counting: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).expect("below 32"));
    let fields: [&[u8]; 2] = [&counting, &[0xaa; 32]];
    assert_eq!(
        hex(&ID_2.frame(&id, fields)),
        "63331bc96e0f6ce84fa1b07222e054853530f1c22eed0ac65caad702d2121d6c"
    );
    let wide = ID_2_WIDE.frame(&id, fields);
    assert_eq!(
        hex(&wide),
        "63331bc96e0f6ce84fa1b07222e054853530f1c22eed0ac65caad702d2121d6c\
         538ea991c4dee6772906cadcd76d354412e8baa3b316782af6048c27968e9981"
    );
    assert_eq!(
        hex(&NAME_2.frame(&Network::Testnet.name_id(), [b"", b"abc"])),
        "3b43163155a891e9ea9bd7a36d2c83f29fd4510f1da2f791d3c05fbf808205ba"
    );
}

/// The binding is what changes between networks: the same domain and
/// fields frame to a different digest on every network, under either
/// binding.
#[test]
fn every_network_frames_differently() {
    let fields: [&[u8]; 2] = [b"prefix", b"base"];
    for (i, a) in Network::ALL.iter().enumerate() {
        for b in &Network::ALL[i + 1..] {
            assert_ne!(
                ID_2.frame(&a.network_id(), fields),
                ID_2.frame(&b.network_id(), fields),
                "{a} and {b} under the id"
            );
            assert_ne!(
                NAME_2.frame(&a.name_id(), fields),
                NAME_2.frame(&b.name_id(), fields),
                "{a} and {b} under the name"
            );
        }
    }
}
