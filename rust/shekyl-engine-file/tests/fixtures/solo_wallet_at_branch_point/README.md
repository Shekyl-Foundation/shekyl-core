<!--
Copyright (c) 2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# A solo wallet written at multisig 4a-2a's branch point

`solo.wallet.keys` and `solo.wallet` are a solo wallet written by `dev` at
`25745115a4`, the commit multisig slice 4a-2a branched from (wallet ledger
format 26, ledger block 15, send journal block 6).

R-36 (the group ledger changes nothing in the solo ledger) was shown with
them at `6e35cbef15`: the branch opened these files and saved the same
ledger bytes back. R-37 then moved the send journal to version 7 and the
wallet ledger to 27, so `tests/solo_wallet_at_branch_point.rs` now holds the
other side: the same files are refused by their ledger version, the one
refusal that names the remedy.

## What the wallet holds

The ledger is `populated_solo_ledger()` in that test as it stands at
`6e35cbef15`, every block filled:
four transfers (one spent, one refused for its leaf, one attributed to a
payment request), a reorg trail, an address book, a note, a retained
transaction key for each of two sends, a restore anchor, staking with a bond
sighting, and a send journal with a confirmed send to an address and a held
send funding the wallet's own persona. The password is
`r36-branch-point`; the seed is `[0x36; 32]`, the network testnet, and the
key-derivation cost the smallest the format takes (`m_log2` 8, `t` 1,
`p` 1).

## How it was written

At a clean checkout of `25745115a4`, the test file as committed with this
fixture (`6e35cbef15`) was copied into `rust/shekyl-engine-file/tests/`,
with this one test added, and run with
`cargo test -p shekyl-engine-file --test solo_wallet_at_branch_point -- --ignored --exact write_the_fixture_at_the_branch_point`:

```rust
#[test]
#[ignore = "writes the fixture; run at the branch point only"]
fn write_the_fixture_at_the_branch_point() {
    use shekyl_crypto_pq::wallet_envelope::{
        CapabilityContent, KdfParams, EXPECTED_CLASSICAL_ADDRESS_BYTES,
    };
    use shekyl_engine_file::CreateParams;
    let out = fixture_dir();
    std::fs::create_dir_all(&out).unwrap();
    let base = out.join("solo.wallet");
    assert!(!base.exists(), "the fixture is written once");
    let seed = [0x36u8; 32];
    let capability = CapabilityContent::Full { seed: &seed };
    let mut address = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
    address[0] = 0x01;
    let ledger = populated_solo_ledger();
    ledger.preflight_save().expect("the fixture's ledger is save-safe");
    let file = WalletFile::create(&CreateParams {
        base_path: &base,
        password: PASSWORD,
        network: Network::Testnet,
        capability: &capability,
        creation_timestamp: 0x6000_0000,
        restore_height_hint: 100,
        expected_classical_address: &address,
        kdf: KdfParams { m_log2: 0x08, t: 1, p: 1 },
        initial_ledger: &ledger,
    })
    .expect("create");
    file.save_state(file.session_wrap_key_region_2(), &ledger)
        .expect("save");
}
```

The generator is not committed: run again, it would write the files at
whatever ledger format the checkout has, and the point of the fixture is
that `dev` at the branch point wrote it.
