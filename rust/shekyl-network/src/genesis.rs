// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Each network's genesis: the coinbase transaction and the block hash
//! (`NETWORK_IDENTITY.md` NI-Q3).
//!
//! The genesis tool (`geblock pin`) writes both files under `genesis/` from
//! the network's recipients file, and its table test rebuilds them; nothing
//! edits them by hand. The block is the transaction under the fixed genesis
//! header (nonce 0, NI-Q1), which the node assembles; the hash is pinned
//! here because assembling a block needs the wire crate this table sits
//! below.

/// One network's genesis.
#[derive(Debug)]
pub struct Genesis {
    tx_hex: &'static str,
    hash: [u8; 32],
    provisional: bool,
}

impl Genesis {
    /// The genesis coinbase transaction, hex.
    #[must_use]
    pub fn tx_hex(&self) -> &'static str {
        self.tx_hex.trim_end()
    }

    /// The genesis block hash: the chain id, from which the network id is
    /// derived.
    #[must_use]
    pub const fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Whether this genesis waits on its recipients' ceremony (NI-R11):
    /// mainnet's, until its custodians deliver their re-derived recipients
    /// files. Nothing ships on a provisional genesis.
    #[must_use]
    pub const fn provisional(&self) -> bool {
        self.provisional
    }
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("a genesis hash file holds 64 lowercase hex digits"),
    }
}

/// A hash file's 64 hex digits, with an optional trailing newline.
const fn hash_file(text: &str) -> [u8; 32] {
    let b = text.as_bytes();
    assert!(
        b.len() == 64 || (b.len() == 65 && b[64] == b'\n'),
        "a genesis hash file holds 64 hex digits and a newline"
    );
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

pub(crate) const MAINNET: Genesis = Genesis {
    tx_hex: include_str!("../genesis/mainnet.tx.hex"),
    hash: hash_file(include_str!("../genesis/mainnet.hash")),
    provisional: true,
};

pub(crate) const TESTNET: Genesis = Genesis {
    tx_hex: include_str!("../genesis/testnet.tx.hex"),
    hash: hash_file(include_str!("../genesis/testnet.hash")),
    provisional: false,
};

pub(crate) const STAGENET: Genesis = Genesis {
    tx_hex: include_str!("../genesis/stagenet.tx.hex"),
    hash: hash_file(include_str!("../genesis/stagenet.hash")),
    provisional: false,
};

pub(crate) const REGTEST: Genesis = Genesis {
    tx_hex: include_str!("../genesis/regtest.tx.hex"),
    hash: hash_file(include_str!("../genesis/regtest.hash")),
    provisional: false,
};
