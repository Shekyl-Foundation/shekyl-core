// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Each network's genesis: the coinbase transaction, the mint time and the
//! block hash (`NETWORK_IDENTITY.md` NI-Q3, NI-R18).
//!
//! The genesis tool writes the three files under `genesis/`: `geblock mint`
//! stamps a network's mint time from the clock and pins it, and `geblock
//! pin` rebuilds the transaction and hash from the recipients file under the
//! recorded time. Its table test rebuilds them; nothing edits them by hand.
//! The block is the transaction under the genesis header (the mint time,
//! nonce 0, NI-Q1), which the node assembles; the hash is pinned here
//! because assembling a block needs the wire crate this table sits below.

use core::num::NonZeroU64;

/// A genesis block's timestamp: the second its genesis was minted, never
/// zero (NI-R18). Every other block's timestamp is checked against the
/// chain before it; genesis has no chain before it, so its time is the
/// tool's clock when the network was minted, recorded with its pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenesisTimestamp(NonZeroU64);

impl GenesisTimestamp {
    /// The mint time `seconds` after the Unix epoch, or `None` at zero.
    #[must_use]
    pub const fn new(seconds: u64) -> Option<Self> {
        match NonZeroU64::new(seconds) {
            Some(s) => Some(Self(s)),
            None => None,
        }
    }

    /// Seconds after the Unix epoch, the header's timestamp.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// One network's genesis.
#[derive(Debug)]
pub struct Genesis {
    tx_hex: &'static str,
    timestamp: GenesisTimestamp,
    hash: [u8; 32],
    provisional: bool,
}

impl Genesis {
    /// The genesis coinbase transaction, hex.
    #[must_use]
    pub fn tx_hex(&self) -> &'static str {
        self.tx_hex.trim_end()
    }

    /// The genesis block's timestamp: when this network was minted.
    #[must_use]
    pub const fn timestamp(&self) -> GenesisTimestamp {
        self.timestamp
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

/// A timestamp file's decimal seconds, with an optional trailing newline.
/// Zero, a sign, a leading zero or anything but digits fails the build.
pub(crate) const fn timestamp_file(text: &str) -> GenesisTimestamp {
    let b = text.as_bytes();
    let len = if !b.is_empty() && b[b.len() - 1] == b'\n' {
        b.len() - 1
    } else {
        b.len()
    };
    assert!(
        len > 0 && len <= 20 && b[0] != b'0',
        "a genesis timestamp file holds the mint second in decimal, not zero"
    );
    let mut seconds: u64 = 0;
    let mut i = 0;
    while i < len {
        let c = b[i];
        assert!(
            c.is_ascii_digit(),
            "a genesis timestamp file holds decimal digits"
        );
        seconds = match seconds.checked_mul(10) {
            Some(v) => match v.checked_add((c - b'0') as u64) {
                Some(v) => v,
                None => panic!("a genesis timestamp overflows u64"),
            },
            None => panic!("a genesis timestamp overflows u64"),
        };
        i += 1;
    }
    match GenesisTimestamp::new(seconds) {
        Some(t) => t,
        None => panic!("a genesis timestamp is never zero"),
    }
}

pub(crate) const MAINNET: Genesis = Genesis {
    tx_hex: include_str!("../genesis/mainnet.tx.hex"),
    timestamp: timestamp_file(include_str!("../genesis/mainnet.timestamp")),
    hash: hash_file(include_str!("../genesis/mainnet.hash")),
    provisional: true,
};

pub(crate) const TESTNET: Genesis = Genesis {
    tx_hex: include_str!("../genesis/testnet.tx.hex"),
    timestamp: timestamp_file(include_str!("../genesis/testnet.timestamp")),
    hash: hash_file(include_str!("../genesis/testnet.hash")),
    provisional: false,
};

pub(crate) const STAGENET: Genesis = Genesis {
    tx_hex: include_str!("../genesis/stagenet.tx.hex"),
    timestamp: timestamp_file(include_str!("../genesis/stagenet.timestamp")),
    hash: hash_file(include_str!("../genesis/stagenet.hash")),
    provisional: false,
};

pub(crate) const REGTEST: Genesis = Genesis {
    tx_hex: include_str!("../genesis/regtest.tx.hex"),
    timestamp: timestamp_file(include_str!("../genesis/regtest.timestamp")),
    hash: hash_file(include_str!("../genesis/regtest.hash")),
    provisional: false,
};
