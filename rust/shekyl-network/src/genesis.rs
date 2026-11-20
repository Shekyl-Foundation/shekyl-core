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
//! The mint time's pin text has one reading, [`GenesisTimestamp::from_pin`],
//! and one writing, [`GenesisTimestamp::to_pin`].

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

    /// The pin file's text for `self`: decimal seconds and one newline.
    /// [`from_pin`](Self::from_pin) reads it back.
    #[must_use]
    pub fn to_pin(self) -> String {
        format!("{}\n", self.get())
    }

    /// `text` as a mint time. One optional trailing newline, then decimal
    /// digits with no sign and no leading zero. `None` when the text is
    /// empty, zero, signed, padded, not decimal, or does not fit in a `u64`.
    #[must_use]
    pub const fn from_pin(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        let len = if !bytes.is_empty() && bytes[bytes.len() - 1] == b'\n' {
            bytes.len() - 1
        } else {
            bytes.len()
        };
        if len == 0 || bytes[0] == b'0' {
            return None;
        }
        let mut seconds: u64 = 0;
        let mut i = 0;
        while i < len {
            let c = bytes[i];
            if !c.is_ascii_digit() {
                return None;
            }
            let Some(scaled) = seconds.checked_mul(10) else {
                return None;
            };
            let Some(next) = scaled.checked_add((c - b'0') as u64) else {
                return None;
            };
            seconds = next;
            i += 1;
        }
        // The first digit is `1..=9`, so `seconds` is not zero.
        Self::new(seconds)
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

/// A timestamp pin, read by [`GenesisTimestamp::from_pin`]. A pin that does
/// not read fails the build.
const fn timestamp_file(text: &str) -> GenesisTimestamp {
    match GenesisTimestamp::from_pin(text) {
        Some(t) => t,
        None => panic!("a genesis timestamp pin holds one non-zero decimal second"),
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
