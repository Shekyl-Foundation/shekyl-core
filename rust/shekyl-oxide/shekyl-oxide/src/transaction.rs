//! Wallet-domain transaction types retained after the block/tx **serializer** was
//! removed (un-vendor slice 1). The canonical genesis tx/block serializer lives in the
//! Shekyl-owned `shekyl-wire` crate; only the wallet-domain types the scanner still
//! consumes (the `Timelock` enum, the `StakingMeta` struct) remain here, pending their
//! native home in Track B of `docs/design/SHEKYL_OXIDE_UNVENDOR.md`.

use core::cmp::Ordering;
use std_shims::io::{self, Read, Write};
#[allow(unused_imports)]
use std_shims::prelude::*;

use zeroize::Zeroize;

use crate::io::{read_varint, write_varint};

/// Metadata attached to a staked output (serialized as tag 0x04).
///
/// `lock_until` is not stored on-chain. The effective lock expiry is computed
/// dynamically as `creation_height + tier_lock_blocks` wherever needed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct StakingMeta {
    /// Tier index: 0=short, 1=medium, 2=long.
    pub lock_tier: u8,
}

/// An additional timelock for a transaction.
///
/// Outputs are locked by a default timelock. If a timelock is explicitly specified, the
/// longer of the two will be the timelock used.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum Timelock {
    /// No additional timelock.
    None,
    /// Additionally locked until this block.
    Block(usize),
    /// Additionally locked until this many seconds since the epoch.
    Time(u64),
}

impl Timelock {
    /// Write the Timelock.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            Timelock::None => write_varint(&0u8, w),
            Timelock::Block(block) => write_varint(block, w),
            Timelock::Time(time) => write_varint(time, w),
        }
    }

    /// Serialize the Timelock to a `Vec<u8>`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(1);
        self.write(&mut res)
            .expect("write failed but <Vec as io::Write> doesn't fail");
        res
    }

    /// Read a Timelock.
    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        const TIMELOCK_BLOCK_THRESHOLD: usize = 500_000_000;

        let raw = read_varint::<_, u64>(r)?;
        Ok(if raw == 0 {
            Timelock::None
        } else if raw
            < u64::try_from(TIMELOCK_BLOCK_THRESHOLD)
                .expect("TIMELOCK_BLOCK_THRESHOLD didn't fit in a u64")
        {
            Timelock::Block(usize::try_from(raw).expect(
        "timelock overflowed usize despite being less than a const representable with a usize",
      ))
        } else {
            Timelock::Time(raw)
        })
    }
}

impl PartialOrd for Timelock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Timelock::None, Timelock::None) => Some(Ordering::Equal),
            (Timelock::None, _) => Some(Ordering::Less),
            (_, Timelock::None) => Some(Ordering::Greater),
            (Timelock::Block(a), Timelock::Block(b)) => a.partial_cmp(b),
            (Timelock::Time(a), Timelock::Time(b)) => a.partial_cmp(b),
            _ => None,
        }
    }
}
