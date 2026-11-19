// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The corpus header, one layout for the writer and the reader.
//!
//! ```text
//! MAGIC ‖ version u32 ‖ net u8 ‖ first_height u64 ‖ count u64
//! ```
//!
//! Field widths live in the crate root. This module places them. A count
//! written later ([`crate::CorpusWriter::finish`]) overwrites the count
//! field at [`crate::COUNT_OFFSET`]; the rest of the header does not move.

use shekyl_network::Network;
use shekyl_types::BlockHeight;

use crate::fault::CorpusFault;
use crate::{
    CORPUS_FORMAT_VERSION, CORPUS_MAGIC, COUNT_OFFSET, HEADER_LEN, HEIGHT_AT, MAGIC_LEN, NET_AT,
    VERSION_AT,
};

/// What [`decode`] read out of a header.
pub(crate) struct Decoded {
    pub net: Network,
    pub first: BlockHeight,
    pub declared: u64,
}

/// A header whose record count is `count`. `create` passes `0`; `finish`
/// does not rebuild the header, it patches the count field in place.
pub(crate) fn encode(net: Network, first: BlockHeight, count: u64) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..MAGIC_LEN].copy_from_slice(&CORPUS_MAGIC);
    header[VERSION_AT..NET_AT].copy_from_slice(&CORPUS_FORMAT_VERSION.to_le_bytes());
    header[NET_AT..HEIGHT_AT].copy_from_slice(&net.code().to_le_bytes());
    header[HEIGHT_AT..COUNT_OFFSET].copy_from_slice(&first.to_raw().to_le_bytes());
    header[COUNT_OFFSET..HEADER_LEN].copy_from_slice(&count.to_le_bytes());
    header
}

/// The header `bytes` are. Refuses a foreign magic, version, or network
/// before any record is read.
///
/// # Errors
///
/// [`CorpusFault::BadMagic`], [`CorpusFault::UnsupportedVersion`],
/// [`CorpusFault::UnknownNet`].
pub(crate) fn decode(header: &[u8; HEADER_LEN]) -> Result<Decoded, CorpusFault> {
    if header[..MAGIC_LEN] != CORPUS_MAGIC {
        return Err(CorpusFault::BadMagic);
    }
    let version = u32::from_le_bytes(
        header[VERSION_AT..NET_AT]
            .try_into()
            .expect("version is a u32: VERSION_LEN is size_of::<u32>()"),
    );
    if version != CORPUS_FORMAT_VERSION {
        return Err(CorpusFault::UnsupportedVersion { found: version });
    }
    let net_tag = header[NET_AT..HEIGHT_AT]
        .try_into()
        .expect("the network tag is one byte: NET_LEN is size_of::<u8>()");
    let net_tag = u8::from_le_bytes(net_tag);
    let net = Network::from_code(net_tag).ok_or(CorpusFault::UnknownNet(net_tag))?;
    let first = BlockHeight::from_raw(u64::from_le_bytes(
        header[HEIGHT_AT..COUNT_OFFSET]
            .try_into()
            .expect("first_height is a u64: HEIGHT_LEN is size_of::<u64>()"),
    ));
    let declared = u64::from_le_bytes(
        header[COUNT_OFFSET..HEADER_LEN]
            .try_into()
            .expect("the record count is a u64: COUNT_LEN is size_of::<u64>()"),
    );
    Ok(Decoded {
        net,
        first,
        declared,
    })
}
