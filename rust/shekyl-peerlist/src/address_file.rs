// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The address file: what the peer lists keep across a restart
//! (`P2P_3_SLICE_1_PEERLIST_BRIEF.md` §7).
//!
//! The file is an unordered set of addresses. It holds no timestamp, no
//! list name and no connector tag, so nothing in it can rebuild a white
//! entry: a restart puts every address on gray, and white is reached
//! again only through a draw and a handshake (§2). The connector is
//! derived from the address type at load.
//!
//! The encoder writes the addresses sorted by their encoded bytes. The
//! order in memory is the order addresses arrived and moved, and a file
//! is read by whoever holds the disk.
//!
//! # Format, version 1
//!
//! All integers are little-endian.
//!
//! ```text
//! magic    8 bytes   "SKLPEERS"
//! version  u32       ADDRESS_FILE_VERSION
//! count    u32       number of entries
//! entry    count times:
//!   tag    u8        1 IPv4, 2 IPv6, 3 Tor
//!   IPv4:  4 bytes address, u16 port
//!   IPv6:  16 bytes address, u16 port
//!   Tor:   u8 host length, host bytes (UTF-8), u16 port
//! ```
//!
//! Nothing follows the last entry.
//!
//! # A file this build cannot read is dropped whole
//!
//! [`decode`] returns an error for any other magic, any other version, a
//! short file, trailing bytes, an unknown tag, or a count over
//! [`MAX_ENTRIES`]. The caller starts with empty lists and the next store
//! replaces the file. There is no migration: the lists refill from the
//! compiled seeds and from peers. That is also what happens to the C++
//! `p2pstate.bin` (a boost archive, version 9) on the first start of a
//! build that reads this format: its first bytes are not the magic.
//!
//! A change to these bytes bumps [`ADDRESS_FILE_VERSION`] in the same
//! commit (rule 42). `schemas/address_file.snap` pins the encoding of a
//! fixed set, and `schema-snapshot.yml` fails a PR that moves the
//! snapshot without raising the constant.

use std::net::{Ipv4Addr, Ipv6Addr};

use shekyl_net_address::NetworkAddress;
use shekyl_transport_layer::ConnectorId;

use crate::{GRAY_CAP, WHITE_CAP};

/// The address file's format version. A file with any other value is
/// dropped whole.
///
/// History:
/// - 1 (2026-10-12): the first Rust format. Addresses only.
pub const ADDRESS_FILE_VERSION: u32 = 1;

/// The file's first eight bytes.
pub const ADDRESS_FILE_MAGIC: [u8; 8] = *b"SKLPEERS";

/// The most entries a file may declare: every seat of every connector.
/// A larger count is refused before anything is allocated for it.
pub const MAX_ENTRIES: usize = (GRAY_CAP + WHITE_CAP) * ConnectorId::COUNT;

const TAG_IPV4: u8 = 1;
const TAG_IPV6: u8 = 2;
const TAG_TOR: u8 = 3;

/// Why a file was not read. Every one of these drops the whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressFileError {
    /// The first eight bytes are not [`ADDRESS_FILE_MAGIC`]: not an
    /// address file of any version this crate wrote.
    NotAnAddressFile,
    /// The file is an address file of a version this build does not read.
    Version {
        /// The version the file declares.
        found: u32,
    },
    /// The file declares more than [`MAX_ENTRIES`].
    TooManyEntries {
        /// The count the file declares.
        declared: u32,
    },
    /// The file ends before the entries it declares.
    Truncated,
    /// Bytes follow the last declared entry.
    TrailingBytes,
    /// An entry's tag is not one this version defines.
    UnknownTag {
        /// The tag byte.
        tag: u8,
    },
    /// A Tor host is not UTF-8.
    HostNotUtf8,
}

impl std::fmt::Display for AddressFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnAddressFile => write!(f, "not an address file"),
            Self::Version { found } => write!(
                f,
                "address file version {found}, this build reads {ADDRESS_FILE_VERSION}"
            ),
            Self::TooManyEntries { declared } => {
                write!(
                    f,
                    "address file declares {declared} entries, over {MAX_ENTRIES}"
                )
            }
            Self::Truncated => write!(f, "address file ends before its last entry"),
            Self::TrailingBytes => write!(f, "address file has bytes after its last entry"),
            Self::UnknownTag { tag } => write!(f, "address file entry has unknown tag {tag}"),
            Self::HostNotUtf8 => write!(f, "address file holds a host that is not UTF-8"),
        }
    }
}

impl std::error::Error for AddressFileError {}

/// One entry's bytes, or `None` for a Tor host too long for the one-byte
/// length (a v3 onion name is 62 bytes; nothing the lists hold is longer).
fn encode_entry(address: &NetworkAddress) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match address {
        NetworkAddress::Ipv4 { ip, port } => {
            out.push(TAG_IPV4);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_le_bytes());
        }
        NetworkAddress::Ipv6 { ip, port } => {
            out.push(TAG_IPV6);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_le_bytes());
        }
        NetworkAddress::Tor { host, port } => {
            out.push(TAG_TOR);
            out.push(u8::try_from(host.len()).ok()?);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_le_bytes());
        }
    }
    Some(out)
}

/// Encode `addresses` as a version-[`ADDRESS_FILE_VERSION`] file.
///
/// The entries are written sorted by their bytes and without duplicates,
/// so the file is the same for any order of the same set. An address
/// that cannot be encoded (a host over 255 bytes) and anything past
/// [`MAX_ENTRIES`] is left out; the lists hold neither.
#[must_use]
pub fn encode(addresses: &[NetworkAddress]) -> Vec<u8> {
    let mut entries: Vec<Vec<u8>> = addresses.iter().filter_map(encode_entry).collect();
    entries.sort();
    entries.dedup();
    entries.truncate(MAX_ENTRIES);
    let count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(16 + entries.iter().map(Vec::len).sum::<usize>());
    out.extend_from_slice(&ADDRESS_FILE_MAGIC);
    out.extend_from_slice(&ADDRESS_FILE_VERSION.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    for entry in entries {
        out.extend_from_slice(&entry);
    }
    out
}

/// A cursor over the file's bytes.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AddressFileError> {
        if self.rest.len() < n {
            return Err(AddressFileError::Truncated);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], AddressFileError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, AddressFileError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, AddressFileError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, AddressFileError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
}

/// Decode a file. Any error drops the whole file: no entry of a file that
/// fails is returned.
pub fn decode(bytes: &[u8]) -> Result<Vec<NetworkAddress>, AddressFileError> {
    let mut reader = Reader { rest: bytes };
    let magic = reader
        .array::<8>()
        .map_err(|_| AddressFileError::NotAnAddressFile)?;
    if magic != ADDRESS_FILE_MAGIC {
        return Err(AddressFileError::NotAnAddressFile);
    }
    let found = reader.u32()?;
    if found != ADDRESS_FILE_VERSION {
        return Err(AddressFileError::Version { found });
    }
    let declared = reader.u32()?;
    let count = usize::try_from(declared)
        .ok()
        .filter(|count| *count <= MAX_ENTRIES)
        .ok_or(AddressFileError::TooManyEntries { declared })?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let address = match reader.u8()? {
            TAG_IPV4 => NetworkAddress::Ipv4 {
                ip: Ipv4Addr::from(reader.array::<4>()?),
                port: reader.u16()?,
            },
            TAG_IPV6 => NetworkAddress::Ipv6 {
                ip: Ipv6Addr::from(reader.array::<16>()?),
                port: reader.u16()?,
            },
            TAG_TOR => {
                let len = usize::from(reader.u8()?);
                let host = std::str::from_utf8(reader.take(len)?)
                    .map_err(|_| AddressFileError::HostNotUtf8)?
                    .to_owned();
                NetworkAddress::Tor {
                    host,
                    port: reader.u16()?,
                }
            }
            tag => return Err(AddressFileError::UnknownTag { tag }),
        };
        out.push(address);
    }
    if !reader.rest.is_empty() {
        return Err(AddressFileError::TrailingBytes);
    }
    Ok(out)
}

#[cfg(test)]
mod snapshot {
    //! The rule-42 pin. `schema-snapshot.yml` runs this module by its
    //! path (`address_file::snapshot`) and compares
    //! [`ADDRESS_FILE_VERSION`] across the PR when the `.snap` moves.

    use super::{decode, encode, ADDRESS_FILE_VERSION};
    use shekyl_net_address::NetworkAddress;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    /// Built inline (rule 42): the subject is the encoding, so no shared
    /// fixture another change could move.
    fn fixture() -> Vec<NetworkAddress> {
        vec![
            NetworkAddress::Tor {
                host: format!("{}.onion", "a".repeat(56)),
                port: 18080,
            },
            NetworkAddress::Ipv6 {
                ip: Ipv6Addr::new(0x2a00, 0x1450, 0, 0, 0, 0, 0, 1),
                port: 18080,
            },
            NetworkAddress::Ipv4 {
                ip: Ipv4Addr::new(11, 22, 33, 44),
                port: 18080,
            },
            NetworkAddress::Ipv4 {
                ip: Ipv4Addr::new(11, 22, 33, 44),
                port: 1,
            },
        ]
    }

    fn rendered() -> String {
        let bytes = encode(&fixture());
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "# shekyl-peerlist address file, fixture encoding.\n\
             # A change here is a format change: bump ADDRESS_FILE_VERSION\n\
             # (rust/shekyl-peerlist/src/address_file.rs) in the same commit.\n\
             version = {ADDRESS_FILE_VERSION}\n\
             bytes = {hex}\n"
        )
    }

    fn snap_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas/address_file.snap")
    }

    #[test]
    fn the_fixture_encoding_matches_the_committed_snapshot() {
        let now = rendered();
        if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
            std::fs::write(snap_path(), &now).expect("write snapshot");
            panic!(
                "address_file.snap regenerated. Bump ADDRESS_FILE_VERSION if the bytes \
                 moved, then re-run without UPDATE_SNAPSHOTS: a run that rewrites its \
                 own expectation asserts nothing."
            );
        }
        let committed = std::fs::read_to_string(snap_path())
            .expect("schemas/address_file.snap is committed; regenerate with UPDATE_SNAPSHOTS=1");
        assert_eq!(
            committed, now,
            "the address file's bytes moved. If intended, bump ADDRESS_FILE_VERSION and \
             run UPDATE_SNAPSHOTS=1 cargo test -p shekyl-peerlist address_file::snapshot"
        );
    }

    #[test]
    fn the_fixture_decodes_back_to_its_set() {
        let mut expected = fixture();
        let mut decoded = decode(&encode(&fixture())).expect("decodes");
        expected.sort_by_key(|a| format!("{a:?}"));
        decoded.sort_by_key(|a| format!("{a:?}"));
        assert_eq!(decoded, expected);
    }

    /// Rule 47: the workflow is this gate's other half. If it stops
    /// running this module, or stops reading the constant the way the
    /// source declares it, the pin protects nothing.
    #[test]
    fn the_workflow_still_runs_this_module_and_reads_the_constant() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let workflow = std::fs::read_to_string(root.join(".github/workflows/schema-snapshot.yml"))
            .expect("schema-snapshot.yml");
        assert!(
            workflow.contains("cargo test -p shekyl-peerlist address_file::snapshot"),
            "schema-snapshot.yml runs this module by path"
        );
        assert!(
            workflow.contains("rust/shekyl-peerlist/schemas/")
                && workflow.contains("rust/shekyl-peerlist/src/address_file.rs")
                && workflow.contains("ADDRESS_FILE_VERSION"),
            "schema-snapshot.yml pairs the snapshot directory with the constant"
        );
        let source = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/address_file.rs"),
        )
        .expect("source");
        let declaration = format!("pub const ADDRESS_FILE_VERSION: u32 = {ADDRESS_FILE_VERSION};");
        assert_eq!(
            source.lines().filter(|line| *line == declaration).count(),
            1,
            "the declaration is one line at column 0, in the grammar the workflow's sed reads"
        );
    }
}
