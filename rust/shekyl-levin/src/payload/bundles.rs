// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bundle transport, 2015–2017 (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.5,
//! `SCS-P25`, `SCS-P27`, `SCS-P28`).
//!
//! - **2015, a bundle relayed between queues**: its reference and its
//!   body. A receiving node admits it by the rule its own queue runs, and
//!   relays it on only if it admitted it. It is fluffed: a bundle has no
//!   Dandelion++ stem, because its author is already public through `0x0C`
//!   (`SCS-P25`).
//! - **2016, a body request**: prunable hashes.
//! - **2017, the body response**: each held body beside the hash it was
//!   asked for. The asker accepts a body only at the length its reference
//!   fixes and only on hash equality
//!   (`shekyl_archival_retention::BundleRef::accept_body`).
//!
//! This module moves bytes; it does not judge them. A reference and a body
//! are the retention crate's types, decoded by the receiver.

use shekyl_portable_storage::{Section, Value};

use super::error::Error;
use super::get::{self, HASH_SIZE};
use super::PortableMap;
use crate::header::DEFAULT_MAX_PACKET_SIZE;
use crate::ingress::hash_list_cap;

/// `NOTIFY_NEW_BUNDLE`: a bundle relayed between queues.
pub const NOTIFY_NEW_BUNDLE: u32 = 2015;
/// `NOTIFY_REQUEST_BUNDLE_BODIES`: bundle bodies asked for by hash.
pub const NOTIFY_REQUEST_BUNDLE_BODIES: u32 = 2016;
/// `NOTIFY_RESPONSE_BUNDLE_BODIES`: the bodies held, each with its hash.
pub const NOTIFY_RESPONSE_BUNDLE_BODIES: u32 = 2017;

/// The most hashes one body request names: one block's references.
///
/// A section's references all lie in the window `h < h_incl ≤ h + W₂`
/// (CEN-J31), so a section holds at most `W₂` of them, and `W₂` is at most
/// `W2_MAX_DEFENSIBLE_BLOCKS` (500) on every rule set
/// `ArchivalParams::validate` admits. A test pins the two together, since
/// this crate does not depend on the retention crate.
pub const MAX_BUNDLE_BODY_REQUEST_COUNT: u64 = 500;

/// Encoded cap of [`RequestBundleBodies`].
pub const CAP_REQUEST_BUNDLE_BODIES: u64 = hash_list_cap(MAX_BUNDLE_BODY_REQUEST_COUNT);

/// Encoded cap of [`NewBundle`]: the packet.
///
/// A bundle's body is `3,193 + 1,397 ×` its set bits, and its draw count is
/// capped at `⌊9·D / SEB⌋ + 1` (§7.4), where `D` is the drawable pairs:
/// chain state, with no bound this crate can name at compile time. The
/// spec's largest tabled case, `D = 3,100,000`, is 3.9 MB. So the ingress
/// bound is the packet, as it is for the first block of a body response,
/// and the receiver's exact-length check refuses any body its own
/// reference does not fix.
pub const CAP_NEW_BUNDLE: u64 = DEFAULT_MAX_PACKET_SIZE;

/// Encoded cap of [`ResponseBundleBodies`]: the packet. The first held
/// body is sent whatever its size, as [`CAP_NEW_BUNDLE`] bounds it; later
/// ones are added under [`crate::BODIES_RESPONSE_BYTES`], the budget a
/// block body response uses.
pub const CAP_RESPONSE_BUNDLE_BODIES: u64 = DEFAULT_MAX_PACKET_SIZE;

const _: () = assert!(CAP_REQUEST_BUNDLE_BODIES == 24_256);

/// Body of [`NOTIFY_NEW_BUNDLE`] (2015).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewBundle {
    /// The reference, `BundleRef::encode`.
    pub reference: Vec<u8>,
    /// The body it names, `BundleBody::as_bytes`.
    pub body: Vec<u8>,
}

impl PortableMap for NewBundle {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("body", Value::Bytes(self.body.clone()));
        section.insert("reference", Value::Bytes(self.reference.clone()));
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            reference: get::bytes(section, "reference")?.to_vec(),
            body: get::bytes(section, "body")?.to_vec(),
        })
    }
}

/// Body of [`NOTIFY_REQUEST_BUNDLE_BODIES`] (2016).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestBundleBodies {
    /// Prunable hashes, `CONTAINER_POD_AS_BLOB`.
    pub hashes: Vec<[u8; HASH_SIZE]>,
}

impl PortableMap for RequestBundleBodies {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        get::insert_pod_hashes(&mut section, "hashes", &self.hashes);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            hashes: get::pod_hashes(section, "hashes")?,
        })
    }
}

/// One body a response carries, beside the hash it was asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldBundleBody {
    /// The prunable hash asked for.
    pub hash: [u8; HASH_SIZE],
    /// The body the responder holds under it.
    pub body: Vec<u8>,
}

/// Body of [`NOTIFY_RESPONSE_BUNDLE_BODIES`] (2017).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseBundleBodies {
    /// The bodies held, in the order they were asked for. A hash the
    /// responder holds no body for, or one the byte budget deferred, is
    /// absent.
    pub bodies: Vec<HeldBundleBody>,
}

impl PortableMap for ResponseBundleBodies {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        let entries = self
            .bodies
            .iter()
            .map(|held| {
                let mut entry = Section::new();
                entry.insert("body", Value::Bytes(held.body.clone()));
                entry.insert("hash", Value::Bytes(held.hash.to_vec()));
                entry
            })
            .collect();
        get::insert_object_array(&mut section, "bodies", entries);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        let bodies = get::object_array(section, "bodies")?
            .into_iter()
            .map(|entry| {
                Ok(HeldBundleBody {
                    hash: get::blob(entry, "hash")?,
                    body: get::bytes(entry, "body")?.to_vec(),
                })
            })
            .collect::<Result<_, Error>>()?;
        Ok(Self { bodies })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request's count is one block's references, and that is `W₂`'s
    /// ruled upper edge. Red edit: re-pin the W₂ band's top without this
    /// constant — this assertion names the drift.
    #[test]
    fn a_body_request_names_at_most_one_sections_references() {
        assert_eq!(
            MAX_BUNDLE_BODY_REQUEST_COUNT,
            shekyl_archival_retention::constants::W2_MAX_DEFENSIBLE_BLOCKS
        );
    }

    /// Each message reads back as it was written. Red edit: swap two keys
    /// in a `from_section` — the round trip moves a field.
    #[test]
    fn the_three_messages_round_trip() {
        let relay = NewBundle {
            reference: vec![1, 2, 3],
            body: vec![4; 3_193],
        };
        assert_eq!(NewBundle::load(&relay.store().expect("store")), Ok(relay));
        let request = RequestBundleBodies {
            hashes: vec![[7; 32], [8; 32]],
        };
        assert_eq!(
            RequestBundleBodies::load(&request.store().expect("store")),
            Ok(request)
        );
        let response = ResponseBundleBodies {
            bodies: vec![
                HeldBundleBody {
                    hash: [7; 32],
                    body: vec![9; 3_193],
                },
                HeldBundleBody {
                    hash: [8; 32],
                    body: vec![10; 4_590],
                },
            ],
        };
        assert_eq!(
            ResponseBundleBodies::load(&response.store().expect("store")),
            Ok(response)
        );
        let none = ResponseBundleBodies { bodies: Vec::new() };
        assert_eq!(
            ResponseBundleBodies::load(&none.store().expect("store")),
            Ok(none)
        );
    }

    /// A hash that is not 32 bytes is a malformed response, not a short
    /// key. Red edit: read `hash` as bytes — the 31-byte hash parses.
    #[test]
    fn a_response_hash_is_32_bytes() {
        let mut entry = Section::new();
        entry.insert("body", Value::Bytes(vec![0; 3_193]));
        entry.insert("hash", Value::Bytes(vec![0; 31]));
        let mut section = Section::new();
        get::insert_object_array(&mut section, "bodies", vec![entry]);
        assert!(ResponseBundleBodies::from_section(&section).is_err());
    }
}
