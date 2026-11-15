// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The key file's known answer (RT-O34, rule 30).
//!
//! The expected bytes are built from the hybridXK vectors' daemon static,
//! which an independent implementation produced (clatter, RT-O18): its
//! X25519 secret and its ML-KEM-768 decapsulation key, behind this
//! format's magic and version. Reading them must give the vectors' public
//! bundle, and the seeded identity this crate draws from the same stream
//! must write exactly them.

use serde_json::Value;

use super::pinned::seeded::SeededRng;
use super::{KeyFileError, StaticKeypair, KEY_FILE_LEN, KEY_FILE_MAGIC, KEY_FILE_VERSION};

const PINNED: &str =
    include_str!("../../../docs/test_vectors/RPC_CHANNEL_HYBRIDXK_V1/vectors.json");

/// The daemon static's stream, as the vectors name it.
const DAEMON_STATIC: u8 = 2;

fn field(name: &str) -> Vec<u8> {
    let vectors: Value = serde_json::from_str(PINNED).expect("vectors");
    hex::decode(
        vectors["daemon_static"][name]
            .as_str()
            .unwrap_or_else(|| panic!("daemon_static.{name}")),
    )
    .expect("hex")
}

fn expected_file() -> Vec<u8> {
    let mut file = KEY_FILE_MAGIC.to_vec();
    file.push(KEY_FILE_VERSION);
    file.extend(field("x25519_secret_hex"));
    file.extend(field("mlkem768_dk_hex"));
    file
}

/// Red edit: write the decapsulation key before the X25519 secret, and the
/// bytes differ.
#[test]
fn the_key_file_is_the_pinned_bytes_and_reads_back_to_the_pinned_bundle() {
    let expected = expected_file();
    assert_eq!(expected.len(), KEY_FILE_LEN);
    let drawn = StaticKeypair::generate_from(&mut SeededRng::<DAEMON_STATIC>::default())
        .expect("the seeded static");
    assert_eq!(drawn.to_key_file().as_slice(), expected.as_slice());

    let read = StaticKeypair::from_key_file(&expected).expect("the pinned file reads");
    assert_eq!(
        read.public().x25519().as_slice(),
        field("x25519_public_hex")
    );
    assert_eq!(
        read.public().mlkem_ek().as_slice(),
        field("mlkem768_ek_hex")
    );
    assert_eq!(read.public().fingerprint(), drawn.public().fingerprint());
}

#[test]
fn a_generated_identity_round_trips() {
    let key = StaticKeypair::generate().expect("a key");
    let read = StaticKeypair::from_key_file(&key.to_key_file()).expect("reads");
    assert_eq!(read.public().fingerprint(), key.public().fingerprint());
}

/// Each way a file can be wrong is refused with its own reason. Red edit:
/// drop the version check, and the version-2 file is read.
#[test]
fn a_file_that_is_not_this_format_is_refused() {
    let good = expected_file();
    let at_version = KEY_FILE_MAGIC.len();

    let mut wrong_magic = good.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(
        StaticKeypair::from_key_file(&wrong_magic).err(),
        Some(KeyFileError::Format)
    );

    let mut next_version = good.clone();
    next_version[at_version] = 2;
    assert_eq!(
        StaticKeypair::from_key_file(&next_version).err(),
        Some(KeyFileError::Version(2))
    );

    assert_eq!(
        StaticKeypair::from_key_file(&good[..good.len() - 1]).err(),
        Some(KeyFileError::Format)
    );
    let mut long = good.clone();
    long.push(0);
    assert_eq!(
        StaticKeypair::from_key_file(&long).err(),
        Some(KeyFileError::Format)
    );

    // A decapsulation key whose embedded hash of `ek` no longer matches.
    let mut bad_dk = good.clone();
    let ek_at = at_version + 1 + 32 + 3 * 384;
    bad_dk[ek_at] ^= 1;
    assert_eq!(
        StaticKeypair::from_key_file(&bad_dk).err(),
        Some(KeyFileError::Key)
    );
}
