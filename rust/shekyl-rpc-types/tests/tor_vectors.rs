// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Tor status's oracle vectors (`tests/vectors/rpc/tor/`, the README
//! there): hand-written from `INPUT_GRAMMAR.md` §23 and Part G, each the
//! Status part's Tor fields, spliced into the hand-written `daemon_status`
//! reply (`wire/daemon_status.reply.json`) and read as the RPC reads it:
//! through `DaemonStatus`, the method's reply type, against its schema
//! (Rick, 2026-11-12: the one-key decoders proved against the RPC's
//! encoding, not only the crate's JSON).
//!
//! - `known/`: each conforms to the schema, decodes, and encodes back to
//!   the same document, with nothing unknown in it.
//! - `unknown/`: a keyword or key this build does not know. The schema,
//!   which lists this build's sets, refuses it; the reply type still reads
//!   it, the status says it holds something unknown, the send flow's one
//!   accessor reads it as not address-hiding, and the renderer says to
//!   update.
//! - `refused/`: a one-key object with no key or two, which the reply type
//!   refuses.

use std::path::{Path, PathBuf};

use serde_json::Value;
use shekyl_rpc_types::schema::{conforms, Schema};
use shekyl_rpc_types::wire::daemon::DaemonStatus;
use shekyl_tor_status::{render, UNKNOWN_SENTENCE};

const TOR_KEYS: [&str; 5] = [
    "posture",
    "origination",
    "sync_connector",
    "tor_quiet",
    "tor",
];

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/rpc")
}

fn read(path: &Path) -> Value {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Every vector of `kind`, by name, as a whole `daemon_status` reply.
fn replies(kind: &str) -> Vec<(String, Value)> {
    let base = read(&vectors().join("wire/daemon_status.reply.json"));
    let mut files: Vec<PathBuf> = std::fs::read_dir(vectors().join("tor").join(kind))
        .unwrap_or_else(|error| panic!("tor/{kind}: {error}"))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let tor = read(&path);
            let mut reply = base.clone();
            for key in TOR_KEYS {
                let value = tor
                    .get(key)
                    .unwrap_or_else(|| panic!("{}: `{key}` is missing", path.display()));
                reply[key] = value.clone();
            }
            let name = path
                .file_stem()
                .expect("a file name")
                .to_string_lossy()
                .into_owned();
            (format!("{kind}/{name}"), reply)
        })
        .collect()
}

/// The subject exists: each directory holds the vectors the README lists.
#[test]
fn the_vector_set_is_there() {
    assert_eq!(replies("known").len(), 27);
    assert_eq!(replies("unknown").len(), 14);
    assert_eq!(replies("refused").len(), 4);
}

/// **Every known state reads as the RPC reads it, and writes back the
/// same.** Fails if a hand-written decoder disagrees with the schema or
/// with its own encoder on any state §23 rules.
#[test]
fn every_known_state_conforms_decodes_and_round_trips() {
    for (name, reply) in replies("known") {
        conforms(&reply, &DaemonStatus::shape())
            .unwrap_or_else(|why| panic!("{name}: does not conform: {why}"));
        let status: DaemonStatus = serde_json::from_value(reply.clone())
            .unwrap_or_else(|error| panic!("{name}: does not decode: {error}"));
        let tor = status.tor_status().expect("the Status part is shown");
        assert!(!tor.has_unknown(), "{name}: read as unknown: {tor:?}");
        assert!(
            !render(&tor, None).contains(UNKNOWN_SENTENCE),
            "{name}: says to update"
        );
        assert_eq!(
            serde_json::to_value(&status).expect("encodes"),
            reply,
            "{name}: does not write back the same"
        );
    }
}

/// **A value this build does not know is read, said, and never trusted.**
/// Fails if the reply type refuses a newer daemon's keyword (the whole
/// reply would be lost), if the status does not say it holds something
/// unknown, or if the send flow could read it as address-hiding.
#[test]
fn every_unknown_value_is_read_said_and_fails_closed() {
    for (name, reply) in replies("unknown") {
        assert!(
            conforms(&reply, &DaemonStatus::shape()).is_err(),
            "{name}: the schema lists this build's sets, and this is not in them"
        );
        let status: DaemonStatus = serde_json::from_value(reply.clone())
            .unwrap_or_else(|error| panic!("{name}: the reply is lost: {error}"));
        let tor = status.tor_status().expect("the Status part is shown");
        assert!(tor.has_unknown(), "{name}: not read as unknown: {tor:?}");
        assert!(
            !tor.own_tx_hides_address(),
            "{name}: read as address-hiding"
        );
        let line = render(&tor, None);
        assert_eq!(line.matches(UNKNOWN_SENTENCE).count(), 1, "{name}: {line}");
        assert_eq!(
            status.height,
            serde_json::from_value(reply["height"].clone()).unwrap()
        );
    }
}

/// **A one-key object with no key or two is refused** by the reply type:
/// it is not a state, and reading the first key would pick one silently.
#[test]
fn a_one_key_object_with_no_key_or_two_is_refused() {
    for (name, reply) in replies("refused") {
        assert!(
            serde_json::from_value::<DaemonStatus>(reply).is_err(),
            "{name}: read"
        );
    }
}
