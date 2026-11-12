// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The 4.0 wire vectors (`tests/vectors/rpc/4.0/`): one request and one
//! reply for every row of [`wire::TABLE`], written by hand from
//! `INPUT_GRAMMAR.md` Part C (§17, §18, §19) and Part F (§25, §26), never
//! from the types (Rick's ruling, 2026-11-12).
//!
//! Every vector is held to the table four ways: it exists, and every file
//! in the directory names a row; it conforms to the row's schema shape;
//! parsed into the method's type and written back, it is the file again;
//! and that written form, parsed again, is the first parse. A vector the
//! types cannot read, or read and write differently, is the grammar and
//! the code disagreeing, named by its file.

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use shekyl_rpc_types::method::RpcMethod;
use shekyl_rpc_types::schema::conforms;
use shekyl_rpc_types::wire::{self, Id, TABLE};

fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/rpc/4.0")
}

/// The file's JSON, or why there is none.
fn read(file: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| format!("{}: not readable: {e}", file.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: not JSON: {e}", file.display()))
}

/// One side of one method: the vector conforms to `shape`, reads as `T`,
/// writes back as itself, and its written form reads as the same `T`.
fn side<T>(file: &Path, shape: &shekyl_rpc_types::schema::Shape) -> Vec<String>
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let name = file.display();
    let doc = match read(file) {
        Ok(doc) => doc,
        Err(fault) => return vec![fault],
    };
    let mut faults = Vec::new();
    if let Err(why) = conforms(&doc, shape) {
        faults.push(format!("{name}: does not conform to the schema: {why}"));
    }
    let parsed: T = match serde_json::from_value(doc.clone()) {
        Ok(parsed) => parsed,
        Err(e) => {
            faults.push(format!("{name}: the type does not read it: {e}"));
            return faults;
        }
    };
    let written = match serde_json::to_value(&parsed) {
        Ok(written) => written,
        Err(e) => {
            faults.push(format!("{name}: the type does not write it back: {e}"));
            return faults;
        }
    };
    if written != doc {
        faults.push(format!(
            "{name}: written back differently:\n  file:    {doc}\n  written: {written}"
        ));
    }
    match serde_json::from_value::<T>(written) {
        Ok(again) if again == parsed => {}
        Ok(again) => faults.push(format!(
            "{name}: the written form reads differently: {parsed:?} then {again:?}"
        )),
        Err(e) => faults.push(format!("{name}: the written form does not read: {e}")),
    }
    faults
}

/// Both sides of method `M`.
fn method<M>() -> Vec<String>
where
    M: RpcMethod,
    M::Request: PartialEq + Debug,
    M::Reply: PartialEq + Debug,
{
    let row = shekyl_rpc_types::method::Row::of::<M>();
    let dir = directory();
    let mut faults = side::<M::Request>(
        &dir.join(format!("{}.request.json", M::NAME)),
        &(row.request)(),
    );
    faults.extend(side::<M::Reply>(
        &dir.join(format!("{}.reply.json", M::NAME)),
        &(row.reply)(),
    ));
    faults
}

/// Every row's vectors, checked through the row's own types. The match has
/// no wildcard arm, so a row added to the table does not compile here until
/// its vectors are checked.
fn row_faults(id: Id) -> Vec<String> {
    match id {
        Id::Version => method::<wire::Version>(),
        Id::ChainHeight => method::<wire::ChainHeight>(),
        Id::BlockHeaderShow => method::<wire::BlockHeaderShow>(),
        Id::BlockHeaderList => method::<wire::BlockHeaderList>(),
        Id::BlockShow => method::<wire::BlockShow>(),
        Id::BlockList => method::<wire::BlockList>(),
        Id::TxShow => method::<wire::TxShow>(),
        Id::TxList => method::<wire::TxList>(),
        Id::ChainSpent => method::<wire::ChainSpent>(),
        Id::Fee => method::<wire::Fee>(),
        Id::ChainCoinbaseSum => method::<wire::ChainCoinbaseSum>(),
        Id::ChainAlt => method::<wire::ChainAlt>(),
        Id::CurveShow => method::<wire::CurveShow>(),
        Id::ArchivalClaimShow => method::<wire::ArchivalClaimShow>(),
        Id::ShardCoverage => method::<wire::ShardCoverage>(),
        Id::ShardFetch => method::<wire::ShardFetch>(),
        Id::DaemonStatus => method::<wire::DaemonStatus>(),
        Id::SyncStatus => method::<wire::SyncStatus>(),
        Id::PeerConnections => method::<wire::PeerConnections>(),
        Id::PeerList => method::<wire::PeerList>(),
        Id::P2pStats => method::<wire::P2pStats>(),
        Id::OptionSet => method::<wire::OptionSet>(),
        Id::OptionShow => method::<wire::OptionShow>(),
        Id::DaemonStop => method::<wire::DaemonStop>(),
        Id::TxpoolList => method::<wire::TxpoolList>(),
        Id::TxpoolStats => method::<wire::TxpoolStats>(),
        Id::TxpoolFlush => method::<wire::TxpoolFlush>(),
        Id::TxRelay => method::<wire::TxRelay>(),
        Id::TxSubmit => method::<wire::TxSubmit>(),
        Id::BlockTemplate => method::<wire::BlockTemplate>(),
        Id::BlockSubmit => method::<wire::BlockSubmit>(),
        Id::Pow => method::<wire::Pow>(),
        Id::MineStart => method::<wire::MineStart>(),
        Id::MineStop => method::<wire::MineStop>(),
        Id::MineStatus => method::<wire::MineStatus>(),
        Id::BanAdd => method::<wire::BanAdd>(),
        Id::BanRemove => method::<wire::BanRemove>(),
        Id::BanList => method::<wire::BanList>(),
        Id::BanShow => method::<wire::BanShow>(),
        Id::RelayStats => method::<wire::RelayStats>(),
        Id::DevBlockGenerate => method::<wire::DevBlockGenerate>(),
        Id::DevChainPop => method::<wire::DevChainPop>(),
    }
}

/// Every row has its request and its reply, and every file names a row's
/// request or reply. Red edits: delete one request vector; add a stray
/// file.
#[test]
fn every_row_has_its_two_vectors_and_nothing_else_is_there() {
    let expected: BTreeSet<String> = TABLE
        .iter()
        .flat_map(|row| {
            [
                format!("{}.request.json", row.name),
                format!("{}.reply.json", row.name),
            ]
        })
        .collect();
    assert_eq!(expected.len(), 84, "42 rows, two vectors each");
    let present: BTreeSet<String> = std::fs::read_dir(directory())
        .expect("the 4.0 vector directory")
        .map(|entry| {
            entry
                .expect("a directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let missing: Vec<&String> = expected.difference(&present).collect();
    let stray: Vec<&String> = present.difference(&expected).collect();
    assert!(
        missing.is_empty() && stray.is_empty(),
        "missing vectors: {missing:?}; files that name no row: {stray:?}"
    );
}

/// Every vector conforms to its row's shape and round-trips through the
/// row's type in both directions. Red edits: misspell a field in a reply
/// vector; write a height as a string.
#[test]
fn every_vector_conforms_and_round_trips_through_its_type() {
    let faults: Vec<String> = Id::ALL.iter().flat_map(|id| row_faults(*id)).collect();
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}
