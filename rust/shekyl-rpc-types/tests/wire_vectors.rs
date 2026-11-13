// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wire vectors (`tests/vectors/rpc/wire/`): one request and one reply
//! for every shape of every row of [`wire::TABLE`], written by hand from
//! `INPUT_GRAMMAR.md` Part C (§17, §18, §19) and Part F (§25, §26), never
//! from the types (Rick's rulings, 2026-11-12).
//!
//! A row whose reply has fields a request switch selects (RW-Q4, 4.1) has
//! one pair per set of switches turned on, named by them:
//! `<method>.plain.*`, `<method>.pow.*`, `<method>.prune.*`,
//! `<method>.pow-prune.*`. Any other row has `<method>.request.json` and
//! `<method>.reply.json`.
//!
//! Every vector is held to the table four ways: it exists, and every file
//! in the directory names a row's shape; it conforms to the row's schema
//! shape, the reply read against the switches its request turned on; parsed
//! into the method's type and written back, it is the file again; and that
//! written form, parsed again, is the first parse. A vector the types
//! cannot read, or read and write differently, is the grammar and the code
//! disagreeing, named by its file.

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use shekyl_rpc_types::method::RpcMethod;
use shekyl_rpc_types::schema::{conforms, conforms_asked, request_switches, switches_on, Shape};
use shekyl_rpc_types::wire::{self, Id, TABLE};

fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/rpc/wire")
}

/// The file's JSON, or why there is none.
fn read(file: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| format!("{}: not readable: {e}", file.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: not JSON: {e}", file.display()))
}

/// The shapes of a row: each set of the switches its request takes that
/// select fields of its reply, as a file label and the switches it turns
/// on. `None` labels a row with no such switch.
fn shapes(request: &Shape, reply: &Shape) -> Vec<(Option<String>, Vec<&'static str>)> {
    let all = request_switches(request, reply);
    if all.is_empty() {
        return vec![(None, Vec::new())];
    }
    (0..1usize << all.len())
        .map(|mask| {
            let on: Vec<&'static str> = all
                .iter()
                .enumerate()
                .filter(|(bit, _)| mask & (1 << bit) != 0)
                .map(|(_, switch)| *switch)
                .collect();
            let label = if on.is_empty() {
                "plain".to_owned()
            } else {
                on.join("-")
            };
            (Some(label), on)
        })
        .collect()
}

/// A shape's file: `<method>.<label>.<side>.json`, or `<method>.<side>.json`.
fn file_name(method: &str, label: Option<&str>, side: &str) -> String {
    match label {
        Some(label) => format!("{method}.{label}.{side}.json"),
        None => format!("{method}.{side}.json"),
    }
}

/// One side of one shape: the vector conforms to `shape` (a reply read
/// against the switches `asked` names), reads as `T`, writes back as
/// itself, and its written form reads as the same `T`.
fn side<T>(file: &Path, shape: &Shape, asked: Option<&[&str]>) -> Vec<String>
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let name = file.display();
    let doc = match read(file) {
        Ok(doc) => doc,
        Err(fault) => return vec![fault],
    };
    let mut faults = Vec::new();
    let conformed = match asked {
        Some(on) => conforms_asked(&doc, shape, on),
        None => conforms(&doc, shape),
    };
    if let Err(why) = conformed {
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

/// Both sides of every shape of method `M`. A shape's request must turn
/// on exactly the switches its label names, and its reply is read against
/// them.
fn method<M>() -> Vec<String>
where
    M: RpcMethod,
    M::Request: PartialEq + Debug,
    M::Reply: PartialEq + Debug,
{
    let row = shekyl_rpc_types::method::Row::of::<M>();
    let dir = directory();
    let reply = (row.reply)();
    let mut faults = Vec::new();
    for (label, on) in shapes(&(row.request)(), &reply) {
        let request_file = dir.join(file_name(M::NAME, label.as_deref(), "request"));
        faults.extend(side::<M::Request>(&request_file, &(row.request)(), None));
        if let Ok(request) = read(&request_file) {
            let turned_on = switches_on(&request, &reply);
            if turned_on != on {
                faults.push(format!(
                    "{}: turns on {turned_on:?}, and its name says {on:?}",
                    request_file.display()
                ));
            }
        }
        faults.extend(side::<M::Reply>(
            &dir.join(file_name(M::NAME, label.as_deref(), "reply")),
            &reply,
            Some(&on),
        ));
    }
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

/// Every shape of every row has its request and its reply, and every file
/// names one. Red edits: delete one request vector; add a stray file.
#[test]
fn every_shape_has_its_two_vectors_and_nothing_else_is_there() {
    let expected: BTreeSet<String> = TABLE
        .iter()
        .flat_map(|row| {
            shapes(&(row.request)(), &(row.reply)())
                .into_iter()
                .flat_map(move |(label, _)| {
                    ["request", "reply"].map(|side| file_name(row.name, label.as_deref(), side))
                })
        })
        .collect();
    assert_eq!(
        expected.len(),
        100,
        "42 rows: 36 of one shape, five of two (pow or prune) and block_show's four"
    );
    let present: BTreeSet<String> = std::fs::read_dir(directory())
        .expect("the wire vector directory")
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

/// Every selected field, in every shape, is held to its request (RW-Q4):
/// removed from a reply whose request asked for it, or added to one whose
/// request did not, the reply no longer conforms. This is each shape's red
/// edit, run on every selected field rather than one picked by hand.
#[test]
fn every_shape_refuses_a_selected_field_its_request_did_not_select() {
    let mut faults = Vec::new();
    let mut edits = 0usize;
    for row in TABLE {
        let reply_shape = (row.reply)();
        for (label, on) in shapes(&(row.request)(), &reply_shape) {
            let Some(label) = label else { continue };
            let file = directory().join(file_name(row.name, Some(&label), "reply"));
            let doc = read(&file).expect("the vector reads");
            for (path, switch) in selected_paths(&doc, &reply_shape) {
                let mut edited = doc.clone();
                let asked = on.contains(&switch);
                let field = path.last().expect("a field").clone();
                let holder = path[..path.len() - 1]
                    .iter()
                    .try_fold(&mut edited, |value, step| match step.parse::<usize>() {
                        Ok(index) => value.get_mut(index),
                        Err(_) => value.get_mut(step.as_str()),
                    })
                    .and_then(serde_json::Value::as_object_mut)
                    .expect("the holder is an object");
                if asked {
                    holder.remove(&field);
                } else {
                    holder.insert(field.clone(), serde_json::Value::Bool(true));
                }
                edits += 1;
                if conforms_asked(&edited, &reply_shape, &on).is_ok() {
                    faults.push(format!(
                        "{}: `{}` {} and the reply still conforms",
                        file.display(),
                        path.join("."),
                        if asked { "removed" } else { "added" }
                    ));
                }
            }
        }
    }
    assert!(
        edits > 0,
        "no selected field was edited: the walk found no subject"
    );
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

/// Where each field a switch selects sits in `doc`: its path, and the
/// switch. A field present in the document, or one its holder lacks
/// because its switch was off, is listed either way.
fn selected_paths(doc: &serde_json::Value, shape: &Shape) -> Vec<(Vec<String>, &'static str)> {
    let mut out = Vec::new();
    walk_selected(doc, shape, &mut Vec::new(), &mut out);
    out
}

fn walk_selected(
    doc: &serde_json::Value,
    shape: &Shape,
    path: &mut Vec<String>,
    out: &mut Vec<(Vec<String>, &'static str)>,
) {
    match (shape, doc) {
        (Shape::Object { fields, parts, .. }, serde_json::Value::Object(object)) => {
            for field in fields
                .iter()
                .chain(parts.iter().flat_map(|part| &part.fields))
            {
                path.push(field.name.to_owned());
                match &field.shape {
                    Shape::Asked { switch, .. } => out.push((path.clone(), switch)),
                    shape => {
                        if let Some(value) = object.get(field.name) {
                            walk_selected(value, shape, path, out);
                        }
                    }
                }
                path.pop();
            }
        }
        (Shape::List(inner), serde_json::Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                path.push(index.to_string());
                walk_selected(item, inner, path, out);
                path.pop();
            }
        }
        // A slot holds the item or a state; only an item has its fields.
        (Shape::Either(item, _), _) if conforms(doc, item).is_ok() => {
            walk_selected(doc, item, path, out);
        }
        (Shape::Nullable(inner) | Shape::Hidden { inner, .. }, _) if !doc.is_null() => {
            walk_selected(doc, inner, path, out);
        }
        _ => {}
    }
}
