// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Every corpus committed in this crate decodes through `shekyl-corpus`
//! and re-encodes, from the parsed records, to the same bytes (Rick,
//! 2026-11-18: "The five committed corpora must round-trip byte for
//! byte"). The bench fixtures are corpora too, so they are held to it
//! with the five replay vectors.
//!
//! It lives beside the corpora, not in the codec's crate, so that a
//! regenerated corpus and a changed codec both run it: this crate owns the
//! files, and it depends on the codec (`change_scope.py` scopes a change
//! by its owner and the owner's dependents).
//!
//! Re-encoding from the parsed values, not from the blobs read, is the
//! point: it shows the reader kept everything the writer wrote, and that
//! the wire types' serializers reproduce each blob exactly.

use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use shekyl_corpus::{CorpusReader, CorpusWriter, Record};

/// This crate, where the committed corpora live.
fn ingest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The replay vectors every DRS-E2 test reads (`tests/vectors/<name>/corpus.e2`).
const VECTORS: [&str; 5] = [
    "spend-1in-2out",
    "bond-post",
    "limit-full",
    "median-full",
    "spend-depth3",
];

/// Every committed corpus: the five vectors and the bench fixtures
/// (`benches/fixtures/*.corpus`).
fn committed() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = VECTORS
        .iter()
        .map(|name| ingest().join("tests/vectors").join(name).join("corpus.e2"))
        .collect();
    let fixtures = ingest().join("benches/fixtures");
    let mut benches: Vec<PathBuf> = fs::read_dir(&fixtures)
        .unwrap_or_else(|e| panic!("{}: {e}", fixtures.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "corpus"))
        .collect();
    benches.sort();
    found.extend(benches);
    found
}

/// `bytes` decoded and written again from the parsed records.
fn re_encoded(bytes: &[u8]) -> (Vec<u8>, u64) {
    let mut reader = CorpusReader::open(Cursor::new(bytes)).expect("the corpus opens");
    let mut writer =
        CorpusWriter::create(Cursor::new(Vec::new()), reader.net(), reader.first_height())
            .expect("a header");
    let mut records = 0u64;
    while let Some(record) = reader.next_record().expect("a record") {
        match record {
            Record::Extend(extend) => {
                let txs: Vec<Vec<u8>> = extend
                    .transactions
                    .iter()
                    .map(shekyl_wire::Transaction::serialize)
                    .collect();
                let references = extend
                    .bundle_references
                    .as_ref()
                    .map(|section| section.as_slice().to_vec())
                    .unwrap_or_default();
                let bodies: Vec<Vec<u8>> = extend
                    .bundle_bodies
                    .iter()
                    .map(|body| body.as_bytes().to_vec())
                    .collect();
                writer
                    .append_carrying(&extend.block.serialize(), &txs, &references, &bodies)
                    .expect("the record verifies again");
            }
            Record::Rewind { to } => writer.rewind(to).expect("the rewind holds again"),
        }
        records += 1;
    }
    assert_eq!(records, reader.declared(), "every declared record was read");
    (writer.finish().expect("finish").into_inner(), records)
}

#[test]
fn every_committed_corpus_round_trips_byte_for_byte() {
    let corpora = committed();
    // Rule 47: the subject is present. The five vectors are named; the
    // bench fixtures are found, and there are some.
    assert!(
        corpora.len() > VECTORS.len(),
        "no bench fixture corpus found under {}",
        ingest().join("benches/fixtures").display()
    );
    let mut total = 0u64;
    for path in &corpora {
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let (again, records) = re_encoded(&bytes);
        assert!(records > 0, "{} holds no record", path.display());
        assert!(
            again == bytes,
            "{} does not round-trip: {} bytes read, {} written, first difference at {:?}",
            path.display(),
            bytes.len(),
            again.len(),
            bytes.iter().zip(&again).position(|(a, b)| a != b)
        );
        total += records;
    }
    eprintln!(
        "{} committed corpora, {total} records, each re-encoded byte for byte",
        corpora.len()
    );
}
