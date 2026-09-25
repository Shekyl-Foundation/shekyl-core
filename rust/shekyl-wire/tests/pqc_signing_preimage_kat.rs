// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! KAT for the **per-input PQC signing preimage** —
//! `FCMP_SPEND_SIGNING_PREIMAGE.md` §1.1, the bytes every hybrid signature on
//! a transaction is over:
//!
//! ```text
//! payload(i)     = pruned_segment ‖ prunable_hash ‖ pqc_header(i) ‖ key_hashes
//! signed_hash(i) = keccak256(payload(i))
//! ```
//!
//! `tests/fixtures/pqc_signing_preimage_v1.json` holds, for each of eight
//! daemon-accepted transactions, the transaction's bytes and — **per input** —
//! the payload bytes and the signed hash, as the **specification's output**:
//! what §1.1 defines for those bytes. The transactions are real: every one
//! was accepted and connected by a running `shekyld` (the captured chains
//! under `shekyl-chain-ingest/tests/vectors`, the live-oracle spend, the
//! serve-credit parity capture), chosen so the shapes a divergence could hide
//! in are all present — one input, two, six (twice: a captured chain's and
//! the live oracle's), the bond post's `to_key ‖ bond_post` and the
//! emission's `to_key ‖ to_key ‖ emission` (mixed archival
//! arms, whose pseudo-out count is the *spend* subset), and the serve-credit
//! form, which carries no per-input authentication and so has **no**
//! preimage at all.
//!
//! **Why a fixture and not a live comparison.** The payload was assembled in
//! C++ (`tx_pqc_verify.cpp`, `get_transaction_signed_payload`) until E6
//! slice 6 commit 7 made this crate's derivation the one of record and the
//! daemon a caller of it. A test that compared the two implementations was
//! meaningful only while both existed; the moment the C++ became a call, it
//! would compare Rust against itself and pass forever for no reason. So the
//! payloads were **captured** from the C++ oracle before it went — by the
//! C++ leg of this KAT, in its capture mode, over these bytes — and the
//! fixture is the gate that survives the oracle's deletion. It is documented
//! against the specification, not against the program that produced it:
//! the same bytes today, and the claim that outlives the C++.
//!
//! The Rust leg below holds [`Transaction::pqc_signing_payload_hashes`] to the
//! fixture. The C++ leg (`tests/unit_tests/pqc_signing_preimage_kat.cpp`)
//! held the C++ assembly to it while the assembly existed.

use std::path::PathBuf;

use serde_json::Value;
use shekyl_crypto_hash::keccak256;
use shekyl_wire::Transaction;

const FIXTURE: &str = "tests/fixtures/pqc_signing_preimage_v1.json";

fn hex_str(b: impl AsRef<[u8]>) -> String {
    b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex in fixture");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn manifest(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// The workspace root, for the captured chains another crate owns.
fn workspace(rel: &str) -> PathBuf {
    manifest("..").join(rel)
}

/// One transaction the fixture carries: where its bytes came from, and the
/// bytes. The provenance is recorded so a reader knows each shape was
/// accepted by a daemon, not built to fit.
struct Subject {
    name: &'static str,
    source: &'static str,
    tx: Vec<u8>,
}

fn json_hex_field(path: &std::path::Path, field: &str) -> Vec<u8> {
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json");
    hex_bytes(doc[field].as_str().expect(field))
}

fn captured_tx(shape: &str, txid: &str) -> Vec<u8> {
    std::fs::read(workspace(&format!(
        "shekyl-chain-ingest/tests/vectors/{shape}/txs/{txid}.tx"
    )))
    .expect("captured transaction")
}

/// The eight subjects, in the fixture's order.
fn subjects() -> Vec<Subject> {
    vec![
        Subject {
            name: "spend-1in-2out",
            source: "shekyl-chain-ingest/tests/vectors/bond-post, the bond's funding spend (daemon-accepted, connected)",
            tx: captured_tx(
                "bond-post",
                "566dd5081b0f51e218573f7269b79c670283e2e287d9775053487e39a963bbe3",
            ),
        },
        Subject {
            name: "spend-2in-2out",
            source: "shekyl-chain-ingest/tests/vectors/spend-depth3 (daemon-accepted, connected)",
            tx: captured_tx(
                "spend-depth3",
                "afe08b8b69b1c3c72926eef98b49991e248d949e9988697b0748aa2039f4e9e1",
            ),
        },
        Subject {
            name: "spend-6in-2out",
            source: "shekyl-chain-ingest/tests/vectors/spend-1in-2out (daemon-accepted, connected)",
            tx: captured_tx(
                "spend-1in-2out",
                "a220cc5d719c925e3fd26b7d5b09214d351fa31a4777af1ce63b01ed3f3ec76e",
            ),
        },
        Subject {
            name: "spend-6in-2out-live-oracle",
            source: "shekyl-wire/tests/fixtures/live_oracle_spend_v1.json (daemon-accepted, connected)",
            tx: json_hex_field(&manifest("tests/fixtures/live_oracle_spend_v1.json"), "tx_hex"),
        },
        Subject {
            name: "bond-post-to_key-bond_post",
            source: "shekyl-chain-ingest/tests/vectors/bond-post (daemon-accepted, connected)",
            tx: captured_tx(
                "bond-post",
                "1292cfc5035c57c704b6ad9c04aa462da7bd960839fba301dee97dbe9f58b8cc",
            ),
        },
        Subject {
            name: "emission-bond-post-to_key-bond_post",
            source: "shekyl-chain-ingest/tests/vectors/emission-claim (daemon-accepted, connected)",
            tx: captured_tx(
                "emission-claim",
                "3e3c7e7951f66ec01ea1084be1e968712d9a3daf5f974795443e63a362ffa438",
            ),
        },
        Subject {
            name: "emission-to_key-to_key-emission",
            source: "shekyl-chain-ingest/tests/vectors/emission-claim (daemon-accepted, connected)",
            tx: captured_tx(
                "emission-claim",
                "a7244fa4c353a496c02e7fac8d635856094761e1834cf0354f9eb04d5b0ef96a",
            ),
        },
        Subject {
            name: "serve-credit-only",
            source: "shekyl-wire/tests/fixtures/serve_credit_tx_parity_v1.json (no per-input authentication: no preimage)",
            tx: json_hex_field(
                &manifest("tests/fixtures/serve_credit_tx_parity_v1.json"),
                "tx_hex",
            ),
        },
    ]
}

/// Write the fixture's **inputs** — the subjects' bytes and provenance, with
/// empty payload lists — for the C++ leg's capture mode to fill from the
/// oracle. Run once, before the C++ assembly was deleted; kept so the
/// fixture's construction is reproducible from a checkout and a build at
/// the pre-deletion era, not a one-off.
#[test]
#[ignore = "writes tests/fixtures/pqc_signing_preimage_v1.json (inputs only; the C++ leg's capture mode fills the payloads)"]
fn emit_pqc_signing_preimage_kat_inputs() {
    let entries: Vec<Value> = subjects()
        .into_iter()
        .map(|s| {
            let tx = Transaction::from_bytes(&s.tx).expect("a captured transaction parses");
            assert_eq!(tx.serialize(), s.tx, "{}: the bytes round-trip", s.name);
            serde_json::json!({
                "name": s.name,
                "source": s.source,
                "inputs": tx.prefix.inputs.len(),
                "tx_hex": hex_str(&s.tx),
                "payloads_hex": [],
                "signed_hashes_hex": [],
            })
        })
        .collect();
    let doc = serde_json::json!({
        "format_version": 1,
        "specification": "docs/design/FCMP_SPEND_SIGNING_PREIMAGE.md §1.1",
        "description": "Per-input PQC signing preimage KAT. For each transaction: \
         payloads_hex[i] is the §1.1 payload the i-th input's hybrid signature is \
         over (pruned segment ‖ keccak256(prunable) ‖ pqc_header(i) ‖ keccak256 of \
         every input's hybrid public key) and signed_hashes_hex[i] = keccak256 of it. \
         Every transaction was accepted and connected by a running shekyld. The \
         payloads are the specification's output for these bytes, captured from the \
         C++ assembly (tx_pqc_verify.cpp, get_transaction_signed_payload) by the C++ \
         leg's capture mode before E6 slice 6 commit 7 made shekyl-wire the \
         derivation of record and deleted that assembly. A transaction with no \
         per-input authentication (the serve-credit form) has no preimage: empty lists.",
        "captured_by": "",
        "transactions": entries,
    });
    std::fs::write(
        manifest(FIXTURE),
        serde_json::to_string_pretty(&doc).expect("json"),
    )
    .expect("write");
}

/// The Rust leg: this crate's derivation reproduces every captured payload
/// and hash, transaction by transaction, input by input; the eight shapes
/// are all present; the serve-credit form yields nothing.
#[test]
fn pqc_signing_preimage_matches_the_captured_specification_output() {
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(manifest(FIXTURE)).expect("fixture"))
            .expect("json");
    assert!(
        !doc["captured_by"].as_str().expect("captured_by").is_empty(),
        "the fixture has not been captured: run the C++ leg's capture mode"
    );
    let transactions = doc["transactions"].as_array().expect("transactions");
    assert_eq!(
        transactions.len(),
        subjects().len(),
        "every subject is pinned"
    );
    let mut input_counts = Vec::new();
    for entry in transactions {
        let name = entry["name"].as_str().expect("name");
        let tx = Transaction::from_bytes(&hex_bytes(entry["tx_hex"].as_str().expect("tx_hex")))
            .unwrap_or_else(|e| panic!("{name}: the pinned bytes parse: {e}"));
        let payloads: Vec<Vec<u8>> = entry["payloads_hex"]
            .as_array()
            .expect("payloads_hex")
            .iter()
            .map(|p| hex_bytes(p.as_str().expect("hex")))
            .collect();
        let hashes: Vec<[u8; 32]> = entry["signed_hashes_hex"]
            .as_array()
            .expect("signed_hashes_hex")
            .iter()
            .map(|h| <[u8; 32]>::try_from(hex_bytes(h.as_str().expect("hex"))).expect("32 bytes"))
            .collect();
        assert_eq!(payloads.len(), hashes.len(), "{name}: one hash per payload");
        for (i, (payload, hash)) in payloads.iter().zip(&hashes).enumerate() {
            assert_eq!(
                keccak256(payload),
                *hash,
                "{name} input {i}: the fixture's own hash is of its own payload"
            );
        }
        // The derivation of record, against the specification's output.
        assert_eq!(
            tx.pqc_signing_payload_hashes(),
            hashes,
            "{name}: signed hashes"
        );
        input_counts.push((name.to_owned(), tx.prefix.inputs.len(), payloads.len()));
    }
    // The shapes the fixture exists for are all here: a single input, several,
    // the mixed archival arms, and the form with no preimage.
    assert!(
        input_counts.iter().any(|(_, inputs, _)| *inputs == 1),
        "a one-input spend"
    );
    assert!(
        input_counts.iter().any(|(_, inputs, _)| *inputs >= 6),
        "a many-input spend"
    );
    assert!(
        input_counts
            .iter()
            .any(|(name, _, _)| name.contains("bond_post")),
        "a bond post"
    );
    assert!(
        input_counts
            .iter()
            .any(|(name, _, _)| name.contains("-emission")),
        "an emission"
    );
    let serve_credit = input_counts
        .iter()
        .find(|(name, _, _)| name == "serve-credit-only")
        .expect("the serve-credit form");
    assert_eq!(
        serve_credit.2, 0,
        "the serve-credit form carries no per-input authentication and has no preimage"
    );
}
