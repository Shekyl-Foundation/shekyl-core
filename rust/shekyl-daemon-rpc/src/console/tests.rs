// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::alt_chain::headers_in_correspondence;
use super::blockchain::{median, version_tally};
use super::info::daa_target_seconds;
use super::status::{fork_extra_info, mining_speed, sync_percentage};
use super::*;
use crate::ctl_client;
use std::ffi::CString;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::raw::c_char;

use shekyl_rpc_types::{HashHex, RpcStatus};

fn run(args: &[&str], address: Option<&str>) -> (i32, String) {
    let cstrs: Vec<CString> = args.iter().map(|a| CString::new(*a).unwrap()).collect();
    let ptrs: Vec<*const c_char> = cstrs.iter().map(|c| c.as_ptr()).collect();
    let addr = address.map(|a| CString::new(a).unwrap());
    let mut ptr: *mut u8 = std::ptr::null_mut();
    let mut len: usize = 0;
    // SAFETY: valid argv/address/out pointers; null core (remote arm).
    let code = unsafe {
        shekyl_daemon_console_run(
            ptrs.as_ptr(),
            ptrs.len(),
            std::ptr::null_mut(),
            addr.as_ref().map_or(std::ptr::null(), |a| a.as_ptr()),
            5,
            &raw mut ptr,
            &raw mut len,
        )
    };
    let text = if ptr.is_null() {
        String::new()
    } else {
        // SAFETY: the export produced this pair.
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned() }
    };
    // SAFETY: freeing exactly the produced pair.
    unsafe { ctl_client::shekyl_daemon_ctl_free(ptr, len) };
    (code, text)
}

/// One-request HTTP acceptor answering `reply` with 200.
/// A reply built through the wire type rather than hand-written, so a
/// fixture cannot describe a document the daemon could never send. Two
/// of these were hand-written `"hash"` strings that RK-3's `HashHex`
/// immediately refused.
fn typed_reply<T: serde::Serialize>(reply: &T) -> String {
    serde_json::to_string(reply).expect("wire type serializes")
}

fn one_shot(reply: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = s.read(&mut buf).expect("read request");
        assert!(n > 0, "empty request");
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reply.len()
        );
        s.write_all(head.as_bytes()).unwrap();
        s.write_all(reply.as_bytes()).unwrap();
    });
    address
}

/// A **multi-request** acceptor that routes on what the console asked
/// for: by request path for the REST legs, and by the JSON-RPC `method`
/// in the body for `/json_rpc`.
///
/// Its reason to exist is the bridged legs (§2.1.1). A console command
/// that crosses to a route this slice does not serve makes *two or more*
/// requests, and `one_shot` can only answer the first — so the commands
/// whose safety condition is "the console gate covers this command" were
/// the exact commands no gate could reach. Routing rather than replaying
/// a queue also means the assertion is on the reply the console asked
/// for, not on call order: a command that stopped issuing one of its legs
/// gets `no reply`, not a silently shifted answer.
///
/// An unrouted request is answered `404` with an empty body, which is
/// what a daemon that no longer serves the route would do.
fn route_server(routes: Vec<(&'static str, String)>) -> String {
    route_server_recording(routes).0
}

/// [`route_server`], plus the log of what was asked of it.
///
/// A canned reply is blind to the request that fetched it, so a test that
/// only reads the output cannot tell a command that asked for the right
/// window from one that asked for the wrong window and was answered
/// anyway. The log makes the *request* assertable, which for the
/// window-resolving commands is the whole behaviour under test.
#[expect(clippy::type_complexity, reason = "a test log of (route, body)")]
fn route_server_recording(
    routes: Vec<(&'static str, String)>,
) -> (
    String,
    std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
) {
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let recorder = std::sync::Arc::clone(&log);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { return };
            let Some((path, body)) = read_request(&mut s) else {
                continue;
            };
            if let Ok(mut log) = recorder.lock() {
                log.push((path.clone(), body.clone()));
            }
            // `/json_rpc` carries the name in the body; every other route
            // *is* the name.
            let key = if path == "/json_rpc" {
                serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("method")?.as_str().map(str::to_owned))
                    .map_or_else(|| path.clone(), |m| format!("json_rpc:{m}"))
            } else {
                path.clone()
            };
            let reply = routes.iter().find(|(k, _)| *k == key).map(|(_, v)| v);
            let (status, body) = reply.map_or_else(
                || ("404 Not Found", String::new()),
                |r| ("200 OK", r.clone()),
            );
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            // One write: a head-then-body pair lets a client that hung
            // up between them see a truncated reply, which reads as a
            // malformed daemon rather than a closed socket.
            let mut response = head.into_bytes();
            response.extend_from_slice(body.as_bytes());
            if s.write_all(&response).is_err() {
                continue;
            }
        }
    });
    (address, log)
}

/// Read one HTTP request, returning its path and body.
///
/// Headers first, then exactly `Content-Length` more bytes — a single
/// `read` would truncate a body split across packets, which on loopback
/// is rare enough to pass locally and fail in CI.
fn read_request(s: &mut std::net::TcpStream) -> Option<(String, String)> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).ok()? == 0 {
            return None;
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let path = head.split_whitespace().nth(1)?.to_owned();
    let length: usize = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    s.read_exact(&mut body).ok()?;
    Some((path, String::from_utf8_lossy(&body).into_owned()))
}

/// A one-request acceptor that answers by running the **real projection**
/// over fixed facts, so the reply depends on the request the console
/// actually sent.
///
/// A canned reply would be blind to the defect this exists to catch: the
/// "(pruned)" label reads `prunable_as_hex`, which only the split form
/// fills, so a fixture that always returns split-form data would pass
/// whatever the console asked for. Serving the projection makes the
/// request an input rather than a formality.
fn one_shot_projected(slot: crate::core::TxSlot, txid: [u8; 32]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 8192];
        let n = s.read(&mut buf).expect("read request");
        let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
        let request: shekyl_rpc_types::GetTransactionsRequest =
            serde_json::from_str(&body).expect("the console sends a typed request");
        let reply =
            crate::methods::project_transactions(&request, &[txid], &[slot], 9, |blob, pruned| {
                Ok(format!(
                    "{{\"json\":\"{}\",\"pruned\":{pruned}}}",
                    hex::encode(blob)
                ))
            })
            .expect("projection succeeds");
        let out = serde_json::to_string(&reply).unwrap();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            out.len()
        );
        s.write_all(head.as_bytes()).unwrap();
        s.write_all(out.as_bytes()).unwrap();
    });
    address
}

/// A structurally canonical spend for the body-binding: the console now
/// recomputes each entry's identity from its bytes, so a fixture can no
/// longer label an arbitrary blob — a fixture that invents a hash is
/// staging the substitution the binding exists to refuse (the engine's
/// doubles learned this the same way).
fn console_spend() -> shekyl_wire::Transaction {
    use shekyl_wire::transaction::{PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN};
    use shekyl_wire::{BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, TxPrefix};
    shekyl_wire::Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: vec![],
                key_image: [0x42; 32],
            }],
            outputs: vec![
                Output {
                    amount: 0,
                    key: [1; 32],
                    view_tag: 0,
                },
                Output {
                    amount: 0,
                    key: [3; 32],
                    view_tag: 1,
                },
            ],
            extra: vec![],
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: [0; 32],
            base: CtBase {
                enc_amounts: vec![[0; 9], [0; 9]],
                enc_labels: vec![[0; 9], [0; 9]],
                commitments: vec![[2; 32], [3; 32]],
            },
            pqc_auths: vec![PqcAuth {
                auth_version: 1,
                scheme_id: 1,
                flags: 0,
                hybrid_public_key: vec![0; PQC_HYBRID_SINGLE_KEY_LEN],
                hybrid_signature: vec![0; PQC_HYBRID_SINGLE_SIG_LEN],
            }],
            prunable: Some(Prunable {
                serve_credit_pruned: vec![],
                bulletproofs: vec![BpPlus {
                    a: [0; 32],
                    a1: [0; 32],
                    b: [0; 32],
                    r1: [0; 32],
                    s1: [0; 32],
                    d1: [0; 32],
                    l: vec![[0; 32]; 7],
                    r: vec![[0; 32]; 7],
                }],
                tree_depth: 1,
                fcmp_proof: vec![0; 8],
                pseudo_outs: vec![[0; 32]],
            }),
        },
    }
}

/// [`console_spend`] split at the production boundary: (pruned form,
/// prunable tail) — the two halves a split `get_transactions` reply
/// carries, whose concatenation is the full serialization.
fn console_spend_halves() -> (Vec<u8>, Vec<u8>) {
    let tx = console_spend();
    let full = tx.serialize();
    let mut pruned_tx = console_spend();
    let shekyl_wire::Ct::Fcmp { prunable, .. } = &mut pruned_tx.ct else {
        unreachable!("console_spend is Fcmp by construction");
    };
    *prunable = None;
    let pruned = pruned_tx.serialize();
    let tail = full[pruned.len()..].to_vec();
    (pruned, tail)
}

fn mined_slot(prunable: Vec<u8>) -> crate::core::TxSlot {
    crate::core::TxSlot::Chain {
        pruned: console_spend_halves().0,
        prunable,
        // Nonempty: this transaction HAS a prunable half, so an empty
        // `prunable_as_hex` would mean the daemon dropped it.
        prunable_hash: [0x5A; 32],
        block_height: 3,
        block_timestamp: 1_700_000_000,
        output_indices: vec![1],
        pruned_flag: false,
    }
}

/// **An ordinary confirmed transaction is not labelled `(pruned)`.**
///
/// It was, until this test: the console asked for the whole transaction,
/// so the halves came back concatenated in `as_hex` with `prunable_as_hex`
/// empty — which the label cannot tell apart from a daemon that pruned the
/// half away. Every mined transaction printed as `(pruned)`.
#[test]
fn a_retained_transaction_is_not_reported_pruned() {
    // The halves reassemble to the full body, so the identity is the
    // whole-transaction hash.
    let txid = console_spend().hash();
    let addr = one_shot_projected(mined_slot(console_spend_halves().1), txid);
    let (_, out) = run(&["print_transaction", &hex::encode(txid)], Some(&addr));
    assert!(
        out.contains("Found in blockchain at height 3"),
        "expected the confirmed line, got: {out}"
    );
    assert!(
        !out.contains("(pruned)"),
        "a transaction whose prunable half the daemon still holds must not \
         be labelled pruned: {out}"
    );
}

/// And the label still fires when the half really is gone — so the test
/// above is not passing by disabling the label.
#[test]
fn a_pruned_transaction_is_reported_pruned() {
    // The prunable half is gone, so the identity mixes the reply's
    // supplied digest — the same recomputation the binding performs.
    let txid = console_spend().hash_with_supplied_prunable([0x5A; 32]);
    let addr = one_shot_projected(mined_slot(Vec::new()), txid);
    let (_, out) = run(&["print_transaction", &hex::encode(txid)], Some(&addr));
    assert!(
        out.contains("(pruned)"),
        "a transaction whose prunable half is absent must be labelled \
         pruned: {out}"
    );
}

/// **An echoed label over a substituted body is refused.** The label
/// check compares two daemon-chosen strings, so a daemon that echoes the
/// requested hash while serving another canonical body sails through it;
/// the binding recomputes the identity from the bytes and refuses. This
/// is `parse_tx_batch`'s rule applied to the console's remote arm, which
/// posts wherever the operator pointed it.
#[test]
fn an_echoed_label_over_a_substituted_body_is_refused() {
    // The identity of a DIFFERENT transaction (unlock_time moved), which
    // the daemon echoes while serving `console_spend`'s body.
    let mut other = console_spend();
    other.prefix.unlock_time = 5;
    let requested = other.hash();
    let (pruned, tail) = console_spend_halves();
    let entry = shekyl_rpc_types::TxEntry {
        tx_hash: HashHex::from_bytes(requested),
        as_hex: String::new(),
        pruned_as_hex: hex::encode(pruned),
        prunable_as_hex: hex::encode(tail),
        prunable_hash: HashHex::from_bytes([0x5A; 32]),
        as_json: String::new(),
        pruned: false,
        double_spend_seen: false,
        location: shekyl_rpc_types::TxLocation::Mined {
            block_height: 3,
            confirmations: 6,
            block_timestamp: 1_700_000_000,
            output_indices: vec![1],
        },
    };
    let reply = shekyl_rpc_types::GetTransactionsResponse {
        status: RpcStatus::ok(),
        txs: vec![entry],
        missed_tx: vec![],
    };
    let addr = one_shot_raw(reply);
    let (code, out) = run(&["print_transaction", &hex::encode(requested)], Some(&addr));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
    assert!(
        out.contains("a label is not an identity"),
        "the substituted body must be refused by the binding, not \
         rendered: {out}"
    );
}

/// **And on the pruned arm, where the daemon also chooses the digest.**
/// The test above substitutes a body whose prunable half is present, so
/// the identity is a whole-body hash the daemon cannot steer. The pruned
/// arm is the interesting one: `prunable_hash` is the daemon's to pick,
/// and the comment on the binding claims picking it freely buys nothing
/// because it leaves `H(prefix ‖ base ‖ pqc ‖ X) = txid` to solve for
/// `X`. That claim is argued at the call site and pinned here — the
/// daemon serves another transaction's pruned body under this label and
/// supplies the very digest that makes the *requested* identity come out
/// right for its own body, which is the best choice available to it.
#[test]
fn a_substituted_pruned_body_is_refused_even_with_a_chosen_digest() {
    const CHOSEN: [u8; 32] = [0x11; 32];
    // The pruned identity of a DIFFERENT transaction, under the digest
    // the daemon will also supply — so only the body differs.
    let mut other = console_spend();
    other.prefix.unlock_time = 5;
    let requested = other.hash_with_supplied_prunable(CHOSEN);
    // Sanity: the two bodies really do have different pruned identities,
    // or the refusal below would prove nothing.
    assert_ne!(
        requested,
        console_spend().hash_with_supplied_prunable(CHOSEN),
        "the fixture must substitute a genuinely different body"
    );
    let (pruned, _tail) = console_spend_halves();
    let entry = shekyl_rpc_types::TxEntry {
        tx_hash: HashHex::from_bytes(requested),
        as_hex: String::new(),
        pruned_as_hex: hex::encode(pruned),
        // The half is gone, so the binding takes the pruned arm.
        prunable_as_hex: String::new(),
        prunable_hash: HashHex::from_bytes(CHOSEN),
        as_json: String::new(),
        pruned: true,
        double_spend_seen: false,
        location: shekyl_rpc_types::TxLocation::Mined {
            block_height: 3,
            confirmations: 6,
            block_timestamp: 1_700_000_000,
            output_indices: vec![1],
        },
    };
    let reply = shekyl_rpc_types::GetTransactionsResponse {
        status: RpcStatus::ok(),
        txs: vec![entry],
        missed_tx: vec![],
    };
    let addr = one_shot_raw(reply);
    let (code, out) = run(&["print_transaction", &hex::encode(requested)], Some(&addr));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
    assert!(
        out.contains("a label is not an identity"),
        "a substituted pruned body must be refused however the digest is \
         chosen, not rendered: {out}"
    );
}

/// A reply with extra entries is unreadable, not "use the first one".
/// The command requested one hash; the adjacent key-image command already
/// requires a one-element slice for the same reason.
#[test]
fn extra_transaction_entries_are_a_malformed_reply() {
    let txid = [0x33; 32];
    let entry = |n: u8| shekyl_rpc_types::TxEntry {
        tx_hash: HashHex::from_bytes([n; 32]),
        as_hex: String::new(),
        pruned_as_hex: "aabb".to_owned(),
        prunable_as_hex: "ccdd".to_owned(),
        prunable_hash: HashHex::from_bytes([0x5A; 32]),
        as_json: String::new(),
        pruned: false,
        double_spend_seen: false,
        location: shekyl_rpc_types::TxLocation::Mined {
            block_height: 3,
            confirmations: 6,
            block_timestamp: 1_700_000_000,
            output_indices: vec![1],
        },
    };
    let reply = shekyl_rpc_types::GetTransactionsResponse {
        status: RpcStatus::ok(),
        txs: vec![entry(0x33), entry(0x34)],
        missed_tx: vec![],
    };
    let addr = one_shot(typed_reply(&reply));
    let (code, out) = run(&["print_transaction", &hex::encode(txid)], Some(&addr));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
    assert!(
        out.contains("asked about 1 transaction, got 2"),
        "extra entries must be named, not silently truncated: {out}"
    );
}

/// A one-request acceptor answering with a fixed document, for the cases
/// where the point is that the daemon said something the request did not
/// ask for — which the projection-backed fixture cannot stage, because it
/// only ever answers about the hash it was handed.
fn one_shot_raw(reply: shekyl_rpc_types::GetTransactionsResponse) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf).expect("read request");
        let out = serde_json::to_string(&reply).unwrap();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            out.len()
        );
        s.write_all(head.as_bytes()).unwrap();
        s.write_all(out.as_bytes()).unwrap();
    });
    address
}

fn mined_entry(txid: [u8; 32]) -> shekyl_rpc_types::TxEntry {
    shekyl_rpc_types::TxEntry {
        tx_hash: HashHex::from_bytes(txid),
        as_hex: String::new(),
        pruned_as_hex: hex::encode([0xAAu8, 0xBB]),
        prunable_as_hex: hex::encode([0xCCu8]),
        prunable_hash: HashHex::from_bytes([0x5A; 32]),
        as_json: String::new(),
        pruned: false,
        double_spend_seen: false,
        location: shekyl_rpc_types::TxLocation::Mined {
            block_height: 3,
            block_timestamp: 1_700_000_000,
            confirmations: 1,
            output_indices: vec![1],
        },
    }
}

/// **The server's reason survives to the operator.**
///
/// A native handler reports failure as a `RestErrorEnvelope`, which the
/// success type does not model — so a success-only decode reported
/// "malformed reply" over the reason the daemon actually gave, and refusing
/// unknown fields made that certain rather than incidental. `decode_reply`
/// tries the envelope second, which is what keeps the failure actionable.
#[test]
fn a_handler_error_envelope_reaches_the_operator() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf).expect("read request");
        let out = r#"{"error":"the store is inconsistent at height 7"}"#;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            out.len()
        );
        s.write_all(head.as_bytes()).unwrap();
        s.write_all(out.as_bytes()).unwrap();
    });
    let (_, out) = run(
        &["print_transaction", &hex::encode([0x31u8; 32])],
        Some(&address),
    );
    assert!(
        out.contains("the store is inconsistent at height 7"),
        "the daemon's own reason must reach the operator, not be replaced \
         by a decode complaint: {out}"
    );
}

/// **A reply about a different transaction is not an answer.** The count
/// matched, every field was well-formed, and only the identity was wrong —
/// so a console binding the reply to the request by arity alone would have
/// printed another transaction under the operator's hash.
#[test]
fn an_entry_for_a_different_hash_is_refused() {
    let asked = [0x31u8; 32];
    let served = [0x99u8; 32];
    let addr = one_shot_raw(shekyl_rpc_types::GetTransactionsResponse {
        status: shekyl_rpc_types::RpcStatus::ok(),
        txs: vec![mined_entry(served)],
        missed_tx: Vec::new(),
    });
    let (_, out) = run(&["print_transaction", &hex::encode(asked)], Some(&addr));
    assert!(
        out.contains("asked about") && !out.contains("Found in blockchain"),
        "an entry for another hash must be refused, not rendered: {out}"
    );
}

/// A reply that answers AND reports the hash missed is self-contradictory;
/// the miss is the honest half, so it decides.
#[test]
fn an_entry_alongside_a_missed_hash_is_not_found() {
    let asked = [0x31u8; 32];
    let addr = one_shot_raw(shekyl_rpc_types::GetTransactionsResponse {
        status: shekyl_rpc_types::RpcStatus::ok(),
        txs: vec![mined_entry(asked)],
        missed_tx: vec![HashHex::from_bytes(asked)],
    });
    let (_, out) = run(&["print_transaction", &hex::encode(asked)], Some(&addr));
    assert!(
        out.contains("wasn't found"),
        "a contradictory reply must not render as a hit: {out}"
    );
}

/// The C++ printed `<unknown>` below its cutoff and UTC
/// `%Y-%m-%d %H:%M:%S` above it. A genesis block with timestamp 0 is the
/// case an operator actually sees.
#[test]
fn timestamps_render_as_the_cpp_did() {
    assert_eq!(human_readable_timestamp(0), "<unknown>");
    assert_eq!(human_readable_timestamp(1_234_567_889), "<unknown>");
    assert_eq!(
        human_readable_timestamp(1_234_567_890),
        "2009-02-13 23:31:30"
    );
    assert_eq!(
        human_readable_timestamp(1_700_000_000),
        "2023-11-14 22:13:20"
    );
    // A leap day, and the end of a year — the civil-from-days arithmetic
    // is where a hand-rolled calendar goes wrong.
    assert_eq!(
        human_readable_timestamp(1_709_164_800),
        "2024-02-29 00:00:00"
    );
    assert_eq!(
        human_readable_timestamp(1_735_689_599),
        "2024-12-31 23:59:59"
    );
}

/// The console showed the difficulty in decimal, which the C++ got by
/// constructing a `difficulty_type` from the `0x` wide form.
#[test]
fn wide_difficulty_renders_in_decimal() {
    assert_eq!(wide_difficulty_decimal("0x1"), "1");
    // 2^70 + 12345, the value the oracle emitter used.
    assert_eq!(
        wide_difficulty_decimal("0x400000000000003039"),
        "1180591620717411315769"
    );
    // Above 2^64, which is the reason the wide form exists at all.
    assert_eq!(
        wide_difficulty_decimal("0x10000000000000000"),
        "18446744073709551616"
    );
    // Unreadable input is shown rather than swallowed.
    assert_eq!(wide_difficulty_decimal("not-hex"), "not-hex");
}

/// Every line of `print_block_header`, in its order and wording.
/// `reward` is SKL with nine fractional digits (`print_money`), `is
/// orphan` is the 0/1 a streamed C++ bool produced, and an unfilled
/// `pow_hash` prints as nothing after the colon.
#[test]
fn the_block_header_renders_line_for_line() {
    let header = shekyl_rpc_types::BlockHeader {
        major_version: 1,
        minor_version: 0,
        timestamp: 0,
        prev_hash: HashHex::ZERO,
        nonce: 10101,
        orphan_status: false,
        height: 0,
        depth: 0,
        hash: HashHex::from_bytes([7u8; 32]),
        difficulty: 1,
        wide_difficulty: "0x1".to_owned(),
        difficulty_top64: 0,
        cumulative_difficulty: 1,
        wide_cumulative_difficulty: "0x1".to_owned(),
        cumulative_difficulty_top64: 0,
        reward: 100_000_000_000_000,
        block_size: 6263,
        block_weight: 6263,
        num_txes: 0,
        pow_hash: None,
        long_term_weight: 176_470,
        miner_tx_hash: HashHex::from_bytes([9u8; 32]),
        curve_tree_root: HashHex::ZERO,
        attestation_root: HashHex::ZERO,
    };
    let seven = HashHex::from_bytes([7u8; 32]).to_string();
    let nine = HashHex::from_bytes([9u8; 32]).to_string();
    let zero = HashHex::ZERO.to_string();
    assert_eq!(
        render_block_header(&header),
        format!(
            "timestamp: 0 (<unknown>)\n\
             previous hash: {zero}\n\
             nonce: 10101\n\
             is orphan: 0\n\
             height: 0\n\
             depth: 0\n\
             hash: {seven}\n\
             difficulty: 1\n\
             cumulative difficulty: 1\n\
             POW hash: \n\
             block size: 6263\n\
             block weight: 6263\n\
             long term weight: 176470\n\
             num txes: 0\n\
             reward: 100000.000000000\n\
             miner tx hash: {nine}"
        )
    );
}

#[test]
fn print_height_renders_the_remote_reply() {
    let address = one_shot(typed_reply(&GetHeightResponse {
        status: RpcStatus::ok(),
        height: 42,
        hash: HashHex::from_bytes([7u8; 32]),
    }));
    let (code, text) = run(&["print_height"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{text}");
    assert_eq!(text, "42");
}

#[test]
fn non_ok_status_is_a_request_failure_with_the_status_as_reason() {
    let address = one_shot(typed_reply(&GetHeightResponse {
        status: RpcStatus(RpcStatus::BUSY.to_owned()),
        height: 0,
        hash: HashHex::ZERO,
    }));
    let (code, text) = run(&["print_height"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
    assert_eq!(text, "BUSY");
}

/// A daemon that could not answer sends the error envelope (HTTP 500,
/// body still delivered); the operator sees its reason, not a serde
/// complaint about the success type.
#[test]
fn error_envelope_reason_is_surfaced() {
    let address = one_shot(typed_reply(&RestErrorEnvelope {
        status: RpcStatus("ERROR".to_owned()),
        error: "chain facts unavailable".to_owned(),
    }));
    let (code, text) = run(&["print_height"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
    assert_eq!(text, "get_height failed: chain facts unavailable");
}

/// Neither shape: the reply is reported as malformed, with a bounded
/// excerpt of what arrived.
#[test]
fn malformed_reply_is_named_as_such() {
    // Deliberately raw: this fixture's point is that it is not a reply.
    let address = one_shot(r#"<html>not json</html>"#.to_owned());
    let (code, text) = run(&["print_height"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
    assert!(
        text.starts_with("malformed get_height reply: <html>"),
        "{text}"
    );
}

#[test]
fn refused_connection_is_a_request_failure_with_a_reason() {
    let (code, text) = run(&["print_height"], Some("127.0.0.1:1"));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
    assert!(!text.is_empty());
}

/// Both sources given: refused before either is touched (the live
/// pointer is never dereferenced — it is a sentinel here).
#[test]
fn both_sources_is_ambiguous_and_refused() {
    let cmd = CString::new("print_height").unwrap();
    let argv = [cmd.as_ptr()];
    let address = CString::new("127.0.0.1:1").unwrap();
    let mut ptr: *mut u8 = std::ptr::null_mut();
    let mut len: usize = 0;
    let sentinel = std::ptr::dangling_mut::<c_void>();
    // SAFETY: valid argv/address/out pointers; the non-null core pointer
    // is refused before any dereference.
    let code = unsafe {
        shekyl_daemon_console_run(
            argv.as_ptr(),
            1,
            sentinel,
            address.as_ptr(),
            1,
            &raw mut ptr,
            &raw mut len,
        )
    };
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_AMBIGUOUS_SOURCE);
    assert!(ptr.is_null());
}

#[test]
fn unknown_command_and_null_arguments_refuse() {
    let (code, _) = run(&["no_such_command"], Some("127.0.0.1:1"));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_UNKNOWN);
    let (code, _) = run(&["print_height"], None);
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_NULL_PTR);
}

// ── RK-5a: the ported format helpers ───────────────────────────────────
//
// Every expected string below was **printed by the C++ it replaces**, by
// linking `get_human_readable_timespan`, `get_human_readable_bytes` and
// `get_time_interval_string` into the unit-test binary and dumping them
// for these inputs. They are transcriptions of an oracle's output, not a
// reading of its source — which is the difference between a test that
// pins the format and one that repeats whatever the port got wrong.

#[test]
fn a_timespan_reads_the_way_the_daemon_has_always_printed_it() {
    for (seconds, expected) in [
        (0u64, "0 seconds"),
        (1, "1 seconds"),
        (59, "59 seconds"),
        (60, "1.0 minutes"),
        (90, "1.5 minutes"),
        // The boundary is `< 3600`, so one second short of an hour is
        // sixty minutes rather than an hour.
        (3599, "60.0 minutes"),
        (3600, "1.0 hours"),
        (5400, "1.5 hours"),
        (86399, "24.0 hours"),
        (86400, "1.0 days"),
        (200_000, "2.3 days"),
        // A "month" is 30.5 days and a "year" 365.25, and the boundary
        // uses the same expression as the divisor.
        (2_635_200, "1.0 months"),
        (31_557_600, "1.0 years"),
        // Exactly a century is not "100.0 years".
        (3_155_760_000, "a long time"),
        (4_000_000_000, "a long time"),
    ] {
        assert_eq!(human_readable_timespan(seconds), expected, "{seconds}s");
    }
}

#[test]
fn bytes_read_in_base_two_units() {
    for (bytes, expected) in [
        (0u64, "0 B"),
        (1, "1 B"),
        (1023, "1023 B"),
        (1024, "1.00 kB"),
        (1500, "1.46 kB"),
        // One byte short of a mebibyte rounds *up* to "1024.00 kB"
        // rather than crossing into MB.
        (1_048_575, "1024.00 kB"),
        (1_048_576, "1.00 MB"),
        (1_073_741_824, "1.00 GB"),
        (1_099_511_627_776, "1.00 TB"),
        (5_000_000_000_000, "4.55 TB"),
    ] {
        assert_eq!(human_readable_bytes(bytes), expected, "{bytes} bytes");
    }
}

#[test]
fn a_time_interval_is_the_dotted_dhms_form() {
    for (seconds, expected) in [
        (0u64, "d0.h0.m0.s0"),
        (1, "d0.h0.m0.s1"),
        (59, "d0.h0.m0.s59"),
        (61, "d0.h0.m1.s1"),
        (3661, "d0.h1.m1.s1"),
        (90061, "d1.h1.m1.s1"),
        (1_000_000, "d11.h13.m46.s40"),
    ] {
        assert_eq!(time_interval(seconds), expected, "{seconds}s");
    }
}

/// A peer never seen reads "never", not an interval measured from 1970.
#[test]
fn a_peer_never_seen_has_no_interval() {
    let peer = shekyl_rpc_types::Peer {
        id: 0x1122_3344_5566_7788,
        host: "10.32.0.7".to_owned(),
        ip: 0x0700_200a,
        port: 18080,
        last_seen: 0,
        pruning_seed: 0,
    };
    let line = render_peer("white", &peer, 1_750_000_000);
    assert!(line.contains("never"), "{line}");
    // The id is zero-padded to 16 hex characters, as `peerid_to_string`
    // padded it.
    assert!(line.contains("1122334455667788"), "{line}");
    assert!(line.contains("10.32.0.7:18080"), "{line}");

    let seen = shekyl_rpc_types::Peer {
        last_seen: 1_750_000_000 - 90061,
        ..peer
    };
    assert!(
        render_peer("gray", &seen, 1_750_000_000).contains("d1.h1.m1.s1"),
        "a seen peer carries its interval"
    );
}

/// The three address arms, rendered.
///
/// The tor arm is the one the C++ got wrong: its `host` is the whole
/// `str()`, port included, and its `port` is 0, so appending produced
/// `…onion:18080:0`.
#[test]
fn a_peer_address_gains_a_port_only_when_it_has_one() {
    let peer = |host: &str, port: u16| shekyl_rpc_types::Peer {
        id: 1,
        host: host.to_owned(),
        ip: 0,
        port,
        last_seen: 1_750_000_000,
        pruning_seed: 0,
    };
    let line = |p: &shekyl_rpc_types::Peer| render_peer("white", p, 1_750_000_000);

    assert!(line(&peer("10.32.0.7", 18080)).contains("10.32.0.7:18080"));
    assert!(line(&peer("2001:db8::1", 18081)).contains("2001:db8::1:18081"));

    let tor = line(&peer("abcdefghijklmnop.onion:18080", 0));
    assert!(tor.contains("abcdefghijklmnop.onion:18080"), "{tor}");
    assert!(
        !tor.contains(":18080:0"),
        "the port must not be appended to an address that already carries \
         one; got:\n{tor}"
    );
}

/// The address type names the console prints, including the arm the C++
/// `default:` produced.
#[test]
fn address_types_have_their_own_names() {
    assert_eq!(address_type_name(1), "IPv4");
    assert_eq!(address_type_name(2), "IPv6");
    assert_eq!(address_type_name(3), "I2P");
    assert_eq!(address_type_name(4), "Tor");
    assert_eq!(address_type_name(0), "invalid");
    assert_eq!(address_type_name(200), "invalid");
}

/// The capacities are a parameter now, so this can be tested against the
/// values the daemon actually holds. Before the hoist it read
/// `shekyl_rpc_peerlist_limits` directly, whose unit-test link stub
/// answers **0** — so a test here would have asserted `0/0` and agreed
/// with a number no daemon reports, which is precisely what `ffi.rs`'s
/// comment prohibited and nothing enforced.
#[test]
fn the_peerlist_stats_report_real_capacities() {
    let out = render_peer_list_stats(7, 250, 1000, 5000);
    assert!(out.contains("White list size: 7/1000 (0.7%)"), "{out}");
    assert!(out.contains("Gray list size: 250/5000 (5%)"), "{out}");
    // The float noise this rounding exists to stop: 7/1000 is exactly the
    // value that renders `0.7000000000000001` under `{}` on an `f64`.
    assert!(!out.contains("0.7000000000000001"), "{out}");
}

/// A zero capacity is what the link stub would have supplied, and the
/// divide-by-zero guard makes it *survivable* — which is why a test that
/// touched it would have gone green rather than crashed.
#[test]
fn a_zero_capacity_renders_rather_than_dividing_by_zero() {
    let out = render_peer_list_stats(3, 0, 0, 0);
    assert!(out.contains("White list size: 3/0 (0%)"), "{out}");
}

/// Every selector the C++ parser can forward, plus the ones it cannot.
///
/// The parser resolves an unqualified `print_pl` to both lists and sends
/// `both`; `white` and `gray` narrow. The last two rows are the reason
/// this is a function: an argument in that position that is neither
/// keyword must not silently select nothing.
#[test]
fn the_peer_list_selector_narrows_only_on_its_two_keywords() {
    assert_eq!(peer_list_selection(Some("both")), (true, true));
    assert_eq!(peer_list_selection(None), (true, true));
    assert_eq!(peer_list_selection(Some("white")), (true, false));
    assert_eq!(peer_list_selection(Some("gray")), (false, true));
    assert_eq!(peer_list_selection(Some("0")), (true, true));
    assert_eq!(peer_list_selection(Some("")), (true, true));
}

fn net_stats_reply(status: &str) -> String {
    typed_reply(&shekyl_rpc_types::GetNetStatsResponse {
        status: RpcStatus(status.to_owned()),
        start_time: 1_700_000_000,
        total_packets_in: 40,
        total_bytes_in: 4096,
        total_packets_out: 10,
        total_bytes_out: 2048,
    })
}

/// `print_net_stats` over its two legs — the native `/get_net_stats` and
/// the bridged `/get_limit`.
///
/// The command the §2.1.1 note calls covered, finally covered.
///
/// The byte counts come from the native leg and the two limits from the
/// **bridged** one, so the assertions below cannot both hold unless both
/// legs arrived. The limits are also asymmetric (8 down, 4 up) because a
/// single number would pass a renderer that read one field twice — the
/// defect a missing `#[serde(default)]` cannot catch. Elapsed time is
/// wall-clock here (`unix_now`), so the averages are deliberately not
/// asserted; what this test owns is the leg, not the arithmetic.
#[test]
fn net_stats_renders_the_bridged_limits_beside_the_native_counters() {
    let address = route_server(vec![
        ("/get_net_stats", net_stats_reply("OK")),
        (
            "/get_limit",
            r#"{"status":"OK","limit_up":4,"limit_down":8}"#.to_owned(),
        ),
    ]);
    let (code, out) = run(&["print_net_stats"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(out.contains("Received 4096 bytes"), "{out}");
    assert!(out.contains("Sent 2048 bytes"), "{out}");
    assert!(out.contains("limit of 8.00 kB/s"), "{out}");
    assert!(out.contains("limit of 4.00 kB/s"), "{out}");
}

/// A `/get_limit` reply missing a field is **named**, not defaulted.
///
/// This is the assertion that makes `GetLimitReplyProvisional`'s missing
/// `#[serde(default)]` load-bearing rather than a style choice. With the
/// attribute this test goes green while printing a limit of `0 B/s` — a
/// number the daemon never sent — so the failure it guards against is
/// precisely a passing run. RK-8 renaming the field gets an error naming
/// it instead of four confident zeros.
#[test]
fn a_get_limit_reply_missing_a_field_is_refused_rather_than_defaulted() {
    let address = route_server(vec![
        ("/get_net_stats", net_stats_reply("OK")),
        ("/get_limit", r#"{"status":"OK","limit_up":4}"#.to_owned()),
    ]);
    let (code, out) = run(&["print_net_stats"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
    assert!(out.contains("malformed get_limit reply"), "{out}");
    assert!(out.contains("limit_down"), "{out}");
}

fn info_reply(height: u64) -> String {
    serde_json::json!({
        "status": "OK",
        "height": height,
        "target_height": 0,
        "target": crate::consensus::DAA_TARGET_SECONDS,
        "wide_difficulty": "0x1e240",
        "wide_cumulative_difficulty": "0x2dc6c0",
        "testnet": false,
        "stagenet": false,
        "start_time": 1_700_000_000u64,
        "outgoing_connections_count": 8,
        "incoming_connections_count": 3,
        // A field the console does not read, present because the daemon
        // sends about thirty of them: an unknown field must be ignored,
        // since RK-5c *adding* one is not a break.
        "tx_pool_size": 4
    })
    .to_string()
}

fn header_at(height: u64) -> shekyl_rpc_types::BlockHeader {
    shekyl_rpc_types::BlockHeader {
        major_version: 1,
        minor_version: 0,
        timestamp: 1_600_000_000u64.saturating_add(height),
        prev_hash: HashHex::ZERO,
        nonce: 42,
        orphan_status: false,
        height,
        depth: 0,
        hash: HashHex::from_bytes([u8::try_from(height % 256).unwrap(); 32]),
        difficulty: 1000,
        wide_difficulty: "0x3e8".to_owned(),
        difficulty_top64: 0,
        cumulative_difficulty: 1000,
        wide_cumulative_difficulty: "0x3e8".to_owned(),
        cumulative_difficulty_top64: 0,
        reward: 600_000_000_000,
        block_size: 100,
        block_weight: 100,
        num_txes: 1,
        pow_hash: None,
        long_term_weight: 100,
        miner_tx_hash: HashHex::ZERO,
        curve_tree_root: HashHex::ZERO,
        attestation_root: HashHex::ZERO,
    }
}

fn headers_range_reply(heights: &[u64]) -> String {
    typed_reply(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": "0",
        "result": shekyl_rpc_types::GetBlockHeadersRangeResponse {
            status: RpcStatus::ok(),
            headers: heights.iter().copied().map(header_at).collect(),
        },
    }))
}

/// `print_blockchain_info 2 3` asks for exactly that window and lists it.
#[test]
fn blockchain_info_lists_the_window_it_was_given() {
    let address = route_server(vec![(
        "json_rpc:get_block_headers_range",
        headers_range_reply(&[2, 3]),
    )]);
    let (code, out) = run(&["print_blockchain_info", "2", "3"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(out.contains("height: 2, timestamp: 1600000002"), "{out}");
    assert!(out.contains("height: 3, timestamp: 1600000003"), "{out}");
    assert!(out.contains("major version: 1, minor version: 0"), "{out}");
    assert!(
        out.contains("difficulty: 1000, nonce 42, reward 600.000000000"),
        "{out}"
    );
    // Entries are separated by a blank line, as the C++ listed them.
    assert!(out.contains("\n\nheight: 3"), "{out}");
}

/// The positive form does not read `/get_info` at all.
///
/// Asserted from the log rather than inferred from a passing run: the
/// route server has no `/get_info` row, so a leg that fired would 404 and
/// fail — but only for as long as nobody adds that row to this fixture.
#[test]
fn a_non_negative_start_needs_no_tip_read() {
    let (address, log) = route_server_recording(vec![
        ("/get_info", info_reply(100)),
        (
            "json_rpc:get_block_headers_range",
            headers_range_reply(&[2, 3]),
        ),
    ]);
    let (code, out) = run(&["print_blockchain_info", "2", "3"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    let asked = log.lock().unwrap();
    assert!(
        asked.iter().all(|(path, _)| path != "/get_info"),
        "the literal form must not spend a bridged leg: {asked:?}"
    );
    let (_, body) = &asked[0];
    let params: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(params["params"]["start_height"], 2);
    assert_eq!(params["params"]["end_height"], 3);
}

/// The negative form resolves its window against the tip, which is the
/// only reason this command reads `/get_info`.
///
/// Height 100 with `-3` asks for the last three blocks: 97, 98, 99. The
/// **request** is what this pins, read out of the server's log — a canned
/// reply arrives whatever window was asked for, so asserting only on the
/// output would pass a command that resolved the window wrongly.
#[test]
fn a_negative_start_counts_back_from_the_tip() {
    let (address, log) = route_server_recording(vec![
        ("/get_info", info_reply(100)),
        (
            "json_rpc:get_block_headers_range",
            headers_range_reply(&[97, 98, 99]),
        ),
    ]);
    let (code, out) = run(&["print_blockchain_info", "-3", "3"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(out.contains("height: 97"), "{out}");
    assert!(out.contains("height: 99"), "{out}");

    let asked = log.lock().unwrap();
    let (_, body) = asked
        .iter()
        .find(|(path, _)| path == "/json_rpc")
        .expect("the range was asked for");
    let params: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(params["params"]["start_height"], 97);
    assert_eq!(params["params"]["end_height"], 99);
    // And the tip read came first: resolving the window needs it.
    assert_eq!(asked[0].0, "/get_info");
}

/// A window longer than the chain is refused by name.
///
/// The C++ said so and it is worth keeping: an operator who typed a
/// number too large can act on "larger than blockchain height" and cannot
/// act on an empty listing.
#[test]
fn a_window_longer_than_the_chain_is_refused_by_name() {
    let address = route_server(vec![("/get_info", info_reply(3))]);
    let (code, out) = run(&["print_blockchain_info", "-10", "10"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
    assert!(out.contains("larger than blockchain height"), "{out}");
}

/// A `/get_info` reply missing a field the console reads is named.
///
/// The same assertion as `/get_limit`'s, on the leg RK-5c will actually
/// move. Without it, a renamed `height` would make this command resolve
/// its window against a tip of zero and report the chain as empty.
#[test]
fn a_get_info_reply_missing_a_field_is_refused_rather_than_defaulted() {
    let mut info: serde_json::Value = serde_json::from_str(&info_reply(100)).unwrap();
    info.as_object_mut().unwrap().remove("height");
    let address = route_server(vec![("/get_info", info.to_string())]);
    let (code, out) = run(&["print_blockchain_info", "-3", "3"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
    assert!(out.contains("malformed get_info reply"), "{out}");
    assert!(out.contains("height"), "{out}");
}

fn fee_reply(fees: [u64; 4]) -> String {
    typed_reply(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": "0",
        "result": shekyl_rpc_types::GetFeeEstimateResponse {
            status: RpcStatus::ok(),
            fees: shekyl_rpc_types::FeeTiers(fees),
            quantization_mask: 10_000,
        },
    }))
}

/// epee's median, both parities.
///
/// The even case is the one with a decision in it: epee averages the two
/// middle elements and floors, which a lower-middle median (the usual
/// Rust one-liner) would silently change.
#[test]
fn the_median_is_epees_including_its_even_length_average() {
    assert_eq!(median(&mut []), 0);
    assert_eq!(median(&mut [7]), 7);
    assert_eq!(median(&mut [3, 1, 2]), 2);
    // (2 + 4) / 2 = 3, not 2.
    assert_eq!(median(&mut [4, 2, 1, 8]), 3);
    // Floors: (1 + 2) / 2 = 1.
    assert_eq!(median(&mut [2, 1]), 1);
    // And it cannot overflow forming the sum.
    assert_eq!(median(&mut [u64::MAX, u64::MAX]), u64::MAX);
}

/// The version tallies list ascending, omit versions with no votes, and
/// separate with `", "` — the string the C++ built by hand.
#[test]
fn a_version_tally_lists_only_the_versions_present() {
    let mut counts = [0u32; 256];
    assert_eq!(version_tally(&counts), "");
    counts[2] = 3;
    counts[1] = 1;
    assert_eq!(version_tally(&counts), "1 v1, 3 v2");
}

/// A range reply that does not fill the window it was asked for is refused,
/// not summarised.
///
/// **The `alt_chain_info` finding, one command over.** That one declared a
/// length its hashes did not support; this one requests a range the headers
/// need not fill. Round 2 fixed the instance it was reported against and not
/// the rule, which is why this arrived as a separate finding — correspondence
/// is a property of every reply read against a request, not of the command it
/// was first noticed in.
///
/// Both shapes are covered: too few headers, and the right count for the
/// wrong heights. The second is the one an output-only assertion cannot see,
/// because a plausible summary is exactly what it produces.
#[test]
fn a_range_reply_that_misses_the_window_is_refused() {
    let short = typed_reply(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": "0",
        "result": shekyl_rpc_types::GetBlockHeadersRangeResponse {
            status: RpcStatus::ok(),
            headers: vec![header_at(7)],
        },
    }));
    let address = route_server(vec![
        ("/get_info", info_reply(10)),
        ("json_rpc:get_fee_estimate", fee_reply([20, 80, 320, 4000])),
        ("json_rpc:get_block_headers_range", short),
    ]);
    let (code, out) = run(&["print_blockchain_dynamic_stats", "3"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
    assert!(out.contains("answered 1 headers for the 3 blocks"), "{out}");

    // Right count, wrong heights — the case that would otherwise print a
    // correct-looking "Last 3" summary of blocks nobody asked about.
    let wrong = typed_reply(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": "0",
        "result": shekyl_rpc_types::GetBlockHeadersRangeResponse {
            status: RpcStatus::ok(),
            headers: vec![header_at(100), header_at(101), header_at(102)],
        },
    }));
    let address = route_server(vec![
        ("/get_info", info_reply(10)),
        ("json_rpc:get_fee_estimate", fee_reply([20, 80, 320, 4000])),
        ("json_rpc:get_block_headers_range", wrong),
    ]);
    let (code, out) = run(&["print_blockchain_dynamic_stats", "3"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
    assert!(out.contains("starting at height 100"), "{out}");
    assert!(!out.contains("Last 3:"), "{out}");
}

/// `print_blockchain_dynamic_stats` over its four legs, minus the one
/// this slice deleted.
///
/// The fixture makes every aggregate distinguishable: three blocks with
/// weights 100/300/200 (median 200, which a mean would report as 200 too,
/// so the weights are chosen with an even sibling case in the median test
/// above), one and two transactions, and two block versions.
#[test]
fn dynamic_stats_reports_the_window_it_summarized() {
    let mut headers: Vec<shekyl_rpc_types::BlockHeader> =
        [7u64, 8, 9].iter().map(|h| header_at(*h)).collect();
    headers[0].block_weight = 100;
    headers[1].block_weight = 300;
    headers[2].block_weight = 200;
    headers[0].num_txes = 1;
    headers[1].num_txes = 2;
    headers[2].num_txes = 3;
    headers[2].minor_version = 2;
    headers[0].timestamp = 1000;
    headers[1].timestamp = 1120;
    headers[2].timestamp = 1300;
    let range = typed_reply(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": "0",
        "result": shekyl_rpc_types::GetBlockHeadersRangeResponse {
            status: RpcStatus::ok(),
            headers,
        },
    }));
    let (address, log) = route_server_recording(vec![
        ("/get_info", info_reply(10)),
        ("json_rpc:get_fee_estimate", fee_reply([20, 80, 320, 4000])),
        ("json_rpc:get_block_headers_range", range),
    ]);
    let (code, out) = run(&["print_blockchain_dynamic_stats", "3"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");

    // The header line: `wide_difficulty` 0x1e240 is 123456, the
    // cumulative 0x2dc6c0 is 3000000, and the fee is **tier 0** — the
    // value the retired `fee` scalar carried.
    assert!(
        out.contains("Height: 10, diff 123456, cum. diff 3000000, target 120 sec"),
        "{out}"
    );
    assert!(out.contains("dyn fee 0.000000020/byte"), "{out}");

    // avg diff 1000; span 300 / 3 = 100 sec; (1+2+3)/3 = 2 txes;
    // reward is constant so its mean is itself; median weight 200.
    assert!(out.contains("Last 3: avg. diff 1000"), "{out}");
    assert!(out.contains("100 avg sec/block"), "{out}");
    assert!(out.contains("avg num txes 2"), "{out}");
    assert!(out.contains("avg. reward 600.000000000"), "{out}");
    assert!(out.contains("median block weight 200"), "{out}");
    assert!(out.contains("Block versions: 3 v1"), "{out}");
    assert!(out.contains("Voting for: 2 v0, 1 v2"), "{out}");

    // The window: height 10, three blocks, so [7, 9].
    let asked = log.lock().unwrap();
    let range_body = asked
        .iter()
        .filter(|(path, _)| path == "/json_rpc")
        .map(|(_, body)| serde_json::from_str::<serde_json::Value>(body).unwrap())
        .find(|v| v["method"] == "get_block_headers_range")
        .expect("the range was asked for");
    assert_eq!(range_body["params"]["start_height"], 7);
    assert_eq!(range_body["params"]["end_height"], 9);

    // And the deleted leg is not asked for. Asserted, because "the
    // fixture has no row for it" stops being evidence the moment someone
    // adds one.
    assert!(
        asked
            .iter()
            .all(|(path, body)| path != "/hard_fork_info" && !body.contains("hard_fork_info")),
        "the tautological hard-fork leg must be gone: {asked:?}"
    );
}

/// A window longer than the chain is clamped to the chain, not refused.
///
/// `nblocks.min(height)` — the C++ clamped too, and the difference from
/// `print_blockchain_info`'s refusal is deliberate: that command names a
/// window and this one asks for "the last N", which a shorter chain still
/// answers.
#[test]
fn dynamic_stats_clamps_a_window_longer_than_the_chain() {
    let (address, log) = route_server_recording(vec![
        ("/get_info", info_reply(2)),
        ("json_rpc:get_fee_estimate", fee_reply([20, 80, 320, 4000])),
        (
            "json_rpc:get_block_headers_range",
            headers_range_reply(&[0, 1]),
        ),
    ]);
    let (code, out) = run(&["print_blockchain_dynamic_stats", "500"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(out.contains("Last 2:"), "{out}");
    let asked = log.lock().unwrap();
    let range_body = asked
        .iter()
        .filter(|(path, _)| path == "/json_rpc")
        .map(|(_, body)| serde_json::from_str::<serde_json::Value>(body).unwrap())
        .find(|v| v["method"] == "get_block_headers_range")
        .expect("the range was asked for");
    assert_eq!(range_body["params"]["start_height"], 0);
    assert_eq!(range_body["params"]["end_height"], 1);
}

fn hash_n(n: u8) -> HashHex {
    HashHex::from_bytes([n; 32])
}

fn alt_chains_reply(chains: &serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": "0",
        "result": {"status": "OK", "chains": chains},
    })
    .to_string()
}

fn one_alt_chain(
    tip: u8,
    height: u64,
    length: u64,
    hashes: &[u8],
    parent: u8,
) -> serde_json::Value {
    serde_json::json!({
        "block_hash": hash_n(tip),
        "height": height,
        "length": length,
        "difficulty": 1000,
        "wide_difficulty": "0x3e8",
        "difficulty_top64": 0,
        "block_hashes": hashes.iter().map(|h| hash_n(*h)).collect::<Vec<_>>(),
        "main_chain_parent_block": hash_n(parent),
    })
}

fn slots_reply(slots: Vec<shekyl_rpc_types::BlockHeaderSlot>) -> String {
    typed_reply(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": "0",
        "result": shekyl_rpc_types::GetBlockHeaderByHashResponse {
            status: RpcStatus::ok(),
            block_headers: slots,
        },
    }))
}

fn slot(hash: u8, timestamp: u64) -> shekyl_rpc_types::BlockHeaderSlot {
    let mut header = header_at(0);
    header.timestamp = timestamp;
    header.hash = hash_n(hash);
    shekyl_rpc_types::BlockHeaderSlot {
        hash: hash_n(hash),
        block_header: Some(header),
    }
}

/// The listing form: sorted by height, filtered, and each line carrying
/// the fork point and its depth below our tip.
#[test]
fn alt_chain_info_lists_and_filters() {
    let address = route_server(vec![
        ("/get_info", info_reply(100)),
        (
            "json_rpc:get_alternate_chains",
            alt_chains_reply(&serde_json::json!([
                one_alt_chain(9, 90, 2, &[8, 9], 7),
                one_alt_chain(5, 50, 1, &[5], 4),
            ])),
        ),
    ]);
    let (code, out) = run(&["alt_chain_info", "", "0", "0"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(out.starts_with("2 alternate chains found:"), "{out}");
    // Sorted by height: the height-50 chain first.
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[1].contains("from height 50"), "{out}");
    assert!(lines[2].contains("from height 89"), "{out}");
    // 100 - 89 - 1 = 10 deep; 100 - 50 - 1 = 49.
    assert!(lines[1].contains("(49 deep)"), "{out}");
    assert!(lines[2].contains("(10 deep)"), "{out}");

    // `>1` keeps only chains longer than one block.
    let address = route_server(vec![
        ("/get_info", info_reply(100)),
        (
            "json_rpc:get_alternate_chains",
            alt_chains_reply(&serde_json::json!([
                one_alt_chain(9, 90, 2, &[8, 9], 7),
                one_alt_chain(5, 50, 1, &[5], 4),
            ])),
        ),
    ]);
    let (code, out) = run(&["alt_chain_info", "", "1", "0"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(out.starts_with("1 alternate chains found:"), "{out}");
    assert!(out.contains("from height 89"), "{out}");
}

/// The tip form: the chain's blocks, its parent, and the derived age,
/// span and hash-rate share.
#[test]
fn alt_chain_info_reports_one_chain_by_tip() {
    let tip = hash_n(9).to_string();
    let address = route_server(vec![
        ("/get_info", info_reply(100)),
        (
            "json_rpc:get_alternate_chains",
            alt_chains_reply(&serde_json::json!([one_alt_chain(9, 90, 2, &[8, 9], 7)])),
        ),
        (
            "json_rpc:get_block_header_by_hash",
            // Asked in this order: the chain's blocks, then the parent.
            slots_reply(vec![slot(8, 1000), slot(9, 1240), slot(7, 880)]),
        ),
    ]);
    let (code, out) = run(&["alt_chain_info", &tip, "0", "0"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(
        out.contains(&format!("Found alternate chain with tip {tip}")),
        "{out}"
    );
    assert!(
        out.contains("2 blocks long, from height 89 (10 deep)"),
        "{out}"
    );
    assert!(
        out.contains(&format!("Chain parent on main chain: {}", hash_n(7))),
        "{out}"
    );
    // Span 1240 - 880 = 360 s; share = 100 * 120 * 2 / 360 = 66.666667%.
    assert!(out.contains("Time span:"), "{out}");
    assert!(
        out.contains("Approximated 66.666667% of network hash rate"),
        "{out}"
    );
}

/// A chain declaring more blocks than it lists is refused.
///
/// **The half of the C++ check the correspondence check did not
/// replace.** `block_headers.size() != chain.length + 1` was
/// `block_hashes.len() == length` said indirectly; per-hash
/// correspondence is stronger about *which* hash answered and blind to
/// this, because every slot of a short list corresponds perfectly. The
/// console would have printed a depth and a hash-rate share derived from
/// a length no header supports — a wrong number with every input
/// agreeing. Found in review; the claim that the new check was "strictly
/// stronger" was wrong on this axis.
#[test]
fn a_chain_declaring_more_blocks_than_it_lists_is_refused() {
    let tip = hash_n(9).to_string();
    let (address, log) = route_server_recording(vec![
        ("/get_info", info_reply(100)),
        (
            "json_rpc:get_alternate_chains",
            // length 10, two hashes.
            alt_chains_reply(&serde_json::json!([one_alt_chain(9, 90, 10, &[8, 9], 7)])),
        ),
        (
            "json_rpc:get_block_header_by_hash",
            slots_reply(vec![slot(8, 1000), slot(9, 1240), slot(7, 880)]),
        ),
    ]);
    let (code, out) = run(&["alt_chain_info", &tip, "0", "0"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
    assert!(out.contains("declared a 10-block alt chain"), "{out}");
    assert!(out.contains("listed 2"), "{out}");
    // Refused before the headers are fetched: a malformed reply must not
    // cost a round trip per block it claims.
    let asked = log.lock().unwrap();
    assert!(
        asked
            .iter()
            .all(|(_, body)| !body.contains("get_block_header_by_hash")),
        "the header batch must not be issued: {asked:?}"
    );
}

/// A hash whose header the daemon does not hold is named.
///
/// This is the case the C++ could not express. Its check was
/// `block_headers.size() != chain.length + 1`, so a reorg between
/// `get_alternate_chains` and the header batch produced "Failed to get
/// block header info for alt chain" — true, and naming nothing. The
/// per-element reply carries a slot for the missing hash, so the console
/// can say which one moved.
#[test]
fn a_hash_with_no_header_is_named_rather_than_counted() {
    let tip = hash_n(9).to_string();
    let missing = hash_n(9).to_string();
    let address = route_server(vec![
        ("/get_info", info_reply(100)),
        (
            "json_rpc:get_alternate_chains",
            alt_chains_reply(&serde_json::json!([one_alt_chain(9, 90, 2, &[8, 9], 7)])),
        ),
        (
            "json_rpc:get_block_header_by_hash",
            slots_reply(vec![
                slot(8, 1000),
                shekyl_rpc_types::BlockHeaderSlot {
                    hash: hash_n(9),
                    block_header: None,
                },
                slot(7, 880),
            ]),
        ),
    ]);
    let (code, out) = run(&["alt_chain_info", &tip, "0", "0"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
    assert!(
        out.contains(&format!("no block header for {missing}")),
        "{out}"
    );
}

/// A reply of the right length whose slots answer different hashes is
/// refused — which the count check could not see at all.
#[test]
fn a_slot_answering_a_different_hash_is_refused() {
    let requested = vec![hash_n(1), hash_n(2)];
    let slots = vec![slot(1, 10), slot(3, 20)];
    let err = headers_in_correspondence(&slots, &requested)
        .expect_err("slot 1 answers hash 3, not hash 2");
    assert!(err.contains(&hash_n(3).to_string()), "{err}");
    assert!(err.contains(&hash_n(2).to_string()), "{err}");

    // And the length disagreement it replaces.
    let err =
        headers_in_correspondence(&slots[..1], &requested).expect_err("one slot for two hashes");
    assert!(err.contains("1 of 2"), "{err}");

    // The agreeing case, so this is not a test that only knows how to
    // refuse.
    let good = headers_in_correspondence(&[slot(1, 10), slot(2, 20)], &requested)
        .expect("both slots answer what was asked");
    assert_eq!(good.len(), 2);
}

/// Blocks sharing a timestamp get a sentence, not `inf%`.
///
/// The C++ guarded this site with `back().difficulty > 0` — a check on a
/// value the percentage does not contain, whose message named
/// `cumulative difficulty` while reading `difficulty`. The reachable
/// hazard is a zero span, which divided straight through.
#[test]
fn a_zero_span_reports_why_rather_than_dividing() {
    let tip = hash_n(9).to_string();
    let address = route_server(vec![
        ("/get_info", info_reply(100)),
        (
            "json_rpc:get_alternate_chains",
            alt_chains_reply(&serde_json::json!([one_alt_chain(9, 90, 2, &[8, 9], 7)])),
        ),
        (
            "json_rpc:get_block_header_by_hash",
            slots_reply(vec![slot(8, 1000), slot(9, 1000), slot(7, 1000)]),
        ),
    ]);
    let (code, out) = run(&["alt_chain_info", &tip, "0", "0"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(out.contains("share a timestamp"), "{out}");
    assert!(!out.contains("inf"), "{out}");
}

/// A tip that is not a known alt chain says so.
#[test]
fn an_unknown_tip_is_named() {
    let tip = hash_n(200).to_string();
    let address = route_server(vec![
        ("/get_info", info_reply(100)),
        (
            "json_rpc:get_alternate_chains",
            alt_chains_reply(&serde_json::json!([])),
        ),
    ]);
    let (code, out) = run(&["alt_chain_info", &tip, "0", "0"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
    assert!(
        out.contains("is not the tip of any known alternate chain"),
        "{out}"
    );
}

fn fork_reply(active: u8, queried: u8, earliest: u64) -> String {
    typed_reply(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": "0",
        "result": shekyl_rpc_types::HardForkInfoResponse {
            status: RpcStatus::ok(),
            queried_version: queried,
            active_version: active,
            enabled: true,
            window: 10080,
            votes: 10080,
            threshold: 0,
            voting: active,
            state: 2,
            earliest_height: earliest,
        },
    }))
}

fn mining_reply(active: bool, speed: u64, background: bool) -> String {
    serde_json::json!({
        "status": "OK",
        "active": active,
        "speed": speed,
        "is_background_mining_enabled": background,
    })
    .to_string()
}

/// A hash rate for a human, at every prefix boundary the C++ had.
#[test]
fn a_mining_speed_picks_the_prefix_the_cpp_picked() {
    assert_eq!(mining_speed(0), "0 H/s");
    assert_eq!(mining_speed(999), "999 H/s");
    // 1000 is the first prefixed value: still under a million, so `k`.
    assert_eq!(mining_speed(1000), "1.00 kH/s");
    // 999999 / 1000 is 999.999, which `%.2f` rounds up — so the largest
    // value that still reads in kilohashes prints as `1000.00 kH/s`.
    // The C++ did this too; it is recorded rather than corrected,
    // because the alternative is a second rounding rule for a console
    // line.
    assert_eq!(mining_speed(999_999), "1000.00 kH/s");
    // A million divides once, then reads as thousands of thousands.
    assert_eq!(mining_speed(1_000_000), "1.00 MH/s");
    assert_eq!(mining_speed(2_500_000_000), "2.50 GH/s");
    // Past every prefix, the raw number — the C++ fell out of its loop
    // with `prefix = 0` and formatted the value it started with.
    assert_eq!(
        mining_speed(10u128.pow(33)),
        format!("{} H/s", 10u128.pow(33))
    );
}

/// The sync percentage, including the 99.9 clamp that exists so a daemon
/// one block short does not read as finished.
#[test]
fn the_sync_percentage_never_rounds_up_to_a_hundred() {
    assert!((sync_percentage(50, 100) - 50.0).abs() < f64::EPSILON);
    // Fully synced is a real 100.
    assert!((sync_percentage(100, 100) - 100.0).abs() < f64::EPSILON);
    // A target below our height means we are ahead of it.
    assert!((sync_percentage(100, 50) - 100.0).abs() < f64::EPSILON);
    // 99999/100000 would print as 100.0%; it must not.
    assert!((sync_percentage(99_999, 100_000) - 99.9).abs() < f64::EPSILON);
    // And an empty chain divides by one, not by zero.
    assert!((sync_percentage(0, 0) - 0.0).abs() < f64::EPSILON);
}

/// The fork countdown, in each of its units and in the cases that say
/// nothing.
#[test]
fn the_fork_countdown_changes_units_where_the_cpp_did() {
    assert_eq!(fork_extra_info(100, 100, 120), " (forking now)");
    // Already past: nothing to count down to.
    assert_eq!(fork_extra_info(50, 100, 120), "");
    assert_eq!(fork_extra_info(120, 100, 120), " (next fork in 20 blocks)");
    // 720 blocks/day at a 120 s target, so 30 blocks/hour: 100 blocks is
    // under half a day and reads in hours.
    assert_eq!(fork_extra_info(200, 100, 120), " (next fork in 3.3 hours)");
    assert_eq!(fork_extra_info(1_540, 100, 120), " (next fork in 2.0 days)");
    // Past thirty days, nothing.
    assert_eq!(fork_extra_info(100_000, 100, 120), "");
    // A target the daemon reports as zero, or as longer than an hour,
    // divided straight through in the C++.
    assert_eq!(fork_extra_info(200, 100, 0), "");
    assert_eq!(fork_extra_info(200, 100, 90_000), "");
}

/// The whole status line, on the remote arm, with all three legs.
#[test]
fn the_status_line_reads_the_way_the_daemon_has_always_printed_it() {
    let address = route_server(vec![
        ("/get_info", info_reply(100)),
        ("json_rpc:hard_fork_info", fork_reply(3, 7, 100)),
        ("/mining_status", mining_reply(true, 2500, false)),
    ]);
    let (code, out) = run(&["status"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(out.contains("Height: 100/100 (100.0%) on mainnet"), "{out}");
    assert!(out.contains("mining at 2.50 kH/s"), "{out}");
    // net hash = difficulty 123456 / target 120, integer-divided to
    // 1028 H/s, which reads as 1.03 kH/s.
    assert!(out.contains("net hash 1.03 kH/s"), "{out}");
    // **`v3`, not `v7`.** The fixture's queried and active versions
    // differ on purpose: `on_hard_fork_info` set `res.version` from
    // `get_current_hard_fork_version()` regardless of the request, so
    // this line is the active fork. Reading `queried_version` here would
    // invert the reason RK-5b split the two.
    assert!(out.contains("v3 (forking now)"), "{out}");
    assert!(out.contains("8(out)+3(in) connections"), "{out}");
    assert!(out.contains(", uptime "), "{out}");
}

/// A restricted daemon discloses no start time, and the uptime clause is
/// omitted rather than reported as zero.
#[test]
fn a_daemon_that_hides_its_start_time_gets_no_uptime_clause() {
    let mut info: serde_json::Value = serde_json::from_str(&info_reply(100)).unwrap();
    info["start_time"] = serde_json::json!(0);
    let address = route_server(vec![
        ("/get_info", info.to_string()),
        ("json_rpc:hard_fork_info", fork_reply(3, 3, 0)),
        ("/mining_status", mining_reply(false, 0, false)),
    ]);
    let (code, out) = run(&["status"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(out.contains("not mining"), "{out}");
    assert!(!out.contains("uptime"), "{out}");
}

/// A remote daemon that will not serve `/mining_status` still gets a
/// status line.
///
/// A restricted listener does not serve the route at all — an ordinary
/// posture, not a fault — so the eight other things the line knows are
/// still worth printing. The route server has no `/mining_status` row, so
/// it answers 404.
#[test]
fn a_restricted_remote_daemon_still_reports_its_status() {
    let address = route_server(vec![
        ("/get_info", info_reply(100)),
        ("json_rpc:hard_fork_info", fork_reply(3, 3, 0)),
    ]);
    let (code, out) = run(&["status"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(out.contains("mining info unavailable"), "{out}");
    assert!(out.contains("Height: 100/100"), "{out}");
}

/// A syncing daemon answers `BUSY`, which is neither mining nor idle.
#[test]
fn a_busy_mining_status_reads_as_syncing() {
    let address = route_server(vec![
        ("/get_info", info_reply(100)),
        ("json_rpc:hard_fork_info", fork_reply(3, 3, 0)),
        (
            "/mining_status",
            serde_json::json!({
                "status": "BUSY",
                "active": false,
                "speed": 0,
                "is_background_mining_enabled": false,
            })
            .to_string(),
        ),
    ]);
    let (code, out) = run(&["status"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(out.contains(", syncing,"), "{out}");
}

/// `hard_fork_info` names the fork its numbers describe.
///
/// The fixture gives queried, active and voting three **different**
/// values, so each of the two lines pins its own field: a port that
/// confused any pair could not pass by coincidence. The C++ labelled
/// line one with `voting` when asked about no particular version, which
/// here would print `v9`.
#[test]
fn hard_fork_info_labels_line_one_with_the_version_it_counted() {
    let reply = typed_reply(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": "0",
        "result": shekyl_rpc_types::HardForkInfoResponse {
            status: RpcStatus::ok(),
            queried_version: 7,
            active_version: 3,
            enabled: false,
            window: 10080,
            votes: 42,
            threshold: 8064,
            voting: 9,
            state: 2,
            earliest_height: 0,
        },
    }));
    let address = route_server(vec![("json_rpc:hard_fork_info", reply)]);
    let (code, out) = run(&["hard_fork_info", "0"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "version 7 not enabled, 42/10080 votes, threshold 8064",
            "current version 3, voting for version 9",
        ]
    );
}

/// T comes from the generated authority, and a daemon that disagrees is
/// reported rather than believed.
///
/// The C++ read `ires.target` and computed from it. That is one source
/// too many for a genesis-frozen constant that
/// `config/consensus_constants.json` already single-sources into both
/// languages — and on the remote arm the extra source is a daemon that
/// can report anything. The reply is still read, because a disagreement
/// means different consensus rules, i.e. a different chain, which is
/// worth saying out loud.
#[test]
fn the_daa_target_comes_from_the_build_not_the_wire() {
    let authority = crate::consensus::DAA_TARGET_SECONDS;
    assert_eq!(
        daa_target_seconds(authority),
        (authority, None),
        "agreement is silent"
    );
    let (used, warning) = daa_target_seconds(authority.saturating_add(1));
    assert_eq!(used, authority, "the authority wins, never the wire");
    let warning = warning.expect("a disagreement must be reported");
    assert!(warning.contains("different chain"), "{warning}");
    assert!(warning.contains(&format!("{authority}s")), "{warning}");
}

/// A daemon reporting a foreign T gets the warning printed above the
/// figures, and the figures are still computed with the build's T.
#[test]
fn a_foreign_target_warns_and_does_not_change_the_arithmetic() {
    let mut info: serde_json::Value = serde_json::from_str(&info_reply(10)).unwrap();
    // The fixture already carries the real T; make this daemon claim 60.
    info["target"] = serde_json::json!(60);
    let address = route_server(vec![
        ("/get_info", info.to_string()),
        ("json_rpc:hard_fork_info", fork_reply(3, 3, 0)),
        ("/mining_status", mining_reply(false, 0, false)),
    ]);
    let (code, out) = run(&["status"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
    assert!(out.contains("WARNING:"), "{out}");
    assert!(out.contains("reports a block target of 60s"), "{out}");
    // net hash = 123456 / 120 = 1028 -> 1.03 kH/s, the build's T. Under
    // the daemon's 60 it would be 2057 -> 2.06 kH/s.
    assert!(out.contains("net hash 1.03 kH/s"), "{out}");
    assert!(!out.contains("2.06 kH/s"), "{out}");
}

/// The warning appears only where T actually changes a number.
///
/// `alt_chain_info`'s listing form derives nothing from T, so it stays
/// silent even against a daemon reporting a foreign one — the inverse
/// direction of the test above, and the reason it exists: a warning
/// attached to output it cannot affect is how a reader learns to skip
/// the one that matters. The tip form, which computes a hash-rate share,
/// does warn.
#[test]
fn the_target_warning_appears_only_where_t_changes_a_number() {
    let mut info: serde_json::Value = serde_json::from_str(&info_reply(100)).unwrap();
    info["target"] = serde_json::json!(60);
    let chains = alt_chains_reply(&serde_json::json!([one_alt_chain(9, 90, 2, &[8, 9], 7)]));

    let address = route_server(vec![
        ("/get_info", info.to_string()),
        ("json_rpc:get_alternate_chains", chains.clone()),
    ]);
    let (code, listing) = run(&["alt_chain_info", "", "0", "0"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{listing}");
    assert!(
        !listing.contains("WARNING:"),
        "the listing form uses no T: {listing}"
    );

    let tip = hash_n(9).to_string();
    let address = route_server(vec![
        ("/get_info", info.to_string()),
        ("json_rpc:get_alternate_chains", chains),
        (
            "json_rpc:get_block_header_by_hash",
            slots_reply(vec![slot(8, 1000), slot(9, 1240), slot(7, 880)]),
        ),
    ]);
    let (code, detail) = run(&["alt_chain_info", &tip, "0", "0"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{detail}");
    assert!(detail.contains("WARNING:"), "{detail}");
    // And the share is computed with the build's T, not the daemon's 60:
    // 100 * 120 * 2 / 360 = 66.666667, where 60 would give 33.333333.
    assert!(
        detail.contains("Approximated 66.666667% of network hash rate"),
        "{detail}"
    );
}

/// A route the daemon no longer serves is a request failure, not a zero.
///
/// The other half of §2.1.1: the acceptor answers `404` for an unrouted
/// path, which is what a daemon that dropped `/get_limit` would do.
#[test]
fn a_bridged_route_the_daemon_stopped_serving_fails_loudly() {
    let address = route_server(vec![("/get_net_stats", net_stats_reply("OK"))]);
    let (code, out) = run(&["print_net_stats"], Some(&address));
    assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
    assert!(!out.contains("limit of 0 B/s"), "{out}");
}
