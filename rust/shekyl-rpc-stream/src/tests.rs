// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The adapter's tests. Each requirement of `RPC_CHANNEL.md` §4.4 has one,
//! and the HTTP tests run hyper over the adapter as the daemon and its
//! clients will.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use shekyl_noise::{SplitRole, SymmetricState};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;

/// Two ends of one session: the client's (send, receive) and the daemon's.
fn directions() -> ((Direction, Direction), (Direction, Direction)) {
    let state = || {
        let mut s = SymmetricState::new(b"shekyl-rpc-stream test", b"");
        s.mix_key(&[0x42; 32]);
        s
    };
    (
        state().into_directions(SplitRole::Initiator),
        state().into_directions(SplitRole::Responder),
    )
}

/// Smaller than one largest-class record (1 + 65,535 + 16 tag bytes), so
/// sealing one record blocks until the peer reads.
const RECORD_DOES_NOT_FIT: usize = 1 << 16;

/// A client stream and a daemon stream over an in-memory transport of
/// `capacity` bytes each way.
fn pair(capacity: usize) -> (RecordStream<DuplexStream>, RecordStream<DuplexStream>) {
    let ((c_send, c_recv), (d_send, d_recv)) = directions();
    let (a, b) = duplex(capacity);
    (
        RecordStream::new(a, c_send, c_recv),
        RecordStream::new(b, d_send, d_recv),
    )
}

fn bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

/// Write `message` and flush on one end; read exactly it on the other.
/// Returns the records the writer cut, per class.
async fn send_one(len: usize) -> [u64; 3] {
    let (mut client, mut daemon) = pair(4096);
    let counters = client.counters();
    let message = bytes(len);
    let expected = message.clone();
    let write = async move {
        client.write_all(&message).await.unwrap();
        client.flush().await.unwrap();
        client
    };
    let read = async move {
        let mut got = vec![0u8; len];
        daemon.read_exact(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::join!(write, read);
    assert_eq!(got, expected);
    let sent = counters.lock().unwrap().sent;
    sent
}

/// RT-P5's flush policy at the class boundaries: a flush cuts the bytes in
/// the smallest class that holds them; a full record is the largest class.
#[tokio::test]
async fn a_flush_cuts_the_smallest_class_that_holds_the_bytes() {
    let table = class_table();
    let most = |id: u8| table.max_payload(ClassId(id)).unwrap();
    assert_eq!(send_one(1).await, [1, 0, 0]);
    assert_eq!(send_one(most(0)).await, [1, 0, 0]);
    assert_eq!(send_one(most(0) + 1).await, [0, 1, 0]);
    assert_eq!(send_one(most(1)).await, [0, 1, 0]);
    assert_eq!(send_one(most(1) + 1).await, [0, 0, 1]);
    assert_eq!(send_one(most(2)).await, [0, 0, 1]);
    assert_eq!(send_one(most(2) + 1).await, [1, 0, 1]);
}

/// A block batch, larger than one record, is cut into full records and a
/// tail and arrives whole. The pre-flight's named edit: with the cut removed
/// this fails.
#[tokio::test]
async fn a_message_larger_than_a_record_is_cut_and_arrives_whole() {
    let len = 300_000;
    // 4 full records of 65,533 and a tail of 37,868, in the largest class.
    assert_eq!(send_one(len).await, [0, 0, 5]);
    let len = 200_000;
    // 3 full records and a tail of 3,401, in the 16,384 class.
    assert_eq!(send_one(len).await, [0, 1, 3]);
}

/// A slow reader holds the writer: the adapter never holds more than one
/// record's payload and one sealed record, however much is written.
#[tokio::test]
async fn a_slow_reader_holds_the_writer_to_one_record() {
    let (mut client, mut daemon) = pair(1024);
    let counters = client.counters();
    let len = 2_000_000;
    let message = bytes(len);
    let expected = message.clone();
    let write = async move {
        client.write_all(&message).await.unwrap();
        client.flush().await.unwrap();
    };
    let read = async move {
        let mut got = Vec::with_capacity(len);
        let mut chunk = [0u8; 700];
        while got.len() < len {
            let n = daemon.read(&mut chunk).await.unwrap();
            got.extend_from_slice(&chunk[..n]);
            tokio::task::yield_now().await;
        }
        got
    };
    let ((), got) = tokio::join!(write, read);
    assert_eq!(got, expected);
    let c = counters.lock().unwrap();
    assert!(c.max_pending <= MAX_PAYLOAD, "pending {}", c.max_pending);
    let largest_wire = class_table().wire_len(class_table().largest()).unwrap();
    assert!(c.max_out <= largest_wire, "out {}", c.max_out);
    assert!(
        c.payload_while_record_in_flight,
        "the next payload fills while the sealed record is still leaving"
    );
}

/// Half-close: the client sends its request and shuts its write side; the
/// daemon reads to the end, then answers on its own side.
#[tokio::test]
async fn half_close_ends_one_direction_and_leaves_the_other() {
    let (mut client, mut daemon) = pair(4096);
    client.write_all(b"request").await.unwrap();
    client.shutdown().await.unwrap();
    let mut got = Vec::new();
    daemon.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"request");
    daemon.write_all(b"response").await.unwrap();
    daemon.shutdown().await.unwrap();
    let mut got = Vec::new();
    client.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"response");
}

/// What a client puts on the wire for one message, then the end of it.
async fn wire_of(message: &[u8]) -> Vec<u8> {
    let ((c_send, c_recv), _) = directions();
    let (a, mut raw) = duplex(1 << 20);
    let mut client = RecordStream::new(a, c_send, c_recv);
    client.write_all(message).await.unwrap();
    client.shutdown().await.unwrap();
    drop(client);
    let mut wire = Vec::new();
    raw.read_to_end(&mut wire).await.unwrap();
    wire
}

/// The daemon's half of a session, fed `wire` and then the end of the
/// transport.
async fn daemon_reading(wire: &[u8]) -> io::Result<Vec<u8>> {
    let (_, (d_send, d_recv)) = directions();
    let (mut feed, x) = duplex(1 << 20);
    let mut daemon = RecordStream::new(x, d_send, d_recv);
    feed.write_all(wire).await.unwrap();
    drop(feed);
    let mut got = Vec::new();
    daemon.read_to_end(&mut got).await.map(|_| got)
}

#[tokio::test]
async fn an_end_inside_a_record_is_an_error_not_an_end() {
    let wire = wire_of(b"request").await;
    assert_eq!(daemon_reading(&wire).await.unwrap(), b"request");
    let cut = &wire[..wire.len() - 1];
    let error = daemon_reading(cut).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<ClassedError>()),
        Some(&ClassedError::Truncated)
    );
}

#[tokio::test]
async fn a_changed_byte_is_refused() {
    let mut wire = wire_of(b"request").await;
    let last = wire.len() - 1;
    wire[last] ^= 1;
    let error = daemon_reading(&wire).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<ClassedError>()),
        Some(&ClassedError::Refused)
    );
}

/// A request flushed in two pieces, head then body, is two records and one
/// byte stream to the reader.
#[tokio::test]
async fn a_request_split_across_records_reads_as_one_stream() {
    let (mut client, mut daemon) = pair(4096);
    let counters = client.counters();
    let head = b"POST / HTTP/1.1\r\n\r\n";
    let body = bytes(20_000);
    let head_len = head.len();
    let body_len = body.len();
    let write = async move {
        client.write_all(head).await.unwrap();
        client.flush().await.unwrap();
        client.write_all(&body).await.unwrap();
        client.flush().await.unwrap();
    };
    let read = async move {
        let mut got = vec![0u8; head_len + body_len];
        daemon.read_exact(&mut got).await.unwrap();
        got
    };
    let ((), got) = tokio::join!(write, read);
    assert_eq!(&got[..head_len], head);
    assert_eq!(&got[head_len..], &bytes(body_len)[..]);
    let c = counters.lock().unwrap();
    assert_eq!(c.sent, [1, 0, 1]);
    assert_eq!(c.flushes_with_records, 2);
}

/// RT-O28: an armed message goes out as exactly SUBMISSION_RECORDS records
/// of the largest class, whatever its size, and reads back as itself; the
/// mark covers that one message.
#[tokio::test]
async fn a_submission_is_always_its_fixed_record_count() {
    // A message is never empty: an armed flush with nothing written leaves
    // the mark for the next message.
    for len in [
        1,
        1_000,
        MAX_PAYLOAD,
        3 * MAX_PAYLOAD + 7,
        SUBMISSION_RECORDS * MAX_PAYLOAD,
    ] {
        let (mut client, mut daemon) = pair(RECORD_DOES_NOT_FIT);
        let counters = client.counters();
        let received = daemon.counters();
        client.submission_mark().arm();
        let message = bytes(len);
        let expected = message.clone();
        let write = async move {
            client.write_all(&message).await.unwrap();
            client.flush().await.unwrap();
            client.write_all(b"next").await.unwrap();
            client.flush().await.unwrap();
        };
        let read = async move {
            let mut got = vec![0u8; len + 4];
            daemon.read_exact(&mut got).await.unwrap();
            // Kept open until the writer's last flush has returned.
            (got, daemon)
        };
        let ((), (got, _daemon)) = tokio::join!(write, read);
        assert_eq!(&got[..len], &expected[..], "{len} bytes");
        assert_eq!(&got[len..], b"next");
        let sent = counters.lock().unwrap().sent;
        assert_eq!(
            sent,
            [1, 0, u64::try_from(SUBMISSION_RECORDS).unwrap()],
            "{len} bytes: the submission's records, then one small one"
        );
        assert_eq!(received.lock().unwrap().received, sent);
    }
}

/// A submission that would need a record past its count is refused, and
/// no record past the count is sealed.
#[tokio::test]
async fn a_submission_past_its_count_is_refused() {
    let (mut client, mut daemon) = pair(1 << 20);
    let counters = client.counters();
    client.submission_mark().arm();
    let message = bytes(SUBMISSION_CAP + 1);
    let reader = tokio::spawn(async move {
        let mut sink = Vec::new();
        // The writer's refusal ends the stream; how the reader sees that
        // end is not this test's subject.
        drop(daemon.read_to_end(&mut sink).await);
    });
    let result = async {
        client.write_all(&message).await?;
        client.flush().await
    }
    .await;
    let error = result.unwrap_err();
    assert!(error
        .get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<SubmissionTooLarge>));
    assert_eq!(
        counters.lock().unwrap().sent,
        [0, 0, u64::try_from(SUBMISSION_RECORDS).unwrap()]
    );
    drop(client);
    reader.await.unwrap();
}

/// An armed flush with nothing written does not classify, so the mark
/// still covers the next message.
#[tokio::test]
async fn an_empty_flush_leaves_the_mark_armed() {
    let (mut client, mut daemon) = pair(RECORD_DOES_NOT_FIT);
    let counters = client.counters();
    let write = async move {
        client.submission_mark().arm();
        client.flush().await.unwrap();
        client.write_all(&[0x11]).await.unwrap();
        client.flush().await.unwrap();
    };
    let read = async move {
        let mut got = [0u8; 1];
        daemon.read_exact(&mut got).await.unwrap();
        got
    };
    let ((), got) = tokio::join!(write, read);
    assert_eq!(got, [0x11]);
    assert_eq!(
        counters.lock().unwrap().sent,
        [0, 0, u64::try_from(SUBMISSION_RECORDS).unwrap()]
    );
}

/// One record's bytes are still unclassified. An arm before the flush
/// pads that message; the mark is not sampled when the bytes arrive.
#[tokio::test]
async fn an_arm_while_the_message_is_still_open_pads_it() {
    let (mut client, mut daemon) = pair(RECORD_DOES_NOT_FIT);
    let counters = client.counters();
    let write = async move {
        client.write_all(&[0x22]).await.unwrap();
        client.submission_mark().arm();
        client.flush().await.unwrap();
    };
    let read = async move {
        let mut got = [0u8; 1];
        daemon.read_exact(&mut got).await.unwrap();
        got
    };
    let ((), got) = tokio::join!(write, read);
    assert_eq!(got, [0x22]);
    assert_eq!(
        counters.lock().unwrap().sent,
        [0, 0, u64::try_from(SUBMISSION_RECORDS).unwrap()]
    );
}

/// The full record of an ordinary message is already classified. Arming
/// on its tail covers the next message, and the flush does not clear it.
#[tokio::test]
async fn an_arm_after_classification_covers_the_next_message() {
    let (mut client, mut daemon) = pair(RECORD_DOES_NOT_FIT);
    let counters = client.counters();
    let first_len = MAX_PAYLOAD + 1;
    let write = async move {
        client.write_all(&bytes(first_len)).await.unwrap();
        client.submission_mark().arm();
        client.flush().await.unwrap();
        client.write_all(&[0x7e]).await.unwrap();
        client.flush().await.unwrap();
    };
    let read = async move {
        let mut got = vec![0u8; first_len + 1];
        daemon.read_exact(&mut got).await.unwrap();
        got
    };
    let ((), got) = tokio::join!(write, read);
    assert_eq!(&got[..first_len], &bytes(first_len)[..]);
    assert_eq!(got[first_len], 0x7e);
    assert_eq!(
        counters.lock().unwrap().sent,
        [1, 0, u64::try_from(1 + SUBMISSION_RECORDS).unwrap()]
    );
}

/// The handshake opens the first record, then hands the direction back.
/// That payload is read before bytes already pulled past the record, and
/// those before whatever the transport still has. The new half continues
/// at the next nonce; a direction that had not spent the first record
/// would refuse the second.
#[tokio::test]
async fn the_opened_first_record_is_read_before_the_transport() {
    let ((c_send, _), (d_send, d_recv)) = directions();
    let table = class_table();
    let class = table.smallest_for(b"first".len()).unwrap();
    let mut send = ClassedRecord::new(c_send, table.clone());
    let first = send.seal(class, b"first").unwrap();
    let second = send.seal(class, b"second").unwrap();
    let third = send.seal(class, b"third").unwrap();

    let mut framed = ClassedRecord::new(d_recv, table);
    let opened = framed.open(&first).unwrap();
    assert_eq!(opened.payload, b"first");
    let d_recv = framed.into_direction();
    assert_eq!(d_recv.opened(), 1);

    let mut unread = second;
    unread.push(third[0]);
    let (mut peer, daemon_io) = duplex(RECORD_DOES_NOT_FIT);
    let mut daemon =
        RecordStream::after_first_record(daemon_io, d_send, d_recv, opened.payload, unread);
    let rest = third[1..].to_vec();
    let write = async move {
        peer.write_all(&rest).await.unwrap();
    };
    let read = async move {
        let mut got = vec![0u8; b"firstsecondthird".len()];
        daemon.read_exact(&mut got).await.unwrap();
        got
    };
    let ((), got) = tokio::join!(write, read);
    assert_eq!(got, b"firstsecondthird");
}

/// SUBMISSION_RECORDS is derived from the consensus bound: the largest
/// admissible transaction's request body fits five records with room for
/// a request head, and does not fit four.
#[test]
fn the_submission_count_is_the_consensus_bound_in_records() {
    /// Room the five records were chosen to leave for the HTTP head.
    /// A floor for the count, not a second protocol constant.
    const MIN_HEAD_ROOM: usize = 16 * 1024;
    let largest_body = submit_envelope_len() + 2 * shekyl_wire::transaction::TX_WEIGHT_LIMIT;
    let head_room = SUBMISSION_CAP - largest_body;
    assert!(head_room >= MIN_HEAD_ROOM, "{head_room} bytes for the head");
    assert!(largest_body > (SUBMISSION_RECORDS - 1) * MAX_PAYLOAD);
}

fn submit_envelope_len() -> usize {
    serde_json::to_vec(&shekyl_rpc_types::SubmitTransactionRequest {
        tx_blob: String::new(),
    })
    .unwrap()
    .len()
}

// ------------------------------------------------------------- HTTP over it

/// Leading bytes of an answer that carry the request body's length.
const ECHOED_LEN: usize = std::mem::size_of::<usize>();

const SUBMIT_TRANSACTION: &str = "/submit_transaction";

/// The daemon side: answers every request with the length of its body, in
/// a body of `answer_len` bytes. A `submit_transaction` body is collected
/// only after all [`SUBMISSION_RECORDS`] records have been opened.
async fn serve(daemon: RecordStream<DuplexStream>, answer_len: usize) {
    assert!(answer_len >= ECHOED_LEN);
    let received = daemon.counters();
    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
        let received = Arc::clone(&received);
        async move {
            let submission = request.uri().path() == SUBMIT_TRANSACTION;
            let body = request.into_body().collect().await.unwrap().to_bytes();
            if submission {
                // Padding sealed after the payload would let the body
                // finish while those records were still unsent.
                let counts = received.lock().unwrap().received;
                assert_eq!(
                    counts,
                    [0, 0, u64::try_from(SUBMISSION_RECORDS).unwrap()],
                    "the body was collected with records {counts:?}"
                );
            }
            let mut answer = bytes(answer_len);
            let len = body.len().to_le_bytes();
            answer[..ECHOED_LEN].copy_from_slice(&len);
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(answer))))
        }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(daemon), service)
        .await
        .unwrap();
}

fn submit(tx_len: usize) -> Request<Full<Bytes>> {
    let body = serde_json::to_vec(&shekyl_rpc_types::SubmitTransactionRequest {
        tx_blob: hex::encode(bytes(tx_len)),
    })
    .unwrap();
    Request::post(SUBMIT_TRANSACTION)
        .header("host", "node")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// RT-O28, as ruled: every `submit_transaction` upload is exactly
/// SUBMISSION_RECORDS records of the largest class, whatever the
/// transaction's size, through hyper as a client sends it. A request that
/// is not a submission is one small record.
#[tokio::test]
async fn every_submit_transaction_upload_is_the_fixed_record_count() {
    for tx_len in [
        0,
        1,
        26_599,
        97_585,
        shekyl_wire::transaction::TX_WEIGHT_LIMIT,
    ] {
        let (client, daemon) = pair(RECORD_DOES_NOT_FIT);
        let mark = client.submission_mark();
        let received = daemon.counters();
        let server = tokio::spawn(serve(daemon, 64));
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .unwrap();
        let conn = tokio::spawn(conn);

        mark.arm();
        let response = sender.send_request(submit(tx_len)).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let mut width = [0u8; ECHOED_LEN];
        width.copy_from_slice(&body[..ECHOED_LEN]);
        let echoed = usize::from_le_bytes(width);
        assert_eq!(
            echoed,
            submit_envelope_len() + 2 * tx_len,
            "the daemon got the whole body"
        );
        assert_eq!(
            received.lock().unwrap().received,
            [0, 0, u64::try_from(SUBMISSION_RECORDS).unwrap()],
            "a {tx_len}-byte transaction's upload"
        );

        let request = Request::get("/get_info")
            .header("host", "node")
            .body(Full::new(Bytes::new()))
            .unwrap();
        sender.send_request(request).await.unwrap();
        assert_eq!(
            received.lock().unwrap().received,
            [1, 0, u64::try_from(SUBMISSION_RECORDS).unwrap()],
            "the next request is one small record"
        );
        drop(sender);
        conn.await.unwrap().unwrap();
        server.await.unwrap();
    }
}

/// RT-P5's registered flush policy, observed (RT-W9 step 5): hyper flushes
/// once per message, so each request and each response is one flush, cut
/// into full records and a tail. Messages from a few bytes to a block
/// batch's size, both directions, on one kept-alive connection.
#[tokio::test]
async fn hyper_flushes_once_per_message() {
    let sizes = [0usize, 431, 20_000, 300_000];
    for answer_len in [64usize, 20_000, 300_000] {
        let (client, daemon) = pair(RECORD_DOES_NOT_FIT);
        let requests = client.counters();
        let responses = daemon.counters();
        let server = tokio::spawn(serve(daemon, answer_len));
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .unwrap();
        let conn = tokio::spawn(conn);
        for len in sizes {
            let request = Request::post("/json_rpc")
                .header("host", "node")
                .body(Full::new(Bytes::from(bytes(len))))
                .unwrap();
            let response = sender.send_request(request).await.unwrap();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body.len(), answer_len);
        }
        let n = u64::try_from(sizes.len()).unwrap();
        assert_eq!(
            requests.lock().unwrap().flushes_with_records,
            n,
            "one flush per request (answers of {answer_len} bytes)"
        );
        assert_eq!(
            responses.lock().unwrap().flushes_with_records,
            n,
            "one flush per response of {answer_len} bytes"
        );
        drop(sender);
        conn.await.unwrap().unwrap();
        server.await.unwrap();
    }
}
