// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether a run of records is a submission. The stream reports the shape;
//! these tests are the daemon's route reading it.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{bytes, pair};
use crate::SUBMISSION_CAP;

/// F2: the stream reports the shape of the records it just read, and the
/// daemon's route can tell a padded submission from anything else.
#[tokio::test]
async fn the_inbound_shape_tells_a_submission_from_anything_else() {
    // One client stream, one daemon stream, several requests in turn.
    let (mut client, mut daemon) = pair(1 << 20);
    let shape = daemon.inbound_shape();
    let mark = client.submission_mark();
    let mut got = vec![0u8; 1 << 20];

    // An ordinary request.
    client.write_all(b"GET /info").await.unwrap();
    client.flush().await.unwrap();
    daemon.read_exact(&mut got[..9]).await.unwrap();
    assert!(!shape.ends_in_submission());

    // A padded submission (one payload record, four padding).
    mark.arm();
    client.write_all(&bytes(300)).await.unwrap();
    client.flush().await.unwrap();
    daemon.read_exact(&mut got[..300]).await.unwrap();
    assert!(shape.ends_in_submission());

    // A submission that fills all five records carries no padding. The
    // padded frame that preceded it is the boundary the five are counted from.
    mark.arm();
    client.write_all(&bytes(SUBMISSION_CAP)).await.unwrap();
    client.flush().await.unwrap();
    daemon.read_exact(&mut got[..SUBMISSION_CAP]).await.unwrap();
    assert!(shape.ends_in_submission());

    // The same bytes sent unarmed: five full ordinary records, after a
    // message that ended on a full record. Not taken for a submission.
    client.write_all(&bytes(SUBMISSION_CAP)).await.unwrap();
    client.flush().await.unwrap();
    daemon.read_exact(&mut got[..SUBMISSION_CAP]).await.unwrap();
    assert!(!shape.ends_in_submission());

    // A submission's size sent unarmed: ordinary records, refused.
    client.write_all(&bytes(1_000)).await.unwrap();
    client.flush().await.unwrap();
    daemon.read_exact(&mut got[..1_000]).await.unwrap();
    assert!(!shape.ends_in_submission());
}

/// Two full-size submissions on one connection, each answered. The
/// response is the boundary the second is counted from, so it is not
/// refused for following a message that ended on a full record.
#[tokio::test]
async fn a_full_size_submission_after_a_response_is_a_submission() {
    let (mut client, mut daemon) = pair(1 << 20);
    let shape = daemon.inbound_shape();
    let mark = client.submission_mark();
    let mut got = vec![0u8; SUBMISSION_CAP];
    for attempt in 0..3 {
        mark.arm();
        client.write_all(&bytes(SUBMISSION_CAP)).await.unwrap();
        client.flush().await.unwrap();
        daemon.read_exact(&mut got).await.unwrap();
        assert!(shape.ends_in_submission(), "submission {attempt}");
        daemon.write_all(b"HTTP/1.1 200 OK").await.unwrap();
        daemon.flush().await.unwrap();
        let mut answer = [0u8; 15];
        client.read_exact(&mut answer).await.unwrap();
    }
    // Two in a row with no response between: the second continues the run.
    mark.arm();
    client.write_all(&bytes(SUBMISSION_CAP)).await.unwrap();
    client.flush().await.unwrap();
    daemon.read_exact(&mut got).await.unwrap();
    assert!(shape.ends_in_submission());
    mark.arm();
    client.write_all(&bytes(SUBMISSION_CAP)).await.unwrap();
    client.flush().await.unwrap();
    daemon.read_exact(&mut got).await.unwrap();
    assert!(!shape.ends_in_submission(), "no boundary in front of it");
}

/// A largest-class ordinary record after a padded frame is not a submission.
/// The padding belongs to the frame that finished; borrowing it would make
/// this record look like the end of a shorter frame.
#[tokio::test]
async fn an_ordinary_record_after_a_padded_frame_is_not_a_submission() {
    let (mut client, mut daemon) = pair(1 << 20);
    let shape = daemon.inbound_shape();
    client.submission_mark().arm();
    client.write_all(&bytes(300)).await.unwrap();
    client.flush().await.unwrap();
    let mut got = vec![0u8; 300];
    daemon.read_exact(&mut got).await.unwrap();
    assert!(shape.ends_in_submission());

    // 20,000 bytes is one record of the largest class: more than the middle
    // class holds, and at most one largest payload.
    let medium = 20_000;
    client.write_all(&bytes(medium)).await.unwrap();
    client.flush().await.unwrap();
    let mut got = vec![0u8; medium];
    daemon.read_exact(&mut got).await.unwrap();
    assert!(!shape.ends_in_submission());

    // The same bytes with no frame behind them are not a submission either.
    let (mut client, mut daemon) = pair(1 << 20);
    let shape = daemon.inbound_shape();
    client.write_all(&bytes(medium)).await.unwrap();
    client.flush().await.unwrap();
    let mut got = vec![0u8; medium];
    daemon.read_exact(&mut got).await.unwrap();
    assert!(!shape.ends_in_submission());
}
