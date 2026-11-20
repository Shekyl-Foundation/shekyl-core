// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! PWD-B12's release bound, held to the encoder.
//!
//! `CAP_NEW_TRANSACTIONS` is the encoded size of a 2002 that carries one
//! transaction of `MAX_TX_SIZE` bytes, and `NewTransactionsSize` is the
//! count the relay's flush fills a notice by. Both are arithmetic over the
//! portable-storage layout; these tests encode the notices and compare, so
//! the arithmetic and the encoder cannot drift apart.
//!
//! The layout, for a stem of one transaction of `n` bytes with no padding:
//!
//! | bytes | what |
//! | --- | --- |
//! | 9 | the storage header |
//! | 1 | the varint of the member count (3) |
//! | 2 + 1 + 1 | `_`: key length and name, type tag, varint of length 0 |
//! | 18 + 1 + 1 | `dandelionpp_fluff`: key length and name, type tag, the boolean |
//! | 4 + 1 + 1 | `txs`: key length and name, type tag, varint of the entry count (1) |
//! | varint(n) + n | the entry: 4 + 1 000 000 at `MAX_TX_SIZE` |
//!
//! 40 bytes of envelope, 4 of length varint and the transaction: 1 000 044.
//! A fluff leaves the flag member out (its default) and is 20 bytes smaller.

use shekyl_levin::{
    ingress_payload_cap, notify, BucketHead, BucketReader, Command, Error, Flags, NewTransactions,
    NewTransactionsSize, PortableMap, Received, CAP_NEW_TRANSACTIONS, DEFAULT_MAX_PACKET_SIZE,
    NOTIFY_NEW_TRANSACTIONS,
};
use shekyl_wire::transaction::MAX_TX_SIZE;

fn notice(lens: &[usize], fluff: bool) -> NewTransactions {
    NewTransactions {
        txs: lens.iter().map(|len| vec![0xA5; *len]).collect(),
        padding: Vec::new(),
        dandelionpp_fluff: fluff,
    }
}

fn encoded_len(lens: &[usize], fluff: bool) -> u64 {
    let bytes = notice(lens, fluff).store().expect("stores");
    u64::try_from(bytes.len()).expect("fits")
}

fn counted_len(lens: &[usize], fluff: bool) -> u64 {
    lens.iter()
        .fold(NewTransactionsSize::EMPTY, |size, len| size.with(*len))
        .encoded_len(fluff)
}

/// The cap is exactly what the encoder writes for a stem of one
/// maximum-size transaction, and one more byte of transaction is over it.
///
/// Red edit: set `CAP_NEW_TRANSACTIONS` to any other figure (the packet
/// limit it was, `MAX_TX_SIZE` alone, the fluff form), or add a member to
/// `NewTransactions::to_section` without counting it.
#[test]
fn the_cap_is_a_stem_of_one_maximum_size_transaction() {
    assert_eq!(encoded_len(&[MAX_TX_SIZE], false), CAP_NEW_TRANSACTIONS);
    assert_eq!(CAP_NEW_TRANSACTIONS, 1_000_044);
    assert_eq!(
        encoded_len(&[MAX_TX_SIZE + 1], false),
        CAP_NEW_TRANSACTIONS + 1
    );
    // The fluff form is smaller by the flag member, so it fits as well.
    assert_eq!(encoded_len(&[MAX_TX_SIZE], true), CAP_NEW_TRANSACTIONS - 20);
}

/// The receiver's 2002 cap is that figure, on a request and a response.
///
/// Red edit: point `Command::NewTransactions`'s arm of `payload_cap` back
/// at `DEFAULT_MAX_PACKET_SIZE`.
#[test]
fn the_receiver_caps_2002_at_the_derived_figure() {
    assert_eq!(Command::NewTransactions.payload_cap(), CAP_NEW_TRANSACTIONS);
    for flags in [Flags::REQUEST, Flags::RESPONSE] {
        assert_eq!(
            ingress_payload_cap(NOTIFY_NEW_TRANSACTIONS, flags).expect("defined"),
            CAP_NEW_TRANSACTIONS
        );
    }
}

/// On an established session the reader refuses a 2002 one byte over the
/// cap at its header, before any of its body is buffered, and admits one
/// at the cap. The packet limit is 100 MB there, so the cap is what
/// refuses.
///
/// Red edit: the same as above; the header one byte over is then admitted
/// and the reader waits for a megabyte of body.
#[test]
fn a_2002_one_byte_over_the_cap_is_refused_at_its_header() {
    let over = BucketHead::make(
        NOTIFY_NEW_TRANSACTIONS,
        CAP_NEW_TRANSACTIONS + 1,
        Flags::REQUEST,
        false,
    );
    let mut reader = BucketReader::new();
    reader.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
    reader.feed(&over.write()).expect("a header");
    assert_eq!(
        reader.next_message(),
        Err(Error::OversizePacket {
            claimed: CAP_NEW_TRANSACTIONS + 1,
            limit: CAP_NEW_TRANSACTIONS,
        })
    );

    let stem = notice(&[MAX_TX_SIZE], false).store().expect("stores");
    let mut reader = BucketReader::new();
    reader.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
    reader
        .feed(&notify(NOTIFY_NEW_TRANSACTIONS, &stem))
        .expect("within the packet limit");
    assert_eq!(
        reader.next_message(),
        Ok(Some(Received::Notification {
            command: NOTIFY_NEW_TRANSACTIONS,
            payload: stem,
        }))
    );
}

/// The count is the encoder's size for every shape the relay sends: no
/// transaction, one, several, lengths on each side of every varint band
/// the cap reaches, and enough entries to move the count's own varint.
///
/// Red edit: drop the entry count's varint, a blob's length varint or the
/// flag member from `NewTransactionsSize::encoded_len`.
#[test]
fn the_count_is_the_encoded_size() {
    let sixty_four_ones = vec![1usize; 64];
    let shapes: [&[usize]; 9] = [
        &[],
        &[0],
        &[1],
        &[63],
        &[64],
        &[16_383],
        &[16_384],
        &[3_000, 63, 20_000, 64, 0],
        &sixty_four_ones,
    ];
    for lens in shapes {
        for fluff in [true, false] {
            assert_eq!(
                counted_len(lens, fluff),
                encoded_len(lens, fluff),
                "{} entries, fluff {fluff}",
                lens.len()
            );
        }
    }
}

/// A notice the count admits decodes to what was sent.
#[test]
fn a_counted_notice_round_trips() {
    let sent = notice(&[3_000, 63, 20_000], true);
    let bytes = sent.store().expect("stores");
    assert_eq!(NewTransactions::load(&bytes).expect("loads"), sent);
}
