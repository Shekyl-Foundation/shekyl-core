// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How one HTTP message is cut into records.
//!
//! The stream owns the transport. This module owns the bytes that are not
//! sealed yet, and the rule that decides the next record. The two meet at
//! [`WritePlan`] and [`EndPlan`]: the stream seals only what a plan names,
//! and only then tells the message the seal committed. A seal that fails
//! leaves the bytes where they were.
//!
//! A message is classified once, the moment its kind would change what is
//! sealed. Until then it is [`Phase::Open`] and an arm still applies to it.
//! Classification is a further byte arriving while one full record is
//! buffered, or a flush that finds bytes waiting. An empty flush finds
//! nothing and does not classify, so the arm stays for the next message.
//!
//! **A flush ends the message.** The first call to [`Message::plan_flush`]
//! moves it to [`Phase::Ending`], before anything is sealed or drained, and
//! an ending message accepts no byte. If the flush is interrupted (the
//! transport is not ready), the next write does not join the old message:
//! it finishes sealing it first, then starts a new one. Without this, a
//! write that arrived while a flush was pending joined the previous
//! message, and an armed submission went out as an ordinary record.
//!
//! An ordinary message streams. One full record is sealed as soon as the
//! next byte arrives, and the tail waits for the flush in the smallest
//! class that holds it. A submission does not stream: its bytes stay
//! buffered until the flush, and the flush seals the padding records
//! first. The HTTP body is then a suffix of the five records, so it is
//! not complete — and a peer cannot answer — until the last record
//! arrives. Sealing the payload first would let that answer start while
//! the padding was still unsent, and the wait would publish the size.
//!
//! A submission that would pass [`SUBMISSION_CAP`] is discarded unsealed:
//! nothing of a submission is on the wire before its flush, so refusing it
//! sends nothing.

use shekyl_noise::{ClassId, ClassTable, MAX_RECORD_PLAINTEXT, OCCUPANCY_LEN};
use zeroize::Zeroizing;

/// The channel's class table, in both directions (RT-O6 re-ruled
/// 2026-10-18; RT-O29, 2026-10-20): plaintext lengths, occupancy included.
pub const CLASS_LENGTHS: [usize; 3] = [512, 16_384, MAX_RECORD_PLAINTEXT];

/// The most payload one record carries: a record of the largest class.
pub const MAX_PAYLOAD: usize = MAX_RECORD_PLAINTEXT - OCCUPANCY_LEN;

/// The records every `submit_transaction` upload takes, whatever the
/// transaction's size (RT-O28).
///
/// The largest admissible transaction is `shekyl-wire`'s `TX_WEIGHT_LIMIT`
/// (weight is size plus the Bp+ clawback). Its request body is that many
/// bytes, hex-encoded, inside the JSON envelope. Five records of the
/// largest class hold it and leave room for the request head. A test pins
/// the count against the wire constant.
pub const SUBMISSION_RECORDS: usize = 5;

/// The most bytes one submission holds. Five largest-class payloads.
/// Past this the submission is discarded unsealed and refused.
pub const SUBMISSION_CAP: usize = SUBMISSION_RECORDS * MAX_PAYLOAD;

/// The class table both directions pad to.
#[must_use]
pub fn class_table() -> ClassTable {
    ClassTable::new(&CLASS_LENGTHS).expect("the ruled table is strictly increasing")
}

/// Which way a classified message is cut. Chosen once, from the mark.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MessageKind {
    /// Full records in the largest class, and a tail in the smallest
    /// class that holds it.
    Ordinary,
    /// [`SUBMISSION_RECORDS`] records of the largest class, padding first.
    Submission,
}

/// One record the stream should seal. `len` bytes come off the front of
/// the buffer. Zero is padding: the buffer stays, and the record's
/// occupancy is 0, which delivers no bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SealPlan {
    pub(crate) class: ClassId,
    pub(crate) len: usize,
}

impl SealPlan {
    /// Padding carries no HTTP bytes, so it can be sealed before the body
    /// without the peer learning that a body has started.
    pub(crate) fn is_padding(self) -> bool {
        self.len == 0
    }
}

/// What [`Message::plan_write`] asks for. The stream performs one step
/// and asks again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WritePlan {
    /// Copy this many bytes of the caller's buffer into the message.
    Accept(usize),
    /// One full record is buffered and another byte arrived. The stream
    /// consumes the mark and calls [`Message::classify`].
    Classify,
    /// Drain the sealed record already in flight, then seal this one.
    /// Two sealed records never wait together.
    Seal(SealPlan),
    /// The previous message has ended and every record of it is sealed.
    /// Drain its last record, [`Message::finish`], then plan again.
    Close { counted: bool },
    /// A full submission and another byte. The stream discards the
    /// submission unsealed and refuses; the byte was not accepted.
    TooLarge,
}

/// What [`Message::plan_flush`] asks for, and what an ending message asks
/// of a write that arrives before the flush completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EndPlan {
    /// No message: drain, and the flush is done.
    Nothing,
    /// Bytes are waiting and the kind is not chosen. Consume the mark.
    Classify,
    /// Drain, then seal.
    Seal(SealPlan),
    /// Every record is sealed. Drain, then [`Message::finish`].
    /// `counted` is a message that sent records.
    Close { counted: bool },
}

/// Bytes not yet sealed, and how many records of this message already are.
struct Cut {
    pending: Zeroizing<Vec<u8>>,
    sealed: usize,
}

/// Where one message is. The variants are the combinations that can occur.
enum Phase {
    /// Nothing buffered. A flush here does not classify.
    Idle,
    /// At most one record, kind not chosen.
    Open(Zeroizing<Vec<u8>>),
    /// Classified ordinary and still taking bytes. `pending` is at most
    /// one record.
    Ordinary(Cut),
    /// Classified submission. The payload is whole and unsealed, at most
    /// [`SUBMISSION_CAP`].
    Held(Zeroizing<Vec<u8>>),
    /// A flush has begun: the message takes no more bytes. What is left is
    /// sealed, then the message closes. For a submission `payload_at` is
    /// the sealed-count at which the HTTP bytes begin, so those bytes are a
    /// suffix of the five records; an ordinary message has none, and its
    /// tail goes in the smallest class that holds it.
    Ending { cut: Cut, payload_at: Option<usize> },
}

/// The bytes of one HTTP message, up to the flush that ends it.
#[derive(Debug)]
pub(crate) struct Message {
    phase: Phase,
}

impl std::fmt::Debug for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => f.write_str("Idle"),
            Self::Open(buf) => write!(f, "Open({})", buf.len()),
            Self::Ordinary(cut) => write!(
                f,
                "Ordinary(pending {}, sealed {})",
                cut.pending.len(),
                cut.sealed
            ),
            Self::Held(buf) => write!(f, "Held({})", buf.len()),
            Self::Ending { cut, payload_at } => write!(
                f,
                "Ending(pending {}, sealed {}, payload at {payload_at:?})",
                cut.pending.len(),
                cut.sealed
            ),
        }
    }
}

impl Message {
    pub(crate) fn new() -> Self {
        Self { phase: Phase::Idle }
    }

    /// Bytes buffered and not sealed. A submission may hold its whole
    /// payload; an ordinary message never holds more than one record.
    /// The stream's tests are the reader; production seals from [`prefix`].
    #[cfg(test)]
    pub(crate) fn buffered_len(&self) -> usize {
        self.pending().len()
    }

    fn pending(&self) -> &[u8] {
        match &self.phase {
            Phase::Idle => &[],
            Phase::Open(buf) | Phase::Held(buf) => buf,
            Phase::Ordinary(cut) | Phase::Ending { cut, .. } => &cut.pending,
        }
    }

    /// The next write step.
    pub(crate) fn plan_write(&self, incoming: usize, table: &ClassTable) -> WritePlan {
        match &self.phase {
            Phase::Ending { .. } => match self.plan_end(table) {
                EndPlan::Seal(plan) => WritePlan::Seal(plan),
                EndPlan::Close { counted } => WritePlan::Close { counted },
                EndPlan::Nothing | EndPlan::Classify => {
                    unreachable!("an ending message seals or closes")
                }
            },
            Phase::Idle | Phase::Open(_) => self.plan_open_write(incoming),
            Phase::Held(buf) => {
                let room = SUBMISSION_CAP - buf.len();
                if room == 0 && incoming > 0 {
                    WritePlan::TooLarge
                } else {
                    WritePlan::Accept(incoming.min(room))
                }
            }
            Phase::Ordinary(cut) => {
                let room = MAX_PAYLOAD - cut.pending.len();
                if room == 0 && incoming > 0 {
                    WritePlan::Seal(SealPlan {
                        class: table.largest(),
                        len: MAX_PAYLOAD,
                    })
                } else {
                    WritePlan::Accept(incoming.min(room))
                }
            }
        }
    }

    /// An open message accepts at most one record. The byte that would
    /// start the next record classifies instead of joining the buffer.
    fn plan_open_write(&self, incoming: usize) -> WritePlan {
        let buffered = match &self.phase {
            Phase::Idle => 0,
            Phase::Open(buf) => buf.len(),
            _ => unreachable!("an open write is idle or open"),
        };
        let room = MAX_PAYLOAD - buffered;
        if room == 0 && incoming > 0 {
            WritePlan::Classify
        } else {
            WritePlan::Accept(incoming.min(room))
        }
    }

    pub(crate) fn accept(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        match &mut self.phase {
            Phase::Idle => {
                let mut buf = Zeroizing::new(Vec::with_capacity(MAX_PAYLOAD));
                buf.extend_from_slice(bytes);
                self.phase = Phase::Open(buf);
            }
            Phase::Open(buf) | Phase::Held(buf) => buf.extend_from_slice(bytes),
            Phase::Ordinary(cut) => cut.pending.extend_from_slice(bytes),
            Phase::Ending { .. } => unreachable!("an ending message does not take bytes"),
        }
    }

    /// The mark has been consumed. `buf` is one full record when this
    /// follows a write, and whatever the flush found when it follows a flush.
    pub(crate) fn classify(&mut self, kind: MessageKind) {
        let Phase::Open(buf) = std::mem::replace(&mut self.phase, Phase::Idle) else {
            unreachable!("only an open message is classified");
        };
        debug_assert!(!buf.is_empty(), "an empty buffer is not a message");
        self.phase = match kind {
            MessageKind::Ordinary => Phase::Ordinary(Cut {
                pending: buf,
                sealed: 0,
            }),
            MessageKind::Submission => {
                // One allocation for the rest of the cap, so the held bytes
                // are never copied by a growing buffer. The flush seals from
                // this buffer; it does not grow a record at a time.
                let mut held = Zeroizing::new(Vec::with_capacity(SUBMISSION_CAP));
                held.extend_from_slice(&buf);
                Phase::Held(held)
            }
        };
    }

    /// The next flush step. The first call ends the message, before any of
    /// it is sealed: an ordinary message stops taking bytes, and a held
    /// submission plans its padding from the whole payload.
    pub(crate) fn plan_flush(&mut self, table: &ClassTable) -> EndPlan {
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Idle => return EndPlan::Nothing,
            Phase::Open(buf) => {
                debug_assert!(!buf.is_empty(), "an open message has bytes");
                self.phase = Phase::Open(buf);
                return EndPlan::Classify;
            }
            Phase::Ordinary(cut) => {
                self.phase = Phase::Ending {
                    cut,
                    payload_at: None,
                };
            }
            Phase::Held(pending) => {
                let payload_records = payload_record_count(pending.len());
                debug_assert!((1..=SUBMISSION_RECORDS).contains(&payload_records));
                self.phase = Phase::Ending {
                    // Padding records are the ones before the payload, so
                    // the body cannot be complete until the last record.
                    payload_at: Some(SUBMISSION_RECORDS - payload_records),
                    cut: Cut { pending, sealed: 0 },
                };
            }
            ending @ Phase::Ending { .. } => self.phase = ending,
        }
        self.plan_end(table)
    }

    /// What an ending message needs next.
    fn plan_end(&self, table: &ClassTable) -> EndPlan {
        let Phase::Ending { cut, payload_at } = &self.phase else {
            unreachable!("only an ending message plans its end");
        };
        let close = EndPlan::Close {
            counted: cut.sealed > 0,
        };
        match payload_at {
            None if cut.pending.is_empty() => close,
            None => {
                let len = cut.pending.len();
                let class = table.smallest_for(len).expect(
                    "an ordinary tail is at most one record, and the largest class holds that",
                );
                EndPlan::Seal(SealPlan { class, len })
            }
            Some(payload_at) if cut.sealed < *payload_at => EndPlan::Seal(SealPlan {
                class: table.largest(),
                len: 0,
            }),
            Some(_) if cut.pending.is_empty() => {
                debug_assert_eq!(cut.sealed, SUBMISSION_RECORDS);
                close
            }
            Some(_) => EndPlan::Seal(SealPlan {
                class: table.largest(),
                len: cut.pending.len().min(MAX_PAYLOAD),
            }),
        }
    }

    /// The bytes a planned seal will take. Empty when the plan is padding.
    pub(crate) fn prefix(&self, len: usize) -> &[u8] {
        &self.pending()[..len]
    }

    /// The seal succeeded. Padding leaves the buffer, because those
    /// records carry none of it.
    pub(crate) fn commit_seal(&mut self, plan: SealPlan) {
        let (Phase::Ordinary(cut) | Phase::Ending { cut, .. }) = &mut self.phase else {
            unreachable!("a seal was planned from a phase that has no cut");
        };
        if !plan.is_padding() {
            debug_assert!(plan.len <= cut.pending.len());
            cut.pending.drain(..plan.len);
        }
        cut.sealed += 1;
    }

    /// The message is closed and its last record has left.
    pub(crate) fn finish(&mut self) {
        debug_assert!(
            matches!(self.phase, Phase::Ending { ref cut, .. } if cut.pending.is_empty()),
            "only a message whose records are all sealed finishes: {self:?}"
        );
        self.phase = Phase::Idle;
    }

    /// A submission past [`SUBMISSION_CAP`]: its bytes are dropped, and
    /// wiped as they go, without a record sealed.
    pub(crate) fn discard(&mut self) {
        debug_assert!(matches!(self.phase, Phase::Held(_)));
        self.phase = Phase::Idle;
    }
}

/// How many payload records `len` bytes fill. Empty is zero records,
/// not one empty record: a message with no bytes is not flushed as a
/// submission at all.
fn payload_record_count(len: usize) -> usize {
    if len == 0 {
        0
    } else {
        len.div_ceil(MAX_PAYLOAD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive `bytes` in as `kind`, the way `poll_write` does.
    fn push(message: &mut Message, mut bytes: &[u8], kind: MessageKind) {
        let table = class_table();
        while !bytes.is_empty() {
            match message.plan_write(bytes.len(), &table) {
                WritePlan::Accept(n) => {
                    assert!(n > 0, "a non-empty write made no progress");
                    message.accept(&bytes[..n]);
                    bytes = &bytes[n..];
                }
                WritePlan::Classify => message.classify(kind),
                WritePlan::Seal(plan) => {
                    assert!(!plan.is_padding(), "a write seals payload, not padding");
                    message.commit_seal(plan);
                }
                WritePlan::Close { .. } => message.finish(),
                WritePlan::TooLarge => panic!("push stopped at {message:?}"),
            }
        }
    }

    fn flush_seals(message: &mut Message, kind_if_open: Option<MessageKind>) -> Vec<SealPlan> {
        let table = class_table();
        let mut seals = Vec::new();
        loop {
            match message.plan_flush(&table) {
                EndPlan::Classify => {
                    message.classify(kind_if_open.expect("an open message names its kind"));
                }
                EndPlan::Seal(plan) => {
                    seals.push(plan);
                    message.commit_seal(plan);
                }
                EndPlan::Close { .. } => {
                    message.finish();
                    return seals;
                }
                EndPlan::Nothing => return seals,
            }
        }
    }

    #[test]
    fn an_empty_flush_does_not_classify() {
        let mut message = Message::new();
        assert_eq!(message.plan_flush(&class_table()), EndPlan::Nothing);
    }

    #[test]
    fn a_full_record_stays_open_until_another_byte_or_a_flush() {
        let mut message = Message::new();
        push(&mut message, &vec![1; MAX_PAYLOAD], MessageKind::Ordinary);
        assert!(
            matches!(message.phase, Phase::Open(ref buf) if buf.len() == MAX_PAYLOAD),
            "one record is not yet a kind: {message:?}"
        );
        assert_eq!(message.plan_write(1, &class_table()), WritePlan::Classify);
    }

    #[test]
    fn an_ordinary_tail_uses_the_smallest_class() {
        let table = class_table();
        let most = table.max_payload(ClassId(0)).unwrap();
        let mut message = Message::new();
        push(&mut message, &vec![1; most + 1], MessageKind::Ordinary);
        let seals = flush_seals(&mut message, Some(MessageKind::Ordinary));
        assert_eq!(
            seals,
            vec![SealPlan {
                class: ClassId(1),
                len: most + 1,
            }]
        );
    }

    #[test]
    fn an_ordinary_message_past_one_record_seals_the_full_one_while_writing() {
        let mut message = Message::new();
        let mut sealed = 0;
        let table = class_table();
        let mut rest = vec![1; MAX_PAYLOAD + 1];
        while !rest.is_empty() {
            match message.plan_write(rest.len(), &table) {
                WritePlan::Accept(n) => {
                    message.accept(&rest[..n]);
                    rest.drain(..n);
                }
                WritePlan::Classify => message.classify(MessageKind::Ordinary),
                WritePlan::Seal(plan) => {
                    assert_eq!(plan.class, table.largest());
                    assert_eq!(plan.len, MAX_PAYLOAD);
                    message.commit_seal(plan);
                    sealed += 1;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(sealed, 1, "the full record is sealed before the flush");
        let tail = flush_seals(&mut message, None);
        assert_eq!(
            tail,
            vec![SealPlan {
                class: table.smallest_for(1).unwrap(),
                len: 1,
            }]
        );
    }

    #[test]
    fn a_submission_seals_its_padding_before_its_payload() {
        for len in [1, MAX_PAYLOAD, 3 * MAX_PAYLOAD + 7, SUBMISSION_CAP] {
            let mut message = Message::new();
            push(&mut message, &vec![9; len], MessageKind::Submission);
            let seals = flush_seals(&mut message, Some(MessageKind::Submission));
            let largest = class_table().largest();
            assert_eq!(seals.len(), SUBMISSION_RECORDS, "{len} bytes");
            assert!(seals.iter().all(|plan| plan.class == largest), "{len}");
            let padding = seals.iter().take_while(|plan| plan.is_padding()).count();
            let payload: Vec<_> = seals.iter().skip(padding).copied().collect();
            assert!(payload.iter().all(|plan| !plan.is_padding()), "{len}");
            assert_eq!(
                payload.iter().map(|plan| plan.len).sum::<usize>(),
                len,
                "{len} bytes of payload"
            );
            assert_eq!(padding, SUBMISSION_RECORDS - payload_record_count(len));
            assert!(payload
                .iter()
                .rev()
                .skip(1)
                .all(|plan| plan.len == MAX_PAYLOAD));
        }
    }

    /// A byte past the cap is refused, and nothing of the submission was
    /// sealed: there is no record to plan.
    #[test]
    fn a_submission_past_the_cap_is_refused_unsealed() {
        let mut message = Message::new();
        push(
            &mut message,
            &vec![1; SUBMISSION_CAP],
            MessageKind::Submission,
        );
        assert_eq!(message.plan_write(1, &class_table()), WritePlan::TooLarge);
        message.discard();
        assert!(matches!(message.phase, Phase::Idle));
    }

    /// The defect this module was rewritten for: a write after a flush
    /// began never joins the ending message. It is asked to finish the old
    /// message's records first, and only then starts a new message.
    #[test]
    fn a_write_after_a_flush_began_finishes_the_old_message_first() {
        let table = class_table();
        // An ordinary message whose flush began (tail planned, not sealed).
        let mut message = Message::new();
        push(&mut message, b"GET /info", MessageKind::Ordinary);
        assert_eq!(message.plan_flush(&table), EndPlan::Classify);
        message.classify(MessageKind::Ordinary);
        let EndPlan::Seal(tail) = message.plan_flush(&table) else {
            panic!("the tail is planned");
        };
        // The flush is interrupted here. A write arrives.
        assert_eq!(message.plan_write(1_000, &table), WritePlan::Seal(tail));
        message.commit_seal(tail);
        assert_eq!(
            message.plan_write(1_000, &table),
            WritePlan::Close { counted: true }
        );
        message.finish();
        assert_eq!(message.plan_write(1_000, &table), WritePlan::Accept(1_000));

        // A submission whose flush began: the write seals every remaining
        // record of it, padding first, before any new byte is taken.
        let mut message = Message::new();
        push(&mut message, b"x", MessageKind::Submission);
        assert_eq!(message.plan_flush(&table), EndPlan::Classify);
        message.classify(MessageKind::Submission);
        let mut sealed = Vec::new();
        assert!(matches!(message.plan_flush(&table), EndPlan::Seal(_)));
        loop {
            match message.plan_write(1, &table) {
                WritePlan::Seal(plan) => {
                    sealed.push(plan);
                    message.commit_seal(plan);
                }
                WritePlan::Close { counted: true } => break,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(sealed.len(), SUBMISSION_RECORDS);
        assert!(sealed[..SUBMISSION_RECORDS - 1]
            .iter()
            .all(|p| p.is_padding()));
        assert_eq!(sealed[SUBMISSION_RECORDS - 1].len, 1);
    }
}
