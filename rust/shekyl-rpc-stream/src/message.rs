// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How one HTTP message is cut into records.
//!
//! The stream owns the transport. This module owns the bytes that are not
//! sealed yet, and the rule that decides the next record. The two meet at
//! [`WritePlan`] and [`FlushPlan`]: the stream seals only what a plan names,
//! and only then tells the message the seal committed. A seal that fails
//! leaves the bytes where they were.
//!
//! A message is classified once, the moment its kind would change what is
//! sealed. Until then it is [`Phase::Open`] and an arm still applies to it.
//! Classification is a further byte arriving while one full record is
//! buffered, or a flush that finds bytes waiting. An empty flush finds
//! nothing and does not classify, so the arm stays for the next message.
//!
//! An ordinary message streams. One full record is sealed as soon as the
//! next byte arrives, and the tail waits for the flush in the smallest
//! class that holds it. A submission does not stream: its bytes stay
//! buffered until the flush, and the flush seals the padding records
//! first. The HTTP body is then a suffix of the five records, so it is
//! not complete — and a peer cannot answer — until the last record
//! arrives. Sealing the payload first would let that answer start while
//! the padding was still unsent, and the wait would publish the size.

use shekyl_noise::{ClassId, ClassTable, MAX_RECORD_PLAINTEXT, OCCUPANCY_LEN};

/// The channel's class table, in both directions (RT-O6 re-ruled
/// 2026-10-18; RT-O29, 2026-10-20): plaintext lengths, occupancy included.
pub const CLASS_LENGTHS: [usize; 3] = [512, 16_384, MAX_RECORD_PLAINTEXT];

/// The most payload one record carries: a record of the largest class.
pub const MAX_PAYLOAD: usize = MAX_RECORD_PLAINTEXT - OCCUPANCY_LEN;

/// The records every `submit_transaction` upload takes, whatever the
/// transaction's size (RT-O28).
///
/// The largest admissible transaction is `TX_WEIGHT_LIMIT` = 149,400 bytes
/// (weight is size plus the Bp+ clawback). Its request body,
/// `{"tx_blob":"<hex>"}`, is at most 298,814 bytes: 4.56 records. Five
/// leave 28,851 bytes for the request head. A test pins this against
/// `shekyl-wire`'s `TX_WEIGHT_LIMIT`.
pub const SUBMISSION_RECORDS: usize = 5;

/// The most bytes one submission holds. Five largest-class payloads.
/// Past this the message is shed as payload records and refused: there
/// is no room left to pad, and a sixth record is never sealed.
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
    /// The cap has been sealed as payload and drained. Refuse the byte
    /// that did not fit. It was not accepted.
    TooLarge,
    /// A flush is already sealing this message. Its record count was
    /// fixed when the flush began, so more bytes cannot join it.
    Sealing,
}

/// What [`Message::plan_flush`] asks for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FlushPlan {
    /// Bytes are waiting and the kind is not chosen. Consume the mark.
    Classify,
    /// Drain, then seal.
    Seal(SealPlan),
    /// Nothing more to seal. `counted` is a flush that sent records.
    Done { counted: bool },
    /// The cap was shed. The stream drains the last record and refuses.
    TooLarge,
}

/// Bytes not yet sealed, and how many records of this message already are.
struct Cut {
    pending: Vec<u8>,
    sealed: usize,
}

/// Where one message is. The variants are the combinations that can occur.
/// A submission's payload cannot be half-sealed while more bytes are still
/// accepted: that state is [`Phase::Overflow`], which accepts nothing.
enum Phase {
    /// Nothing buffered. A flush here does not classify.
    Idle,
    /// At most one record, kind not chosen.
    Open(Vec<u8>),
    /// Classified ordinary. `pending` is at most one record.
    Ordinary(Cut),
    /// Classified submission. The payload is whole and unsealed, at most
    /// [`SUBMISSION_CAP`].
    Held(Vec<u8>),
    /// Padding while `cut.sealed < payload_at`, then the payload.
    /// `payload_at` is the sealed-count at which the HTTP bytes begin,
    /// so those bytes are a suffix of the five records.
    Flushing { cut: Cut, payload_at: usize },
    /// The payload would pass [`SUBMISSION_CAP`]. Shed it as
    /// [`SUBMISSION_RECORDS`] payload records, then refuse.
    Overflow(Cut),
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
            Self::Flushing { cut, payload_at } => write!(
                f,
                "Flushing(pending {}, sealed {}, payload at {payload_at})",
                cut.pending.len(),
                cut.sealed
            ),
            Self::Overflow(cut) => {
                write!(
                    f,
                    "Overflow(pending {}, sealed {})",
                    cut.pending.len(),
                    cut.sealed
                )
            }
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
            Phase::Ordinary(cut) | Phase::Flushing { cut, .. } | Phase::Overflow(cut) => {
                &cut.pending
            }
        }
    }

    /// The next write step. May move a full submission into [`Phase::Overflow`].
    pub(crate) fn plan_write(&mut self, incoming: usize, largest: ClassId) -> WritePlan {
        if let Phase::Held(buf) = &self.phase {
            if buf.len() == SUBMISSION_CAP && incoming > 0 {
                self.begin_overflow();
            }
        }
        match &self.phase {
            Phase::Flushing { .. } => WritePlan::Sealing,
            Phase::Idle | Phase::Open(_) => self.plan_open_write(incoming),
            Phase::Held(buf) => {
                let room = SUBMISSION_CAP - buf.len();
                WritePlan::Accept(incoming.min(room))
            }
            Phase::Ordinary(cut) => {
                let room = MAX_PAYLOAD - cut.pending.len();
                if room == 0 && incoming > 0 {
                    WritePlan::Seal(SealPlan {
                        class: largest,
                        len: MAX_PAYLOAD,
                    })
                } else {
                    WritePlan::Accept(incoming.min(room))
                }
            }
            Phase::Overflow(cut) => {
                if cut.pending.is_empty() {
                    debug_assert_eq!(cut.sealed, SUBMISSION_RECORDS);
                    WritePlan::TooLarge
                } else {
                    WritePlan::Seal(SealPlan {
                        class: largest,
                        len: cut.pending.len().min(MAX_PAYLOAD),
                    })
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
                let mut buf = Vec::with_capacity(MAX_PAYLOAD);
                buf.extend_from_slice(bytes);
                self.phase = Phase::Open(buf);
            }
            Phase::Open(buf) | Phase::Held(buf) => buf.extend_from_slice(bytes),
            Phase::Ordinary(cut) => cut.pending.extend_from_slice(bytes),
            Phase::Flushing { .. } | Phase::Overflow(_) => {
                unreachable!("a sealing message does not take bytes")
            }
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
                let mut buf = buf;
                // One allocation for the rest of the cap. The flush seals
                // from this buffer; it does not grow a record at a time.
                if buf.capacity() < SUBMISSION_CAP {
                    buf.reserve(SUBMISSION_CAP - buf.capacity());
                }
                Phase::Held(buf)
            }
        };
    }

    /// The next flush step. A held submission becomes [`Phase::Flushing`]
    /// here, before any of it is sealed, so the padding is planned from
    /// the whole payload.
    pub(crate) fn plan_flush(&mut self, table: &ClassTable) -> FlushPlan {
        if matches!(self.phase, Phase::Held(_)) {
            self.begin_flush();
        }
        match &self.phase {
            Phase::Idle => FlushPlan::Done { counted: false },
            Phase::Open(buf) if buf.is_empty() => FlushPlan::Done { counted: false },
            Phase::Open(_) => FlushPlan::Classify,
            Phase::Ordinary(cut) => plan_ordinary_flush(cut, table),
            Phase::Flushing { cut, payload_at } => {
                if cut.sealed < *payload_at {
                    return FlushPlan::Seal(SealPlan {
                        class: table.largest(),
                        len: 0,
                    });
                }
                if cut.pending.is_empty() {
                    debug_assert_eq!(cut.sealed, SUBMISSION_RECORDS);
                    return FlushPlan::Done {
                        counted: cut.sealed > 0,
                    };
                }
                FlushPlan::Seal(SealPlan {
                    class: table.largest(),
                    len: cut.pending.len().min(MAX_PAYLOAD),
                })
            }
            Phase::Held(_) => unreachable!("a held submission starts its flush above"),
            Phase::Overflow(cut) => {
                if cut.pending.is_empty() {
                    FlushPlan::TooLarge
                } else {
                    FlushPlan::Seal(SealPlan {
                        class: table.largest(),
                        len: cut.pending.len().min(MAX_PAYLOAD),
                    })
                }
            }
        }
    }

    /// The bytes a planned seal will take. Empty when the plan is padding.
    pub(crate) fn prefix(&self, len: usize) -> &[u8] {
        &self.pending()[..len]
    }

    /// The seal succeeded. Padding leaves the buffer, because those
    /// records carry none of it.
    pub(crate) fn commit_seal(&mut self, plan: SealPlan) {
        let (Phase::Ordinary(cut) | Phase::Flushing { cut, .. } | Phase::Overflow(cut)) =
            &mut self.phase
        else {
            unreachable!("a seal was planned from a phase that has no cut");
        };
        if !plan.is_padding() {
            debug_assert!(plan.len <= cut.pending.len());
            cut.pending.drain(..plan.len);
        }
        cut.sealed += 1;
    }

    pub(crate) fn finish(&mut self) {
        self.phase = Phase::Idle;
    }

    fn begin_flush(&mut self) {
        let Phase::Held(pending) = std::mem::replace(&mut self.phase, Phase::Idle) else {
            unreachable!("a submission flush starts from held bytes");
        };
        let payload_records = payload_record_count(pending.len());
        debug_assert!(payload_records <= SUBMISSION_RECORDS);
        self.phase = Phase::Flushing {
            // Padding records are the ones before the payload, so the
            // body cannot be complete until the last record.
            payload_at: SUBMISSION_RECORDS - payload_records,
            cut: Cut { pending, sealed: 0 },
        };
    }

    fn begin_overflow(&mut self) {
        let Phase::Held(pending) = std::mem::replace(&mut self.phase, Phase::Idle) else {
            unreachable!("overflow starts from a full submission");
        };
        debug_assert_eq!(pending.len(), SUBMISSION_CAP);
        self.phase = Phase::Overflow(Cut { pending, sealed: 0 });
    }
}

fn plan_ordinary_flush(cut: &Cut, table: &ClassTable) -> FlushPlan {
    if cut.pending.is_empty() {
        return FlushPlan::Done {
            counted: cut.sealed > 0,
        };
    }
    let len = cut.pending.len();
    let class = table
        .smallest_for(len)
        .expect("an ordinary tail is at most one record, and the largest class holds that");
    FlushPlan::Seal(SealPlan { class, len })
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

    fn largest() -> ClassId {
        class_table().largest()
    }

    /// Drive `bytes` in as `kind`, the way `poll_write` does.
    fn push(message: &mut Message, mut bytes: &[u8], kind: MessageKind) {
        let largest = largest();
        while !bytes.is_empty() {
            match message.plan_write(bytes.len(), largest) {
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
                WritePlan::TooLarge | WritePlan::Sealing => {
                    panic!("push stopped at {message:?}")
                }
            }
        }
    }

    fn flush_seals(message: &mut Message, kind_if_open: Option<MessageKind>) -> Vec<SealPlan> {
        let table = class_table();
        let mut seals = Vec::new();
        loop {
            match message.plan_flush(&table) {
                FlushPlan::Classify => {
                    message.classify(kind_if_open.expect("an open message names its kind"));
                }
                FlushPlan::Seal(plan) => {
                    seals.push(plan);
                    message.commit_seal(plan);
                }
                FlushPlan::Done { .. } => {
                    message.finish();
                    return seals;
                }
                FlushPlan::TooLarge => panic!("flush refused {message:?}"),
            }
        }
    }

    #[test]
    fn an_empty_flush_does_not_classify() {
        let mut message = Message::new();
        assert_eq!(
            message.plan_flush(&class_table()),
            FlushPlan::Done { counted: false }
        );
    }

    #[test]
    fn a_full_record_stays_open_until_another_byte_or_a_flush() {
        let mut message = Message::new();
        push(&mut message, &vec![1; MAX_PAYLOAD], MessageKind::Ordinary);
        assert!(
            matches!(message.phase, Phase::Open(ref buf) if buf.len() == MAX_PAYLOAD),
            "one record is not yet a kind: {message:?}"
        );
        assert_eq!(message.plan_write(1, largest()), WritePlan::Classify);
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
        let largest = largest();
        let mut rest = vec![1; MAX_PAYLOAD + 1];
        while !rest.is_empty() {
            match message.plan_write(rest.len(), largest) {
                WritePlan::Accept(n) => {
                    message.accept(&rest[..n]);
                    rest.drain(..n);
                }
                WritePlan::Classify => message.classify(MessageKind::Ordinary),
                WritePlan::Seal(plan) => {
                    assert_eq!(plan.class, largest);
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
                class: class_table().smallest_for(1).unwrap(),
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
            assert_eq!(seals.len(), SUBMISSION_RECORDS, "{len} bytes");
            assert!(seals.iter().all(|plan| plan.class == largest()), "{len}");
            let padding = seals.iter().take_while(|plan| plan.is_padding()).count();
            let payload: Vec<_> = seals.iter().skip(padding).copied().collect();
            assert!(payload.iter().all(|plan| !plan.is_padding()), "{len}");
            assert_eq!(
                payload.iter().map(|plan| plan.len).sum::<usize>(),
                len,
                "{len} bytes of payload"
            );
            let records = payload_record_count(len);
            assert_eq!(padding, SUBMISSION_RECORDS - records, "{len}");
            assert!(payload
                .iter()
                .rev()
                .skip(1)
                .all(|plan| plan.len == MAX_PAYLOAD));
        }
    }

    #[test]
    fn a_submission_past_the_cap_seals_payload_only_and_then_refuses() {
        let mut message = Message::new();
        push(
            &mut message,
            &vec![1; SUBMISSION_CAP],
            MessageKind::Submission,
        );
        let largest = largest();
        assert!(matches!(message.plan_write(1, largest), WritePlan::Seal(_)));
        let mut seals = Vec::new();
        loop {
            match message.plan_write(1, largest) {
                WritePlan::Seal(plan) => {
                    assert!(!plan.is_padding());
                    assert_eq!(plan.len, MAX_PAYLOAD);
                    seals.push(plan);
                    message.commit_seal(plan);
                }
                WritePlan::TooLarge => break,
                other => panic!("{other:?} after {} seals", seals.len()),
            }
        }
        assert_eq!(seals.len(), SUBMISSION_RECORDS);
        message.finish();
        assert!(matches!(message.phase, Phase::Idle));
    }

    #[test]
    fn a_flush_that_has_started_accepts_nothing_more() {
        let mut message = Message::new();
        push(&mut message, b"x", MessageKind::Submission);
        let table = class_table();
        assert_eq!(message.plan_flush(&table), FlushPlan::Classify);
        message.classify(MessageKind::Submission);
        assert!(matches!(message.plan_flush(&table), FlushPlan::Seal(_)));
        assert!(matches!(message.phase, Phase::Flushing { .. }));
        assert_eq!(message.plan_write(1, largest()), WritePlan::Sealing);
    }
}
